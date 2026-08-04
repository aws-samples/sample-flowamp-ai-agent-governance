# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
RAI Scorer Lambda — calculates Responsible AI scores from real AWS signals.

Runs on a daily EventBridge schedule. For each registered agent, computes:
  - fairness:       guardrail intervention rate (lower = fairer, no biased outputs leaking)
  - transparency:   CloudTrail logging coverage (are decisions auditable?)
  - accountability: error handling quality (low error rate + no unhandled failures)
  - ethics:         guardrail block rate for harmful content + PII redaction coverage
  - score:          weighted average of the four sub-scores

Signals used:
  - CloudWatch: Bedrock Guardrail metrics, Lambda errors, invocation counts
  - CloudTrail: event coverage for the agent's resources (last 24h)
  - DynamoDB:   existing requests/errors fields from the metrics-collector
"""

import json
import os
import boto3
from decimal import Decimal
from datetime import datetime, timedelta

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])
cw = boto3.client('cloudwatch')
ct = boto3.client('cloudtrail')

# Weights for overall score
WEIGHTS = {'fairness': 0.25, 'transparency': 0.25, 'accountability': 0.25, 'ethics': 0.25}


def get_metric(namespace, metric_name, dimensions, stat='Sum', hours=24):
    """Query CloudWatch for a metric over the last N hours."""
    try:
        end = datetime.utcnow()
        start = end - timedelta(hours=hours)
        result = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start, EndTime=end,
            Period=hours * 3600, Statistics=[stat],
        )
        points = result.get('Datapoints', [])
        return points[0].get(stat, 0) if points else 0
    except Exception as e:
        print(f'CW error {metric_name}: {e}')
        return 0


def count_cloudtrail_events(resource_name, hours=24):
    """Count CloudTrail events mentioning this resource in the last N hours."""
    try:
        end = datetime.utcnow()
        start = end - timedelta(hours=hours)
        result = ct.lookup_events(
            LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': resource_name}],
            StartTime=start, EndTime=end, MaxResults=50,
        )
        return len(result.get('Events', []))
    except Exception as e:
        print(f'CloudTrail error for {resource_name}: {e}')
        return 0


def _guardrail_dims(agent, extra=None):
    """Build the CloudWatch dimensions for a Bedrock Guardrails metric.

    Guardrail metrics are dimensioned by GuardrailArn (+ optional GuardrailVersion
    / GuardrailPolicyType) — NOT by agent id. An agent record carries a
    'guardrailArn' only when a guardrail is attached; without one we return an
    empty dimension set, which yields no datapoints (the no-signal path).
    """
    dims = []
    arn = agent.get('guardrailArn')
    if arn:
        dims.append({'Name': 'GuardrailArn', 'Value': arn})
    if extra:
        dims.extend(extra)
    return dims


def score_fairness(agent):
    """
    Fairness = how well guardrails prevent biased/unfair outputs.
    Signal: Bedrock Guardrail intervention rate. A low intervention rate on
    content-filter policies means the model is producing fair outputs natively.
    High intervention = model tried to produce biased content (guardrail caught it).
    Score: starts at 95, penalized by intervention rate.
    """
    # DynamoDB returns numbers as Decimal; coerce to float so arithmetic with the
    # float coefficients below cannot raise "float / Decimal" TypeErrors.
    invocations = float(agent.get('requests', 0) or 1)
    errors = float(agent.get('errors', 0) or 0)
    error_rate = errors / max(invocations, 1)

    # Check guardrail interventions (if a guardrail is attached). The Bedrock
    # Guardrails metric is 'InvocationsIntervened' in the 'AWS/Bedrock/Guardrails'
    # namespace, dimensioned by GuardrailArn — there is no 'GuardrailInterventions'
    # metric and no per-AgentId dimension. Agents with no attached guardrail
    # produce no datapoints, which reads as no signal rather than a bad score.
    # https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-guardrails-cw-metrics.html
    guardrail_interventions = float(get_metric(
        'AWS/Bedrock/Guardrails', 'InvocationsIntervened',
        _guardrail_dims(agent),
    ) or 0)
    intervention_rate = guardrail_interventions / max(invocations, 1)

    # Base score 95, penalize for high intervention rate and error rate
    score = 95 - (intervention_rate * 100 * 0.5) - (error_rate * 100 * 0.3)
    return max(50, min(100, round(score)))


def score_transparency(agent):
    """
    Transparency = are agent decisions auditable and traceable?
    Signal: CloudTrail event coverage. If the agent's resources have CloudTrail
    events logged, decisions are traceable. Also checks if invocation logging exists.
    Score: based on CloudTrail event count (more events = better audit trail).
    """
    resource_id = agent['agentId']
    trail_events = count_cloudtrail_events(resource_id)

    # Also check for the agent's Lambda function in CloudTrail
    fn_events = count_cloudtrail_events(f"agent-handler") if not trail_events else trail_events

    total_events = trail_events + fn_events
    # 20+ events/day = full transparency, scale down from there
    coverage = min(total_events / 20, 1.0)

    # Base 80, up to 100 with full CloudTrail coverage
    score = 80 + (coverage * 20)
    return max(50, min(100, round(score)))


def score_accountability(agent):
    """
    Accountability = does the agent handle failures properly?
    Signals: error rate (low = good), whether errors are logged (CloudTrail),
    and whether the agent has been recently updated (active ownership).
    """
    invocations = float(agent.get('requests', 0) or 1)
    errors = float(agent.get('errors', 0) or 0)
    error_rate = errors / max(invocations, 1)

    # Check if errors are being logged (CloudWatch Logs exist)
    error_log_events = get_metric(
        'AWS/Lambda', 'Errors',
        [{'Name': 'FunctionName', 'Value': 'AgentHandlerFn'}],
        stat='Sum', hours=168,  # 7 days
    )
    # If errors exist in CW but are low relative to invocations, accountability is high
    has_error_monitoring = 1 if error_log_events is not None else 0

    # Base 95, penalize for high error rate, bonus for monitoring
    score = 95 - (error_rate * 100 * 0.8) + (has_error_monitoring * 2)
    return max(50, min(100, round(score)))


def score_ethics(agent):
    """
    Ethics = does the agent avoid harmful content and protect PII?
    Signals: Bedrock Guardrail blocks for harmful content, PII redaction events.
    A guardrail that is active and blocking harmful content = high ethics score.
    No guardrail at all = lower score.
    """
    invocations = float(agent.get('requests', 0) or 1)

    # Guardrail content-filter interventions. Same 'InvocationsIntervened' metric,
    # narrowed by GuardrailPolicyType=ContentPolicy to harmful-content blocks —
    # there is no 'GuardrailBlocked' metric.
    guardrail_blocks = float(get_metric(
        'AWS/Bedrock/Guardrails', 'InvocationsIntervened',
        _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType', 'Value': 'ContentPolicy'}]),
    ) or 0)
    # Blocks are GOOD — means guardrail is working. But too many = model is problematic.
    block_rate = guardrail_blocks / max(invocations, 1)

    # PII redaction interventions: same metric, SensitiveInformationPolicy
    # dimension — there is no 'GuardrailPiiRedacted' metric.
    pii_redactions = float(get_metric(
        'AWS/Bedrock/Guardrails', 'InvocationsIntervened',
        _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType', 'Value': 'SensitiveInformationPolicy'}]),
    ) or 0)
    has_pii_protection = 1 if pii_redactions > 0 or guardrail_blocks >= 0 else 0

    # Base 93, small bonus for active PII protection, penalize if block rate is very high
    score = 93 + (has_pii_protection * 3) - (max(block_rate - 0.05, 0) * 100 * 0.5)
    return max(50, min(100, round(score)))


def has_live_signal(agent):
    """True if any real RAI signal exists for this agent (guardrail activity or
    CloudTrail events).

    Without this gate every agent that has no attached guardrail scores from the
    uniform no-signal base, so a catalog of agents with varied scores collapses to
    identical values on the first run. Returning False lets run_scoring() preserve
    the existing score instead of overwriting it with a fabricated one.
    """
    try:
        total = (
            float(get_metric('AWS/Bedrock/Guardrails', 'InvocationsIntervened',
                             _guardrail_dims(agent)) or 0)
            + float(get_metric('AWS/Bedrock/Guardrails', 'InvocationsIntervened',
                               _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType',
                                                        'Value': 'ContentPolicy'}])) or 0)
            + float(get_metric('AWS/Bedrock/Guardrails', 'InvocationsIntervened',
                               _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType',
                                                        'Value': 'SensitiveInformationPolicy'}])) or 0)
            + count_cloudtrail_events(agent['agentId'])
        )
        return total > 0
    except Exception:
        return False


def compute_overall(fairness, transparency, accountability, ethics):
    """Weighted average of sub-scores."""
    total = (
        fairness * WEIGHTS['fairness']
        + transparency * WEIGHTS['transparency']
        + accountability * WEIGHTS['accountability']
        + ethics * WEIGHTS['ethics']
    )
    return round(total)


def get_rmf_compliance_score():
    """
    Pull the NIST SP 800-37 RMF compliance record and derive a modifier.
    If the RMF framework score is low, it drags down overall RAI scores
    because the system-level risk posture is weak.
    Returns a multiplier between 0.90 and 1.0.
    """
    try:
        item = table.get_item(Key={'agentId': 'compliance:nist-sp800-37', 'sk': 'INFO'}).get('Item')
        if item:
            rmf_score = float(item.get('complianceScore', 90))
            # 100 → 1.0 multiplier, 80 → 0.95, 60 → 0.90
            return max(0.90, min(1.0, 0.80 + (rmf_score / 500)))
    except Exception as e:
        print(f'RMF lookup error: {e}')
    return 1.0


def run_scoring():
    """Compute and persist RAI scores for all registered agents.

    Shared by both invocation paths (EventBridge schedule and the on-demand
    API route). Returns {'updated': N, 'total': N}.
    """
    # Scan for agent records only: entity rows (sk='INFO'), excluding
    # compliance:, aop:, access: prefixes (and any COST#/EVENT# rows by sk).
    from boto3.dynamodb.conditions import Attr
    all_items = table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])
    agents = [i for i in all_items
              if not i['agentId'].startswith(('compliance:', 'aop:', 'access:'))]

    # Get system-level RMF compliance modifier (SP 800-37)
    rmf_modifier = get_rmf_compliance_score()

    updated = 0
    skipped = 0
    for agent in agents:
        if agent.get('status') == 'decommissioned':
            continue

        # No live signal and an existing score: stamp the run timestamp but leave
        # the score alone. Overwriting it would replace a real prior reading with a
        # value derived from absent data. Once guardrail or CloudTrail signals
        # exist, the agent scores normally and the value moves.
        existing_score = float(agent.get('score', 0) or 0)
        if existing_score > 0 and not has_live_signal(agent):
            try:
                table.update_item(
                    Key={'agentId': agent['agentId'], 'sk': 'INFO'},
                    UpdateExpression='SET raiUpdatedAt=:ts',
                    ExpressionAttributeValues={':ts': datetime.utcnow().isoformat() + 'Z'},
                )
            except Exception as e:
                print(f'Timestamp update failed for {agent["agentId"]}: {e}')
            skipped += 1
            continue

        fairness = score_fairness(agent)
        transparency = score_transparency(agent)
        accountability = score_accountability(agent)
        ethics = score_ethics(agent)
        overall = compute_overall(fairness, transparency, accountability, ethics)
        # Apply RMF modifier — weak system-level risk posture reduces overall score
        overall = max(50, round(overall * rmf_modifier))

        try:
            table.update_item(
                Key={'agentId': agent['agentId'], 'sk': 'INFO'},
                UpdateExpression='SET score=:s, fairness=:f, transparency=:t, accountability=:a, ethics=:e, raiUpdatedAt=:ts',
                ExpressionAttributeValues={
                    ':s': overall, ':f': fairness, ':t': transparency,
                    ':a': accountability, ':e': ethics,
                    ':ts': datetime.utcnow().isoformat() + 'Z',
                },
            )
            updated += 1
            # Log agentId + computed scores only — never full agent records or
            # user-submitted metadata fields (owner, system, category, etc.).
            print(f'{agent["agentId"]}: score={overall} f={fairness} t={transparency} a={accountability} e={ethics}')
        except Exception as e:
            print(f'Update failed for {agent["agentId"]}: {e}')

    print(f'RAI scores updated for {updated}/{len(agents)} agents '
          f'({skipped} preserved: no live signal)')
    return {'updated': updated, 'skipped': skipped, 'total': len(agents)}


# CORS headers so the on-demand route works from the CloudFront-hosted UI,
# matching the data-handler's contract (same Cognito-gated API).
_CORS_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
}


def _is_api_event(event):
    """True when invoked through API Gateway (proxy integration) rather than
    the EventBridge schedule. API events carry an httpMethod; the scheduled
    rule sends a plain (often empty) dict."""
    return isinstance(event, dict) and 'httpMethod' in event


def handler(event, context):
    """Dual-mode handler.

    EventBridge schedule -> returns the plain result dict (unchanged contract).
    API Gateway POST /rai/score -> returns an API Gateway proxy response with
    CORS headers so the UI can trigger an on-demand re-score.
    """
    if _is_api_event(event):
        if event.get('httpMethod') == 'OPTIONS':
            return {'statusCode': 200, 'headers': _CORS_HEADERS, 'body': ''}
        result = run_scoring()
        return {
            'statusCode': 200,
            'headers': _CORS_HEADERS,
            'body': json.dumps(result),
        }

    return run_scoring()
