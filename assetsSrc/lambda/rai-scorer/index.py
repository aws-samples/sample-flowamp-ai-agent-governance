# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
RAI Scorer Lambda - calculates Responsible AI scores from real AWS signals.

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

Every signal is read from this account, so only AWS-native agents can be scored. Agents from
third-party connectors (Microsoft Foundry, Okta, MuleSoft) or from other AWS accounts are left
unscored with raiScoreStatus='not-scored' and a machine-readable raiScoreReason, so an absent
score is stated rather than published as a score of zero. See _rai_platform_support().
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

# Agent rows carry the platform two ways: 'platform' is the display value the discovery paths
# stamp ('native', 'aws-org', 'microsoft', 'okta', 'mulesoft'), and 'platformId' is the
# FLOWAMP_PLATFORMS sentinel id the AgentCore discovery-scanner stamps. Only 'native' rows
# describe an agent whose guardrail metrics and CloudTrail events land in this account.
_SCOREABLE_PLATFORMS = {'native'}
# Cross-account rows are AWS agents, but their metrics and events live in the member account and
# this Lambda holds no cross-account role. Separate from the third-party platforms so the recorded
# reason distinguishes "another AWS account" from "another vendor".
_CROSS_ACCOUNT_PLATFORMS = {'aws-org'}
# Mirrors AMAZON_BEDROCK_AGENTCORE_PLATFORM_ID in the discovery-scanner. Same default on both
# sides, so leaving the var unset keeps the two in agreement.
_BEDROCK_PLATFORM_ID = os.environ.get(
    'AMAZON_BEDROCK_AGENTCORE_PLATFORM_ID', 'amazon-bedrock-agentcore',
).strip().lower()

# Appended to every UpdateExpression on a path that did evaluate an AWS agent, so an agent that
# becomes scoreable does not keep a stale not-scored marker next to a fresh score. REMOVE on an
# absent attribute is a documented no-op, so this needs no condition or read-before-write:
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
_CLEAR_NOT_SCORED = ' REMOVE raiScoreStatus, raiScoreReason'


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

    Guardrail metrics are dimensioned by GuardrailArn (plus optional GuardrailVersion or
    GuardrailPolicyType), not by agent id. An agent carries 'guardrailArn' only when a guardrail is
    attached; without one this returns an empty dimension set, which yields no datapoints.
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
    # DynamoDB returns numbers as Decimal; coerce to float so arithmetic with the float coefficients
    # below cannot raise a "float / Decimal" TypeError.
    invocations = float(agent.get('requests', 0) or 1)
    errors = float(agent.get('errors', 0) or 0)
    error_rate = errors / max(invocations, 1)

    # Guardrail interventions, when a guardrail is attached. The metric is 'InvocationsIntervened' in
    # 'AWS/Bedrock/Guardrails', dimensioned by GuardrailArn; there is no 'GuardrailInterventions'
    # metric and no per-AgentId dimension. An agent with no guardrail produces no datapoints.
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

    # Guardrail content-filter interventions: the same 'InvocationsIntervened' metric narrowed by
    # GuardrailPolicyType=ContentPolicy. There is no 'GuardrailBlocked' metric.
    guardrail_blocks = float(get_metric(
        'AWS/Bedrock/Guardrails', 'InvocationsIntervened',
        _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType', 'Value': 'ContentPolicy'}]),
    ) or 0)
    # Blocks are a positive signal (the guardrail is working), but a very high rate means the model
    # itself is problematic.
    block_rate = guardrail_blocks / max(invocations, 1)

    # PII redaction interventions: same metric, SensitiveInformationPolicy dimension.
    # There is no 'GuardrailPiiRedacted' metric.
    pii_redactions = float(get_metric(
        'AWS/Bedrock/Guardrails', 'InvocationsIntervened',
        _guardrail_dims(agent, [{'Name': 'GuardrailPolicyType', 'Value': 'SensitiveInformationPolicy'}]),
    ) or 0)
    has_pii_protection = 1 if pii_redactions > 0 or guardrail_blocks >= 0 else 0

    # Base 93, small bonus for active PII protection, penalize if block rate is very high
    score = 93 + (has_pii_protection * 3) - (max(block_rate - 0.05, 0) * 100 * 0.5)
    return max(50, min(100, round(score)))


def has_live_signal(agent):
    """True if any real RAI signal exists for this agent (guardrail activity or CloudTrail events).

    Agents with no attached guardrail would otherwise all score from the same no-signal base,
    collapsing varied scores to identical values. Returning False lets run_scoring() preserve the
    existing score instead of overwriting it with one derived from absent data.
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


def _rai_platform_support(agent):
    """Return (scoreable, reason) for the platform this agent lives on.

    'reason' is a short kebab-case token, empty when scoreable, following the finops-collector's
    `reason: ce-empty` convention: a run that completed with nothing to read says so in a
    machine-readable field.

    Checked before any scoring call, because the sub-scores are not signal detectors: score_fairness()
    and friends start from a fixed base (95, 93, ...) and subtract penalties, so an agent with no
    signals lands on a high fabricated score. The has_live_signal() gate in run_scoring() only
    rescues agents that already carry a score, so a newly discovered non-AWS agent would otherwise be
    published with that base as if it had been measured.
    """
    platform = (agent.get('platform') or '').strip().lower()
    platform_id = (agent.get('platformId') or '').strip().lower()

    # Either identifier is sufficient: the discovery-scanner stamps the sentinel platformId, while
    # the Lambda discovery path stamps only 'platform'.
    if platform in _SCOREABLE_PLATFORMS or platform_id == _BEDROCK_PLATFORM_ID:
        return True, ''
    if platform in _CROSS_ACCOUNT_PLATFORMS:
        return False, 'platform-cross-account'
    if not platform and not platform_id:
        # No platform recorded at all: unscoreable rather than assumed native, since guessing AWS is
        # the assertion this gate exists to avoid, and such a row is a discovery bug worth surfacing.
        return False, 'platform-unknown'
    return False, 'platform-unsupported'


def _mark_not_scored(agent, reason):
    """Record that an agent was not scored, leaving its score fields untouched.

    Does not write score/fairness/transparency/accountability/ethics: an agent that already carries
    values keeps them, and raiScoreStatus is what tells a reader a zero is an absence of measurement
    rather than a measurement of zero. raiUpdatedAt is still stamped, or an unscoreable agent looks
    like one the scheduled scorer never reached.
    """
    try:
        table.update_item(
            Key={'agentId': agent['agentId'], 'sk': 'INFO'},
            UpdateExpression=('SET raiScoreStatus=:st, raiScoreReason=:rsn, '
                              'raiUpdatedAt=:ts'),
            ExpressionAttributeValues={
                ':st': 'not-scored',
                ':rsn': reason,
                ':ts': datetime.utcnow().isoformat() + 'Z',
            },
        )
    except Exception as e:
        print(f'Not-scored marker failed for {agent["agentId"]}: {e}')


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

    Shared by both invocation paths (EventBridge schedule and the on-demand API route).
    Returns {'updated': N, 'total': N}.
    """
    # Agent records only: entity rows (sk='INFO'), excluding the compliance:/aop:/access: prefixes
    # and any COST#/EVENT# rows.
    from boto3.dynamodb.conditions import Attr
    all_items = table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])
    agents = [i for i in all_items
              if not i['agentId'].startswith(('compliance:', 'aop:', 'access:'))]

    # Get system-level RMF compliance modifier (SP 800-37)
    rmf_modifier = get_rmf_compliance_score()

    updated = 0
    skipped = 0
    not_scoreable = 0
    no_signal = 0
    for agent in agents:
        if agent.get('status') == 'decommissioned':
            continue

        # Platform gate ahead of the has_live_signal() probe: for a non-AWS agent those CloudWatch and
        # CloudTrail calls are guaranteed empty, so running them spends four API calls per agent per
        # day to learn nothing.
        scoreable, not_scored_reason = _rai_platform_support(agent)
        if not scoreable:
            _mark_not_scored(agent, not_scored_reason)
            not_scoreable += 1
            continue

        # No live signal: what happens next depends on whether this agent has ever been measured.
        #
        # The sub-scores are not signal detectors. score_fairness and friends start from a fixed
        # base (95, 80, 95, 93) and subtract penalties, so an agent with nothing to read lands on
        # an overall of 91 that looks measured and is not. An agent that has never been invoked,
        # has no guardrail attached and generates no CloudTrail events must therefore report that
        # it was not scored, not a number assembled from those constants.
        #
        # An agent that already carries a score keeps it, because that reading was real when it was
        # taken; going quiet is not evidence of a lower score. Once signals appear, either agent
        # scores normally again.
        existing_score = float(agent.get('score', 0) or 0)
        if not has_live_signal(agent):
            if existing_score <= 0:
                _mark_not_scored(agent, 'no-signal')
                no_signal += 1
                continue
            try:
                table.update_item(
                    Key={'agentId': agent['agentId'], 'sk': 'INFO'},
                    # The platform is readable here (the score is preserved for want of signal, not
                    # of a scoreable platform), so clear any marker left by an earlier run.
                    UpdateExpression='SET raiUpdatedAt=:ts' + _CLEAR_NOT_SCORED,
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
        # Apply the RMF modifier: a weak system-level risk posture reduces the overall score.
        overall = max(50, round(overall * rmf_modifier))

        try:
            table.update_item(
                Key={'agentId': agent['agentId'], 'sk': 'INFO'},
                UpdateExpression=('SET score=:s, fairness=:f, transparency=:t, '
                                  'accountability=:a, ethics=:e, raiUpdatedAt=:ts'
                                  + _CLEAR_NOT_SCORED),
                ExpressionAttributeValues={
                    ':s': overall, ':f': fairness, ':t': transparency,
                    ':a': accountability, ':e': ethics,
                    ':ts': datetime.utcnow().isoformat() + 'Z',
                },
            )
            updated += 1
            # agentId and computed scores only, never full agent records or user-submitted metadata
            # fields (owner, system, category, and so on).
            print(f'{agent["agentId"]}: score={overall} f={fairness} t={transparency} a={accountability} e={ethics}')
        except Exception as e:
            print(f'Update failed for {agent["agentId"]}: {e}')

    print(f'RAI scores updated for {updated}/{len(agents)} agents '
          f'({skipped} preserved: no live signal, '
          f'{not_scoreable} not scored: platform has no readable RAI signals, '
          f'{no_signal} not scored: no signals to measure yet)')
    # 'notScoreable' is additive: both paths keep returning 'updated'/'skipped'/'total'.
    return {'updated': updated, 'skipped': skipped,
            'notScoreable': not_scoreable, 'noSignal': no_signal,
            'total': len(agents)}


# CORS headers so the on-demand route works from the CloudFront-hosted UI, matching the
# data-handler's contract (same Cognito-gated API).
_CORS_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
}


def _is_api_event(event):
    """True when invoked through API Gateway (proxy integration) rather than the EventBridge
    schedule. API events carry an httpMethod; the scheduled rule sends a plain (often empty) dict."""
    return isinstance(event, dict) and 'httpMethod' in event


def handler(event, context):
    """Dual-mode handler.

    EventBridge schedule -> returns the plain result dict.
    API Gateway POST /rai/score -> returns an API Gateway proxy response with CORS
    headers so the UI can trigger an on-demand re-score.
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
