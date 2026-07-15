"""Fairness category cheap-tier checks.

Checks:
  guardrail-attached         — verifies a Bedrock guardrail is configured on the agent.
  guardrail-content-policy   — verifies the guardrail has at least one content filter.
"""
from __future__ import annotations
import os
from ..base import (
    AgentTarget,
    Check,
    CheckContext,
    CheckResult,
    Target,
    _register,
)


def _resolve_guardrail(target: AgentTarget, ctx: CheckContext) -> dict | None:
    """Fetch and cache the guardrail config for target.

    Returns the guardrail dict or None if no guardrail is attached.
    Caches under "_guardrail::{agent_id}" in ctx.cache to avoid a second
    API call from guardrail-content-policy within the same run.
    """
    cache_key = f"_guardrail::{target.agent_id}"
    if cache_key in ctx.cache:
        return ctx.cache[cache_key]

    guardrail_id: str | None = None

    # Try live API first
    if target.runtime_arn or target.primary_resource_id:
        bedrock = ctx.client("bedrock")
        try:
            resource_id = target.primary_resource_id or ""
            # For AgentCore runtimes the ARN is the resource ID; strip to runtime ID.
            short_id = resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id
            resp = bedrock.get_agent(agentId=short_id)
            guardrail_id = (
                resp.get("agent", {})
                .get("guardrailConfiguration", {})
                .get("guardrailIdentifier")
            )
        except Exception:
            pass

    # Fall back to the record populated by Discovery Scanner.
    if not guardrail_id:
        guardrail_id = target.record.get("guardrailId") or target.record.get("guardrailIdentifier")

    if not guardrail_id:
        ctx.cache[cache_key] = None
        return None

    # Fetch the full guardrail definition.
    bedrock = ctx.client("bedrock")
    try:
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        ctx.cache[cache_key] = guardrail
        return guardrail
    except Exception:
        # Store the ID so subsequent checks know there's a guardrail even if details fail.
        ctx.cache[cache_key] = {"guardrailId": guardrail_id, "_partial": True}
        return ctx.cache[cache_key]


@_register
class GuardrailAttached(Check):
    check_id = "guardrail-attached"
    category = "fairness"
    description = "A Bedrock guardrail is attached to the agent."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    # Keywords that indicate guardrail / content-filter evidence in agent comments.
    _GUARDRAIL_KEYWORDS = (
        "guardrail", "content filter", "output filter", "safety layer",
    )

    def _check_non_aws_evidence(self, target: AgentTarget) -> CheckResult:
        """For non-AWS agents look for guardrail evidence in registration comments."""
        comment_fields = [
            target.record.get("registrationComments", "") or "",
            target.record.get("approvalNotes", "") or "",
        ]
        combined = " ".join(comment_fields).lower()
        for keyword in self._GUARDRAIL_KEYWORDS:
            if keyword in combined:
                return CheckResult(
                    result="pass",
                    evidence=f"Guardrail evidence found in registration comments (keyword: '{keyword}'); source=registration-comments",
                )
        return CheckResult(
            result="skip",
            evidence="Non-AWS agent: no guardrail evidence in registration comments",
            requiresWorkItem=True,
        )

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        platform = target.record.get("platform", "AWS")
        if platform != "AWS":
            return self._check_non_aws_evidence(target)

        guardrail = _resolve_guardrail(target, ctx)
        if guardrail is None:
            return CheckResult(result="fail", evidence="No guardrail attached to agent")

        gid = guardrail.get("guardrailId") or guardrail.get("guardrailIdentifier", "unknown")
        version = guardrail.get("version", "DRAFT")
        return CheckResult(
            result="pass",
            evidence=f"guardrailIdentifier={gid}, version={version}",
        )


@_register
class GuardrailContentPolicy(Check):
    check_id = "guardrail-content-policy"
    category = "fairness"
    description = "The agent's Bedrock guardrail has at least one content filter configured."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        guardrail = _resolve_guardrail(target, ctx)
        if guardrail is None:
            return CheckResult(result="skip", evidence="No guardrail attached — see guardrail-attached check")

        if guardrail.get("_partial"):
            return CheckResult(result="skip", evidence="Could not retrieve guardrail details")

        cp = guardrail.get("contentPolicy", {}) or guardrail.get("contentPolicyConfig", {})
        filters = cp.get("filters", []) or cp.get("filtersConfig", [])
        if not filters:
            return CheckResult(result="fail", evidence="Guardrail has no content policy filters configured")

        filter_types = ", ".join(sorted(f.get("type", "UNKNOWN") for f in filters))
        return CheckResult(
            result="pass",
            evidence=f"contentPolicy has {len(filters)} filters: {filter_types}",
        )
    
    
@_register
class GuardrailInterventionRate(Check):
    check_id = "guardrail-intervention-rate"
    category = "fairness"
    description = "Guardrail intervention rate over the last 24h is below 10%."
    cost = "moderate"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {"max_intervention_rate": {"type": "number", "default": 0.10}}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        import time
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        guardrail = _resolve_guardrail(target, ctx)
        if not guardrail:
            return CheckResult(result="skip", evidence="No guardrail attached — see guardrail-attached check")
        guardrail_id = guardrail.get("guardrailId") or guardrail.get("guardrailIdentifier", "")
        if not guardrail_id:
            return CheckResult(result="skip", evidence="Could not determine guardrail ID from attached guardrail")

        cw = ctx.client("cloudwatch")
        end = time.time()
        start = end - 86400  # 24h

        def _get_stat(metric_name: str) -> float:
            resp = cw.get_metric_statistics(
                Namespace="AWS/Bedrock",
                MetricName=metric_name,
                Dimensions=[{"Name": "GuardrailId", "Value": guardrail_id}],
                StartTime=start, EndTime=end,
                Period=86400, Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return points[0]["Sum"] if points else 0.0

        try:
            invocations = _get_stat("GuardrailInvocations")
            intervened = _get_stat("GuardrailsIntervened")
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"{type(exc).__name__}: {exc}")

        if invocations == 0:
            return CheckResult(result="skip", evidence="No guardrail invocations in last 24h")

        rate = intervened / invocations
        threshold = params.get("max_intervention_rate", 0.10)
        if rate <= threshold:
            return CheckResult(result="pass", evidence=f"intervention_rate={rate:.2%} invocations={int(invocations)}")
        return CheckResult(result="fail", evidence=f"intervention_rate={rate:.2%} exceeds threshold={threshold:.0%}")


@_register
class InvocationLogPiiSample(Check):
    check_id = "invocation-log-pii-sample"
    category = "fairness"
    description = "Samples recent Bedrock invocation logs from S3 for PII patterns."
    cost = "expensive"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {"sample_count": {"type": "integer", "default": 10}}

    _PII_PATTERNS = [
        r"\b\d{3}-\d{2}-\d{4}\b",          # SSN
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",     # Visa card
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # email
    ]

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        import re, json as _json
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        log_bucket = os.environ.get("BEDROCK_INVOCATION_LOG_BUCKET", "")
        if not log_bucket:
            return CheckResult(result="skip", evidence="BEDROCK_INVOCATION_LOG_BUCKET not set")

        # Bedrock invocation logs are organized by account/region/date, not agent ID.
        # Prefix: bedrock-invocations/AWSLogs/{account}/BedrockModelInvocationLogs/
        # Sampling the root prefix covers all recent model calls in the account.
        s3 = ctx.client("s3")
        prefix = "bedrock-invocations/"
        try:
            objects = s3.list_objects_v2(Bucket=log_bucket, Prefix=prefix, MaxKeys=params.get("sample_count", 10))
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"S3 list failed: {exc}")

        keys = [o["Key"] for o in objects.get("Contents", [])]
        if not keys:
            return CheckResult(result="skip", evidence=f"No invocation logs found at s3://{log_bucket}/{prefix}")

        patterns = [re.compile(p) for p in self._PII_PATTERNS]
        hits = []
        for key in keys:
            try:
                body = s3.get_object(Bucket=log_bucket, Key=key)["Body"].read().decode("utf-8", errors="ignore")
                for pat in patterns:
                    if pat.search(body):
                        hits.append(key)
                        break
            except Exception:
                continue

        if not hits:
            return CheckResult(result="pass", evidence=f"Sampled {len(keys)} logs, no PII patterns detected")
        # Report only the detection count — never the S3 object keys, which
        # identify the specific log objects that contain PII.
        return CheckResult(result="fail", evidence=f"PII pattern detected in {len(hits)}/{len(keys)} sampled logs")


@_register
class UserFeedbackRate(Check):
    check_id = "user-feedback-rate"
    category = "fairness"
    description = "At least one user_feedback event recorded for the agent in the last 30 days."
    cost = "moderate"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {"lookback_days": {"type": "integer", "default": 30}}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        event_table = os.environ.get("EVENT_TABLE_NAME", "")
        if not event_table:
            return CheckResult(result="skip", evidence="EVENT_TABLE_NAME not set")

        from datetime import datetime, timedelta, timezone
        lookback_days = params.get("lookback_days", 30)
        from_ts = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        ddb = ctx.client("dynamodb")
        try:
            response = ddb.query(
                TableName=event_table,
                KeyConditionExpression="agentId = :aid AND sk >= :from_ts",
                FilterExpression="eventType = :et",
                ExpressionAttributeValues={
                    ":aid": {"S": target.agent_id},
                    ":from_ts": {"S": from_ts},
                    ":et": {"S": "user_feedback"},
                },
                Select="COUNT",
            )
            count = response.get("Count", 0)
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"{type(exc).__name__}: {exc}")

        if count == 0:
            # History-dependent: no feedback events in a freshly-deployed account means
            # no user activity has been recorded yet, not a compliance failure. Skip.
            return CheckResult(
                result="skip",
                evidence=f"No user_feedback events in last {lookback_days} days (no activity yet)",
            )
        return CheckResult(
            result="pass",
            evidence=f"{count} user_feedback event(s) in last {lookback_days} days",
        )
