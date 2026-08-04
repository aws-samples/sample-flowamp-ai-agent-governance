# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Accountability category cheap-tier checks.

Checks:
  owner-populated            — agent record has a non-empty owner field.
  escalation-group-assigned  — agent record has a non-empty escalationGroup field.
  dlq-configured             — Lambda-backed agent has a DLQ configured.
  cw-alarms-cover-agent      — CloudWatch alarms cover the agent's error and duration metrics.
  tagging-compliance         — agent's AWS resource has all required tags.
"""
from __future__ import annotations

from ..base import (
    AgentTarget,
    Check,
    CheckContext,
    CheckResult,
    Target,
    _register,
)

_DEFAULT_REQUIRED_TAGS = ["Owner", "CostCenter", "BusinessUnit", "Environment"]


@_register
class OwnerPopulated(Check):
    check_id = "owner-populated"
    category = "accountability"
    description = "The agent record has a non-empty owner field."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        owner = target.record.get("owner") or target.record.get("ownerId", "")
        if owner:
            return CheckResult(result="pass", evidence=f"owner={owner}")
        return CheckResult(result="fail", evidence="owner field is empty")


@_register
class EscalationGroupAssigned(Check):
    check_id = "escalation-group-assigned"
    category = "accountability"
    description = "The agent record has an escalation group assigned."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        group = target.record.get("escalationGroup", "")
        if group:
            return CheckResult(result="pass", evidence=f"escalationGroup={group}")
        return CheckResult(result="fail", evidence="escalationGroup field is empty")


@_register
class DlqConfigured(Check):
    """Checks that a Lambda-backed agent has a Dead Letter Queue configured.

    AgentCore-backed agents have no DLQ concept today — returns skip for them.
    """

    check_id = "dlq-configured"
    category = "accountability"
    description = "Lambda-backed agent has a Dead Letter Queue configured."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        fn_name = target.function_name
        if not fn_name:
            return CheckResult(
                result="skip",
                evidence="Agent is not Lambda-backed (no function_name); DLQ check not applicable",
            )

        lm = ctx.client("lambda")
        try:
            resp = lm.get_function_configuration(FunctionName=fn_name)
            dlq_arn = resp.get("DeadLetterConfig", {}).get("TargetArn", "")
            if dlq_arn:
                return CheckResult(result="pass", evidence=f"DLQ ARN: {dlq_arn}")
            return CheckResult(result="fail", evidence="No Dead Letter Queue configured on Lambda function")
        except Exception as e:
            code = None
            if hasattr(e, "response"):
                code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "AccessDenied"):
                return CheckResult(result="skip", evidence="AccessDeniedException on lambda:GetFunctionConfiguration")
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")


@_register
class LambdaErrorRate(Check):
    check_id = "lambda-error-rate"
    category = "accountability"
    description = "Lambda error rate over the last 24h is below 5%."
    cost = "moderate"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {"max_error_rate": {"type": "number", "default": 0.05}}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        import time
        if not isinstance(target, AgentTarget) or not target.function_name:
            return CheckResult(result="skip", evidence="No Lambda function name on target")

        cw = ctx.client("cloudwatch")
        end = time.time()
        start = end - 86400
        dims = [{"Name": "FunctionName", "Value": target.function_name}]

        def _sum(metric_name: str) -> float:
            resp = cw.get_metric_statistics(
                Namespace="AWS/Lambda", MetricName=metric_name,
                Dimensions=dims, StartTime=start, EndTime=end,
                Period=86400, Statistics=["Sum"],
            )
            pts = resp.get("Datapoints", [])
            return pts[0]["Sum"] if pts else 0.0

        try:
            invocations = _sum("Invocations")
            errors = _sum("Errors")
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"{type(exc).__name__}: {exc}")

        if invocations == 0:
            return CheckResult(result="skip", evidence="No Lambda invocations in last 24h")

        rate = errors / invocations
        threshold = params.get("max_error_rate", 0.05)
        if rate <= threshold:
            return CheckResult(result="pass", evidence=f"error_rate={rate:.2%} invocations={int(invocations)}")
        return CheckResult(result="fail", evidence=f"error_rate={rate:.2%} exceeds threshold={threshold:.0%}")


@_register
class AgentStaleness(Check):
    check_id = "agent-staleness"
    category = "accountability"
    description = "Agent has been updated within the last 180 days."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {"max_days_stale": {"type": "integer", "default": 180}}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        from datetime import datetime, timezone
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        last_updated = (
            target.record.get("lastUpdatedAt")
            or target.record.get("updatedAt")
            or target.record.get("lastDiscoveredAt")
        )
        if not last_updated:
            return CheckResult(result="fail", evidence="No lastUpdatedAt field on agent record")

        try:
            ts = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        except ValueError:
            return CheckResult(result="skip", evidence=f"Cannot parse lastUpdatedAt={last_updated!r}")

        days_old = (datetime.now(timezone.utc) - ts).days
        threshold = params.get("max_days_stale", 180)
        if days_old <= threshold:
            return CheckResult(result="pass", evidence=f"last_updated={last_updated} days_old={days_old}")
        return CheckResult(result="fail", evidence=f"Agent not updated in {days_old} days (threshold={threshold})")

@_register
class CwAlarmsCovertAgent(Check):
    """Checks that CloudWatch alarms cover the agent's error and duration/throttle metrics."""

    check_id = "cw-alarms-cover-agent"
    category = "accountability"
    description = "CloudWatch alarms cover the agent's Errors and Duration/Throttles metrics."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        cw = ctx.client("cloudwatch")
        found_alarms: list[str] = []
        covers_errors = False
        covers_duration_or_throttles = False

        if target.function_name:
            # Lambda-backed agent — standard AWS/Lambda namespace.
            namespace = "AWS/Lambda"
            metrics_to_check = [
                ("Errors", [{"Name": "FunctionName", "Value": target.function_name}]),
                ("Throttles", [{"Name": "FunctionName", "Value": target.function_name}]),
                ("Duration", [{"Name": "FunctionName", "Value": target.function_name}]),
            ]
        elif target.runtime_arn:
            # AgentCore runtime — metrics live in AWS/Bedrock-AgentCore namespace scoped
            # by the full runtime ARN in the Resource dimension.
            namespace = "AWS/Bedrock-AgentCore"
            dims = [
                {"Name": "Resource", "Value": target.runtime_arn},
                {"Name": "Operation", "Value": "InvokeAgentRuntime"},
            ]
            metrics_to_check = [
                ("Errors", dims),
                ("Throttles", dims),
                ("Duration", dims),
            ]
        else:
            return CheckResult(result="skip", evidence="Agent has no resource identifier for alarm lookup")

        for metric_name, dimensions in metrics_to_check:
            try:
                resp = cw.describe_alarms_for_metric(
                    MetricName=metric_name,
                    Namespace=namespace,
                    Dimensions=dimensions,
                )
                alarms = resp.get("MetricAlarms", [])
                for alarm in alarms:
                    alarm_name = alarm.get("AlarmName", "")
                    found_alarms.append(alarm_name)
                    if metric_name == "Errors":
                        covers_errors = True
                    elif metric_name in ("Duration", "Throttles"):
                        covers_duration_or_throttles = True
            except Exception:
                continue

        resource_label = target.function_name or target.runtime_arn or target.agent_id
        if not found_alarms:
            return CheckResult(result="fail", evidence=f"No CloudWatch alarms found for {resource_label} (namespace={namespace})")

        if not covers_errors or not covers_duration_or_throttles:
            missing = []
            if not covers_errors:
                missing.append("Errors")
            if not covers_duration_or_throttles:
                missing.append("Duration/Throttles")
            return CheckResult(
                result="fail",
                evidence=f"Missing alarms for: {', '.join(missing)} on {resource_label}. Found: {', '.join(found_alarms[:3])}",
            )

        names_sample = ", ".join(found_alarms[:3])
        return CheckResult(
            result="pass",
            evidence=f"{len(found_alarms)} alarm(s): {names_sample}",
        )


@_register
class TaggingCompliance(Check):
    """Checks that the agent's AWS resource has all required tags.

    Default required tags: Owner, CostCenter, Environment.
    Override via params['required_tags'] (list of strings).
    """

    check_id = "tagging-compliance"
    category = "accountability"
    description = "Agent AWS resource has all required tags (Owner, CostCenter, BusinessUnit, Environment by default)."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "low"
    parameter_schema = {
        "required_tags": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Tags that must be present. Defaults to "
                "[Owner, CostCenter, BusinessUnit, Environment] — the standard "
                "AWS Cost Allocation Tag names. Platform-internal "
                "`{namespace}:*` tags are intentionally NOT required here so "
                "this check stays portable across deploys with different "
                "namespace values."
            ),
        }
    }

    # Agent INFO fields checked for non-AWS agents — camelCase matches DynamoDB/API field names.
    _NON_AWS_INFO_FIELDS = ["owner", "costCenter", "environment"]

    def _check_non_aws_info_fields(self, target: AgentTarget) -> CheckResult:
        """For non-AWS agents check the agent INFO row directly for required fields."""
        missing = [f for f in self._NON_AWS_INFO_FIELDS if not target.record.get(f)]
        if missing:
            return CheckResult(
                result="fail",
                evidence=(
                    f"Missing agent INFO fields for non-AWS agent: {', '.join(missing)}; "
                    "source=agent-info-fields"
                ),
            )
        return CheckResult(
            result="pass",
            evidence=(
                f"All required fields present on agent INFO row "
                f"(owner, costCenter, environment); source=agent-info-fields"
            ),
        )

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        platform = target.record.get("platform", "AWS")
        if platform != "AWS":
            return self._check_non_aws_info_fields(target)

        required = params.get("required_tags", _DEFAULT_REQUIRED_TAGS)
        tags: dict[str, str] = {}

        fn_name = target.function_name
        resource_arn = target.runtime_arn or target.primary_resource_id

        if fn_name:
            lm = ctx.client("lambda")
            try:
                resp = lm.list_tags(Resource=f"arn:aws:lambda:{target.region or 'us-east-1'}:*:function:{fn_name}")
                tags = resp.get("Tags", {})
            except Exception as e:
                code = None
                if hasattr(e, "response"):
                    code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDeniedException", "AccessDenied"):
                    return CheckResult(result="skip", evidence="AccessDeniedException on lambda:ListTags")
                return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")
        elif resource_arn:
            # Try bedrock-agentcore ListTagsForResource
            try:
                agentcore = ctx.client("bedrock-agentcore")
                resp = agentcore.list_tags_for_resource(resourceArn=resource_arn)
                tags = resp.get("tags", {})
            except Exception:
                # Fall back to record-level tags (populated by Discovery Scanner)
                tags = target.record.get("tags", {})
        else:
            tags = target.record.get("tags", {})

        missing = [t for t in required if t not in tags]
        if missing:
            return CheckResult(
                result="fail",
                evidence=f"missing tags: {', '.join(missing)}",
            )
        return CheckResult(
            result="pass",
            evidence=f"All required tags present: {', '.join(required)}",
        )
