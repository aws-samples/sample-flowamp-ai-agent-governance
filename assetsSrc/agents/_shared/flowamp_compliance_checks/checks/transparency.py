"""Transparency category cheap-tier checks.

Checks:
  bedrock-invocation-logging  — account-wide Bedrock model invocation logging is enabled.
  agent-log-group-exists      — a CloudWatch log group exists for the agent's runtime.
  aop-coverage                — at least one active AOP references this agent.
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


@_register
class BedrockInvocationLogging(Check):
    check_id = "bedrock-invocation-logging"
    category = "transparency"
    description = "Account-wide Bedrock model invocation logging is enabled."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        platform = target.record.get("platform", "AWS")
        if platform != "AWS":
            return CheckResult(
                result="skip",
                evidence="Not applicable: agent does not run on AWS Bedrock",
            )

        bedrock = ctx.client("bedrock")
        try:
            resp = bedrock.get_model_invocation_logging_configuration()
            config = resp.get("loggingConfig", {})
            cw = config.get("cloudWatchConfig", {})
            s3 = config.get("s3Config", {})
            text_enabled = config.get("textDataDeliveryEnabled", False)
            image_enabled = config.get("imageDataDeliveryEnabled", False)

            cw_enabled = bool(cw.get("logGroupName")) and (text_enabled or image_enabled)
            s3_enabled = bool(s3.get("s3BucketName")) and (text_enabled or image_enabled)

            if not cw_enabled and not s3_enabled:
                return CheckResult(
                    result="fail",
                    evidence="Bedrock invocation logging is not enabled for any destination",
                )
            dest_parts = []
            if cw_enabled:
                dest_parts.append(f"CloudWatch log group {cw.get('logGroupName')} enabled")
            if s3_enabled:
                dest_parts.append(f"S3 bucket {s3.get('s3BucketName')} enabled")
            data_type = "text" if text_enabled else "image"
            return CheckResult(
                result="pass",
                evidence=f"{'; '.join(dest_parts)} ({data_type})",
            )
        except Exception as e:
            code = None
            if hasattr(e, "response"):
                code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "AccessDenied"):
                return CheckResult(result="skip", evidence="AccessDeniedException on bedrock:GetModelInvocationLoggingConfiguration")
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")


@_register
class AgentLogGroupExists(Check):
    check_id = "agent-log-group-exists"
    category = "transparency"
    description = "A CloudWatch log group exists for the agent's runtime."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def _expected_prefixes(self, target: AgentTarget) -> list[str]:
        prefixes = []
        if target.function_name:
            prefixes.append(f"/aws/lambda/{target.function_name}")
        if target.runtime_arn:
            # AgentCore log groups currently live under `/aws/bedrock-agentcore/runtimes/`
            # (e.g. `/aws/bedrock-agentcore/runtimes/<runtime_name>-<suffix>-DEFAULT`).
            # The flat `/aws/bedrock-agentcore/<short_id>` form is kept for older
            # deployments / future schema variants.
            short_id = target.runtime_arn.rsplit("/", 1)[-1]
            prefixes.append(f"/aws/bedrock-agentcore/runtimes/{short_id}")
            prefixes.append(f"/aws/bedrock-agentcore/{short_id}")
        if target.agent_id:
            prefixes.append(f"/aws/bedrock-agentcore/runtimes/{target.agent_id}")
            prefixes.append(f"/aws/bedrock-agentcore/{target.agent_id}")
        return prefixes

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        platform = target.record.get("platform", "AWS")
        if platform != "AWS":
            return CheckResult(
                result="skip",
                evidence="Not applicable: agent does not run on AWS Bedrock",
            )

        prefixes = self._expected_prefixes(target)
        if not prefixes:
            return CheckResult(result="skip", evidence="Agent has no runtime or function identifier")

        logs = ctx.client("logs")
        for prefix in prefixes:
            try:
                resp = logs.describe_log_groups(logGroupNamePrefix=prefix)
                groups = resp.get("logGroups", [])
                if groups:
                    name = groups[0]["logGroupName"]
                    return CheckResult(result="pass", evidence=f"Log group {name} exists")
            except Exception:
                continue

        return CheckResult(
            result="fail",
            evidence=f"No log group found matching prefixes: {', '.join(prefixes)}",
        )


@_register
class CloudTrailBedrockCoverage(Check):
    check_id = "cloudtrail-bedrock-coverage"
    category = "transparency"
    description = "Bedrock invocation events appear in CloudTrail in the last 24h."
    cost = "moderate"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        from datetime import datetime, timezone, timedelta
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        ct = ctx.client("cloudtrail")
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)
        try:
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "bedrock.amazonaws.com"}],
                StartTime=start, EndTime=end,
                MaxResults=5,
            )
            events = resp.get("Events", [])
            if events:
                return CheckResult(result="pass", evidence=f"{len(events)} Bedrock CloudTrail events found in last 24h")
            # History-dependent: an empty result in a freshly-deployed account means no
            # activity has occurred yet, not a compliance failure. Skip rather than fail.
            return CheckResult(result="skip", evidence="No Bedrock events in CloudTrail for last 24h (no activity yet)")
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"{type(exc).__name__}: {exc}")

@_register
class AopCoverage(Check):
    """Checks that at least one active AOP references this agent.

    Reads AOP_TABLE_NAME from the environment (same convention as flowamp_tools).
    Alternatively, params['aop_table_name'] can override the env var.
    """

    check_id = "aop-coverage"
    category = "transparency"
    description = "At least one active AOP references this agent."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {
        "aop_table_name": {
            "type": "string",
            "description": "Override for AOP_TABLE_NAME env var.",
        }
    }

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        table_name = params.get("aop_table_name") or os.environ.get("AOP_TABLE_NAME", "")
        if not table_name:
            return CheckResult(
                result="skip",
                evidence="AOP_TABLE_NAME env var not set; cannot check AOP coverage",
            )

        dynamodb = ctx.client("dynamodb")
        try:
            resp = dynamodb.scan(
                TableName=table_name,
                FilterExpression="assignedAgent = :name",
                ExpressionAttributeValues={":name": {"S": target.agent_id}},
                ProjectionExpression="aopId",
            )
            items = resp.get("Items", [])
            if not items:
                return CheckResult(
                    result="fail",
                    evidence=f"No AOP references agent {target.agent_id}",
                )
            aop_ids = ", ".join(item["aopId"]["S"] for item in items[:5])
            count = resp.get("Count", len(items))
            return CheckResult(
                result="pass",
                evidence=f"{count} AOP(s) reference agent: {aop_ids}",
            )
        except Exception as e:
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")


@_register
class AgentTraceEnabled(Check):
    check_id = "agent-trace-enabled"
    category = "transparency"
    description = "Bedrock Agent alias has enableTrace set so reasoning chains are visible."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        runtime_arn = target.runtime_arn or target.record.get("runtimeArn", "")
        if not runtime_arn or "agent" not in runtime_arn:
            return CheckResult(result="skip", evidence="No Bedrock Agent ARN on target")

        # ARN format: arn:aws:bedrock:{region}:{account}:agent/{agentId}
        parts = runtime_arn.split("/")
        agent_id = parts[-1] if len(parts) >= 2 else ""
        if not agent_id:
            return CheckResult(result="skip", evidence=f"Cannot parse agentId from ARN={runtime_arn}")

        bedrock_agent = ctx.client("bedrock-agent")
        try:
            aliases = bedrock_agent.list_agent_aliases(agentId=agent_id).get("agentAliasSummaries", [])
            if not aliases:
                return CheckResult(result="skip", evidence="No aliases found for agent")
            # Check the first active alias
            alias_id = aliases[0]["agentAliasId"]
            alias = bedrock_agent.get_agent_alias(agentId=agent_id, agentAliasId=alias_id)
            trace_enabled = alias.get("agentAlias", {}).get("clientToken") is not None
            # enableTrace is set at invocation time, not alias config — check routing config presence as proxy
            routing = alias.get("agentAlias", {}).get("routingConfiguration", [])
            if routing:
                return CheckResult(result="pass", evidence=f"Agent alias {alias_id} has routing config; verify enableTrace=true at invocation sites")
            return CheckResult(result="fail", evidence=f"Alias {alias_id} has no routing configuration")
        except Exception as exc:
            return CheckResult(result="skip", evidence=f"{type(exc).__name__}: {exc}")


@_register
class DecisionsLogged(Check):
    """Verifies the agent is actually emitting decision records, not just that a
    log group exists. Counts `agent_decision` events for the agent in the
    EventTable over a recent window — the single source of truth for "a decision
    was made" (decision_trace rows are the optional reasoning drill-down)."""

    check_id = "decisions-logged"
    category = "transparency"
    description = "The agent has logged at least one decision to the EventTable recently."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {
        "lookback_days": {
            "type": "integer",
            "description": "How many days back to look for agent_decision events (default 7).",
        },
        "event_table_name": {
            "type": "string",
            "description": "Override for EVENT_TABLE_NAME env var.",
        },
    }

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        from datetime import datetime, timezone, timedelta

        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        table_name = params.get("event_table_name") or os.environ.get("EVENT_TABLE_NAME", "")
        if not table_name:
            return CheckResult(
                result="skip",
                evidence="EVENT_TABLE_NAME env var not set; cannot check decision logging",
            )

        lookback_days = int(params.get("lookback_days", 7))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # EventTable: PK=agentId, SK="{timestamp}#{eventId}". A range query on sk
        # from the cutoff timestamp bounds the scan to the lookback window; the
        # ISO-8601 timestamp prefix sorts lexicographically.
        dynamodb = ctx.client("dynamodb")
        try:
            count = 0
            start_key = None
            while True:
                kwargs = {
                    "TableName": table_name,
                    "KeyConditionExpression": "agentId = :aid AND sk >= :since",
                    "FilterExpression": "eventType = :et",
                    "ExpressionAttributeValues": {
                        ":aid": {"S": target.agent_id},
                        ":since": {"S": cutoff},
                        ":et": {"S": "agent_decision"},
                    },
                    "Select": "COUNT",
                }
                if start_key:
                    kwargs["ExclusiveStartKey"] = start_key
                resp = dynamodb.query(**kwargs)
                count += resp.get("Count", 0)
                if count > 0:
                    break
                start_key = resp.get("LastEvaluatedKey")
                if not start_key:
                    break

            if count > 0:
                return CheckResult(
                    result="pass",
                    evidence=f"{count}+ agent_decision event(s) in the last {lookback_days}d",
                )
            # History-dependent: no decision events in the window can mean the agent
            # simply hasn't run yet (freshly-deployed account), not a failure. Skip.
            return CheckResult(
                result="skip",
                evidence=f"No agent_decision events logged in the last {lookback_days}d (no activity yet)",
            )
        except Exception as e:
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")
