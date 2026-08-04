# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Operational category cheap-tier checks.

Checks:
  vpc-isolated              — agent's Lambda is inside a VPC (uses AwsConfigCheck).
  data-residency-region     — agent's resources are in an approved AWS region.
  audit-frequency           — a compliance audit was performed within the allowed window.
  appconfig-model-selection — agent's model is in the AppConfig active model set.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ..base import (
    AgentTarget,
    AwsConfigCheck,
    Check,
    CheckContext,
    CheckResult,
    Target,
    _register,
)


@_register
class VpcIsolated(AwsConfigCheck):
    """Verifies the agent's Lambda function (or primary resource) is inside a VPC.

    Relies on an AWS Config managed rule such as `lambda-inside-vpc`.
    Falls back to inspecting target.record.get('vpcConfig') if Discovery Scanner
    has populated it. Returns skip when AWS Config is unavailable in the account.
    """

    check_id = "vpc-isolated"
    category = "operational"
    description = "Agent's primary AWS resource is deployed inside a VPC."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    resource_type = "AWS::Lambda::Function"

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        # If the Discovery Scanner has stored vpcConfig in the record, use it directly.
        if isinstance(target, AgentTarget):
            vpc_config = target.record.get("vpcConfig", {})
            if vpc_config:
                subnet_ids = vpc_config.get("subnetIds", []) or vpc_config.get("SubnetIds", [])
                if subnet_ids:
                    return CheckResult(
                        result="pass",
                        evidence=f"Agent is VPC-isolated (subnets: {', '.join(str(s) for s in subnet_ids[:2])})",
                    )

        # Delegate to AwsConfigCheck parent for rule-based evaluation.
        return super().evaluate(target, params, ctx)


@_register
class DataResidencyRegion(Check):
    """Verifies the agent's resources are in an approved AWS region.

    Derives the region from target.runtime_arn, target.role_arn, or target.region.
    Allowed regions default to ["us-east-1", "us-west-2"].
    Override via params['allowed_regions'].
    """

    check_id = "data-residency-region"
    category = "operational"
    description = "Agent resources are deployed in an approved AWS region."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "critical"
    parameter_schema = {
        "allowed_regions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Allowed AWS region codes. Defaults to [us-east-1, us-west-2].",
        }
    }

    _DEFAULT_ALLOWED = ["us-east-1", "us-west-2"]

    def _resolve_region(self, target: AgentTarget) -> str | None:
        # Parse region from ARN components.
        for arn in (target.runtime_arn, target.role_arn, target.primary_resource_id):
            if arn and arn.startswith("arn:aws"):
                parts = arn.split(":")
                if len(parts) >= 4 and parts[3]:
                    return parts[3]
        return target.region

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        allowed = params.get("allowed_regions", self._DEFAULT_ALLOWED)
        region = self._resolve_region(target)
        if not region:
            return CheckResult(result="skip", evidence="Cannot determine agent region from ARN or record")

        if region in allowed:
            return CheckResult(
                result="pass",
                evidence=f"region {region} is in allowed list: {', '.join(allowed)}",
            )
        return CheckResult(
            result="fail",
            evidence=f"region {region} is NOT in allowed list: {', '.join(allowed)}",
        )


@_register
class AuditFrequency(Check):
    """Checks that a compliance audit was performed within the allowed window.

    Queries AgentComplianceTable for the latest AUDIT# row for this agent.
    Reads AGENT_COMPLIANCE_TABLE_NAME from the environment.
    Default max_age_days is 7; override via params['max_age_days'].
    """

    check_id = "audit-frequency"
    category = "operational"
    description = "A compliance audit was performed within the allowed window."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {
        "max_age_days": {
            "type": "integer",
            "description": "Maximum days since last audit. Defaults to 7.",
        },
        "compliance_table_name": {
            "type": "string",
            "description": "Override for AGENT_COMPLIANCE_TABLE_NAME env var.",
        },
    }

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        table_name = params.get("compliance_table_name") or os.environ.get(
            "AGENT_COMPLIANCE_TABLE_NAME", ""
        )
        if not table_name:
            return CheckResult(
                result="skip",
                evidence="AGENT_COMPLIANCE_TABLE_NAME env var not set; cannot check audit frequency",
            )

        max_age = int(params.get("max_age_days", 7))
        dynamodb = ctx.client("dynamodb")
        try:
            resp = dynamodb.query(
                TableName=table_name,
                KeyConditionExpression="agentId = :pk AND begins_with(sk, :prefix)",
                ExpressionAttributeValues={
                    ":pk": {"S": target.agent_id},
                    ":prefix": {"S": "AUDIT#"},
                },
                Limit=1,
                ScanIndexForward=False,
            )
            items = resp.get("Items", [])
        except Exception as e:
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")

        if not items:
            return CheckResult(
                result="fail",
                evidence=f"No AUDIT row found for agent {target.agent_id}",
            )

        # sk format: AUDIT#{ISO-ts}
        sk = items[0].get("sk", {}).get("S", "")
        ts_str = sk.removeprefix("AUDIT#")
        try:
            audit_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            # createdAt fallback
            created_at = items[0].get("createdAt", {}).get("S", "")
            try:
                audit_ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                return CheckResult(result="skip", evidence=f"Cannot parse audit timestamp from sk={sk}")

        now = datetime.now(tz=timezone.utc)
        age_days = (now - audit_ts).days
        if age_days > max_age:
            return CheckResult(
                result="fail",
                evidence=f"Latest audit is {age_days} days old (max {max_age})",
            )
        return CheckResult(
            result="pass",
            evidence=f"Latest audit {age_days} day(s) ago (max {max_age})",
        )


@_register
class AppconfigModelSelection(Check):
    """Checks that the agent's model is in the AppConfig active model set.

    When params['active_models'] is empty (the current default — AppConfig is not
    yet wired in the platform), the check returns skip. This is intentional per
    plan Risk R-4; the check skeleton is ready for when AppConfig is wired in a
    future sprint.
    """

    check_id = "appconfig-model-selection"
    category = "operational"
    description = "Agent's model is in the AppConfig active model selection set."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "low"
    parameter_schema = {
        "active_models": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Active model list from AppConfig. Empty = skip (AppConfig not wired).",
        }
    }

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        active_models: list[str] = params.get("active_models", [])
        if not active_models:
            return CheckResult(
                result="skip",
                evidence="active_models param not provided; AppConfig not yet wired in this environment",
            )

        model = target.record.get("model", "")
        if not model:
            return CheckResult(result="skip", evidence="Agent record has no model field")

        if model in active_models:
            return CheckResult(
                result="pass",
                evidence=f"model '{model}' is in the AppConfig active set",
            )
        return CheckResult(
            result="fail",
            evidence=f"model '{model}' is NOT in the AppConfig active set ({len(active_models)} models active)",
        )
