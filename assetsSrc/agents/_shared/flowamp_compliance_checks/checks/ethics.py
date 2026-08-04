# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Ethics category cheap-tier checks.

Checks:
  guardrail-sensitive-info-policy — guardrail has PII/regex sensitive-information rules.
  guardrail-topic-policy          — guardrail has at least one DENY topic configured.
  model-on-approved-list          — agent's model is in the FLOWAMP_MODELS registry.
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

# Import the shared guardrail resolver from fairness.
# Delayed import to avoid circular dependency issues at module load.
def _get_guardrail(target: AgentTarget, ctx: CheckContext) -> dict | None:
    from .fairness import _resolve_guardrail

    return _resolve_guardrail(target, ctx)


@_register
class GuardrailSensitiveInfoPolicy(Check):
    check_id = "guardrail-sensitive-info-policy"
    category = "ethics"
    description = "The agent's Bedrock guardrail has a sensitive-information policy (PII or regex rules)."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        guardrail = _get_guardrail(target, ctx)
        if guardrail is None:
            return CheckResult(result="skip", evidence="No guardrail attached — see guardrail-attached check")

        if guardrail.get("_partial"):
            return CheckResult(result="skip", evidence="Could not retrieve guardrail details")

        sip = guardrail.get("sensitiveInformationPolicy", {}) or guardrail.get("sensitiveInformationPolicyConfig", {})
        pii_entities = sip.get("piiEntitiesConfig", []) or sip.get("piiEntities", [])
        regexes = sip.get("regexesConfig", []) or sip.get("regexes", [])

        if not pii_entities and not regexes:
            return CheckResult(
                result="fail",
                evidence="Guardrail has no sensitive-information policy (no PII entities or regex rules)",
            )

        parts = []
        if pii_entities:
            entity_types = ", ".join(sorted(e.get("type", "UNKNOWN") for e in pii_entities[:3]))
            parts.append(f"{len(pii_entities)} PII entity rule(s): {entity_types}")
        if regexes:
            parts.append(f"{len(regexes)} regex rule(s)")
        return CheckResult(result="pass", evidence="; ".join(parts))


@_register
class GuardrailTopicPolicy(Check):
    check_id = "guardrail-topic-policy"
    category = "ethics"
    description = "The agent's Bedrock guardrail has at least one DENY topic configured."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "medium"
    parameter_schema = {}

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        guardrail = _get_guardrail(target, ctx)
        if guardrail is None:
            return CheckResult(result="skip", evidence="No guardrail attached — see guardrail-attached check")

        if guardrail.get("_partial"):
            return CheckResult(result="skip", evidence="Could not retrieve guardrail details")

        tp = guardrail.get("topicPolicy", {}) or guardrail.get("topicPolicyConfig", {})
        topics = tp.get("topicsConfig", []) or tp.get("topics", [])
        deny_topics = [t for t in topics if t.get("type", "") == "DENY" or t.get("action", "") == "DENY"]

        if not deny_topics:
            return CheckResult(result="fail", evidence="Guardrail has no DENY topic policy configured")

        names = ", ".join(t.get("name", "unknown") for t in deny_topics[:3])
        return CheckResult(
            result="pass",
            evidence=f"{len(deny_topics)} DENY topic(s): {names}",
        )


@_register
class ModelOnApprovedList(Check):
    """Checks that the agent's model is in the FLOWAMP_MODELS registry.

    Queries AgentTable for rows under agentId='FLOWAMP_MODELS' with
    begins_with(sk, 'MODEL#'). A model is approved if it exists in that
    partition and its status is not 'deprecated'.

    Reads AGENT_TABLE_NAME from the environment (same convention as flowamp_tools).
    """

    check_id = "model-on-approved-list"
    category = "ethics"
    description = "The agent's model is in the FLOWAMP_MODELS approved model registry."
    cost = "cheap"
    applies_to = ["agent"]
    default_severity = "high"
    parameter_schema = {
        "agent_table_name": {
            "type": "string",
            "description": "Override for AGENT_TABLE_NAME env var.",
        }
    }

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        if not isinstance(target, AgentTarget):
            return CheckResult(result="skip", evidence="Check only applies to AgentTarget")

        model = target.record.get("model", "")
        if not model:
            return CheckResult(result="skip", evidence="Agent record has no model field")

        table_name = params.get("agent_table_name") or os.environ.get("AGENT_TABLE_NAME", "")
        if not table_name:
            return CheckResult(
                result="skip",
                evidence="AGENT_TABLE_NAME env var not set; cannot look up model registry",
            )

        dynamodb = ctx.client("dynamodb")
        try:
            resp = dynamodb.query(
                TableName=table_name,
                KeyConditionExpression="agentId = :pk AND begins_with(sk, :prefix)",
                ExpressionAttributeValues={
                    ":pk": {"S": "FLOWAMP_MODELS"},
                    ":prefix": {"S": "MODEL#"},
                },
                ProjectionExpression="sk, #st",
                ExpressionAttributeNames={"#st": "status"},
            )
            items = resp.get("Items", [])
        except Exception as e:
            return CheckResult(result="skip", evidence=f"{type(e).__name__}: {e}")

        # Build map of model_key -> status
        registry: dict[str, str] = {}
        for item in items:
            sk = item.get("sk", {}).get("S", "")
            # sk format: MODEL#{model_name}
            model_key = sk.removeprefix("MODEL#")
            status = item.get("status", {}).get("S", "active")
            registry[model_key] = status

        if not registry:
            return CheckResult(
                result="skip",
                evidence="FLOWAMP_MODELS registry is empty; cannot validate model",
            )

        status = registry.get(model)
        if status is None:
            return CheckResult(
                result="fail",
                evidence=f"model '{model}' is not in the FLOWAMP_MODELS registry",
            )
        if status == "deprecated":
            return CheckResult(
                result="fail",
                evidence=f"model '{model}' is deprecated in the FLOWAMP_MODELS registry",
            )
        return CheckResult(
            result="pass",
            evidence=f"model '{model}' is approved (status={status})",
        )
