# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""FlowAMP Baseline framework template.

The customer-editable organisational baseline, applied to every agent. It references every
check that can be evaluated from signals inside the account, across all four Responsible AI
dimensions. Weights within a dimension sum to 1.0, and the four dimension weights sum to 1.0.

A check that cannot be evaluated returns 'skip' and is excluded from the score rather than
counted as a failure, so a control that is merely unconfigured does not read as one the agent
failed. See _compute_rai_composite in the compliance-scanner.
"""

BASELINE_TEMPLATE: dict = {
    "frameworkId": "FLOWAMP_BASELINE",
    "sk": "INFO",
    "name": "FlowAMP Baseline",
    "description": "Customer-editable organisational baseline applied to every agent.",
    "status": "active",
    "raiConfig": {
        "perDimension": {
            "fairness": {
                "checks": [
                    "guardrail-attached",
                    "guardrail-content-policy",
                    # Skips unless BEDROCK_INVOCATION_LOG_BUCKET is set and the scanner role can
                    # read that bucket, so it reports "not configured" rather than failing.
                    "invocation-log-pii-sample",
                    "user-feedback-rate",
                    "guardrail-intervention-rate",
                ],
                "weights": {
                    "guardrail-attached": 0.30,
                    "guardrail-content-policy": 0.25,
                    "guardrail-intervention-rate": 0.20,
                    "invocation-log-pii-sample": 0.15,
                    "user-feedback-rate": 0.10,
                },
                "dimensionWeight": 0.25,
            },
            "transparency": {
                "checks": [
                    "bedrock-invocation-logging",
                    "agent-log-group-exists",
                    "decisions-logged",
                    "aop-coverage",
                    "agent-trace-enabled",
                    "cloudtrail-bedrock-coverage",
                ],
                "weights": {
                    "bedrock-invocation-logging": 0.25,
                    "agent-log-group-exists": 0.15,
                    "decisions-logged": 0.15,
                    "aop-coverage": 0.15,
                    "agent-trace-enabled": 0.15,
                    "cloudtrail-bedrock-coverage": 0.15,
                },
                "dimensionWeight": 0.25,
            },
            "accountability": {
                "checks": [
                    "owner-populated",
                    "escalation-group-assigned",
                    "dlq-configured",
                    "cw-alarms-cover-agent",
                    "tagging-compliance",
                    "lambda-error-rate",
                    "agent-staleness",
                ],
                "weights": {
                    "owner-populated": 0.24,
                    "escalation-group-assigned": 0.20,
                    "dlq-configured": 0.12,
                    "cw-alarms-cover-agent": 0.16,
                    "tagging-compliance": 0.08,
                    "lambda-error-rate": 0.12,
                    "agent-staleness": 0.08,
                },
                "dimensionWeight": 0.25,
            },
            "ethics": {
                "checks": [
                    "guardrail-sensitive-info-policy",
                    "guardrail-topic-policy",
                    "model-on-approved-list",
                ],
                "weights": {
                    "guardrail-sensitive-info-policy": 0.4,
                    "guardrail-topic-policy": 0.3,
                    "model-on-approved-list": 0.3,
                },
                "dimensionWeight": 0.25,
            },
        },
        "compositeFormula": "weighted-mean",
    },
    "auditorConfig": {
        "checks": ["tagging-compliance", "audit-frequency", "appconfig-model-selection"],
        "gradingRubric": {
            "A+": 0.95,
            "A": 0.85,
            "B": 0.75,
            "C": 0.65,
            "D": 0.50,
        },
        "promptInstructions": (
            "Evaluate this agent against the baseline organisational standards. Flag any agent "
            "missing an owner, escalation group, or guardrail. Pay attention to whether prior audits "
            "have already been resolved via human override."
        ),
    },
    "escalations": [
        {"group": "compliance-team", "criteria": "any critical check fails"},
    ],
}
