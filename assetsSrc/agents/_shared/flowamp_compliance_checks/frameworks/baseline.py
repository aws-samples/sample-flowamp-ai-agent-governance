# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""FlowAMP Baseline framework template.

The FLOWAMP_BASELINE framework is the customer-editable organisational baseline
applied to every agent. It references all 17 cheap-tier checks shipped in U-078.
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
                "checks": ["guardrail-attached", "guardrail-content-policy"],
                "weights": {
                    "guardrail-attached": 0.6,
                    "guardrail-content-policy": 0.4,
                },
                "dimensionWeight": 0.25,
            },
            "transparency": {
                "checks": [
                    "bedrock-invocation-logging",
                    "agent-log-group-exists",
                    "decisions-logged",
                    "aop-coverage",
                ],
                "weights": {
                    "bedrock-invocation-logging": 0.4,
                    "agent-log-group-exists": 0.2,
                    "decisions-logged": 0.2,
                    "aop-coverage": 0.2,
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
                ],
                "weights": {
                    "owner-populated": 0.30,
                    "escalation-group-assigned": 0.25,
                    "dlq-configured": 0.15,
                    "cw-alarms-cover-agent": 0.20,
                    "tagging-compliance": 0.10,
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
