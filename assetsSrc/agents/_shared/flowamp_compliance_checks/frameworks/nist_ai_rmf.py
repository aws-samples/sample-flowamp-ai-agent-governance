# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""NIST AI Risk Management Framework template.

Aligns to NIST AI RMF GOVERN/MAP/MEASURE/MANAGE.
Moderate-tier checks (decision-trace-coverage, prompt-versioning, iam-no-wildcard-actions)
are not yet implemented and are therefore absent from the checks lists below, not present
and always failing.
"""

NIST_AI_RMF_TEMPLATE: dict = {
    "frameworkId": "nist-ai-rmf",
    "sk": "INFO",
    "name": "NIST AI Risk Management Framework",
    "description": "NIST AI RMF GOVERN/MAP/MEASURE/MANAGE alignment.",
    "status": "active",
    "raiConfig": {
        "perDimension": {
            "fairness": {
                "checks": ["guardrail-attached", "guardrail-content-policy"],
                # Not yet implemented: "negative-feedback-rate".
                "weights": {
                    "guardrail-attached": 0.5,
                    "guardrail-content-policy": 0.5,
                },
                "dimensionWeight": 0.25,
            },
            "transparency": {
                "checks": ["bedrock-invocation-logging", "aop-coverage"],
                # Not yet implemented: "decision-trace-coverage", "prompt-versioning".
                "weights": {
                    "bedrock-invocation-logging": 0.5,
                    "aop-coverage": 0.5,
                },
                "dimensionWeight": 0.25,
            },
            "accountability": {
                "checks": ["owner-populated", "escalation-group-assigned"],
                # Not yet implemented: "iam-no-wildcard-actions".
                "weights": {
                    "owner-populated": 0.5,
                    "escalation-group-assigned": 0.5,
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
        "checks": ["audit-frequency"],
        "gradingRubric": {
            "A+": 0.95,
            "A": 0.85,
            "B": 0.75,
            "C": 0.65,
            "D": 0.50,
        },
        "promptInstructions": (
            "Audit against NIST AI RMF Govern/Map/Measure/Manage. Flag any agents without "
            "documented owner, ungoverned guardrail policy, or missing audit cadence."
        ),
    },
    "escalations": [
        {"group": "compliance-team", "criteria": "any critical or high check fails"},
    ],
}
