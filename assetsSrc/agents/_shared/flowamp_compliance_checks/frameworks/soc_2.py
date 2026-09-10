# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SOC 2 framework template.

SOC 2 Trust Service Criteria focus on security (CC6), availability (CC7),
and confidentiality (C1). Fairness is not a SOC 2 criterion, so that
dimension has zero weight — the RAI Scorer must handle empty/zero-weight
dimensions cleanly (no ZeroDivisionError).

The fairness dimension has dimensionWeight=0.0
and an empty checks list. The scorer must skip zero-weight dimensions from
the per-framework composite computation.
"""

SOC_2_TEMPLATE: dict = {
    "frameworkId": "soc-2",
    "sk": "INFO",
    "name": "SOC 2",
    "description": "SOC 2 Trust Service Criteria alignment (Security, Availability, Confidentiality).",
    "status": "active",
    "raiConfig": {
        "perDimension": {
            "fairness": {
                # SOC 2 does not address fairness directly.
                # Zero weight: scorer must handle this without ZeroDivisionError.
                "checks": [],
                "weights": {},
                "dimensionWeight": 0.0,
            },
            "transparency": {
                "checks": ["bedrock-invocation-logging", "agent-log-group-exists"],
                "weights": {
                    "bedrock-invocation-logging": 0.6,
                    "agent-log-group-exists": 0.4,
                },
                "dimensionWeight": 0.35,
            },
            "accountability": {
                "checks": ["owner-populated", "dlq-configured", "cw-alarms-cover-agent"],
                "weights": {
                    "owner-populated": 0.40,
                    "dlq-configured": 0.30,
                    "cw-alarms-cover-agent": 0.30,
                },
                "dimensionWeight": 0.40,
            },
            "ethics": {
                "checks": ["guardrail-sensitive-info-policy"],
                "weights": {
                    "guardrail-sensitive-info-policy": 1.0,
                },
                "dimensionWeight": 0.25,
            },
        },
        "compositeFormula": "weighted-mean",
    },
    "auditorConfig": {
        "checks": ["audit-frequency", "tagging-compliance"],
        "gradingRubric": {
            "A+": 0.95,
            "A": 0.85,
            "B": 0.75,
            "C": 0.65,
            "D": 0.50,
        },
        "promptInstructions": (
            "Audit against SOC 2 Trust Service Criteria. Focus on availability (DLQ and alarm "
            "coverage), confidentiality (PII guardrail), and security (owner accountability). "
            "The fairness dimension is not part of SOC 2 — skip it in the composite calculation."
        ),
    },
    "escalations": [
        {
            "group": "compliance-team",
            "criteria": "any high or critical check fails",
        },
    ],
}
