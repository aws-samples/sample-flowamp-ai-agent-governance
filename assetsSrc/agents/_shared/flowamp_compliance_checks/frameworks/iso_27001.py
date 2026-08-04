# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ISO 27001 framework template.

Focuses on information security controls. VPC isolation and tagging are elevated
because ISO 27001 A.9 (access control) and A.12 (operations security) directly
apply to network isolation and resource inventory.
"""

ISO_27001_TEMPLATE: dict = {
    "frameworkId": "iso-27001",
    "sk": "INFO",
    "name": "ISO/IEC 27001",
    "description": "ISO 27001 information security management alignment for AI agents.",
    "status": "active",
    "raiConfig": {
        "perDimension": {
            "fairness": {
                "checks": ["guardrail-attached", "guardrail-content-policy"],
                "weights": {
                    "guardrail-attached": 0.5,
                    "guardrail-content-policy": 0.5,
                },
                "dimensionWeight": 0.20,
            },
            "transparency": {
                "checks": ["bedrock-invocation-logging"],
                # Deferred to U-079: "prompt-versioning"
                "weights": {
                    "bedrock-invocation-logging": 1.0,
                },
                "dimensionWeight": 0.25,
            },
            "accountability": {
                "checks": ["owner-populated", "escalation-group-assigned"],
                "weights": {
                    "owner-populated": 0.6,
                    "escalation-group-assigned": 0.4,
                },
                "dimensionWeight": 0.30,
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
        "checks": ["vpc-isolated", "tagging-compliance"],
        "gradingRubric": {
            "A+": 0.95,
            "A": 0.85,
            "B": 0.75,
            "C": 0.65,
            "D": 0.50,
        },
        "promptInstructions": (
            "Audit against ISO 27001 information security controls. Pay close attention to "
            "access control (A.9), operational security (A.12), and whether the agent's "
            "network isolation and resource tagging meet documentation standards."
        ),
    },
    "escalations": [
        {
            "group": "platform-engineering",
            "criteria": "VPC isolation check fails",
        },
        {
            "group": "compliance-team",
            "criteria": "any critical check fails",
        },
    ],
}
