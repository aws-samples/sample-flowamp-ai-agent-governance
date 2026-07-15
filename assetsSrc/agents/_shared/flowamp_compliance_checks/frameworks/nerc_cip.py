"""NERC CIP (Critical Infrastructure Protection) framework template.

Focused on grid-operations AI agents. Data residency and VPC isolation are
critical-severity concerns for grid systems. Audit frequency is mandatory.
"""

NERC_CIP_TEMPLATE: dict = {
    "frameworkId": "nerc-cip",
    "sk": "INFO",
    "name": "NERC CIP",
    "description": "NERC Critical Infrastructure Protection standards for grid-operations AI agents.",
    "status": "active",
    "raiConfig": {
        "perDimension": {
            "fairness": {
                # NERC CIP focuses less on fairness; guardrail presence is still a baseline.
                "checks": ["guardrail-attached"],
                "weights": {
                    "guardrail-attached": 1.0,
                },
                "dimensionWeight": 0.10,
            },
            "transparency": {
                "checks": ["bedrock-invocation-logging", "agent-log-group-exists"],
                "weights": {
                    "bedrock-invocation-logging": 0.6,
                    "agent-log-group-exists": 0.4,
                },
                "dimensionWeight": 0.30,
            },
            "accountability": {
                "checks": ["owner-populated", "cw-alarms-cover-agent"],
                "weights": {
                    "owner-populated": 0.5,
                    "cw-alarms-cover-agent": 0.5,
                },
                "dimensionWeight": 0.35,
            },
            "ethics": {
                "checks": ["model-on-approved-list"],
                "weights": {
                    "model-on-approved-list": 1.0,
                },
                "dimensionWeight": 0.25,
            },
        },
        "compositeFormula": "weighted-mean",
    },
    "auditorConfig": {
        "checks": ["vpc-isolated", "data-residency-region", "audit-frequency"],
        "gradingRubric": {
            "A+": 0.95,
            "A": 0.85,
            "B": 0.75,
            "C": 0.65,
            "D": 0.50,
        },
        "promptInstructions": (
            "Audit against NERC CIP standards. For grid-operations AI agents, VPC isolation and "
            "data residency within approved US regions are non-negotiable. Flag any agent whose "
            "audit cadence exceeds 7 days or whose model is not on the approved list."
        ),
    },
    "escalations": [
        {
            "group": "platform-engineering",
            "criteria": "VPC isolation OR data residency check fails",
        },
        {
            "group": "compliance-team",
            "criteria": "any critical check fails",
        },
    ],
}
