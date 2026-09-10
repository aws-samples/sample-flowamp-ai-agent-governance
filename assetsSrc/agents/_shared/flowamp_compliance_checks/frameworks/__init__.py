# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Framework templates for the five built-in compliance frameworks.

Each template matches the INFO row schema in DES-11 §ComplianceFrameworkTable schema.
Per-check override rows (CHECK#{checkId}) are seeded alongside the framework rows.

`ALL_FRAMEWORKS` is exported as a list of framework definition dicts (each carrying a
`frameworkId` key) so callers can iterate framework definitions directly. The
by-id mapping is preserved as `ALL_FRAMEWORKS_BY_ID` for lookups.
"""
from .baseline import BASELINE_TEMPLATE
from .iso_27001 import ISO_27001_TEMPLATE
from .nerc_cip import NERC_CIP_TEMPLATE
from .nist_ai_rmf import NIST_AI_RMF_TEMPLATE
from .soc_2 import SOC_2_TEMPLATE

# List of every framework definition dict. Each dict carries a `frameworkId` key.
ALL_FRAMEWORKS: list[dict] = [
    BASELINE_TEMPLATE,
    NIST_AI_RMF_TEMPLATE,
    ISO_27001_TEMPLATE,
    NERC_CIP_TEMPLATE,
    SOC_2_TEMPLATE,
]

# Mapping of frameworkId -> template, preserved for by-id lookups.
ALL_FRAMEWORKS_BY_ID: dict[str, dict] = {fw["frameworkId"]: fw for fw in ALL_FRAMEWORKS}

__all__ = [
    "ALL_FRAMEWORKS",
    "ALL_FRAMEWORKS_BY_ID",
    "BASELINE_TEMPLATE",
    "NIST_AI_RMF_TEMPLATE",
    "ISO_27001_TEMPLATE",
    "NERC_CIP_TEMPLATE",
    "SOC_2_TEMPLATE",
]
