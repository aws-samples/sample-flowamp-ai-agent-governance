# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Framework definition access — code-defined frameworks.

Compliance framework definitions are **code-defined** in the
``flowamp_compliance_checks.frameworks`` registry and read from there. Per-agent
framework *assignments* (COMPLIANCE#<id> rows) live on the shared AgentTable and
are read via :func:`list_agent_frameworks` (re-exported from compliance).

Because frameworks are governed as code, the user-editing write path
(put_framework / soft_delete_framework) is not supported here. Both functions
raise NotImplementedError so any accidental caller fails loudly rather than
silently writing to a table that does not exist.
"""
from __future__ import annotations

from .compliance import list_agent_frameworks  # re-export for symmetry


def _framework_registry() -> dict[str, dict]:
    """Return {frameworkId: definition} from the code-defined checks package.

    Imported lazily so flowamp_tools consumers that never touch compliance
    (e.g. the discovery-scanner) don't pull the checks package into memory.
    """
    from flowamp_compliance_checks.frameworks import ALL_FRAMEWORKS
    return {fw["frameworkId"]: fw for fw in ALL_FRAMEWORKS}


def get_framework(framework_id: str) -> dict | None:
    """Return the code-defined framework definition for framework_id, or None."""
    return _framework_registry().get(framework_id)


def list_frameworks(include_inactive: bool = False) -> list[dict]:
    """Return all code-defined framework definitions.

    include_inactive is accepted for signature compatibility; code-defined
    frameworks are always considered active.
    """
    return list(_framework_registry().values())


def put_framework(*args, **kwargs) -> None:
    """Unsupported — frameworks are code-defined in this deployment."""
    raise NotImplementedError(
        "Framework definitions are governed as code (flowamp_compliance_checks.frameworks) "
        "in this deployment; runtime framework edits are not supported."
    )


def soft_delete_framework(*args, **kwargs) -> None:
    """Unsupported — frameworks are code-defined in this deployment."""
    raise NotImplementedError(
        "Framework definitions are governed as code (flowamp_compliance_checks.frameworks) "
        "in this deployment; runtime framework deletion is not supported."
    )


__all__ = [
    "get_framework",
    "list_frameworks",
    "put_framework",
    "soft_delete_framework",
    "list_agent_frameworks",
]
