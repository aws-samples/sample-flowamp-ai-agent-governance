# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""flowamp_compliance_checks — shared check registry for RAI Scorer and Compliance Auditor.

Usage:
    from flowamp_compliance_checks import REGISTRY, run_checks
    from flowamp_compliance_checks import Check, CheckResult, CheckContext, AgentTarget
"""
from __future__ import annotations

import logging
from importlib.metadata import entry_points

from .base import (
    AgentTarget,
    AthenaCheck,
    AwsConfigCheck,
    Check,
    CheckContext,
    CheckResult,
    DatasetTarget,
    IamPolicyCheck,
    Target,
    ToolTarget,
)

_log = logging.getLogger(__name__)

# Module-level list populated at import time by the @_register decorator in base.py.
# Checks modules are imported below; each decorated class appends itself here.
_BUILTIN_CHECKS: list[type[Check]] = []

# Import each checks module to trigger @_register side effects.
from .checks import fairness, transparency, accountability, ethics, operational  # noqa: F401, E402


def _build_registry() -> dict[str, Check]:
    """Build REGISTRY from built-in checks plus installed flowamp.checks entry_points.

    Built-ins always win on check_id collision — a third-party check cannot
    shadow a platform check. Entry-point load failures are WARNING-logged and
    skipped; the platform's built-ins are unaffected.
    """
    reg: dict[str, Check] = {}

    for cls in _BUILTIN_CHECKS:
        try:
            inst = cls()
            if inst.check_id in reg:
                _log.warning(
                    "Duplicate built-in checkId %s; second instance (%s) ignored",
                    inst.check_id,
                    cls.__name__,
                )
                continue
            reg[inst.check_id] = inst
        except Exception as exc:
            _log.warning("Built-in check %s failed to instantiate: %s", cls.__name__, exc)

    # Third-party extension hook via setuptools entry_points.
    try:
        eps = entry_points(group="flowamp.checks")
    except TypeError:
        # Defensive fallback for unusual importlib.metadata implementations.
        all_eps = entry_points()
        eps = all_eps.get("flowamp.checks", []) if hasattr(all_eps, "get") else []

    for ep in eps:
        try:
            obj = ep.load()
            classes = obj if isinstance(obj, list) else [obj]
            for cls in classes:
                if not (isinstance(cls, type) and issubclass(cls, Check)):
                    _log.warning("Entry-point %s yielded non-Check object %s; skipped", ep.name, cls)
                    continue
                inst = cls()
                if inst.check_id in reg:
                    _log.warning(
                        "Entry-point check %s (id=%s) conflicts with built-in; built-in kept",
                        ep.name,
                        inst.check_id,
                    )
                    continue
                reg[inst.check_id] = inst
        except Exception as exc:
            _log.warning("Entry-point %s failed to load: %s", ep.name, exc)

    return reg


REGISTRY: dict[str, Check] = _build_registry()

# Re-export runner helpers for convenience.
from .runner import run_check, run_checks  # noqa: F401, E402

__all__ = [
    "Check",
    "CheckResult",
    "CheckContext",
    "Target",
    "AgentTarget",
    "DatasetTarget",
    "ToolTarget",
    "AthenaCheck",
    "AwsConfigCheck",
    "IamPolicyCheck",
    "REGISTRY",
    "run_checks",
    "run_check",
]
