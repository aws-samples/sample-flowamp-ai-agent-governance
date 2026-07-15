"""Single entry point for executing compliance checks.

Used by both the RAI Scorer Lambda and the Compliance Auditor agent's
`run_check` tool surface. All caching and exception isolation is handled here.

Cache key conventions:
  - Check results are stored under the checkId slug (e.g. "guardrail-attached").
  - Internal helper-cache entries used by checks themselves use a leading
    underscore prefix (e.g. "_guardrail::{agent_id}") to avoid key collisions
    with the runner's dedup namespace.
"""
from __future__ import annotations

import logging
import time

from .base import CheckContext, CheckResult, Target

_log = logging.getLogger(__name__)


def run_checks(
    check_ids: list[str],
    target: Target,
    framework_overrides: dict,
    ctx: CheckContext,
) -> dict[str, CheckResult]:
    """Run each checkId once for `target`, using ctx.cache for dedup.

    Behaviour:
      - Dedup: if checkId is already in ctx.cache, the cached CheckResult is
        returned without re-invoking the check.
      - Exception isolation: if Check.evaluate raises, a WARNING is logged and
        CheckResult(result="skip", evidence="<ExcClass>: <msg>") is returned.
        The run continues — one failing check does not abort the others.
      - Unknown checkId: a CheckResult(result="skip") is returned and a WARNING
        is logged. The check is still cached so a second call is free.

    `framework_overrides` is dict[check_id, dict] of per-framework overrides
    (severity, weight, enabled, params). The runner passes the 'params' value
    through to check.evaluate(). Severity/weight are applied by the RAI Scorer
    at scoring time, not here.
    """
    # Import here to avoid a circular import at module load time.
    from . import REGISTRY

    results: dict[str, CheckResult] = {}

    for check_id in check_ids:
        if check_id in ctx.cache:
            results[check_id] = ctx.cache[check_id]
            continue

        check = REGISTRY.get(check_id)
        if check is None:
            res = CheckResult(result="skip", evidence=f"Check not registered: {check_id}")
            _log.warning("checkId %s is not in REGISTRY", check_id)
            ctx.cache[check_id] = res
            results[check_id] = res
            continue

        params = framework_overrides.get(check_id, {}).get("params", {})
        start = time.monotonic()
        try:
            res = check.evaluate(target, params, ctx)
        except Exception as exc:
            duration = int((time.monotonic() - start) * 1000)
            _log.warning("Check %s raised %s: %s", check_id, type(exc).__name__, exc)
            res = CheckResult(
                result="skip",
                evidence=f"{type(exc).__name__}: {exc}",
                duration_ms=duration,
            )

        ctx.cache[check_id] = res
        results[check_id] = res

    return results


def run_check(
    check_id: str,
    target: Target,
    params: dict,
    ctx: CheckContext,
) -> CheckResult:
    """Single-check convenience wrapper — same caching and exception semantics.

    Used by the Compliance Auditor's `run_check` tool surface when the auditor
    wants to evaluate one specific check with custom params.
    """
    return run_checks(
        check_ids=[check_id],
        target=target,
        framework_overrides={check_id: {"params": params}},
        ctx=ctx,
    )[check_id]
