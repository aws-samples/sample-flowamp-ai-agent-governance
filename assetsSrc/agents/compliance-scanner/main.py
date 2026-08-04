# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Compliance Auditor — Strands agent that evaluates agents against compliance frameworks daily.

This agent runs one-shot: it is invoked directly (rotation path with no explicit
agentId, or on-demand with an agentId in the payload). This deployment has no AOP
runtime / WorkItemTable, so work-item lifecycle tools resolve to safe no-ops
(flowamp_tools.work_items).

The auditor runs once per day per target agent. It combines deterministic checks
(from the shared flowamp_compliance_checks registry) with agentic judgement to
produce a narrative, recommendations, and per-framework letter Grade. The entire
audit is committed atomically through the finalize_audit tool.

Single-table model:
  * Event, AOP, and agent-compliance data all live in one physical table, so
    every DynamoDB access uses AGENT_TABLE_NAME.
  * ``list_active_agents`` (flowamp_tools.agent_catalog) Scans the AgentTable
    with a ``sk='INFO'`` FilterExpression (this table has no GSI).
  * The foundation model comes from ``get_model_config()['complianceScannerModel']``.
"""
# ---------------------------------------------------------------------------
# OTEL bootstrap — MUST run before any other import (boto3, strands, etc.).
#
# OpenTelemetry auto-instrumentation is enabled by launching the agent as
# `opentelemetry-instrument python main.py`. That wrapper reads the
# OTEL_*/AGENT_OBSERVABILITY_ENABLED env vars and installs the global
# TracerProvider + OTLP exporter wired to aws/spans. Per the AWS docs
# (bedrock-agentcore/observability-configure §"Enabling observability in agent
# code for AgentCore-hosted agents"), this wrapper is required for spans to be
# exported. Direct-code deploy launches a bare `python main.py`, so this block
# re-execs the process under auto-instrumentation to enable it.
#
# The re-exec invokes the interpreter's public auto-instrumentation entry point,
# opentelemetry.instrumentation.auto_instrumentation.run(), which is importable
# from the vendored packages in the bundle root, rather than the
# `opentelemetry-instrument` console script (uv --target installs it under
# <bundle>/bin, off PATH, with a build-machine shebang). The _OTEL_REEXEC guard
# makes it one-shot. It runs only when AGENT_OBSERVABILITY_ENABLED is set so
# local runs are unaffected, and any failure is swallowed so a missing wrapper
# never crashes the agent.
import os as _os
import sys as _sys

if (
    _os.environ.get("AGENT_OBSERVABILITY_ENABLED") == "true"
    and not _os.environ.get("_OTEL_REEXEC")
):
    _os.environ["_OTEL_REEXEC"] = "1"
    _bundle_dir = _os.path.dirname(_os.path.abspath(__file__))
    _os.environ["PYTHONPATH"] = (
        _bundle_dir + _os.pathsep + _os.environ.get("PYTHONPATH", "")
    ).rstrip(_os.pathsep)
    try:
        # Safe: the exec target and argv are the process's own trusted values
        # (sys.executable, sys.argv) — no external/user input reaches this call.
        # It only re-launches this same script under OpenTelemetry auto-instrumentation.
        _os.execv(  # nosemgrep: dangerous-os-exec-tainted-env-args,dangerous-os-exec-audit
            _sys.executable,
            [
                _sys.executable,
                "-c",
                "from opentelemetry.instrumentation.auto_instrumentation import run; run()",
                _sys.executable,
                *_sys.argv,
            ],
        )
    except Exception as _reexec_exc:  # noqa: BLE001
        print(f"otel auto-instrument re-exec skipped: {_reexec_exc}")

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import boto3
from strands import Agent
from strands.models.bedrock import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp

import flowamp_tools
from flowamp_tools import (
    invoke_agent,
    close_assigned_work_item,
    add_work_item_note,
    add_work_item_task,
    update_work_item_task,
    update_work_item_info,
    log_agent_decision,
    list_active_agents as _list_active_agents,
)
from flowamp_tools.config import get_model_config
from tools import (
    get_agent,
    list_applicable_frameworks,
    run_check,
    query_athena,
    read_past_audits,
    read_past_overrides,
    list_agent_data_access,
    list_agent_tool_access,
    create_work_item,
    add_audit_note,
    finalize_audit,
    reset_run_context,
    set_dispatch_work_item_id,
    _eligible_for_audit,
    list_auditable_platforms,
    stamp_agent_last_audited,
)

logging.basicConfig(level=logging.INFO, force=True)
logger = logging.getLogger(__name__)

_region = os.environ.get("AWS_REGION", "us-east-1")
# Single-table model: agent, event, and AOP data share one physical table, so
# every direct DynamoDB access below uses AGENT_TABLE_NAME.
_agent_table_name = os.environ.get("AGENT_TABLE_NAME", "")
_agent_id = os.environ.get("FLOWAMP_AGENT_ID", "compliance-scanner")
_guardrail_id = os.environ.get("BEDROCK_GUARDRAIL_ID", "")
_guardrail_version = os.environ.get("BEDROCK_GUARDRAIL_VERSION", "DRAFT")

# Escalation group used as the default recipient for guardrail-evidence work
# items when the target agent carries no escalationGroup of its own. Optional in
# this one-shot deployment (create_work_item is a no-op), so absence is a
# WARNING rather than a hard startup failure.
_compliance_escalation_group = os.environ.get("COMPLIANCE_ESCALATION_GROUP", "")
if not _compliance_escalation_group:
    logger.warning(
        "COMPLIANCE_ESCALATION_GROUP is not set; escalation work items (no-op in "
        "this deployment) will fall back to each agent's own escalationGroup."
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_dynamodb = boto3.resource("dynamodb", region_name=_region)
_cloudwatch = boto3.client("cloudwatch", region_name=_region)


# =============================================================================
# PRIVATE HELPERS — retained for testability and eligibility fallback path
# =============================================================================

def _put_metric(metric_name: str, value: float = 1.0) -> None:
    try:
        _cloudwatch.put_metric_data(
            Namespace="FlowAMP/ComplianceScanner",
            MetricData=[{"MetricName": metric_name, "Value": value, "Unit": "Count"}],
        )
    except Exception:
        pass


def _list_all_agents() -> list:
    """Return all agent INFO records from AgentTable via the shared helper.

    ``list_active_agents`` Scans the AgentTable filtering on sk='INFO'
    (this table has no GSI).
    """
    return _list_active_agents()


def _query_agent(agent_id: str) -> dict | None:
    """Fetch a single agent INFO record from AgentTable; returns None if not found."""
    table = _dynamodb.Table(_agent_table_name)
    resp = table.get_item(Key={"agentId": agent_id, "sk": "INFO"})
    return resp.get("Item")


# =============================================================================
# ROTATION SELECTION
# =============================================================================

def _pick_rotation_target() -> Optional[str]:
    """Return the agentId of the auditable-platform agent with the oldest lastAuditedAt.

    Selection algorithm:
    1. Load auditable platform IDs from AgentTable FLOWAMP_PLATFORMS partition.
    2. Load all agent INFO rows; filter for eligible + on-auditable-platform.
    3. Emit a single warning event listing eligible agents that have no platformId
       (orphan agents — visible to operators without blocking the rotation).
    4. Sort eligible agents by lastAuditedAt ascending; absent/null sorts as ''
       so never-audited agents always win over any agent with a real timestamp.
    5. Return the head agentId, or None if the candidate set is empty.

    Absent platform configuration means "audit everything eligible", NOT "audit
    nothing". Nothing in the platform writes the FLOWAMP_PLATFORMS sentinel rows —
    they are an operator-managed allowlist — so on a fresh deploy the auditable set
    is empty. Treating that as "no candidates" made every rotation run (the daily
    schedule and the fleet Re-audit button) a silent no-op that still reported
    success. Failing open is right here because the audit is READ-ONLY: it grades
    agents and writes AUDIT#/RAI# rows, so over-auditing is harmless while
    under-auditing hides governance gaps, which is the opposite of the point.
    """
    auditable_platform_ids = list_auditable_platforms()

    all_agents = _list_all_agents()
    eligible = [a for a in all_agents if _eligible_for_audit(a)]

    if auditable_platform_ids:
        eligible = [a for a in eligible if a.get("platformId") in auditable_platform_ids]
    else:
        logger.warning(
            "No auditable platforms configured (FLOWAMP_PLATFORMS sentinel absent or "
            "no rows flagged auditable=true); auditing all %d eligible agent(s). "
            "Add the sentinel rows to restrict the rotation to specific platforms.",
            len(eligible),
        )

    # Warn about agents that are eligible by status but have no platformId. Only
    # meaningful when a platform allowlist exists — without one, platformId is
    # not used for selection at all.
    if auditable_platform_ids:
        unlinked = [
            a.get("agentId", "") for a in all_agents
            if _eligible_for_audit(a) and not a.get("platformId")
        ]
        if unlinked:
            log_agent_decision(
                action_type="compliance_audit_skip",
                input_summary="Agents eligible by status but unlinked from any platform",
                output_summary=f"Orphan agent IDs: {unlinked}",
                evaluation_result="warning",
            )

    if not eligible:
        logger.warning("Rotation found no eligible agents to audit")
        return None

    # Sort by lastAuditedAt ascending; treat absent/null as "" so never-audited
    # agents sort first (oldest) and are picked before any previously-audited agent.
    eligible.sort(key=lambda a: a.get("lastAuditedAt") or "")
    return eligible[0].get("agentId", "")


# =============================================================================
# STRANDS AGENT
# =============================================================================

_model_id = get_model_config()["complianceScannerModel"]

if _guardrail_id:
    _model = BedrockModel(
        model_id=_model_id,
        guardrail_id=_guardrail_id,
        guardrail_version=_guardrail_version,
    )
else:
    _model = BedrockModel(model_id=_model_id)

_AUDIT_TOOLS = [
    # Read-only discovery tools
    get_agent,
    list_applicable_frameworks,
    run_check,
    query_athena,
    read_past_audits,
    read_past_overrides,
    # U-091: access-matrix read tools for sensitivity-vs-label reasoning
    list_agent_data_access,
    list_agent_tool_access,
    # Mutating tools
    create_work_item,
    add_audit_note,
    finalize_audit,
    # Cross-agent read
    invoke_agent,
    # Work-item lifecycle (no-ops in this deployment)
    add_work_item_note,
    add_work_item_task,
    update_work_item_task,
    update_work_item_info,
    close_assigned_work_item,
]

SYSTEM_PROMPT = """You are the FlowAMP Compliance Auditor. You run once per day per agent —
to produce a structured A-F audit report grounded in deterministic checks AND
your own judgement.

## Role

You are a daily auditor, NOT a continuous scorer. The RAI Scorer runs on its
own cadence and writes raw RAI rows; you run once per day per agent and produce
a narrative + recommendations + per-framework Grade.

## How you work

You combine deterministic checks (the same library the RAI Scorer uses)
with agentic judgement:

1. Discover the agent's framework set (FLOWAMP_BASELINE + per-agent frameworks).
   Inspect the agent's data and tool access (list_agent_data_access,
   list_agent_tool_access) and compare each grant's sensitivity against the
   agent's declared sensitivity label and observed behavior. Flag mismatches
   in your narrative — see "Sensitivity reasoning" below.
2. Read your own past audits (last 5) and recent human overrides (last 10).
   Patterns matter — if a finding has been overridden three times as "false
   positive — owner is in IdP", do NOT re-flag it as a critical issue this run.
3. Run the deterministic checks each framework requires. Use run_check
   for each — results are cached for the run, so duplicates cost nothing.
4. Decide whether any expensive moderate-tier checks are worth running
   based on past audit history.
5. Author a narrative (≤ 4000 chars) that summarises what was checked,
   what was found, and any patterns observed across the agent's audit
   history and override history. Be specific — cite check IDs and
   override decisions.
6. Author recommendations — a list of {checkId, severity, recommendation,
   frameworks[]} where recommendation is a 1-3 sentence remediation step
   targeted at the team that owns the agent.
7. Decide which escalations to fire. Each framework declares its
   escalations rules; you apply your judgement to whether human
   attention is warranted right now. Examples of good judgement:
     - A recurring failure already overridden with decision approved
       does NOT warrant a new escalation unless the severity is critical.
     - A first-time critical failure ALWAYS warrants an escalation.
     - A high-severity failure that an override request is currently
       pending on (open work item with linkedComplianceSk) does NOT
       warrant a duplicate escalation — note it in the narrative instead.
8. The audit body — byFramework + narrative + recommendations + escalation
   decisions — is committed via finalize_audit. Interim notes during the
   reasoning loop go through add_audit_note, and any extra escalation work
   items are created via create_work_item. Those three are the only sanctioned
   mutation tools; all other state-changing access (direct boto3, AgentTable
   writes, cross-runtime invocation) is prohibited.

## Data availability note

This deployment has NO historical Athena / curated warehouse. query_athena
returns no rows (with an explanatory note) and read_past_overrides falls back
to reading human_override events directly from the agent table. Do NOT treat an
empty query_athena result as a compliance finding — base your audit on
run_check results, read_past_audits, and read_past_overrides.

## Sensitivity reasoning

Use list_agent_data_access and list_agent_tool_access to read the agent's
access matrix. Apply the following reasoning patterns:

- If an agent holds a data grant labeled `restricted` but the agent's
  declared output sensitivity is `public`, flag a sensitivity-mismatch
  finding in the narrative (e.g. "Agent holds restricted data access but
  outputs are public — review data handling controls").
- If a tool grant carries sensitivity `restricted` but the agent's role is
  broadly customer-facing or has no output classification, note the elevated
  risk in the narrative.
- When sensitivity is None, the metadata record is absent. Do NOT flag a
  mismatch solely because metadata is missing — surface the grant in the
  narrative but withhold a mismatch finding until metadata is populated.
- Do NOT auto-create work items for sensitivity mismatches in this story.
  Sensitivity escalation criteria belong to a future deterministic check;
  surface findings in the narrative only.

## Guardrails

- You may NOT mutate AgentTable. Lifecycle changes (decommission, suspend)
  are human decisions made via the resulting work items.
- You may NOT call bedrock-agentcore:InvokeAgentRuntime directly.
  Cross-agent inquiry happens through invoke_agent (read-only).
- You may NOT write directly via boto3. Every mutation flows through
  finalize_audit, add_audit_note, or create_work_item.
- If finalize_audit returns failures[] non-empty, mention that in
  your closing note so the operator sees the partial commit.
- When run_check("guardrail-attached", ...) returns a result where
  requiresWorkItem is True, you MUST call create_work_item with:
    title: "Guardrail/safety controls evidence required for {agentId}"
    priority: "high"
    escalationGroup: the agent's escalationGroup field (if set), otherwise
                     the COMPLIANCE_ESCALATION_GROUP environment value
    payload: context describing what evidence the agent owner must provide
  On subsequent audits, use read_past_overrides to check if such a work item
  was already created and resolved; if the override shows it was addressed,
  do NOT create a duplicate work item.

## Tools

(read-only)
- get_agent(agentId)
- list_applicable_frameworks(agentId)
- run_check(checkId, target, params)
- query_athena(sql, params)             — returns no rows in this deployment
- read_past_audits(agentId, n=5)
- read_past_overrides(agentId, n=10)
- list_agent_data_access(agentId)      — DATA# grants + sensitivity metadata
- list_agent_tool_access(agentId)      — TOOL# grants + sensitivity metadata

(mutating)
- add_audit_note(agentId, complianceSk, text)
                                        — drop a NOTE# row alongside the audit
- create_work_item(title, priority, escalationGroup, payload)
- finalize_audit(agentId, byFramework, narrative, recommendations, escalations)
                                        — the SINGLE atomic commit

## Workflow

The target agent ID is provided in your user message. Your sequence:

1. get_agent -> list_applicable_frameworks -> read_past_audits -> read_past_overrides
2. list_agent_data_access + list_agent_tool_access — inspect sensitivity grants
3. For each unique check across all frameworks: run_check (results dedup)
4. Compose byFramework (per-framework score + criticalFailures + highFailures + checks)
5. Author narrative + recommendations + escalations
6. finalize_audit(...) — single commit."""

agent = Agent(model=_model, tools=_AUDIT_TOOLS, system_prompt=SYSTEM_PROMPT)

# =============================================================================
# AGENTCORE RUNTIME ENTRY POINT
# =============================================================================

app = BedrockAgentCoreApp()


async def _invoke_core(payload):
    """Core async generator logic for AgentCore invocations.

    Accepts both shapes:
    1. Work-item-driven dispatch: payload includes workItemId, workItem (full
       snapshot), and messages. The target agentId is read from
       payload.workItem.info.payload.agentId. In this repo the work-item tools
       are no-ops (no AOP runtime), so this path runs harmlessly.
    2. Direct / on-demand: agentId in the payload top-level routes to the
       manual on-demand audit path. If no agentId is present, the rotation
       algorithm picks the eligible agent with the oldest lastAuditedAt on
       an auditable platform.
    """
    reset_run_context()

    messages = payload.get("messages", [])
    work_item = payload.get("workItem", {})
    work_item_info = work_item.get("info", {})
    work_item_payload = work_item_info.get("payload", {})
    target_agent_id = work_item_payload.get("agentId", "")

    # Bind the dispatch workItemId to the run so finalize_audit can close it
    # (no-op in this deployment). The LLM no longer needs to remember the close.
    dispatch_work_item_id = payload.get("workItemId") or work_item_info.get("workItemId")
    set_dispatch_work_item_id(dispatch_work_item_id)

    if not target_agent_id and isinstance(payload, dict):
        target_agent_id = payload.get("agentId", "")

    session_id = payload.get("sessionId", f"session-{id(payload)}")

    if target_agent_id:
        # ── Manual on-demand path ────────────────────────────────────────────
        # Pre-stamp before audit so even a failed manual run advances the
        # rotation cursor consistently with the scheduled path.
        now_ts = _now_iso()
        stamp_agent_last_audited(target_agent_id, now_ts)
        user_message = (
            f"Run a daily compliance audit for agent {target_agent_id}. "
            "Load its applicable frameworks, execute the required checks, "
            "read past audits and overrides for context, then author a narrative, "
            "recommendations, and per-framework Grade. "
            "Commit the entire audit atomically via finalize_audit."
        )
    else:
        # ── Rotation path (no explicit agentId) ───────────────────────────────
        chosen_id = _pick_rotation_target()

        if chosen_id is None:
            # No eligible agents on auditable platforms — emit skip event and
            # yield a terminal output without invoking the Strands agent.
            log_agent_decision(
                action_type="compliance_audit_skip",
                input_summary="No agents on auditable platforms found",
                output_summary="No eligible agents to audit this rotation cycle",
                evaluation_result="not_applicable",
            )
            yield {"type": "output", "result": "no eligible agents", "sessionId": session_id}
            return

        # Pre-stamp lastAuditedAt BEFORE invoking the Strands loop so a flaky
        # audit cannot park the rotation on the same agent forever — the cursor
        # always advances regardless of audit outcome. See ADR-22.
        now_ts = _now_iso()
        stamp_agent_last_audited(chosen_id, now_ts)
        target_agent_id = chosen_id
        user_message = (
            f"Run a daily compliance audit for agent {target_agent_id}. "
            "Load its applicable frameworks, execute the required checks, "
            "read past audits and overrides for context, author a narrative, "
            "recommendations, and per-framework Grade, then commit via finalize_audit."
        )

    complete_response = ""
    try:
        async for event in agent.stream_async(user_message):
            if "data" in event:
                chunk = event["data"]
                complete_response += chunk
                yield {"type": "text", "result": chunk, "sessionId": session_id}
    except Exception as exc:
        # Logged with exc_info=True and re-raised so the runtime fails loudly.
        # lastAuditedAt is NOT rolled back — see ADR-22.
        logger.error(
            "Compliance audit failed for agent %s: %s",
            target_agent_id, exc,
            exc_info=True,
        )
        log_agent_decision(
            action_type="compliance_audit_run",
            input_summary=f"audit failed for {target_agent_id}",
            output_summary=str(exc)[:500],
            evaluation_result="error",
        )
        # Best-effort metric emit — failure here must not mask the original error.
        try:
            _cloudwatch.put_metric_data(
                Namespace="FlowAMP/ComplianceScanner",
                MetricData=[{
                    "MetricName": "AuditError",
                    "Dimensions": [{"Name": "AgentId", "Value": target_agent_id}],
                    "Value": 1.0,
                    "Unit": "Count",
                }],
            )
        except Exception:  # noqa: broad — metric emit failure must never surface
            pass
        raise

    yield {"type": "output", "result": complete_response, "sessionId": session_id}


@app.entrypoint
async def invoke(payload):
    """AgentCore entrypoint — delegates to _invoke_core."""
    async for event in _invoke_core(payload):
        yield event


if __name__ == "__main__":
    app.run()
