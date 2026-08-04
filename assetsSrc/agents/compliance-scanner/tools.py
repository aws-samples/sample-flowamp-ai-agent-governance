# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Compliance Auditor tool surface — the U-081/U-091 agentic auditor.

Tool classification:
  Read-only  : get_agent, list_applicable_frameworks, run_check,
               query_athena, read_past_audits, read_past_overrides,
               list_agent_data_access, list_agent_tool_access
  Mutating   : create_work_item, add_audit_note, finalize_audit

Only finalize_audit, add_audit_note, and create_work_item write to AWS.

Single-table data model:
  * Audit, compliance, event, and access-grant data all live in the ONE
    AgentTable named by ``AGENT_TABLE_NAME``. The distinct row domains are kept
    apart by the ``sk`` prefix convention
    (INFO / EVENT#/ AUDIT# / NOTE# / RAI# / COMPLIANCE# / DATA# / TOOL#).
  * There is NO ``sk-agentId-index`` (or any) GSI in this repo, so any query
    that would need one is expressed as a paginated Scan with a FilterExpression
    on the sk prefix. (Per-partition Query — e.g. get_agent's COMPLIANCE# query —
    is still a Query since it keys on agentId.)
  * There is NO Athena / Glue curated warehouse in this repo. ``query_athena``
    degrades to a safe no-data stub returning a valid empty shape with an
    explanatory note, and ``read_past_overrides`` reads ``human_override``
    EVENT# rows directly from the single table. Neither errors; both preserve
    their return shape so the agent's system prompt (which references both
    tools) keeps working.
  * Data and tool access grants are read straight off the single table:
    ``list_agent_data_access`` / ``list_agent_tool_access`` read the DATA#/TOOL#
    grant rows and surface any sensitivity metadata already carried on the grant
    row itself (no separate INFO join). Missing metadata → sensitivity None,
    when metadata is absent.
  * ``list_applicable_frameworks`` resolves definitions from the code-defined
    ``flowamp_compliance_checks.frameworks`` registry via flowamp_tools
    (get_framework / list_agent_frameworks); there is no ComplianceFrameworkTable.
"""
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key, Attr
from strands import tool

import flowamp_tools
from flowamp_tools import (
    write_audit_report,
    audit_history,
    get_framework,
    list_agent_frameworks,
    add_audit_note as _ft_add_audit_note,
    log_compliance_event,
    close_assigned_work_item as _ft_close_assigned_work_item,
)

_log = logging.getLogger(__name__)

_region = os.environ.get("AWS_REGION", "us-east-1")
# Single-table data model: compliance, extensions, event, framework, AOP, and
# work-item data all live in one physical table, so every direct DynamoDB access
# uses AGENT_TABLE_NAME.
_agent_table_name = os.environ.get("AGENT_TABLE_NAME", "")
_agent_id = os.environ.get("FLOWAMP_AGENT_ID", "compliance-scanner")

_env = os.environ.get("ENVIRONMENT", "dev")
_namespace = os.environ.get("FLOWAMP_NAMESPACE", "flowamp")
_ns_snake = _namespace.replace("-", "_")

# ── Athena config — retained for signature/CheckContext parity only ───────────
# This repo has NO Athena/Glue curated warehouse. These values are still read so
# CheckContext (below) has consistent fields and the Athena-backed checks in
# flowamp_compliance_checks degrade gracefully (they return skip on AccessDenied).
# The query_athena tool itself no longer executes anything — see its docstring.
_athena_database = os.environ.get("ATHENA_DATABASE", f"{_ns_snake}_{_env}_curated")
_athena_schema = _athena_database
_athena_workgroup = os.environ.get("ATHENA_WORKGROUP", "primary")
_athena_output_location = os.environ.get(
    "ATHENA_OUTPUT_LOCATION",
    f"s3://{_namespace}-athena-results-{_env}/auditor/",
)

_dynamodb = boto3.resource("dynamodb", region_name=_region)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Grade computation helpers ─────────────────────────────────────────────────

def _score_to_grade(score: float, rubric: dict) -> str:
    """Map a [0, 1] score to a letter grade using the framework's rubric.

    Iterates from highest threshold downward; below the lowest threshold returns "F".
    """
    ordered = sorted(rubric.items(), key=lambda kv: -kv[1])
    for grade, threshold in ordered:
        if score >= threshold:
            return grade
    return "F"


def _compute_rai_composite(framework: dict, check_results: dict) -> float:
    """Compute the RAI composite score from per-dimension weighted check results."""
    rai_config = framework.get("raiConfig", {})
    per_dim = rai_config.get("perDimension", {})
    if not per_dim:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0
    for dim_name, dim_cfg in per_dim.items():
        dim_weight = dim_cfg.get("dimensionWeight", 0.0)
        checks = dim_cfg.get("checks", [])
        weights = dim_cfg.get("weights", {})
        if not checks:
            continue
        dim_score = 0.0
        for cid in checks:
            cw = weights.get(cid, 1.0 / len(checks))
            result = check_results.get(cid)
            binary = 1.0 if (result and getattr(result, "result", result.get("result") if isinstance(result, dict) else None) == "pass") else 0.0
            dim_score += cw * binary
        weighted_sum += dim_weight * dim_score
        total_weight += dim_weight

    if total_weight == 0:
        return 0.0
    return weighted_sum / total_weight


def _operational_pass_rate(framework: dict, check_results: dict) -> float:
    """Compute pass rate for auditorConfig.checks."""
    op_checks = framework.get("auditorConfig", {}).get("checks", [])
    if not op_checks:
        return 1.0
    passed = 0
    for cid in op_checks:
        result = check_results.get(cid)
        if result:
            r = getattr(result, "result", result.get("result") if isinstance(result, dict) else None)
            if r == "pass":
                passed += 1
    return passed / len(op_checks)


def _count_failures(framework: dict, check_results: dict) -> tuple[int, int]:
    """Return (criticalFailures, highFailures) for a framework's checks."""
    rai_config = framework.get("raiConfig", {})
    per_dim = rai_config.get("perDimension", {})
    auditor_checks = framework.get("auditorConfig", {}).get("checks", [])

    all_check_ids = set()
    for dim_cfg in per_dim.values():
        all_check_ids.update(dim_cfg.get("checks", []))
    all_check_ids.update(auditor_checks)

    check_overrides = framework.get("checkOverrides", {})
    critical = 0
    high = 0
    for cid in all_check_ids:
        result = check_results.get(cid)
        if result:
            r = getattr(result, "result", result.get("result") if isinstance(result, dict) else None)
            if r == "fail":
                severity = check_overrides.get(cid, {}).get("severity", "medium")
                if severity == "critical":
                    critical += 1
                elif severity == "high":
                    high += 1
    return critical, high


# ── Validation helpers ────────────────────────────────────────────────────────

def _validate_byframework(by_framework: dict) -> None:
    """Raise ValueError when byFramework is malformed."""
    if not isinstance(by_framework, dict) or not by_framework:
        raise ValueError("byFramework must be a non-empty dict mapping frameworkId → result dict")
    for fid, fw_result in by_framework.items():
        if not isinstance(fw_result, dict):
            raise ValueError(f"byFramework['{fid}'] must be a dict")
        if "score" not in fw_result:
            raise ValueError(f"byFramework['{fid}'] is missing required key 'score'")
        score = fw_result["score"]
        if not isinstance(score, (int, float)) or not (0.0 <= score <= 1.0):
            raise ValueError(
                f"byFramework['{fid}']['score'] must be a float in [0.0, 1.0], got {score!r}"
            )


def _validate_recommendations(recommendations: list) -> None:
    """Raise ValueError when recommendations list is malformed."""
    if not isinstance(recommendations, list):
        raise ValueError("recommendations must be a list")
    for i, rec in enumerate(recommendations):
        if not isinstance(rec, dict):
            raise ValueError(f"recommendations[{i}] must be a dict")
        for key in ("checkId", "severity", "recommendation", "frameworks"):
            if key not in rec:
                raise ValueError(f"recommendations[{i}] is missing required key '{key}'")


def _validate_escalations(escalations: list) -> None:
    """Raise ValueError when escalations list is malformed."""
    if not isinstance(escalations, list):
        raise ValueError("escalations must be a list")
    for i, esc in enumerate(escalations):
        if not isinstance(esc, dict):
            raise ValueError(f"escalations[{i}] must be a dict")
        for key in ("group", "criteria", "title", "priority", "payload"):
            if key not in esc:
                raise ValueError(f"escalations[{i}] is missing required key '{key}'")


# ── Compliance-event emit helper ──────────────────────────────────────────────

def _emit_compliance_audit_event(
    agent_id_target: str,
    evaluation_result: str,
    output_summary: dict,
) -> str:
    """Write a compliance_audit event (EVENT# row) via flowamp_tools. Returns the eventId."""
    return log_compliance_event(
        agent_id=_agent_id,
        event_type="compliance_audit",
        payload={
            "targetAgentId": agent_id_target,
            "evaluationResult": evaluation_result,
            "outputSummary": output_summary,
        },
    )


def _patch_audit_work_item_ids(agent_id: str, audit_sk: str, work_item_ids: list) -> None:
    """Patch escalatedWorkItems on an existing AUDIT# row via UpdateItem.

    The AUDIT# row lives on AGENT_TABLE_NAME (single-table data model).
    """
    table = _dynamodb.Table(_agent_table_name)
    table.update_item(
        Key={"agentId": agent_id, "sk": audit_sk},
        UpdateExpression="SET #r.#ewi = :ids",
        ExpressionAttributeNames={"#r": "report", "#ewi": "escalatedWorkItems"},
        ExpressionAttributeValues={":ids": work_item_ids},
    )


# ── Auditable platform helpers (Slice B) ─────────────────────────────────────

def list_auditable_platforms() -> set:
    """Return the set of platformId values whose `auditable` flag is True.

    Queries AgentTable with PK=FLOWAMP_PLATFORMS and filters locally for
    rows that carry auditable=true (coercing the string literal 'true' the
    same way platforms.py does for the `native` field). This is a per-partition
    Query (keyed on the FLOWAMP_PLATFORMS sentinel PK), so it needs no GSI.
    """
    table = _dynamodb.Table(_agent_table_name)
    auditable_ids: set = set()
    kwargs = {
        "KeyConditionExpression": Key("agentId").eq("FLOWAMP_PLATFORMS"),
    }
    while True:
        resp = table.query(**kwargs)
        for row in resp.get("Items", []):
            raw = row.get("auditable", False)
            if isinstance(raw, bool):
                is_auditable = raw
            elif isinstance(raw, str):
                is_auditable = raw.strip().lower() == "true"
            else:
                is_auditable = False
            if is_auditable:
                pid = row.get("platformId", "")
                if pid:
                    auditable_ids.add(pid)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return auditable_ids


def stamp_agent_last_audited(agent_id: str, ts: str) -> None:
    """Write lastAuditedAt = ts onto the agent's AgentTable INFO row unconditionally.

    This is the pre-audit stamp written BEFORE the Strands loop runs so that
    a flaky audit cannot park the rotation on the same agent indefinitely.
    No ConditionExpression — we always want this write to land regardless of
    the current value. The post-audit projection in flowamp_tools.compliance
    uses a conditional write to ensure the later (real) timestamp wins if
    both arrive in close succession.
    """
    table = _dynamodb.Table(_agent_table_name)
    table.update_item(
        Key={"agentId": agent_id, "sk": "INFO"},
        UpdateExpression="SET lastAuditedAt = :ts",
        ExpressionAttributeValues={":ts": ts},
    )


# ── Eligibility filter ────────────────────────────────────────────────────────

# Non-agent entities that share the AgentTable and also use sk='INFO':
# compliance frameworks, Agent Operating Policies, and access-matrix rows. The
# same prefix tuple is used by agent-handler, data-handler, discovery-handler and
# rai-scorer to separate agents from other entities in a Scan.
_NON_AGENT_PREFIXES = ("compliance:", "aop:", "access:")


def _eligible_for_audit(agent_record: dict) -> bool:
    """Return True when the record is an agent that should be audited this run.

    Skips FLOWAMP_ sentinel rows, non-agent entities that share the table, and
    terminally-lifecycle'd agents.
    """
    agent_id = agent_record.get("agentId", "")
    status = agent_record.get("status", "")
    if agent_id.startswith("FLOWAMP_"):
        return False
    # Not agents: auditing e.g. compliance:nist-sp800-37 produces a nonsense
    # report about a framework definition. This used to be masked by the
    # platformId filter in _pick_rotation_target (these rows carry no
    # platformId), so it only surfaced once selection stopped requiring one.
    if agent_id.startswith(_NON_AGENT_PREFIXES):
        return False
    if status in ("decommissioned", "rejected"):
        return False
    return True


# ── Tool implementations ──────────────────────────────────────────────────────

@tool
def get_agent(agentId: str) -> dict:  # noqa: N803
    """Return the agent INFO record plus COMPLIANCE# framework assignment rows."""
    table = _dynamodb.Table(_agent_table_name)

    info_resp = table.get_item(Key={"agentId": agentId, "sk": "INFO"})
    info = info_resp.get("Item") or {}

    comp_resp = table.query(
        KeyConditionExpression=(
            Key("agentId").eq(agentId) & Key("sk").begins_with("COMPLIANCE#")
        ),
    )
    assignments = comp_resp.get("Items", [])
    while "LastEvaluatedKey" in comp_resp:
        comp_resp = table.query(
            KeyConditionExpression=(
                Key("agentId").eq(agentId) & Key("sk").begins_with("COMPLIANCE#")
            ),
            ExclusiveStartKey=comp_resp["LastEvaluatedKey"],
        )
        assignments.extend(comp_resp.get("Items", []))

    for row in assignments:
        sk = row.get("sk", "")
        if sk.startswith("COMPLIANCE#"):
            row["frameworkId"] = sk[len("COMPLIANCE#"):]

    return {
        "agentId": agentId,
        "name": info.get("name", ""),
        "status": info.get("status", ""),
        "category": info.get("category", ""),
        "owner": info.get("owner") or info.get("ownerId"),
        "runtimeArn": info.get("runtimeArn") or info.get("runtimeId"),
        "functionName": info.get("functionName"),
        "escalationGroup": info.get("escalationGroup"),
        "complianceAssignments": assignments,
    }


@tool
def list_applicable_frameworks(agentId: str) -> list:  # noqa: N803
    """Return resolved framework dicts for agentId — always includes FLOWAMP_BASELINE.

    Framework definitions are code-defined: they come from the
    ``flowamp_compliance_checks.frameworks`` registry via
    ``flowamp_tools.get_framework`` (there is no ComplianceFrameworkTable). The
    per-agent framework *assignments* (COMPLIANCE# rows) are read from the single
    AgentTable via ``flowamp_tools.list_agent_frameworks``.
    """
    BASELINE_ID = "FLOWAMP_BASELINE"

    framework_ids = [BASELINE_ID]
    assignments = list_agent_frameworks(agentId)
    for row in assignments:
        fid = row.get("frameworkId", "")
        if fid and fid != BASELINE_ID:
            framework_ids.append(fid)

    resolved = []
    for fid in framework_ids:
        fw = get_framework(fid)
        if fw is None:
            _log.warning("Framework %s not found in code-defined registry — skipping", fid)
            continue
        if fw.get("status") == "inactive":
            continue
        resolved.append(fw)

    return resolved


@tool
def run_check(checkId: str, target: dict, params: dict) -> dict:  # noqa: N803
    """Run a single compliance check from the registry. Results are cached per run.

    Returns {checkId, result, evidence, durationMs}.
    """
    from flowamp_compliance_checks.runner import run_check as _runner_run_check
    from flowamp_compliance_checks.base import AgentTarget

    ctx = _get_run_context()
    agent_target = AgentTarget(
        agent_id=target.get("agentId", ""),
        record=target,
        role_arn=target.get("runtimeArn"),
        runtime_arn=target.get("runtimeArn"),
        function_name=target.get("functionName"),
        region=_region,
    )
    check_result = _runner_run_check(checkId, agent_target, params, ctx)
    return {
        "checkId": checkId,
        "result": check_result.result,
        "evidence": check_result.evidence,
        "durationMs": check_result.duration_ms,
        "requiresWorkItem": getattr(check_result, "requiresWorkItem", False),
    }


@tool
def query_athena(sql: str, params: list) -> dict:
    """Run a query against the curated database. NO-DATA STUB in this deployment.

    This repo has NO Athena / Glue curated warehouse, so this tool cannot
    execute the SQL. Instead of erroring (the agent's system prompt still
    references query_athena), it degrades gracefully and returns a valid empty
    result shape with an explanatory note. The returned shape returns rows /
    rowCount / queryExecutionId plus a ``note`` so the LLM understands why no
    rows came back and does not treat the absence as a finding.
    """
    _log.info(
        "query_athena: no Athena warehouse in this deployment — returning empty "
        "result for SQL: %s", (sql or "")[:200],
    )
    return {
        "rows": [],
        "rowCount": 0,
        "queryExecutionId": None,
        "note": (
            "Athena / curated warehouse is not available in this deployment; "
            "query_athena returns no rows. Historical trend data is unavailable — "
            "base your audit on run_check results and read_past_audits instead."
        ),
    }


@tool
def read_past_audits(agentId: str, n: int = 5) -> list:  # noqa: N803
    """Return the last n AUDIT#{ts} rows for agentId, newest-first."""
    return audit_history(agentId, limit=n)


@tool
def read_past_overrides(agentId: str, n: int = 10) -> list:  # noqa: N803
    """Return recent human_override events for agentId, newest-first.

    This repo has no Athena warehouse, so this reads ``human_override`` EVENT#
    rows directly from the single AgentTable. Rows are written by
    flowamp_tools.log_compliance_event under sk EVENT#<ts>#<id>.

    Returns list of {eventId, timestamp, workItemId, decision, annotation,
    linkedComplianceSk, reviewerEmail}. Returns [] on any error or when no rows
    exist — never raises (the agent's prompt references this tool).
    """
    try:
        table = _dynamodb.Table(_agent_table_name)
        rows: list = []
        kwargs = {
            "KeyConditionExpression": (
                Key("agentId").eq(agentId) & Key("sk").begins_with("EVENT#")
            ),
            # newest-first
            "ScanIndexForward": False,
        }
        while True:
            resp = table.query(**kwargs)
            for item in resp.get("Items", []):
                if item.get("eventType") != "human_override":
                    continue
                payload = item.get("payload", {}) or {}
                rows.append({
                    "eventId": item.get("eventId"),
                    "timestamp": item.get("timestamp") or item.get("createdAt"),
                    "workItemId": payload.get("workItemId"),
                    "decision": payload.get("decision"),
                    "annotation": payload.get("annotation"),
                    "linkedComplianceSk": payload.get("linkedComplianceSk"),
                    "reviewerEmail": payload.get("reviewerEmail"),
                })
                if len(rows) >= n:
                    return rows
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return rows
    except Exception as exc:
        _log.warning("read_past_overrides: query failed for %s: %s", agentId, exc)
        return []


# ── Access-matrix helpers (U-091) ────────────────────────────────────────────

def _list_agent_extensions(
    agent_id: str,
    sk_prefix: str,
    id_field: str,
) -> list:
    """Shared pagination helper for list_agent_data_access and list_agent_tool_access.

    This repo has NO separate AgentExtensionsTable, so we read the DATA#/TOOL#
    grant rows straight off the single AgentTable and surface whatever metadata
    the grant row itself carries (name / description / sensitivityLabel /
    sensitivityClassification). When that metadata is absent, ``sensitivity`` is
    None — the "metadata absent" contract the system prompt already handles
    (do not flag a mismatch on a missing record alone).

    Queries AgentTable for rows where sk begins_with sk_prefix (paginated).
    Never raises.

    id_field is the attribute name to use when deriving the resource ID from the
    grant row (e.g. 'datasetId' or 'toolId').
    """
    from botocore.exceptions import ClientError, ParamValidationError

    if not _agent_table_name:
        _log.warning(
            "_list_agent_extensions: AGENT_TABLE_NAME is not set; returning empty "
            "list for agent %s prefix %s", agent_id, sk_prefix,
        )
        return []

    try:
        agent_table = _dynamodb.Table(_agent_table_name)

        grant_rows: list = []
        resp = agent_table.query(
            KeyConditionExpression=(
                Key("agentId").eq(agent_id) & Key("sk").begins_with(sk_prefix)
            ),
        )
        grant_rows.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = agent_table.query(
                KeyConditionExpression=(
                    Key("agentId").eq(agent_id) & Key("sk").begins_with(sk_prefix)
                ),
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            grant_rows.extend(resp.get("Items", []))

        results: list = []
        for row in grant_rows:
            # Derive the resource ID from the dedicated attribute first, then
            # fall back to splitting the sk (e.g. "DATA#abc-123" → "abc-123").
            resource_id = row.get(id_field) or row.get("sk", "").split("#", 1)[-1]

            # No AgentExtensionsTable in this repo — surface any metadata the
            # grant row itself carries. Honor the legacy sensitivityClassification
            # fallback (API service pattern).
            sensitivity = row.get("sensitivityLabel") or row.get("sensitivityClassification")

            results.append({
                id_field: resource_id,
                "name": row.get("name") or resource_id,
                "description": row.get("description", ""),
                "sensitivity": sensitivity,
                "permissionLevel": row.get("permission", "none"),
                "grantedAt": row.get("setAt"),
                "grantedBy": row.get("setBy"),
            })

        return results

    except (ClientError, ParamValidationError) as exc:
        _log.error(
            "_list_agent_extensions: DynamoDB error for agent %s prefix %s: %s",
            agent_id, sk_prefix, exc,
            exc_info=True,
        )
        return []


@tool
def list_agent_data_access(agentId: str) -> list:  # noqa: N803
    """Return the agent's data access grants with sensitivity metadata.

    Reads DATA#{datasetId} rows from AgentTable for the given agentId and
    surfaces name, description, and sensitivity classification carried on each
    grant row (single-table data model — no separate AgentExtensionsTable join).

    Returns [{datasetId, name, description, sensitivity, permissionLevel,
    grantedAt, grantedBy}]. Empty list when no DATA# rows exist; never raises.

    Use the sensitivity field to reason about whether the agent's access aligns
    with its declared label. When sensitivity is None the metadata is absent —
    do not flag a sensitivity mismatch based on a missing record alone.
    """
    return _list_agent_extensions(
        agent_id=agentId,
        sk_prefix="DATA#",
        id_field="datasetId",
    )


@tool
def list_agent_tool_access(agentId: str) -> list:  # noqa: N803
    """Return the agent's tool/extension access grants with sensitivity metadata.

    Reads TOOL#{toolId} rows from AgentTable for the given agentId and surfaces
    name, description, and sensitivity classification carried on each grant row
    (single-table data model — no separate AgentExtensionsTable join).

    Returns [{toolId, name, description, sensitivity, permissionLevel,
    grantedAt, grantedBy}]. Empty list when no TOOL# rows exist; never raises.

    Use the sensitivity field to reason about whether the agent's tool grants
    match its declared role and output sensitivity. When sensitivity is None the
    metadata is absent — surface the grant in your narrative but do not treat
    the absence of metadata as a confirmed mismatch.
    """
    return _list_agent_extensions(
        agent_id=agentId,
        sk_prefix="TOOL#",
        id_field="toolId",
    )


@tool
def create_work_item(title: str, priority: str, escalationGroup: str, payload: dict) -> str:  # noqa: N803
    """Create a human-review work item for an escalation finding.

    This repo has no AOP runtime / WorkItemTable, so the underlying
    ``flowamp_tools.create_work_item`` is a safe NO-OP that returns a
    synthetic (non-persisted) workItemId. This adapter still serialises the
    escalation ``payload`` into the instructions body so the call shape is
    preserved and any future real implementation would receive the full context.
    Returns the workItemId string.
    """
    criteria = payload.get("criteria", "")
    explicit_instructions = payload.get("instructions") or criteria

    # Stable, human-readable rendering of the audit payload.
    extra_keys = [k for k in payload if k not in ("instructions", "criteria")]
    payload_lines = [f"- {k}: {payload[k]!r}" for k in extra_keys]
    instructions = explicit_instructions
    if payload_lines:
        instructions = (
            f"{explicit_instructions}\n\nEscalation context:\n"
            + "\n".join(payload_lines)
        )

    result_str = flowamp_tools.create_work_item(
        title=title,
        instructions=instructions,
        priority=priority,
        assignee_type="human",
        assigned_group=escalationGroup,
        escalation_group=escalationGroup,
        escalation_criteria=criteria,
        tags=["compliance-audit", "review"],
        review_source="compliance_audit",
    )
    data = json.loads(result_str) if isinstance(result_str, str) else result_str
    return data.get("workItemId", "")


@tool
def add_audit_note(agentId: str, complianceSk: str, text: str) -> str:  # noqa: N803
    """Write a NOTE# row alongside an audit record (single AgentTable).

    When complianceSk is a workItemId ("WI#..."), sk is "NOTE#{workItemId}".
    Otherwise sk is "NOTE#general-{ts}". Returns the sk that was written.
    """
    return _ft_add_audit_note(agentId, complianceSk, text)


@tool
def finalize_audit(
    agentId: str,  # noqa: N803
    byFramework: dict,  # noqa: N803
    narrative: str,
    recommendations: list,
    escalations: list,
) -> dict:
    """Atomically commit an audit run: AUDIT row, compliance_audit event, escalation work items.

    Required argument shapes (the LLM should construct these without trial-
    and-error; validators below enforce them strictly):

      agentId: str — the agent under audit. Same value the dispatch payload
        carried under workItem.info.payload.agentId.

      byFramework: dict[frameworkId, {score, criticalFailures, highFailures, checks}]
        - score: float in [0.0, 1.0]. Numeric — do NOT stringify.
        - criticalFailures: int — count of severity=critical check failures for this framework.
        - highFailures: int — count of severity=high check failures.
        - checks: list[{checkId, result, severity}] — one entry per check this
          framework requires. result ∈ {'pass', 'fail', 'skip'}.
        Example:
          {
            "FLOWAMP_BASELINE": {
              "score": 0.78,
              "criticalFailures": 1,
              "highFailures": 2,
              "checks": [{"checkId": "tagging-compliance", "result": "pass", "severity": "low"}, ...],
            },
            "nist-ai-rmf": { ... },
          }

      narrative: str (≤ 4000 chars) — what was checked, what was found, patterns
        observed across history. Cite check IDs and override decisions where
        relevant.

      recommendations: list[{checkId, severity, recommendation, frameworks}]
        - checkId: str — the failing check this remediates (or '' for cross-cutting).
        - severity: str ∈ {'critical', 'high', 'medium', 'low'}.
        - recommendation: str — 1-3 sentence remediation step.
        - frameworks: list[str] — framework ids this rec applies to.

      escalations: list[{group, criteria, title, priority, payload}]
        - group: str — escalation group id. NOT 'escalationGroup'.
        - criteria: str — short reason this escalation fires (≤ 200 chars).
        - title: str — work-item title.
        - priority: str ∈ {'critical', 'high', 'medium', 'low'}.
        - payload: dict — optional context the receiving group will see on
          the work item. May be empty {}.

    Steps (best-effort atomic — AUDIT row is written first for durability):
    1. Validate inputs.
    2. Compute per-framework Grades + compositeGrade against FLOWAMP_BASELINE rubric.
    3. Write AUDIT#{ts} row (via flowamp_tools.write_audit_report → single table).
    4. Emit compliance_audit EVENT# row (via flowamp_tools.log_compliance_event).
    5. Create one work item per escalation entry (no-op create_work_item); collect IDs.
    6. Patch AUDIT row with escalatedWorkItems list.
    7. Close the dispatch work item (no-op close_assigned_work_item).
    8. Return {auditSk, workItemIds, failures, eventId, dispatchWorkItemId}.
    """
    audit_sk = None
    composite_grade = "F"
    event_id = None
    work_item_ids: list = []
    failures: list = []
    close_status = "done"
    close_error_message = None
    try:
        # Normalise common LLM aliases before strict validation.
        if isinstance(escalations, list):
            for esc in escalations:
                if isinstance(esc, dict) and "group" not in esc and "escalationGroup" in esc:
                    esc["group"] = esc.pop("escalationGroup")
        _validate_byframework(byFramework)
        _validate_recommendations(recommendations)
        _validate_escalations(escalations)

        if len(narrative) > 4000:
            narrative = narrative[:4000]
            _log.warning("finalize_audit: narrative truncated to 4000 chars for agent %s", agentId)

        frameworks = list_applicable_frameworks(agentId)
        fw_map = {fw["frameworkId"]: fw for fw in frameworks}

        baseline_rubric = (
            fw_map.get("FLOWAMP_BASELINE", {})
            .get("auditorConfig", {})
            .get("gradingRubric", {"A+": 0.95, "A": 0.85, "B": 0.75, "C": 0.65, "D": 0.50})
        )

        enriched = {}
        for fid, fw_result in byFramework.items():
            fw_def = fw_map.get(fid, {})
            rubric = (
                fw_def.get("auditorConfig", {})
                .get("gradingRubric", baseline_rubric)
            )
            score = fw_result["score"]
            grade = _score_to_grade(score, rubric)
            enriched[fid] = {**fw_result, "grade": grade}

        scores = [fw["score"] for fw in enriched.values()]
        composite_score = sum(scores) / len(scores) if scores else 0.0
        composite_grade = _score_to_grade(composite_score, baseline_rubric)

        report = {
            "byFramework": enriched,
            "compositeGrade": composite_grade,
            "compositeScore": composite_score,
            "narrative": narrative,
            "recommendations": recommendations,
            "escalatedWorkItems": [],
        }

        audit_sk = write_audit_report(agentId, report)

        try:
            event_id = _emit_compliance_audit_event(
                agent_id_target=agentId,
                evaluation_result=composite_grade,
                output_summary={
                    "auditSk": audit_sk,
                    "compositeGrade": composite_grade,
                    "criticalFailures": sum(
                        fw_result.get("criticalFailures", 0) for fw_result in enriched.values()
                    ),
                    "highFailures": sum(
                        fw_result.get("highFailures", 0) for fw_result in enriched.values()
                    ),
                },
            )
        except Exception as exc:
            _log.error(
                "finalize_audit: event emission failed (audit row %s persisted): %s",
                audit_sk, exc,
            )

        for esc in escalations:
            try:
                wi_payload = {
                    **esc.get("payload", {}),
                    "linkedComplianceSk": audit_sk,
                    "reviewSource": "compliance_audit",
                    "criteria": esc.get("criteria", ""),
                }
                wi_id = create_work_item(
                    title=esc["title"],
                    priority=esc["priority"],
                    escalationGroup=esc["group"],
                    payload=wi_payload,
                )
                if wi_id:
                    work_item_ids.append(wi_id)
            except Exception as exc:
                # Surface only the exception class name to operators.
                failures.append({
                    "group": esc["group"],
                    "title": esc["title"],
                    "error": type(exc).__name__,
                })
                _log.error("finalize_audit: create_work_item failed for %s: %s", esc, exc)

        if work_item_ids:
            try:
                _patch_audit_work_item_ids(agentId, audit_sk, work_item_ids)
            except Exception as exc:
                _log.error(
                    "finalize_audit: patch escalatedWorkItems failed for %s/%s: %s",
                    agentId, audit_sk, exc,
                )

        return {
            "auditSk": audit_sk,
            "workItemIds": work_item_ids,
            "failures": failures,
            "eventId": event_id,
            "dispatchWorkItemId": _dispatch_work_item_id,
        }
    except Exception as exc:
        close_status = "failure"
        close_error_message = f"{type(exc).__name__}: {exc}"
        _log.exception("finalize_audit: aborted for agent %s — %s", agentId, exc)
        raise
    finally:
        # Always close the dispatch work item (when bound). No-op in this
        # deployment, but the call shape is preserved so a future AOP runtime
        # integration works unchanged. Closing is best-effort: a close failure is
        # logged but never masks the original exception.
        if _dispatch_work_item_id:
            if close_status == "done":
                close_note = (
                    f"Audit complete: composite grade {composite_grade}, "
                    f"{len(work_item_ids)} escalation(s) created"
                    + (f", {len(failures)} escalation failure(s)" if failures else "")
                )
                result_summary = {
                    "auditSk": audit_sk,
                    "compositeGrade": composite_grade,
                    "escalatedWorkItems": work_item_ids,
                }
            else:
                close_note = (
                    f"Audit aborted before commit: {close_error_message or 'unknown error'}"
                )
                result_summary = {"error": close_error_message, "auditSk": audit_sk}
            try:
                _ft_close_assigned_work_item(
                    _dispatch_work_item_id,
                    status=close_status,
                    note=close_note,
                    result_summary=json.dumps(result_summary, default=str),
                )
                _log.info(
                    "finalize_audit: closed dispatch workItemId=%s status=%s audit=%s",
                    _dispatch_work_item_id, close_status, audit_sk,
                )
            except Exception as close_exc:
                _log.error(
                    "finalize_audit: close_assigned_work_item failed for %s (status=%s): %s",
                    _dispatch_work_item_id, close_status, close_exc,
                )


# ── Run-scoped CheckContext (per-request singleton) ───────────────────────────

_run_context = None  # type: ignore[assignment]


def _get_run_context():
    """Return the per-request CheckContext, creating it on first access."""
    global _run_context
    if _run_context is None:
        from flowamp_compliance_checks.base import CheckContext
        _run_context = CheckContext(
            clients={},
            region=_region,
            athena_database=_athena_database,
            athena_workgroup=_athena_workgroup,
            athena_output_location=_athena_output_location,
        )
    return _run_context


def reset_run_context() -> None:
    """Reset the per-request CheckContext. Called at the start of each agent invocation."""
    global _run_context, _dispatch_work_item_id
    _run_context = None
    _dispatch_work_item_id = None


# ── Dispatch work-item binding ────────────────────────────────────────────────
#
# When the agent is invoked with a workItemId (AOP-style dispatch), the value is
# stashed here (set by main.invoke() and read by finalize_audit) so the audit
# commit and the work-item close become a single atomic gesture. In this repo
# the close is a no-op (no AOP runtime), but the binding is preserved so the
# code path — and any future real implementation — works unchanged.

_dispatch_work_item_id = None  # type: ignore[assignment]


def set_dispatch_work_item_id(work_item_id) -> None:
    """Bind a workItemId to the current run so finalize_audit can close it."""
    global _dispatch_work_item_id
    _dispatch_work_item_id = (work_item_id or "").strip() or None
