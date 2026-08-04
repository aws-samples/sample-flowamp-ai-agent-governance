# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Compliance helpers — read/write path for audit reports, RAI scores, notes,
per-agent framework assignments, and compliance events.

All of these rows share the one AgentTable, separated by sk prefix:

  RAI#<ts>                 responsible-AI score row
  AUDIT#<ts>               compliance audit report row (rowType='AUDIT')
  NOTE#<ref>               audit note row
  COMPLIANCE#<frameworkId> per-agent framework assignment
  EVENT#<ts>#<id>          compliance event (UI Event Explorer)

All writes are PutItem so each row is distinct/append-only. ``_require_env`` only
checks AGENT_TABLE_NAME (there are no per-domain tables), and
``log_compliance_event`` writes an ``EVENT#``-prefixed row with actor/severity so
it surfaces in the data-handler Event Explorer.
"""
import os
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal

from boto3.dynamodb.conditions import Key

from ._config import (
    get_agent_compliance_table,
    get_agent_table,
    get_dynamodb_table,
)


def _to_ddb_numeric(value):
    """Recursively coerce Python floats to Decimal for DynamoDB compatibility.

    DynamoDB's boto3 resource API refuses raw Python floats. LLM-driven callers
    (the auditor's finalize_audit tool) produce floats nested in the report dict;
    converting at the boundary is more reliable than asking callers to remember.
    Strings/ints/bools/None pass through; dict/list are walked; tuples become lists.
    """
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb_numeric(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_ddb_numeric(v) for v in value]
    return value


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_rai_score(agent_id: str, sub_scores: dict, overall: float, source: str) -> str:
    """Write a RAI#{timestamp} row. Validates all scores are in [0.0, 1.0].

    Returns the sk written (e.g. "RAI#2026-04-30T06:00:00Z").
    """
    _require_env()

    if not (0.0 <= overall <= 1.0):
        raise ValueError(f"overall must be in [0.0, 1.0], got {overall}")
    for dim, val in sub_scores.items():
        if not (0.0 <= val <= 1.0):
            raise ValueError(f"sub_scores['{dim}'] must be in [0.0, 1.0], got {val}")

    ts = _now_iso()
    sk = f"RAI#{ts}"

    table = get_agent_compliance_table()
    table.put_item(Item={
        "agentId": agent_id,
        "sk": sk,
        "subScores": _to_ddb_numeric(sub_scores),
        "overall": str(overall),
        "source": source,
        "createdAt": ts,
    })
    return sk


def write_audit_report(agent_id: str, report: dict) -> str:
    """Write an AUDIT#{timestamp} row.

    Report shape: byFramework, compositeGrade, compositeScore, narrative,
    recommendations, escalatedWorkItems. Missing keys are tolerated (logged).
    Returns the sk written.
    """
    _require_env()

    _REQUIRED_KEYS = {"byFramework", "compositeGrade", "compositeScore", "narrative",
                      "recommendations", "escalatedWorkItems"}
    missing = _REQUIRED_KEYS - set(report.keys())
    if missing:
        import logging
        logging.getLogger(__name__).warning(
            "write_audit_report: report is missing expected keys %s for agent %s",
            missing, agent_id,
        )

    ts = _now_iso()
    sk = f"AUDIT#{ts}"

    table = get_agent_compliance_table()
    table.put_item(Item={
        "agentId": agent_id,
        "sk": sk,
        "rowType": "AUDIT",
        "report": _to_ddb_numeric(report),
        "createdAt": ts,
    })

    # Project lastAuditedAt onto the agent's INFO row (best-effort cache).
    try:
        _update_agent_last_audited(agent_id, ts)
    except Exception:
        import logging
        logging.getLogger(__name__).debug(
            "write_audit_report: failed to project lastAuditedAt for %s", agent_id,
        )

    return sk


def _update_agent_last_audited(agent_id: str, ts: str) -> None:
    """Conditional projection of the latest audit timestamp onto the INFO row.

    A conditional UpdateItem prevents an older audit from overwriting a newer one.
    """
    table = get_agent_table()
    try:
        table.update_item(
            Key={"agentId": agent_id, "sk": "INFO"},
            UpdateExpression="SET lastAuditedAt = :ts",
            ConditionExpression="attribute_not_exists(lastAuditedAt) OR lastAuditedAt < :ts",
            ExpressionAttributeValues={":ts": ts},
        )
    except Exception as exc:
        name = exc.__class__.__name__
        if name not in ("ConditionalCheckFailedException", "ClientError"):
            raise
        if "ConditionalCheckFailed" not in str(exc):
            raise


def add_audit_note(agent_id: str, complianceSk: str, text: str) -> str:  # noqa: N803
    """Write a NOTE# row. sk = "NOTE#{workItemId}" when complianceSk starts
    with "WI#", else "NOTE#general-{ts}". Returns the sk written.
    """
    _require_env()

    ts = _now_iso()
    if complianceSk.startswith("WI#"):
        sk = f"NOTE#{complianceSk}"
    else:
        sk = f"NOTE#general-{ts}"

    table = get_agent_compliance_table()
    table.put_item(Item={
        "agentId": agent_id,
        "sk": sk,
        "complianceSk": complianceSk,
        "text": text,
        "createdAt": ts,
    })
    return sk


def latest_rai_score(agent_id: str) -> dict | None:
    """Return the most recent RAI#{timestamp} row for agent_id, or None."""
    _require_env()

    table = get_agent_compliance_table()
    response = table.query(
        KeyConditionExpression=Key("agentId").eq(agent_id) & Key("sk").begins_with("RAI#"),
        ScanIndexForward=False,
        Limit=1,
    )
    items = response.get("Items", [])
    return items[0] if items else None


def audit_history(agent_id: str, limit: int = 10, before_ts: str | None = None) -> list[dict]:
    """Return up to limit AUDIT#{timestamp} rows for agent_id, newest-first.

    before_ts enables cursor pagination (rows with sk < 'AUDIT#{before_ts}').
    """
    _require_env()

    table = get_agent_compliance_table()
    key_cond = Key("agentId").eq(agent_id) & Key("sk").begins_with("AUDIT#")
    kwargs: dict = {"KeyConditionExpression": key_cond, "ScanIndexForward": False, "Limit": limit}
    if before_ts is not None:
        kwargs["KeyConditionExpression"] = (
            Key("agentId").eq(agent_id) & Key("sk").lt(f"AUDIT#{before_ts}")
        )
    response = table.query(**kwargs)
    return response.get("Items", [])


def list_frameworks() -> list[dict]:
    """Deprecated re-export — use flowamp_tools.frameworks.list_frameworks."""
    from .frameworks import list_frameworks as _list_frameworks
    return _list_frameworks()


def get_framework(framework_id: str) -> dict | None:
    """Deprecated re-export — use flowamp_tools.frameworks.get_framework."""
    from .frameworks import get_framework as _get_framework
    return _get_framework(framework_id)


def list_agent_frameworks(agent_id: str) -> list[dict]:
    """Return all COMPLIANCE#{frameworkId} assignment rows for agent_id.

    Each dict is enriched with a `frameworkId` key derived from the sk.
    """
    _require_env()

    table = get_agent_table()
    response = table.query(
        KeyConditionExpression=Key("agentId").eq(agent_id) & Key("sk").begins_with("COMPLIANCE#"),
    )
    items = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = table.query(
            KeyConditionExpression=Key("agentId").eq(agent_id) & Key("sk").begins_with("COMPLIANCE#"),
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        items.extend(response.get("Items", []))

    for item in items:
        sk = item.get("sk", "")
        if sk.startswith("COMPLIANCE#"):
            item["frameworkId"] = sk[len("COMPLIANCE#"):]

    return items


_TTL_DAYS = 90

_ALLOWED_COMPLIANCE_EVENT_TYPES = frozenset({
    "compliance_audit",
    "responsible_ai_alert",
    "human_override",
})


def log_compliance_event(
    agent_id: str,
    event_type: str,
    payload: dict,
    operator_id: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
) -> str:
    """Write a compliance event as an EVENT# row. Returns the eventId.

    Canonical write path for compliance event types (compliance_audit,
    responsible_ai_alert, human_override). The row is keyed EVENT#<ts>#<id> and
    carries actor/severity so it appears in the data-handler Event Explorer.
    """
    if event_type not in _ALLOWED_COMPLIANCE_EVENT_TYPES:
        raise ValueError(
            f"log_compliance_event: unsupported event_type {event_type!r}. "
            f"Allowed: {sorted(_ALLOWED_COMPLIANCE_EVENT_TYPES)}"
        )

    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ttl_epoch = int((datetime.now(timezone.utc) + timedelta(days=_TTL_DAYS)).timestamp())
    severity = "warning" if event_type == "responsible_ai_alert" else "info"

    item: dict = {
        "agentId": agent_id,
        "sk": f"EVENT#{ts}#{event_id}",
        "eventId": event_id,
        "eventType": event_type,
        "timestamp": ts,
        "createdAt": ts,
        "ttl": ttl_epoch,
        "actor": operator_id or agent_id,
        "severity": severity,
        "schemaVersion": "1.0",
        "correlationId": correlation_id if correlation_id is not None else str(uuid.uuid4()),
        "idempotencyKey": f"{agent_id}#{event_type}#{ts}#{event_id}",
        "payload": _to_ddb_numeric(payload),
    }
    if causation_id is not None:
        item["causationId"] = causation_id
        item["parentEventId"] = causation_id
    if operator_id is not None:
        item["operatorId"] = operator_id

    get_dynamodb_table().put_item(Item=item)
    return event_id


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require_env() -> None:
    """Raise RuntimeError if AGENT_TABLE_NAME is absent (the only table here)."""
    if not os.environ.get("AGENT_TABLE_NAME"):
        raise RuntimeError("AGENT_TABLE_NAME is not set")
