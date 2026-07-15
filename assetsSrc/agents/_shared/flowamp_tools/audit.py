"""Audit tools — the write path for agent decisions and human overrides.

All audit rows live on the shared AgentTable. Two conventions to note:

1. **sk prefix.** The data-handler Lambda reads the Event Explorer with
   ``begins_with('EVENT#')`` on the shared AgentTable, so every event row is
   keyed ``EVENT#<ISO-ts>#<eventId>`` — that is the only way an agent-written
   event surfaces in the UI.
2. **actor / severity.** The UI renders an ``actor`` and ``severity`` column, so
   both are stamped on every row (actor defaults to this agent's id).

The decision/override/escalation event shapes, the 90-day TTL, and the
correlation/causation envelope are shared across all event writes.
"""
import json
import uuid
from datetime import datetime, timezone, timedelta

from strands.tools import tool

from ._config import get_agent_id, get_dynamodb_table

_TTL_DAYS = 90


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ttl_epoch() -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=_TTL_DAYS)).timestamp())


def _build_sk(timestamp: str, event_id: str) -> str:
    # EVENT# prefix so the row lands in the data-handler Event Explorer query
    # (begins_with('EVENT#')) rather than colliding with INFO/COST# rows.
    return f"EVENT#{timestamp}#{event_id}"


def _build_envelope(agent_id: str, action_type: str, timestamp: str, correlation_id: str | None, causation_id: str | None) -> dict:
    """Build the standard event envelope fields shared across all event writes."""
    return {
        "schemaVersion": "1.0",
        "correlationId": correlation_id if correlation_id is not None else str(uuid.uuid4()),
        "causationId": causation_id,
        "idempotencyKey": f"{agent_id}#{action_type}#{timestamp}",
    }


def _put_event(event_type: str, payload: dict, *, severity: str = "info", parent_event_id: str | None = None,
               correlation_id: str | None = None, causation_id: str | None = None,
               action_type: str | None = None) -> str:
    """Write one EVENT# row to the shared table and return the eventId."""
    agent_id = get_agent_id()
    event_id = str(uuid.uuid4())
    timestamp = _now_iso()
    envelope = _build_envelope(agent_id, action_type or event_type, timestamp, correlation_id, causation_id)

    item = {
        "agentId": agent_id,
        "sk": _build_sk(timestamp, event_id),
        "eventId": event_id,
        "eventType": event_type,
        "timestamp": timestamp,
        "payload": payload,
        "ttl": _ttl_epoch(),
        # UI-facing columns (data-handler _actor / severity rendering).
        "actor": agent_id,
        "severity": severity,
        **envelope,
    }
    if parent_event_id is not None:
        item["parentEventId"] = parent_event_id

    get_dynamodb_table().put_item(Item=item)
    return event_id


def _emit_agent_decision(
    action_type: str,
    input_summary: str,
    output_summary: str,
    aop_id: str | None = None,
    evaluation_result: str = "compliant",
    trace_id: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    work_item_id: str | None = None,
    extra_payload: dict | None = None,
) -> str:
    """Internal helper — emit an agent_decision event. Returns the eventId."""
    payload: dict = {
        "actionType": action_type,
        "inputSummary": input_summary,
        "outputSummary": output_summary,
        "evaluationResult": evaluation_result,
    }
    if aop_id is not None:
        payload["aopId"] = aop_id
    if trace_id is not None:
        payload["traceId"] = trace_id
    if work_item_id is not None:
        payload["workItemId"] = work_item_id
    if extra_payload:
        payload.update(extra_payload)

    severity = "warning" if evaluation_result in ("escalated", "blocked") else "info"
    return _put_event(
        "agent_decision", payload, severity=severity, action_type=action_type,
        correlation_id=correlation_id, causation_id=causation_id,
    )


def _emit_work_item_escalation(
    action_type: str,
    input_summary: str,
    output_summary: str,
    work_item_id: str,
    escalation_group: str,
    dependency_work_item_id: str | None = None,
    reason: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    extra_payload: dict | None = None,
) -> str:
    """Emit a work_item_escalation event (platform-level routing, no LLM ran)."""
    payload: dict = {
        "actionType": action_type,
        "inputSummary": input_summary,
        "outputSummary": output_summary,
        "workItemId": work_item_id,
        "escalationGroup": escalation_group,
    }
    if dependency_work_item_id is not None:
        payload["dependencyWorkItemId"] = dependency_work_item_id
    if reason is not None:
        payload["reason"] = reason
    if extra_payload:
        payload.update(extra_payload)

    return _put_event(
        "work_item_escalation", payload, severity="warning", action_type=action_type,
        correlation_id=correlation_id, causation_id=causation_id,
    )


@tool
def log_agent_decision(
    action_type: str,
    input_summary: str,
    output_summary: str,
    aop_id: str | None = None,
    evaluation_result: str = "compliant",
    trace_id: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
) -> str:
    """Record an agent decision in the FlowAMP audit log (EVENT# rows).

    Call this for decisions worth surfacing in the Event Explorer — for example
    a scanner classifying an agent, or an evaluator scoring a sample.

    Args:
        action_type: Short label for the action taken (e.g. "discovery_classification").
        input_summary: Human-readable summary of what the agent received as input.
        output_summary: Human-readable summary of the agent's output or recommendation.
        aop_id: ID of the AOP that governed this decision, if any.
        evaluation_result: "compliant", "escalated", or "blocked".
        trace_id: ID of the decision trace written via log_decision_trace, if any.
        correlation_id: Pass-through correlation ID from the triggering call; generated if omitted.
        causation_id: eventId of the event that triggered this decision, if any.

    Returns:
        JSON string with the written eventId.
    """
    event_id = _emit_agent_decision(
        action_type=action_type,
        input_summary=input_summary,
        output_summary=output_summary,
        aop_id=aop_id,
        evaluation_result=evaluation_result,
        trace_id=trace_id,
        correlation_id=correlation_id,
        causation_id=causation_id,
    )
    return json.dumps({"eventId": event_id, "eventType": "agent_decision"})


@tool
def log_human_override_request(
    original_output: str,
    reason: str,
    parent_event_id: str,
    replacement_output: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
) -> str:
    """Record a human override of an agent decision in the FlowAMP audit log.

    Args:
        original_output: The agent output being overridden.
        reason: Why the human is overriding the decision.
        parent_event_id: eventId of the agent_decision event being overridden.
        replacement_output: The corrected output the human provides, if any.
        correlation_id: Pass-through correlation ID from the triggering call; generated if omitted.
        causation_id: eventId of the event that triggered this override.

    Returns:
        JSON string with the written eventId.
    """
    payload: dict = {"originalOutput": original_output, "reason": reason}
    if replacement_output is not None:
        payload["replacementOutput"] = replacement_output

    event_id = _put_event(
        "human_override", payload, severity="warning", parent_event_id=parent_event_id,
        action_type="human_override", correlation_id=correlation_id, causation_id=causation_id,
    )
    return json.dumps({"eventId": event_id, "eventType": "human_override"})
