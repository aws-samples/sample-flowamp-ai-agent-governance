# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Trace tool — record an agent's step-by-step decision reasoning.

A decision trace is the drill-down detail behind a single agent_decision event.
The row is keyed EVENT#<ts>#<id> so it lands in the data-handler Event Explorer,
and carries actor/severity for the UI. The reasoning steps are also mirrored to
the runtime log group.
"""
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta

from strands.tools import tool

from ._config import get_agent_id, get_dynamodb_table

_TTL_DAYS = 90
_log = logging.getLogger("flowamp.decision_trace")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ttl_epoch() -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=_TTL_DAYS)).timestamp())


@tool
def log_decision_trace(
    trace_steps: list,
    trace_id: str,
    correlation_id: str | None = None,
) -> str:
    """Record the step-by-step reasoning behind an agent decision.

    Each step is a dict describing one stage of the agent's reasoning. Pass the
    same trace_id to log_agent_decision so the two link up. The trace is written
    as a decision_trace EVENT# row and mirrored to the runtime log group.

    Args:
        trace_steps: Ordered list of step dicts, each containing at minimum a "step" key.
        trace_id: Shared id linking this trace to its agent_decision event.
        correlation_id: Optional correlation id from the triggering call; generated if omitted.

    Returns:
        JSON string with traceId, eventId, eventType, and stepCount.
    """
    agent_id = get_agent_id()
    event_id = str(uuid.uuid4())
    timestamp = _now_iso()
    correlation = correlation_id if correlation_id is not None else str(uuid.uuid4())

    item = {
        "agentId": agent_id,
        "sk": f"EVENT#{timestamp}#{event_id}",
        "eventId": event_id,
        "eventType": "decision_trace",
        "timestamp": timestamp,
        "actor": agent_id,
        "severity": "info",
        "payload": {
            "traceId": trace_id,
            "steps": trace_steps,
            "stepCount": len(trace_steps),
        },
        "ttl": _ttl_epoch(),
        "schemaVersion": "1.0",
        "correlationId": correlation,
        "causationId": None,
        "idempotencyKey": f"{agent_id}#decision_trace#{trace_id}",
    }

    get_dynamodb_table().put_item(Item=item)

    _log.info(
        "decision_trace traceId=%s steps=%d correlationId=%s detail=%s",
        trace_id, len(trace_steps), correlation, json.dumps(trace_steps, default=str),
    )

    return json.dumps({
        "traceId": trace_id,
        "eventId": event_id,
        "eventType": "decision_trace",
        "stepCount": len(trace_steps),
        "correlationId": correlation,
    })
