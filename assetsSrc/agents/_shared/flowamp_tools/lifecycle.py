# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""lifecycle.py — writes lifecycle_change events to the shared table.

Called on every agent (or AOP) state transition. Single-table port: rows are
keyed EVENT#<ts>#<id> so they surface in the data-handler Event Explorer, and
carry actor/severity for the UI. For non-agent entities the partition key is
prefixed with the entity type to avoid colliding with agent partitions.
"""
import json
import uuid
from datetime import datetime, timezone, timedelta

from ._config import get_dynamodb_table

_TTL_DAYS = 90


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ttl_epoch() -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=_TTL_DAYS)).timestamp())


def log_lifecycle_change(
    entity_type: str,
    entity_id: str,
    previous_state: str,
    new_state: str,
    reason: str,
    operator_id: str,
    correlation_id: str | None = None,
    causation_id: str | None = None,
) -> str:
    """Write a lifecycle_change event for an agent, AOP, dataset, or model.

    For agent entities the partition key is entity_id so the event is discoverable
    via the standard per-agent query; for others the PK is prefixed with the type.

    Args:
        entity_type: "agent" | "aop" | "dataset" | "model"
        entity_id: Primary key of the entity being transitioned.
        previous_state: State before the transition (use "none" for creation events).
        new_state: State after the transition.
        reason: Human-readable explanation for the change.
        operator_id: Cognito sub of the user (or agent id) who initiated the transition.
        correlation_id: Pass-through correlation ID; generated if omitted.
        causation_id: eventId of the event that caused this transition, if any.

    Returns:
        JSON string with the written eventId.
    """
    event_id = str(uuid.uuid4())
    timestamp = _now_iso()
    action_type = "lifecycle_change"

    agent_id_pk = entity_id if entity_type == "agent" else f"{entity_type}:{entity_id}"

    envelope = {
        "schemaVersion": "1.0",
        "correlationId": correlation_id if correlation_id is not None else str(uuid.uuid4()),
        "causationId": causation_id,
        "idempotencyKey": f"{agent_id_pk}#{action_type}#{timestamp}",
    }

    payload = {
        "entityType": entity_type,
        "entityId": entity_id,
        "previousState": previous_state,
        "newState": new_state,
        "reason": reason,
    }

    item = {
        "agentId": agent_id_pk,
        "sk": f"EVENT#{timestamp}#{event_id}",
        "eventId": event_id,
        "eventType": "lifecycle_change",
        "timestamp": timestamp,
        "actor": operator_id,
        "severity": "info",
        "operatorId": operator_id,
        "payload": payload,
        "ttl": _ttl_epoch(),
        **envelope,
    }

    get_dynamodb_table().put_item(Item=item)

    return json.dumps({"eventId": event_id, "eventType": "lifecycle_change"})
