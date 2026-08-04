# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Work-item tools — no-op stubs for the single-table deployment.

Work items are the unit of AOP-runtime dispatch: a WorkItemTable whose DynamoDB
stream feeds EventBridge Pipes into a dispatch handler. This deployment has no AOP
runtime and no WorkItemTable, so the governance agents run in **one-shot mode**
(invoked directly, no workItemId). The agents' code still references these tools on
the dispatch path, so they are provided here as safe no-ops: each logs its call and
returns well-formed JSON, but writes nothing.

If an AOP runtime is ever added, replace this module with a real single-table
implementation that stores work items under a ``WI#<id>`` / ``TASK#`` / ``NOTE#``
sk convention on the shared table.
"""
import json
import logging
import uuid
from datetime import datetime, timezone

from strands.tools import tool

_log = logging.getLogger("flowamp.work_items")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _noop(fn_name: str, **detail) -> None:
    _log.info("work_items.%s is a no-op in this deployment (no AOP runtime): %s",
              fn_name, json.dumps(detail, default=str))


@tool
def create_work_item(
    title: str,
    instructions: str,
    priority: str,
    assignee_type: str = "agent",
    assigned_agent: str | None = None,
    assigned_to: str | None = None,
    assigned_group: str | None = None,
    escalation_group: str | None = None,
    escalation_criteria: str | None = None,
    timeout: int = 900,
    tags: list | None = None,
    dependencies: list | None = None,
    generated_by_aop_id: str | None = None,
    review_source: str | None = None,
    linked_compliance_sk: str | None = None,
    linked_decision_event_id: str | None = None,
) -> str:
    """Create a work item. No-op in this deployment (no AOP runtime / WorkItemTable).

    Returns a synthetic workItemId so callers that log or reference it keep working;
    nothing is persisted. Use log_agent_decision to record outcomes instead.
    """
    work_item_id = f"WI#local-{uuid.uuid4().hex[:12]}"
    _noop("create_work_item", title=title, priority=priority, workItemId=work_item_id)
    return json.dumps({"workItemId": work_item_id, "status": "not-persisted",
                       "note": "work items are not persisted in this deployment"})


@tool
def add_work_item_task(work_item_id: str, instructions: str, status: str = "pending") -> str:
    """Append a task to a work item. No-op in this deployment."""
    _noop("add_work_item_task", workItemId=work_item_id, status=status)
    return json.dumps({"workItemId": work_item_id, "taskSk": f"TASK#{_now_iso()}",
                       "status": "not-persisted"})


@tool
def update_work_item_task(work_item_id: str, task_sk: str, status: str, note: str | None = None) -> str:
    """Update a work-item task's status. No-op in this deployment."""
    _noop("update_work_item_task", workItemId=work_item_id, taskSk=task_sk, status=status)
    return json.dumps({"workItemId": work_item_id, "taskSk": task_sk, "status": "not-persisted"})


@tool
def add_work_item_note(work_item_id: str, text: str, documents_decision: bool = False) -> str:
    """Append a note to a work item. No-op in this deployment."""
    _noop("add_work_item_note", workItemId=work_item_id, documentsDecision=documents_decision)
    return json.dumps({"workItemId": work_item_id, "noteSk": f"NOTE#{_now_iso()}",
                       "status": "not-persisted"})


@tool
def update_work_item_info(work_item_id: str, **fields) -> str:
    """Update work-item INFO fields. No-op in this deployment."""
    _noop("update_work_item_info", workItemId=work_item_id, fields=list(fields.keys()))
    return json.dumps({"workItemId": work_item_id, "updated": list(fields.keys()),
                       "status": "not-persisted"})


@tool
def close_assigned_work_item(
    work_item_id: str,
    status: str,
    note: str,
    result_summary: str | None = None,
    escalation_description: str | None = None,
) -> str:
    """Close the work item assigned to this agent. No-op in this deployment.

    The agent's actual finding is captured by finalize_audit / log_agent_decision;
    closing a dispatch work item is only meaningful under the AOP runtime.
    """
    _noop("close_assigned_work_item", workItemId=work_item_id, status=status)
    return json.dumps({"workItemId": work_item_id, "status": status, "persisted": False})


@tool
def list_assigned_work_items(status_filter: str | None = None) -> list:
    """List work items assigned to this agent. Always empty in this deployment."""
    _noop("list_assigned_work_items", statusFilter=status_filter)
    return []


def increment_dispatch_count(work_item_id: str) -> int:
    """Bump a work item's dispatch counter. No-op; returns 0."""
    _noop("increment_dispatch_count", workItemId=work_item_id)
    return 0


def mark_work_item_externally_blocked(
    work_item_id: str,
    reason: str,
    escalation_group_override: str | None = None,
) -> dict:
    """Block a work item from outside its agent. No-op in this deployment."""
    _noop("mark_work_item_externally_blocked", workItemId=work_item_id, reason=reason)
    return {"workItemId": work_item_id, "status": "not-persisted"}
