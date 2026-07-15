"""flowamp_tools — shared Strands @tool package for all FlowAMP agents.

Exports are loaded lazily on first attribute access (PEP 562) so that
importing ``flowamp_tools`` alone does not pull the full Strands graph
(LLM clients, OTEL tracer, @tool registry) into the process.  Production
agent code that does ``from flowamp_tools.audit import log_agent_decision``
imports the submodule directly and is unaffected.  Tests that only need
pure-mock helpers no longer pay the strands startup cost.
"""

__all__ = [
    "log_agent_decision",
    "log_human_override_request",
    "AuditLogger",
    "log_decision_trace",
    "list_active_agents",
    "create_work_item",
    "add_work_item_task",
    "update_work_item_task",
    "add_work_item_note",
    "update_work_item_info",
    "close_assigned_work_item",
    "list_assigned_work_items",
    "mark_work_item_externally_blocked",
    "increment_dispatch_count",
    "log_lifecycle_change",
    "get_model_config",
    "invoke_agent",
    "write_rai_score",
    "write_audit_report",
    "add_audit_note",
    "latest_rai_score",
    "audit_history",
    "log_compliance_event",
    "get_framework",
    "list_frameworks",
    "put_framework",
    "soft_delete_framework",
    "list_agent_frameworks",
]

# Maps each public name to the submodule that owns it.
_SUBMODULE_FOR_ATTR: dict[str, str] = {
    "log_agent_decision": "audit",
    "log_human_override_request": "audit",
    "AuditLogger": "audit_logger",
    "log_decision_trace": "trace",
    "list_active_agents": "agent_catalog",
    "create_work_item": "work_items",
    "add_work_item_task": "work_items",
    "update_work_item_task": "work_items",
    "add_work_item_note": "work_items",
    "update_work_item_info": "work_items",
    "close_assigned_work_item": "work_items",
    "list_assigned_work_items": "work_items",
    "mark_work_item_externally_blocked": "work_items",
    "increment_dispatch_count": "work_items",
    "log_lifecycle_change": "lifecycle",
    "get_model_config": "config",
    "invoke_agent": "agents",
    "write_rai_score": "compliance",
    "write_audit_report": "compliance",
    "add_audit_note": "compliance",
    "latest_rai_score": "compliance",
    "audit_history": "compliance",
    "log_compliance_event": "compliance",
    "get_framework": "frameworks",
    "list_frameworks": "frameworks",
    "put_framework": "frameworks",
    "soft_delete_framework": "frameworks",
    "list_agent_frameworks": "frameworks",
}


def __getattr__(name: str):
    submodule_name = _SUBMODULE_FOR_ATTR.get(name)
    if submodule_name is None:
        raise AttributeError(f"module 'flowamp_tools' has no attribute {name!r}")
    import importlib
    submodule = importlib.import_module(f".{submodule_name}", __name__)
    value = getattr(submodule, name)
    # Cache in module globals so subsequent accesses bypass __getattr__
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
