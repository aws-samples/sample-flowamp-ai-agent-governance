# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Eval provisioner — creates/enables/disables AgentCore online-evaluation configs.

AgentCore online-evaluation configs CANNOT be created at CDK/deploy time: the control
plane validates at create-time that the agent's trace log group already exists, and that
group's real name carries a runtime-id suffix
(`/aws/bedrock-agentcore/runtimes/<runtimeName>-<runtimeId>-DEFAULT`) that only exists
after the agent has run at least once. So provisioning is a RUNTIME operation, driven
from the UI:

  • POST /evaluations/enable  — for each core agent service.name, discover its live
    `-DEFAULT` runtime log group, then create_online_evaluation_config (idempotent: if a
    config for that agent already exists, reactivate it instead of duplicating). Returns
    a per-agent summary. Judge invocations accrue token cost, hence this is on-demand.
  • POST /evaluations/disable — flip every FlowAMP-managed config to DISABLED (stops the
    sampling + judge cost) without deleting it.

Config naming: `<runtimeName>Eval` (matches ^[a-zA-Z][a-zA-Z0-9_]{0,47}$). Each config
uses session/trace/tool coverage evaluators, 100% sampling (traffic volume is low here),
and a 5-minute session timeout.
"""
import json
import os

import boto3

_region = os.environ.get("AWS_REGION", "us-east-1")
EXECUTION_ROLE_ARN = os.environ.get("EVAL_EXECUTION_ROLE_ARN", "")
SERVICE_NAMES = [s for s in os.environ.get("EVAL_SERVICE_NAMES", "").split(",") if s]

RUNTIME_LOG_GROUP_PREFIX = "/aws/bedrock-agentcore/runtimes/"

# Session/trace/tool coverage — the built-in LLM-as-a-Judge evaluators applied to every
# config. Ids are the documented Builtin.* evaluator ids.
EVALUATOR_IDS = [
    "Builtin.GoalSuccessRate",
    "Builtin.Correctness",
    "Builtin.Helpfulness",
    "Builtin.ToolSelectionAccuracy",
]

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Origin": "*",
}


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def _control():
    return boto3.client("bedrock-agentcore-control", region_name=_region)


def _logs():
    return boto3.client("logs", region_name=_region)


def _config_name(service_name):
    """Deterministic, account-unique config name per agent (matches the name pattern)."""
    return (service_name + "Eval")[:48]


def _discover_log_group(service_name):
    """Find the agent's live `-DEFAULT` trace log group.

    Real name is `<prefix><serviceName>-<runtimeId>-DEFAULT`; there can be more than one
    (stale runtime ids from prior deploys), so prefer the most recently active. Returns
    the log group name, or None if the agent has never run (no group yet).
    """
    paginator = _logs().get_paginator("describe_log_groups")
    candidates = []
    for page in paginator.paginate(logGroupNamePrefix=RUNTIME_LOG_GROUP_PREFIX + service_name):
        for g in page.get("logGroups", []):
            name = g.get("logGroupName", "")
            # Only the DEFAULT (trace) group, not the -<endpoint> log groups.
            if name.endswith("-DEFAULT"):
                candidates.append((g.get("lastEventTimestamp", 0) or g.get("creationTime", 0), name))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _existing_configs():
    """Map onlineEvaluationConfigName -> summary for every existing config."""
    out = {}
    try:
        paginator = _control().get_paginator("list_online_evaluation_configs")
        for page in paginator.paginate():
            for c in page.get("onlineEvaluationConfigs",
                              page.get("onlineEvaluationConfigSummaries", page.get("items", []))):
                name = c.get("onlineEvaluationConfigName")
                if name:
                    out[name] = c
    except Exception as exc:  # noqa: BLE001 — the list API may paginate differently; fall back
        print(f"eval-provisioner: list_online_evaluation_configs failed: {exc}")
    return out


def _enable():
    """Create (or reactivate) one online-eval config per core agent. Idempotent."""
    if not EXECUTION_ROLE_ARN:
        return _resp(503, {"error": "eval execution role not configured"})
    control = _control()
    existing = _existing_configs()
    results = []
    for service_name in SERVICE_NAMES:
        name = _config_name(service_name)
        entry = {"agent": service_name, "configName": name}
        # Already exists → reactivate (ENABLED) rather than duplicate.
        if name in existing:
            cfg = existing[name]
            cfg_id = cfg.get("onlineEvaluationConfigId")
            try:
                control.update_online_evaluation_config(
                    onlineEvaluationConfigId=cfg_id, executionStatus="ENABLED"
                )
                entry.update(status="reactivated", configId=cfg_id)
            except Exception as exc:  # noqa: BLE001
                entry.update(status="error", error=f"reactivate failed: {exc}")
            results.append(entry)
            continue
        # New config: the agent's trace log group must already exist.
        log_group = _discover_log_group(service_name)
        if not log_group:
            entry.update(
                status="skipped",
                reason="No trace log group yet — this agent has not run, so there are no "
                "sessions to evaluate. Invoke it once (e.g. run a scan), then enable again.",
            )
            results.append(entry)
            continue
        try:
            resp = control.create_online_evaluation_config(
                onlineEvaluationConfigName=name,
                description=f"FlowAMP online evaluation for {service_name}",
                rule={
                    "samplingConfig": {"samplingPercentage": 100.0},
                    "sessionConfig": {"sessionTimeoutMinutes": 5},
                },
                dataSourceConfig={
                    "cloudWatchLogs": {
                        "logGroupNames": [log_group],
                        "serviceNames": [service_name],
                    }
                },
                evaluators=[{"evaluatorId": e} for e in EVALUATOR_IDS],
                evaluationExecutionRoleArn=EXECUTION_ROLE_ARN,
                enableOnCreate=True,
            )
            entry.update(
                status="created",
                configId=resp.get("onlineEvaluationConfigId"),
                logGroup=log_group,
            )
        except Exception as exc:  # noqa: BLE001
            entry.update(status="error", error=str(exc), logGroup=log_group)
        results.append(entry)
    ok = any(r["status"] in ("created", "reactivated") for r in results)
    return _resp(200 if ok else 207, {"action": "enable", "results": results})


def _disable():
    """Flip every FlowAMP-managed config (name endswith 'Eval') to DISABLED."""
    control = _control()
    results = []
    for name, cfg in _existing_configs().items():
        if not name.endswith("Eval"):
            continue
        cfg_id = cfg.get("onlineEvaluationConfigId")
        entry = {"configName": name, "configId": cfg_id}
        try:
            control.update_online_evaluation_config(
                onlineEvaluationConfigId=cfg_id, executionStatus="DISABLED"
            )
            entry["status"] = "disabled"
        except Exception as exc:  # noqa: BLE001
            entry.update(status="error", error=str(exc))
        results.append(entry)
    return _resp(200, {"action": "disable", "results": results})


def handler(event, context):
    method = event.get("httpMethod", "POST")
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}
    path = event.get("resource") or event.get("path", "")
    try:
        if path.endswith("/evaluations/disable"):
            return _disable()
        # Default (and /evaluations/enable): provision + enable.
        return _enable()
    except Exception as exc:  # noqa: BLE001 — never 500 the UI; report the failure.
        print(f"eval-provisioner: unhandled error: {exc}")
        return _resp(502, {"error": str(exc)})
