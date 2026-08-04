# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Compliance-scan invoker — bridges the UI "Run compliance audit" button and the
daily EventBridge schedule to the AgentCore compliance-scanner runtime.

The compliance-scanner is an AgentCore runtime (invoke-only, no API of its own) and,
being an LLM auditor running deterministic checks per agent, takes minutes. API
Gateway's hard integration timeout is 29s — so this Lambda CANNOT invoke it
synchronously behind the API. It is **fire-and-forget** (mirrors discovery-scan-invoker):

  • API Gateway (POST /compliance/scan): optionally takes {"agentId": "..."} to audit
    one agent; with no agentId the scanner rotation-picks the oldest-audited agent. It
    async re-invokes ITSELF (InvocationType='Event') and returns HTTP 202 immediately.
  • EventBridge schedule (daily): arrives with {"source": "aws.events"} → treated as a
    rotation run, same async path.
  • Async worker ({"async_audit": true, "agentId": ...}): performs the long
    InvokeAgentRuntime call. The scanner writes AUDIT#/RAI# rows to the AgentTable; the
    UI reads them back via GET /agents/{id}/audit.
"""
import json
import os
import uuid

import boto3

RUNTIME_ARN = os.environ.get("COMPLIANCE_SCANNER_ARN", "")
SELF_FUNCTION_NAME = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "")
_region = os.environ.get("AWS_REGION", "us-east-1")

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Origin": "*",
}


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def _run_audit(agent_id: str) -> str:
    """The long call — invoke the compliance-scanner and let it finish. Runs in the
    async self-invocation, so the multi-minute duration never touches API Gateway.

    Passes agentId when auditing a specific agent; an empty payload tells the scanner
    to rotation-pick the eligible agent with the oldest lastAuditedAt.

    Returns the scanner's response body as text so the caller can tell an audit that
    actually graded an agent from one that selected nothing. A rotation run that
    finds no target is not an error, but it must not be reported as a completed
    audit either — that reads as a clean run and hides the misconfiguration.
    """
    client = boto3.client("bedrock-agentcore", region_name=_region)
    session_id = "ui-compliance-" + uuid.uuid4().hex + uuid.uuid4().hex  # >= 33 chars
    payload = {"agentId": agent_id} if agent_id else {}
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        runtimeSessionId=session_id,
        payload=json.dumps(payload),
    )
    # Drain the response so the runtime completes its work before we return.
    raw = resp["response"].read()
    try:
        return raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


# Markers the scanner emits when a rotation run selected no agent. Matched
# case-insensitively against the response body.
_NO_TARGET_MARKERS = ("no eligible agents", "no agent selected", "no rotation target")


def _audited_nothing(body: str) -> bool:
    low = (body or "").lower()
    return any(m in low for m in _NO_TARGET_MARKERS)


def handler(event, context):
    # Async self-invocation path: do the long audit call.
    if isinstance(event, dict) and event.get("async_audit"):
        if not RUNTIME_ARN:
            print("compliance-scan-invoker: COMPLIANCE_SCANNER_ARN not set; nothing to do")
            return {"ok": False}
        try:
            body = _run_audit(event.get("agentId", ""))
            if _audited_nothing(body):
                print("compliance-scan-invoker: audit selected NO agent — nothing graded")
                return {"ok": True, "audited": False}
            print("compliance-scan-invoker: audit completed")
            return {"ok": True, "audited": True}
        except Exception as exc:  # noqa: BLE001
            print(f"compliance-scan-invoker: audit failed: {exc}")
            return {"ok": False, "error": str(exc)}

    # EventBridge scheduled invocation → rotation audit (no specific agent).
    if isinstance(event, dict) and event.get("source") == "aws.events":
        try:
            body = _run_audit("")  # rotation: scanner picks the oldest-audited eligible agent
            if _audited_nothing(body):
                print("compliance-scan-invoker: scheduled rotation selected NO agent — "
                      "nothing graded (check that eligible agents exist)")
                return {"ok": True, "audited": False}
            print("compliance-scan-invoker: scheduled rotation audit completed")
            return {"ok": True, "audited": True}
        except Exception as exc:  # noqa: BLE001
            print(f"compliance-scan-invoker: scheduled audit failed: {exc}")
            return {"ok": False, "error": str(exc)}

    # API Gateway path (or OPTIONS preflight).
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    if not RUNTIME_ARN:
        return _resp(503, {"error": "compliance scanner is not deployed"})

    # Optional {"agentId": "..."} in the body to audit a specific agent.
    body = {}
    try:
        body = json.loads(event.get("body") or "{}")
    except (TypeError, ValueError):
        body = {}
    agent_id = (body or {}).get("agentId", "")

    # Fire the async worker and return 202 immediately.
    try:
        boto3.client("lambda", region_name=_region).invoke(
            FunctionName=SELF_FUNCTION_NAME,
            InvocationType="Event",
            Payload=json.dumps({"async_audit": True, "agentId": agent_id}).encode(),
        )
    except Exception as exc:  # noqa: BLE001
        return _resp(502, {"error": f"failed to start compliance audit: {exc}"})

    return _resp(202, {
        "status": "started",
        "agentId": agent_id or None,
        "message": ("Compliance audit started. The scanner is running deterministic "
                    "checks and grading; results appear on the agent shortly."),
    })
