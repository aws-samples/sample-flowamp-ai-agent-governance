# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Discovery-scan invoker — bridges the UI "Discover agents" button to the
AgentCore discovery-scanner runtime.

The scanner is an AgentCore runtime (invoke-only, no API of its own) and, being an
LLM agent doing multi-step tool calls, takes ~60-90s to run. API Gateway's hard
integration timeout is 29s — so this Lambda CANNOT invoke the scanner synchronously
behind the API and return the result. Instead it is **fire-and-forget**:

  • Invoked by API Gateway (POST /discovery/scan): it asynchronously re-invokes
    ITSELF (InvocationType='Event') and immediately returns HTTP 202. The browser
    is never held past a second or two.
  • Invoked asynchronously (the {"async_scan": true} payload): it performs the long
    InvokeAgentRuntime call against the scanner and lets it run to completion. The
    scanner writes discovered agents straight to the AgentTable, so the UI just
    reloads the registry after a short delay.
"""
import json
import os
import uuid

import boto3

RUNTIME_ARN = os.environ.get("DISCOVERY_SCANNER_ARN", "")
SELF_FUNCTION_NAME = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "")
_region = os.environ.get("AWS_REGION", "us-east-1")

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
}

_SCAN_PROMPT = (
    "Run a full discovery scan now: enumerate the AgentCore runtimes in this account, "
    "classify and enrich each new one (displayName, category, riskTier, capabilities, "
    "suggestedOwner), then commit them and report how many you discovered and committed."
)


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body)}


def _run_scan() -> None:
    """The long call — invoke the scanner runtime and let it finish. Runs in the
    async self-invocation, so the ~60-90s duration never touches API Gateway."""
    client = boto3.client("bedrock-agentcore", region_name=_region)
    session_id = "ui-discovery-" + uuid.uuid4().hex + uuid.uuid4().hex  # >= 33 chars
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        runtimeSessionId=session_id,
        payload=json.dumps({"prompt": _SCAN_PROMPT}),
    )
    # Drain the response so the runtime completes its work before we return.
    resp["response"].read()


def handler(event, context):
    # Async self-invocation path: do the long scanner call.
    if isinstance(event, dict) and event.get("async_scan"):
        if not RUNTIME_ARN:
            print("discovery-scan-invoker: DISCOVERY_SCANNER_ARN not set; nothing to do")
            return {"ok": False}
        try:
            _run_scan()
            print("discovery-scan-invoker: scan completed")
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001
            print(f"discovery-scan-invoker: scan failed: {exc}")
            return {"ok": False, "error": str(exc)}

    # API Gateway path (or OPTIONS preflight).
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    if not RUNTIME_ARN:
        return _resp(503, {"error": "discovery scanner is not deployed"})

    # Fire the async worker and return immediately (202). The scan runs in the
    # background copy of this function; the UI polls the registry for results.
    try:
        boto3.client("lambda", region_name=_region).invoke(
            FunctionName=SELF_FUNCTION_NAME,
            InvocationType="Event",  # async — returns without waiting
            Payload=json.dumps({"async_scan": True}).encode(),
        )
    except Exception as exc:  # noqa: BLE001
        return _resp(502, {"error": f"failed to start discovery scan: {exc}"})

    return _resp(202, {
        "status": "started",
        "message": ("Discovery scan started. The scanner is enumerating and classifying "
                    "AgentCore runtimes; results appear in the registry shortly."),
    })
