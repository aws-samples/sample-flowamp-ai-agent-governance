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

Because the 202 goes back before the scan runs, the HTTP response cannot carry the
outcome, and the only place the API can read it from afterwards is the platform
sentinel row this Lambda shares with the scanner and with discovery-handler
(agentId=FLOWAMP_PLATFORMS, sk=PLATFORM#native), projected by
GET /discovery/connectors. This Lambda stamps only the states the scanner cannot
report for itself: 'running' before the long invoke, and 'error' when that invoke
throws, which is exactly the case where the scanner never started and so can write
nothing. The terminal 'ok'/'partial'/'error' with discovered counts belongs to the
scanner. Note the success literal is 'ok', not 'success': every other writer in the
repo emits 'ok' and the UI's colour map keys on it, so a record stamped 'success'
would render as the same neutral grey that means "no sync recorded".
"""
import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config

RUNTIME_ARN = os.environ.get("DISCOVERY_SCANNER_ARN", "")
SELF_FUNCTION_NAME = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "")
_region = os.environ.get("AWS_REGION", "us-east-1")

# The outcome row. os.environ.get rather than os.environ[...] on purpose: recording the
# outcome is bookkeeping, and a deploy that has not wired the table must still be able to
# run a scan rather than failing at import.
AGENT_TABLE_NAME = os.environ.get("AGENT_TABLE_NAME", "")
PLATFORM_SENTINEL_PK = "FLOWAMP_PLATFORMS"
# The scanner discovers native (this-account) agents, so its outcome lands on the same tile
# discovery-handler publishes the discovery-ownership details onto.
PLATFORM_ID = "native"

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


def _now() -> str:
    """UTC ISO8601 with a trailing Z, the same format discovery-scanner writes, so the two
    halves of one scan's reporting cannot be told apart by their timestamps.

    Computed per call, never cached at module scope: Lambda reuses a warm container across
    invocations, so a module-level timestamp would report the cold start instead of the scan.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp(status: str, error: str = "", summary: str = "", only_if_running: bool = False) -> None:
    """Record the scan's state on the platform sentinel row, the only place the API can read
    it back from once the 202 has been returned.

    Swallows its own failures deliberately, mirroring `_record_sync_outcome` in
    discovery-handler: a scan must never be reported as failed because the bookkeeping write
    was denied, and the caller's except block has to surface the real exception rather than
    one raised in here.

    Writes no `details` map. `details` is replaced whole by any writer, and discovery-handler
    maintains it for this tile (the discovery-ownership explanation, refreshed on every
    scheduled sync), as may the scanner with per-scan counts. Status fields only, so nothing
    here clobbers either of them.
    """
    if not AGENT_TABLE_NAME:
        print("discovery-scan-invoker: AGENT_TABLE_NAME not set; scan outcome not recorded")
        return
    try:
        ddb_table = boto3.resource("dynamodb", region_name=_region).Table(AGENT_TABLE_NAME)
        values = {
            ":t": _now(),
            ":s": status,
            ":e": error[:500],
            ":sum": summary[:500],
            ":p": PLATFORM_ID,
        }
        condition = {}
        if only_if_running:
            # Atomic: replace the row only while it still reads 'running'. If the scanner
            # already wrote its own terminal status (with counts), the write is rejected
            # with ConditionalCheckFailedException, swallowed below, and that status stands.
            values[":running"] = "running"
            condition = {"ConditionExpression": "lastSyncStatus = :running"}
        ddb_table.update_item(
            Key={"agentId": PLATFORM_SENTINEL_PK, "sk": f"PLATFORM#{PLATFORM_ID}"},
            UpdateExpression=(
                "SET lastSyncAt = :t, lastSyncStatus = :s, lastError = :e, "
                "lastSyncSummary = :sum, platformId = :p"
            ),
            ExpressionAttributeValues=values,
            **condition,
        )
    except Exception as exc:  # noqa: BLE001
        # Type only: the message can quote the update expression and the row contents.
        print(f"discovery-scan-invoker: could not record scan outcome: {type(exc).__name__}")


def _run_scan() -> None:
    """The long call — invoke the scanner runtime and let it finish. Runs in the
    async self-invocation, so the ~60-90s duration never touches API Gateway.

    The payload shape is the scanner entrypoint's, not ours to choose: `invoke` in
    discovery-scanner/main.py reads the newest user message out of `messages` and falls back
    to a generic "Run a discovery scan and report results." for any other shape, silently.
    A bare {"prompt": ...} therefore deployed cleanly, ran a scan, and delivered none of
    _SCAN_PROMPT. `messages` is the convention across both scanners and both entrypoints.
    """
    # botocore's default read timeout is 60s, shorter than the scan this call drains, so a
    # healthy scan would raise ReadTimeoutError here and be stamped 'error' while the scanner
    # was still committing. Note read_timeout bounds a SILENT stall (the gap between reads),
    # not the whole call: a scan that keeps streaming is bounded only by the function's 600s
    # timeout (team-stack.ts), where Lambda's own retries are switched off. No SDK retries
    # either: a retried InvokeAgentRuntime is a second, concurrent scan, not a recovery.
    client = boto3.client(
        "bedrock-agentcore", region_name=_region,
        config=Config(read_timeout=570, connect_timeout=10,
                      retries={"total_max_attempts": 1, "mode": "standard"}),
    )
    session_id = "ui-discovery-" + uuid.uuid4().hex + uuid.uuid4().hex  # >= 33 chars
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        runtimeSessionId=session_id,
        # scanRequested tells the scanner this invocation was stamped 'running', so it must
        # leave a terminal status even if the turn ends before any scan starts.
        payload=json.dumps({"messages": [{"role": "user", "content": _SCAN_PROMPT}],
                            "scanRequested": True}),
    )
    # Drain the response so the runtime completes its work before we return.
    resp["response"].read()


def handler(event, context):
    # Async self-invocation path: do the long scanner call.
    if isinstance(event, dict) and event.get("async_scan"):
        if not RUNTIME_ARN:
            print("discovery-scan-invoker: DISCOVERY_SCANNER_ARN not set; nothing to do")
            return {"ok": False}
        # 'running' before the long call, so a scan that dies mid-flight leaves a row saying
        # a scan started and when, rather than the previous run's stale 'success'.
        _stamp("running", summary="Discovery scan started; the scanner is enumerating agents.")
        try:
            _run_scan()
            print("discovery-scan-invoker: scan completed")
            # No 'success' stamp here on purpose: draining the response proves the runtime
            # answered, not that the scan enumerated or committed anything. Only the scanner
            # knows that, and it writes the terminal status with its counts.
            #
            # But the scan IS over, so a row still reading 'running' means the scanner never
            # reported (a dropped stream, which the scanner deliberately does not treat as a
            # failure, or its own stamp failing). Left alone that reads as in flight forever.
            # Conditional, so any outcome the scanner did write always stands.
            _stamp("error",
                   summary="The discovery scan ended without reporting an outcome.",
                   only_if_running=True)
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001
            print(f"discovery-scan-invoker: scan failed: {exc}")
            if type(exc).__name__ == "ReadTimeoutError":
                # We stopped waiting; that is not the scan failing. The scanner may still be
                # committing and writes its own terminal status, and the UI has its own
                # ceiling for a scanner that dies silently. Reporting 'error' here told the
                # UI the scan had failed and re-enabled the button mid-scan.
                return {"ok": False, "error": str(exc)}
            # The only chance to record this failure anywhere the API can see it: the scanner
            # was never reached (or died before reporting), and the 202 went out long ago.
            # Conditional, because the scanner may have stamped its own outcome (a 'partial'
            # with counts, say) before its stream failed; that is the better record.
            _stamp("error", error=str(exc),
                   summary="The discovery scanner could not be invoked.",
                   only_if_running=True)
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
        # Not stamped as an outcome: this failure is answered synchronously, so the caller
        # already sees it. The row exists for failures that happen after the response.
        return _resp(502, {"error": f"failed to start discovery scan: {exc}"})

    return _resp(202, {
        "status": "started",
        "message": ("Discovery scan started. The scanner is enumerating and classifying "
                    "AgentCore runtimes; results appear in the registry shortly."),
    })
