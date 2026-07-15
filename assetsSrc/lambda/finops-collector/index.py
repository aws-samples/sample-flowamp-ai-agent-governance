"""FinOps daily collector — writes REAL per-agent spend from AWS Cost Explorer.

Writes per-agent daily spend into this repo's single AgentTable (Scan instead of a
GSI; no Athena invocation-count join; no OTEL token merge). Runs on a daily
EventBridge schedule, gated by the `enableCostExplorer` CDK flag.

For the previous UTC day it:
  1. enumerates active agents that have a runtime ARN (so we don't write $0 noise
     for placeholder registrations),
  2. runs FOUR Cost Explorer queries (one total + three per-service-group component
     queries) grouped by the `flowamp:agentId` cost-allocation tag, and
  3. writes one `COST#<date>` row per agent — the schema `data-handler.get_costs`
     reads and the UI aggregates — with `source: 'cost-explorer'`.

Hard prerequisites (external, cannot be automated in a member account):
  1. Resources are tagged `flowamp:agentId` (CDK stack + discovery-scanner do this).
  2. The `flowamp:agentId` cost-allocation tag is ACTIVATED in Billing; after
     activation CE takes up to ~24h to return data grouped by it.
Until both hold, CE returns nothing and the collector writes nothing (CE-only — no
synthetic fallback). Idempotent: an existing `final` row for the day is left as-is.

Cost Explorer notes (per AWS docs): the CE endpoint is ALWAYS us-east-1; tag group
keys come back as 'flowamp:agentId$<value>' (split on '$'); DataUnavailableException
/ empty = the normal "not ready yet" case; LimitExceededException = throttling, so
re-raise and let EventBridge retry.
"""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

TABLE_NAME = os.environ["AGENT_TABLE_NAME"]
COST_TAG_KEY = os.environ.get("COST_TAG_KEY", "flowamp:agentId")

_ddb = boto3.resource("dynamodb")
_table = _ddb.Table(TABLE_NAME)

# Service groups mapped to the UI's costByComponent sub-keys.
# (Lambda overlap between agentCompute and toolExecution is resolved by the service
# filter alone — acceptable for this attribution.) modelInference stays null: real
# per-model token cost needs OTEL token ingestion this repo doesn't have.
_COMPONENTS = {
    "agentCompute": ["AWS Lambda", "Amazon Elastic Compute Cloud - Compute"],
    "toolExecution": ["AWS Step Functions", "Amazon API Gateway"],
    "storage": ["Amazon Simple Storage Service", "Amazon DynamoDB"],
}

_TERMINAL_STATUSES = {"decommissioned", "rejected"}


def _yesterday_utc() -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=1)).strftime("%Y-%m-%d")


def _ce_query(target_date: str, services: list | None) -> dict:
    """Run one CE get_cost_and_usage grouped by the flowamp:agentId tag.

    services=None → account-wide total (all services). Otherwise filter to that
    SERVICE list for a component breakdown. Returns {agentId: Decimal}. Empty on
    DataUnavailableException / error; re-raises LimitExceededException (throttle).
    """
    end = (datetime.strptime(target_date, "%Y-%m-%d").date() + timedelta(days=1)).strftime("%Y-%m-%d")
    ce = boto3.client("ce", region_name="us-east-1")  # CE is always us-east-1
    tag_filter = {"Tags": {"Key": COST_TAG_KEY}}
    cost_filter = tag_filter if services is None else {
        "And": [tag_filter, {"Dimensions": {"Key": "SERVICE", "Values": services}}]
    }
    result: dict = {}
    next_token = None
    while True:
        kwargs = {
            "TimePeriod": {"Start": target_date, "End": end},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "Filter": cost_filter,
            "GroupBy": [{"Type": "TAG", "Key": COST_TAG_KEY}],
        }
        if next_token:
            kwargs["NextPageToken"] = next_token
        try:
            resp = ce.get_cost_and_usage(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "LimitExceededException":
                print("finops-collector: CE throttled; re-raising for EventBridge retry.")
                raise
            # DataUnavailableException and everything else: treat as "no data yet".
            print(f"finops-collector: CE query ({services or 'TOTAL'}) returned no data: {code or exc}")
            return {}
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                tag_val = group["Keys"][0]  # 'flowamp:agentId$<value>'
                agent_id = tag_val.split("$", 1)[-1] if "$" in tag_val else tag_val
                if not agent_id:
                    continue
                amount = group["Metrics"]["UnblendedCost"]["Amount"]
                result[agent_id] = result.get(agent_id, Decimal("0")) + Decimal(str(amount))
        next_token = resp.get("NextPageToken")
        if not next_token:
            break
    return result


def _list_active_agents_with_runtime() -> list:
    """INFO rows for non-terminal agents that have a runtime ARN.

    An agent with no runtimeId/runtimeArn has no tagged AWS resources, so CE would
    return $0 — that's noise, not signal, so skip it. Single-table Scan filtered to
    sk='INFO' (this repo has no sk-agentId-index GSI).
    """
    items, start_key = [], None
    while True:
        kwargs = {"FilterExpression": Attr("sk").eq("INFO")}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return [
        i for i in items
        if i.get("status") not in _TERMINAL_STATUSES and (i.get("runtimeId") or i.get("runtimeArn"))
    ]


def _dec(v):
    return v if isinstance(v, Decimal) else Decimal(str(v))


def handler(event, context):
    target_date = (event or {}).get("date") or _yesterday_utc()
    sk_val = "COST#" + target_date
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    agents = _list_active_agents_with_runtime()
    if not agents:
        print("finops-collector: no active agents with a runtime ARN; nothing to collect.")
        return {"date": target_date, "rowsWritten": 0, "reason": "no-eligible-agents"}

    # Four CE queries in parallel: total + three service-group components.
    with ThreadPoolExecutor(max_workers=4) as pool:
        fut_total = pool.submit(_ce_query, target_date, None)
        fut_components = {
            name: pool.submit(_ce_query, target_date, services)
            for name, services in _COMPONENTS.items()
        }
        ce_total = fut_total.result()  # LimitExceededException propagates → EB retry
        ce_components = {name: fut.result() for name, fut in fut_components.items()}

    if not ce_total:
        print(f"finops-collector: CE empty for {target_date} (tag not activated yet or no spend).")
        return {"date": target_date, "rowsWritten": 0, "reason": "ce-empty"}

    written = 0
    skipped_final = 0
    for agent in agents:
        agent_id = agent.get("agentId", "")
        if not agent_id:
            continue

        # Idempotent: leave an already-final row for the day untouched.
        existing = _table.get_item(Key={"agentId": agent_id, "sk": sk_val}).get("Item")
        if existing and existing.get("status") == "final":
            skipped_final += 1
            continue

        total_cost = ce_total.get(agent_id, Decimal("0"))
        row = {
            "agentId": agent_id,
            "sk": sk_val,
            "date": target_date,
            "status": "final",
            "source": "cost-explorer",
            "totalCost": _dec(total_cost).quantize(Decimal("0.000001")),
            "costByComponent": {
                # modelInference needs OTEL token cost we don't collect — leave null.
                "modelInference": None,
                "agentCompute": _maybe(ce_components["agentCompute"].get(agent_id)),
                "toolExecution": _maybe(ce_components["toolExecution"].get(agent_id)),
                "storage": _maybe(ce_components["storage"].get(agent_id)),
            },
            # No Athena invocation join here → invocationCount unknown (0).
            "invocationCount": 0,
            "tags": {
                "agentClass": agent.get("agentClass", ""),
                "businessUnit": agent.get("businessUnit", ""),
                "costCenter": agent.get("costCenter", ""),
            },
            "recordedAt": (existing or {}).get("recordedAt", now_iso),
            "updatedAt": now_iso,
        }
        _table.put_item(Item=row)
        written += 1

    print(f"finops-collector: wrote {written} COST# row(s) for {target_date} "
          f"({skipped_final} already final) from Cost Explorer")
    return {"date": target_date, "rowsWritten": written, "skippedFinal": skipped_final}


def _maybe(v):
    """Quantize a Decimal cost, or return None when the component had no cost."""
    return _dec(v).quantize(Decimal("0.000001")) if v is not None else None
