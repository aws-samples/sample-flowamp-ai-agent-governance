"""Sample workload: Supply-Chain Disruption Analyst.

A standalone Strands agent deployed on Amazon Bedrock AgentCore Runtime. It
monitors supplier and logistics signals, quantifies the impact of disruptions,
and recommends mitigations across a supply network.

This is an independent sample agent (not part of the FlowAMP control plane) so
that the FlowAMP governance platform can discover, classify, and govern it as a
real deployed workload. All data returned by the tools below is synthetic and
illustrative; a customer swaps in real ERP, TMS, and risk-feed integrations.

RESPONSIBLE USE: This is an illustrative sample for demonstration only. Its
outputs are non-binding suggestions for demonstration, not operational decisions.
Production deployments should attach an Amazon Bedrock Guardrail (set
guardrailId/guardrailVersion on the BedrockModel) and keep human review in the
loop before acting on any recommendation.
"""
# ---------------------------------------------------------------------------
# OTEL bootstrap — must run before any other import (boto3, strands, etc.).
#
# OpenTelemetry auto-instrumentation is enabled by launching the agent under the
# `opentelemetry-instrument` wrapper, which reads the OTEL_*/
# AGENT_OBSERVABILITY_ENABLED env vars and installs the global TracerProvider and
# OTLP exporter wired to aws/spans. See the AWS docs
# (bedrock-agentcore/observability-configure §"Enabling observability in agent
# code for AgentCore-hosted agents"). AgentCore direct-code deploy launches
# `python main.py` directly, so the agent re-execs itself under
# auto-instrumentation at startup to enable span export.
#
# The re-exec runs the container's interpreter and calls the wrapper's public
# entry point, opentelemetry.instrumentation.auto_instrumentation.run(), which is
# importable from the vendored packages in the bundle root. The _OTEL_REEXEC
# guard makes this one-shot. It is gated on AGENT_OBSERVABILITY_ENABLED so local
# runs are unaffected, and any failure is swallowed so a missing wrapper never
# crashes the agent.
import os as _os
import sys as _sys

if (
    _os.environ.get("AGENT_OBSERVABILITY_ENABLED") == "true"
    and not _os.environ.get("_OTEL_REEXEC")
):
    _os.environ["_OTEL_REEXEC"] = "1"
    _bundle_dir = _os.path.dirname(_os.path.abspath(__file__))
    _os.environ["PYTHONPATH"] = (
        _bundle_dir + _os.pathsep + _os.environ.get("PYTHONPATH", "")
    ).rstrip(_os.pathsep)
    try:
        # Safe: the exec target and argv are the process's own trusted values
        # (sys.executable, sys.argv) — no external/user input reaches this call.
        # It only re-launches this same script under OpenTelemetry auto-instrumentation.
        _os.execv(  # nosemgrep: dangerous-os-exec-tainted-env-args,dangerous-os-exec-audit
            _sys.executable,
            [
                _sys.executable,
                "-c",
                "from opentelemetry.instrumentation.auto_instrumentation import run; run()",
                _sys.executable,
                *_sys.argv,
            ],
        )
    except Exception as _reexec_exc:  # noqa: BLE001
        print(f"otel auto-instrument re-exec skipped: {_reexec_exc}")

import os
import json
import hashlib
from strands import Agent, tool
from strands.models.bedrock import BedrockModel


# Illustrative region risk weights and hazard profiles. A production deployment
# would pull these from a geopolitical/weather risk feed and a supplier master.
_REGION_RISK = {
    'apac': 0.55, 'emea': 0.40, 'namer': 0.25, 'latam': 0.50, 'africa': 0.60,
}
_REGION_HAZARDS = {
    'apac': ['typhoon season', 'port congestion'],
    'emea': ['labor strikes', 'energy prices'],
    'namer': ['rail capacity', 'weather events'],
    'latam': ['customs delays', 'currency volatility'],
    'africa': ['infrastructure gaps', 'political instability'],
}


def _stable_unit(seed):
    """Deterministic pseudo-random value in [0, 1) derived from a seed string."""
    digest = hashlib.sha256((seed or '').encode()).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


@tool
def assess_supplier_risk(supplier_name: str, region: str) -> str:
    """Assess the disruption risk for a supplier in a given region.

    Args:
        supplier_name: Name of the supplier to assess.
        region: Region code or name (e.g. apac, emea, namer, latam, africa).
    """
    region_key = (region or '').strip().lower()
    base = _REGION_RISK.get(region_key, 0.35)
    # Blend regional risk with a stable supplier-specific factor.
    supplier_factor = _stable_unit(supplier_name)
    score = round(min(1.0, 0.6 * base + 0.4 * supplier_factor), 2)

    if score >= 0.66:
        tier = 'high'
    elif score >= 0.4:
        tier = 'medium'
    else:
        tier = 'low'

    return json.dumps({
        'supplier': supplier_name,
        'region': region_key or 'unknown',
        'riskScore': score,
        'riskTier': tier,
        'knownHazards': _REGION_HAZARDS.get(region_key, ['general market risk']),
        'singleSourceDependency': supplier_factor > 0.7,
    }, default=str)


@tool
def estimate_delay_impact(shipment_id: str) -> str:
    """Estimate the delay and downstream impact for a delayed shipment.

    Args:
        shipment_id: Identifier of the affected shipment.
    """
    seed = _stable_unit(shipment_id)
    delay_days = int(1 + seed * 20)
    units_affected = int(500 + seed * 9500)
    # Illustrative revenue-at-risk model: units * margin * delay factor.
    revenue_at_risk = round(units_affected * 42.0 * (1 + delay_days / 30.0), 2)

    if delay_days >= 14:
        severity = 'critical'
    elif delay_days >= 7:
        severity = 'high'
    elif delay_days >= 3:
        severity = 'medium'
    else:
        severity = 'low'

    return json.dumps({
        'shipmentId': shipment_id,
        'estimatedDelayDays': delay_days,
        'unitsAffected': units_affected,
        'revenueAtRiskUsd': revenue_at_risk,
        'impactSeverity': severity,
        'stockoutLikely': delay_days >= 7,
    }, default=str)


@tool
def recommend_mitigation(disruption_summary: str) -> str:
    """Recommend mitigation actions for a described disruption.

    Args:
        disruption_summary: A short description of the disruption and its impact.
    """
    lowered = (disruption_summary or '').lower()
    actions = []
    if 'stockout' in lowered or 'shortage' in lowered or 'critical' in lowered:
        actions.append('expedite alternate-carrier freight')
        actions.append('activate secondary/backup supplier')
    if 'port' in lowered or 'congestion' in lowered or 'customs' in lowered:
        actions.append('reroute through alternate port of entry')
    if 'single' in lowered or 'sole' in lowered or 'dependency' in lowered:
        actions.append('initiate dual-sourcing qualification')
    if not actions:
        actions.append('monitor and hold; no immediate action required')

    priority = 'urgent' if ('critical' in lowered or 'stockout' in lowered) else 'standard'

    return json.dumps({
        'recommendedActions': actions,
        'priority': priority,
        'escalateToPlanningTeam': priority == 'urgent',
    }, default=str)


model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")

agent = Agent(
    model=model,
    tools=[assess_supplier_risk, estimate_delay_impact, recommend_mitigation],
    system_prompt="""You are a supply-chain disruption analyst.
You monitor supplier and logistics signals, quantify the operational and
financial impact of disruptions (delays, stockouts, revenue at risk), and
recommend concrete mitigation actions such as expediting freight, rerouting,
or activating backup suppliers.
Always use the available tools to gather risk scores, delay impacts, and
mitigation options before responding. Present quantified impact clearly and
call out single-source dependencies and urgent escalations.

IMPORTANT: This is an illustrative sample for demonstration only; outputs are
non-binding suggestions for demonstration, not operational decisions. A human
reviewer should validate any recommendation before it is acted on.""",
)


def handler(event, context):
    """HTTP handler for AgentCore Runtime."""
    body = json.loads(event.get('body', '{}')) if isinstance(event.get('body'), str) else event.get('body', {})
    prompt = body.get('prompt', body.get('message', ''))
    if not prompt:
        return {'statusCode': 400, 'body': json.dumps({'error': 'No prompt provided'})}

    result = agent(prompt)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'response': str(result)})
    }


if __name__ == '__main__':
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            result = handler({'body': body}, None)
            self.send_response(result['statusCode'])
            for k, v in result.get('headers', {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(result['body'].encode())

    port = int(os.environ.get('PORT', '8080'))
    # Bind host is configurable. Inside the AgentCore container the runtime must
    # reach the server, so this defaults to all interfaces; set BIND_HOST to a
    # specific address to restrict it.
    host = os.environ.get('BIND_HOST', '0.0.0.0')  # nosec B104 - container-internal server, host is configurable
    print(f"Starting agent on {host}:{port}")
    HTTPServer((host, port), Handler).serve_forever()
