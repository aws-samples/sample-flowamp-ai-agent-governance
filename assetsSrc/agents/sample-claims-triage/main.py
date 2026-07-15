"""Sample workload: Insurance Claims Triage Assistant.

A standalone Strands agent deployed on Amazon Bedrock AgentCore Runtime. It
triages incoming insurance claims: summarizing free-text claim narratives,
classifying severity, flagging likely-fraud signals, and recommending routing.

This is an independent sample agent (not part of the FlowAMP control plane) so
that the FlowAMP governance platform can discover, classify, and govern it as a
real deployed workload. All data returned by the tools below is synthetic and
illustrative; a customer swaps in real claims-system integrations.

RESPONSIBLE USE: This is an illustrative sample for demonstration only, not a
production decision-making system. Its output is a preliminary, non-binding
triage suggestion and must not be used as an insurance coverage determination,
claims decision, or fraud adjudication. Production deployments in this regulated
domain should attach an Amazon Bedrock Guardrail (set guardrailId/guardrailVersion
on the BedrockModel) and keep a licensed human adjudicator in the loop for all
final decisions.
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
import re
from strands import Agent, tool
from strands.models.bedrock import BedrockModel


# Lightweight keyword lexicons used to derive illustrative, deterministic
# signals from free-text. A production deployment would replace these with a
# claims-management system, an ML severity model, and a fraud-scoring service.
_INJURY_TERMS = ('injury', 'injured', 'hospital', 'surgery', 'ambulance', 'fatality', 'death')
_PROPERTY_TERMS = ('collision', 'fire', 'flood', 'theft', 'water damage', 'total loss', 'vandalism')
_FRAUD_TERMS = ('no witnesses', 'cash', 'recently added', 'prior claim', 'staged',
                'inconsistent', 'no police report', 'backdated', 'exaggerated')


def _extract_amount(text):
    """Best-effort parse of a dollar figure mentioned in the claim text."""
    match = re.search(r'\$?\s*([\d,]+(?:\.\d{1,2})?)', text or '')
    if not match:
        return None
    try:
        return float(match.group(1).replace(',', ''))
    except ValueError:
        return None


@tool
def summarize_claim(claim_text: str) -> str:
    """Summarize a free-text insurance claim narrative into structured fields.

    Args:
        claim_text: The raw claim narrative submitted by the policyholder.
    """
    text = (claim_text or '').strip()
    lowered = text.lower()
    injury = any(term in lowered for term in _INJURY_TERMS)
    property_damage = any(term in lowered for term in _PROPERTY_TERMS)
    amount = _extract_amount(text)

    if 'auto' in lowered or 'collision' in lowered or 'vehicle' in lowered or 'car' in lowered:
        claim_type = 'auto'
    elif 'home' in lowered or 'property' in lowered or 'fire' in lowered or 'flood' in lowered:
        claim_type = 'property'
    elif injury:
        claim_type = 'bodily_injury'
    else:
        claim_type = 'general'

    summary = {
        'claimType': claim_type,
        'estimatedAmountUsd': amount,
        'involvesInjury': injury,
        'involvesPropertyDamage': property_damage,
        'wordCount': len(text.split()),
        'shortSummary': (text[:180] + '...') if len(text) > 180 else text,
    }
    return json.dumps(summary, default=str)


@tool
def classify_severity(claim_text: str) -> str:
    """Classify the severity of a claim as low, medium, high, or critical.

    Args:
        claim_text: The raw claim narrative to assess.
    """
    text = (claim_text or '').strip()
    lowered = text.lower()
    amount = _extract_amount(text) or 0.0
    injury = any(term in lowered for term in _INJURY_TERMS)
    fatality = 'fatality' in lowered or 'death' in lowered

    reasons = []
    if fatality:
        severity = 'critical'
        reasons.append('narrative indicates a fatality')
    elif injury or amount >= 100000:
        severity = 'high'
        if injury:
            reasons.append('bodily injury reported')
        if amount >= 100000:
            reasons.append(f'estimated exposure ${amount:,.0f} exceeds $100k')
    elif amount >= 10000:
        severity = 'medium'
        reasons.append(f'estimated exposure ${amount:,.0f} in the $10k-$100k band')
    else:
        severity = 'low'
        reasons.append('no injury and low estimated exposure')

    return json.dumps({
        'severity': severity,
        'reasoning': '; '.join(reasons),
        'estimatedAmountUsd': amount or None,
    }, default=str)


@tool
def suggest_next_action(claim_summary: str) -> str:
    """Recommend routing and next actions for a triaged claim.

    Args:
        claim_summary: A short summary of the claim (or its severity/type).
    """
    lowered = (claim_summary or '').lower()
    fraud_signals = [term for term in _FRAUD_TERMS if term in lowered]
    critical = 'critical' in lowered or 'fatality' in lowered or 'death' in lowered
    high = 'high' in lowered or 'injury' in lowered

    if critical:
        route = 'senior_adjuster_and_legal'
        sla_hours = 4
    elif high:
        route = 'senior_adjuster'
        sla_hours = 24
    elif fraud_signals:
        route = 'special_investigations_unit'
        sla_hours = 48
    else:
        route = 'standard_claims_queue'
        sla_hours = 72

    return json.dumps({
        'recommendedRoute': route,
        'targetSlaHours': sla_hours,
        'fraudSignals': fraud_signals,
        'requiresManualReview': bool(fraud_signals or critical),
    }, default=str)


model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")

agent = Agent(
    model=model,
    tools=[summarize_claim, classify_severity, suggest_next_action],
    system_prompt="""You are an insurance claims triage assistant.
You process incoming claims by summarizing the claim narrative, classifying
its severity (low/medium/high/critical), flagging likely-fraud signals, and
recommending how the claim should be routed and prioritized.
Always use the available tools to structure and assess a claim before
responding. Be explicit about fraud indicators and severity reasoning, but note
that final coverage and fraud decisions remain with a human adjuster.

IMPORTANT: This is an illustrative sample for demonstration only. Your output is
a preliminary, non-binding triage suggestion — NOT an insurance coverage
determination, claims decision, or fraud adjudication. A licensed human
adjudicator must review and make all final decisions. Do not provide legal or
financial advice.""",
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
