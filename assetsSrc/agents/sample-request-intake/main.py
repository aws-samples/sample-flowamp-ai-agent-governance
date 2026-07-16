"""Sample workload: Service Request Intake Assistant.

A standalone Strands agent deployed on Amazon Bedrock AgentCore Runtime. It
structures free-text service requests, assigns a priority level, and routes each
request to an appropriate handling team.

IMPORTANT: This agent performs request structuring and routing ONLY. It does NOT
make final decisions; all routing output is a suggestion and should be confirmed
by the responsible team.

This is an independent sample agent (not part of the FlowAMP control plane) so
that the FlowAMP governance platform can discover, classify, and govern it as a
real deployed workload. All data returned by the tools below is synthetic and
illustrative; a customer swaps in real ticketing / service-management
integrations.

RESPONSIBLE USE: This is an illustrative sample for demonstration only, not a
production decision-making system. Its output is administrative request
structuring and routing. Production deployments should attach an Amazon Bedrock
Guardrail (set guardrailId/guardrailVersion on the BedrockModel) and keep a human
reviewer in the loop for consequential decisions.
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


# Illustrative keyword lexicon and team mapping. A production deployment would
# use a validated classifier and the organization's real team/queue registry.
_TOPIC_LEXICON = {
    'network': 'network', 'connectivity': 'network', 'vpn': 'network',
    'outage': 'network', 'latency': 'network',
    'login': 'access', 'password': 'access', 'access denied': 'access',
    'permission': 'access', 'account locked': 'access',
    'database': 'database', 'query': 'database', 'timeout': 'database',
    'security': 'security', 'breach': 'security', 'phishing': 'security',
    'vulnerability': 'security', 'malware': 'security',
    'billing': 'billing', 'invoice': 'billing', 'charge': 'billing',
    'refund': 'billing', 'payment': 'billing',
    'bug': 'application', 'error': 'application', 'crash': 'application',
    'feature request': 'application', 'slow': 'application',
}
# Keywords that indicate a possible critical incident and warrant immediate routing.
_RED_FLAGS = ('outage', 'breach', 'malware', 'data loss', 'security',
              'down', 'unavailable', 'production incident')
_TEAM_LABELS = {
    'network': 'Network Operations', 'access': 'Identity & Access',
    'database': 'Database Team', 'security': 'Security Operations',
    'billing': 'Billing & Accounts', 'application': 'Application Support',
    'general': 'General Support',
}


@tool
def extract_details(request_text: str) -> str:
    """Extract structured topics from a free-text service request.

    Args:
        request_text: The free-text service request submitted by the requester.
    """
    lowered = (request_text or '').lower()
    found = []
    for phrase, category in _TOPIC_LEXICON.items():
        if phrase in lowered:
            found.append({'topic': phrase, 'category': category})

    # Best-effort duration/impact capture for downstream context.
    duration_match = re.search(r'(\d+)\s*(hour|day|week|month)s?', lowered)
    affected_match = re.search(r'(\d{1,6})\s*(?:users?|customers?|systems?)', lowered)

    return json.dumps({
        'topics': found,
        'topicCount': len(found),
        'reportedImpactedCount': int(affected_match.group(1)) if affected_match else None,
        'reportedDuration': (duration_match.group(0) if duration_match else None),
        'note': 'Extraction is administrative only; not a resolution decision.',
    }, default=str)


@tool
def check_priority(topic_list: str) -> str:
    """Assign an administrative priority level for a set of request topics.

    Args:
        topic_list: A comma-separated or free-text list of request topics.
    """
    lowered = (topic_list or '').lower()
    red_flags = [flag for flag in _RED_FLAGS if flag in lowered]
    distinct = [phrase for phrase in _TOPIC_LEXICON if phrase in lowered]

    if red_flags:
        level = 'P1'
        target_minutes = 15
    elif len(distinct) >= 3:
        level = 'P2'
        target_minutes = 60
    elif distinct:
        level = 'P3'
        target_minutes = 240
    else:
        level = 'P4'
        target_minutes = 1440

    return json.dumps({
        'priorityLevel': level,
        'flaggedKeywords': red_flags,
        'targetTimeToResponseMinutes': target_minutes,
        'requiresImmediateReview': bool(red_flags),
        'disclaimer': 'Administrative prioritization only. The handling team must confirm.',
    }, default=str)


@tool
def suggest_team(request_summary: str) -> str:
    """Suggest a routing team based on a request summary.

    Args:
        request_summary: A short summary of the service request.
    """
    lowered = (request_summary or '').lower()
    scores = {}
    for phrase, category in _TOPIC_LEXICON.items():
        if phrase in lowered:
            scores[category] = scores.get(category, 0) + 1

    if any(flag in lowered for flag in _RED_FLAGS):
        category = 'security'
    elif scores:
        category = max(scores, key=scores.get)
    else:
        category = 'general'

    return json.dumps({
        'recommendedTeam': _TEAM_LABELS.get(category, 'General Support'),
        'teamCode': category,
        'alternates': [_TEAM_LABELS[c] for c in scores if c != category],
        'disclaimer': 'Routing suggestion only. The handling team confirms ownership.',
    }, default=str)


model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")

agent = Agent(
    model=model,
    tools=[extract_details, check_priority, suggest_team],
    system_prompt="""You are a service request intake assistant.
Your job is strictly administrative: you structure free-text service requests
into a list of topics, assign a priority level, and route each request to an
appropriate handling team.
You do NOT make final resolution decisions. Always state that your output is
administrative structuring and routing only, and that the responsible team must
review and confirm.
Always use the available tools to structure the request before responding, and
escalate any critical-incident keywords for immediate review.

IMPORTANT: This is an illustrative sample for demonstration only. Output is
administrative request structuring and routing — NOT a final decision. A human
reviewer must confirm consequential actions.""",
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
