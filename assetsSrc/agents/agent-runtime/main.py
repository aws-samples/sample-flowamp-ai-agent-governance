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
import boto3
from strands import Agent, tool
from strands.models.bedrock import BedrockModel

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ.get('AGENT_TABLE_NAME', 'AgentTable'))

# Explicit field allowlist so only non-sensitive agent attributes are returned to
# the LLM (and thus into model responses) — never full database records.
_AGENT_FIELDS = {
    'agentId', 'name', 'description', 'category', 'owner', 'system', 'platform',
    'runtime', 'status', 'monthlyCost', 'costPerInvocation', 'requests', 'errors',
    'avgResponseMs', 'utilization', 'score',
}


def _project(item):
    return {k: v for k, v in item.items() if k in _AGENT_FIELDS}


@tool
def list_agents() -> str:
    """List all registered AI agents across all systems."""
    items = table.scan().get('Items', [])
    return json.dumps([_project(i) for i in items], default=str)


@tool
def get_agent(agent_id: str) -> str:
    """Get details of a specific AI agent by its ID."""
    item = table.get_item(Key={'agentId': agent_id}).get('Item', {})
    return json.dumps(_project(item), default=str)


@tool
def get_agent_metrics(agent_id: str) -> str:
    """Get performance metrics (requests, errors, response time) for an agent."""
    item = table.get_item(Key={'agentId': agent_id}).get('Item', {})
    return json.dumps({k: item.get(k) for k in
        ['agentId', 'name', 'requests', 'errors', 'avgResponseMs', 'status']}, default=str)


model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")

agent = Agent(
    model=model,
    tools=[list_agents, get_agent, get_agent_metrics],
    system_prompt="""You are an AI agent management assistant for an enterprise.
You help operators monitor and manage AI agents deployed across operations,
asset and infrastructure, finance and trading, security and compliance, and customer operations.
Always use the available tools to fetch real data before responding.""",
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
