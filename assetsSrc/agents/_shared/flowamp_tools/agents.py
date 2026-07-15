"""Shared tool for invoking other FlowAMP agents via AgentCore."""
import json
import os
import uuid

import boto3
from strands import tool

_region = os.environ.get('AWS_REGION', 'us-east-1')


def _parse_agentcore_response(raw: str) -> str:
    """Parse SSE or plain JSON response body from an AgentCore invocation."""
    chunks: list[str] = []
    for line in raw.splitlines():
        if line.startswith('data:'):
            try:
                event = json.loads(line[5:].strip())
                if event.get('type') == 'output':
                    return str(event.get('result', ''))
                if event.get('type') == 'text':
                    chunks.append(str(event.get('result', '')))
            except json.JSONDecodeError:
                pass
    if chunks:
        return ''.join(chunks)
    # Not SSE — try plain JSON first, then return raw
    try:
        parsed = json.loads(raw)
        return str(parsed.get('result') or parsed.get('output') or parsed.get('content') or raw)
    except (json.JSONDecodeError, AttributeError):
        return raw


@tool
def invoke_agent(runtime_arn: str, prompt: str, session_id: str = '') -> str:
    """Invoke another FlowAMP agent by its AgentCore runtime ARN with a natural-language prompt.

    Use this to delegate work, ask questions, or request analysis from a registered agent.
    Returns the agent's text response, or an error message if invocation fails.

    Args:
        runtime_arn: The AgentCore runtime ARN of the agent to invoke.
        prompt: The message or question to send to the agent.
        session_id: Optional session ID for conversation continuity. Auto-generated if omitted.

    Returns JSON with status, runtimeArn, and the agent's response text.
    """
    if not runtime_arn:
        return json.dumps({'status': 'error', 'error': 'runtime_arn is required'})

    sid = session_id or str(uuid.uuid4())
    client = boto3.client('bedrock-agentcore', region_name=_region)
    try:
        response = client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            runtimeSessionId=sid,
            payload=json.dumps({'prompt': prompt}),
        )
        raw = response['response'].read().decode('utf-8', errors='replace')
        text = _parse_agentcore_response(raw)
        return json.dumps({'status': 'ok', 'runtimeArn': runtime_arn, 'sessionId': sid, 'response': text})
    except Exception as exc:
        return json.dumps({'status': 'error', 'runtimeArn': runtime_arn, 'error': str(exc)})
