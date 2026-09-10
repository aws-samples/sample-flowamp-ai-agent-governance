# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import os
import boto3

# InvokeHarness needs a recent botocore, and the Lambda-bundled SDK version is not pinned by AWS
# and can vary by region. If /chat fails with "object has no attribute 'invoke_harness'", bundle a
# newer botocore into this function's asset directory (or just its
# bedrock-agentcore/<api-version>/service-2.json model, pointed at by AWS_DATA_PATH).
agentcore = boto3.client('bedrock-agentcore')
HARNESS_ARN = os.environ['HARNESS_ARN']

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])

# Agent whose request counter this handler increments. FinOps cost comes from Cost Explorer
# (finops-collector), not from here.
REP_AGENT = os.environ.get('REP_AGENT_ID', 'service-health-monitor')

# AgentCore runtime sessions require a session id of at least 33 characters, and the UI sends a
# shorter 'session-<epoch>' value, so short ids are padded.
MIN_SESSION_ID_LEN = 33
MAX_SESSION_ID_LEN = 100


def _normalize_session_id(session_id):
    """Pad or truncate a caller session id into the length range AgentCore requires.

    Padding repeats the filler until the minimum is reached, so even a 1-character id is long
    enough. Deterministic, so one browser session always maps to the same harness session and keeps
    its conversation context.
    """
    if len(session_id) >= MIN_SESSION_ID_LEN:
        return session_id[:MAX_SESSION_ID_LEN]
    filler = '-flowamp-chat-session'
    padded = session_id
    while len(padded) < MIN_SESSION_ID_LEN:
        padded += filler
    return padded[:MIN_SESSION_ID_LEN]


def _parse_harness_stream(stream):
    """Assemble the answer, token usage and tool calls from an InvokeHarness stream.

    Returns (answer, tool_calls, rationales, usage). The harness streams the managed agent loop back
    as discrete events, carrying the token counts and the tools the agent called as well as the
    answer text.
    """
    answer = ''
    tool_calls = []
    rationales = []
    usage = {'input': 0, 'output': 0, 'total': 0}

    # Which content-block indices in the current message are tool blocks, so a toolUse block's
    # streamed input deltas are not mistaken for answer text. contentBlockIndex restarts at 0 on
    # every message, so the final answer usually arrives at an index an earlier toolUse block used:
    # this map must be cleared at each messageStart, or every answer following a tool call is
    # silently swallowed.
    tool_blocks = {}

    for event in stream:
        try:
            if 'messageStart' in event:
                tool_blocks = {}
            elif 'contentBlockStart' in event:
                start = event['contentBlockStart'].get('start', {})
                idx = event['contentBlockStart'].get('contentBlockIndex')
                # Test for the key, not its truthiness: an empty toolUse/toolResult marker is a
                # legitimate event, and treating it as absent leaves the block unmarked so its
                # payload leaks into the answer text.
                if 'toolUse' in start:
                    name = (start.get('toolUse') or {}).get('name', '')
                    tool_blocks[idx] = name or 'toolUse'
                    if name:
                        tool_calls.append(name)
                elif 'toolResult' in start:
                    # Tool results stream back as a `user` message; mark the block so its payload
                    # never lands in the answer.
                    tool_blocks[idx] = 'toolResult'
            elif 'contentBlockDelta' in event:
                block = event['contentBlockDelta']
                delta = block.get('delta', {})
                # Only plain `text` deltas are the answer; toolUse/toolResult deltas are the loop's
                # internals, and reasoning goes to the trace log.
                if 'text' in delta and block.get('contentBlockIndex') not in tool_blocks:
                    answer += delta['text']
                reasoning = delta.get('reasoningContent', {}).get('text')
                if reasoning:
                    rationales.append(reasoning.strip().replace('\n', ' ')[:160])
            elif 'metadata' in event:
                # The harness reports usage once, on the terminal metadata event.
                u = event['metadata'].get('usage', {})
                usage['input'] = int(u.get('inputTokens', 0) or 0)
                usage['output'] = int(u.get('outputTokens', 0) or 0)
                usage['total'] = int(u.get('totalTokens', 0) or 0)
            elif ('validationException' in event or 'internalServerException' in event
                    or 'runtimeClientError' in event):
                # Surface a harness-side failure instead of returning an empty answer.
                err = (event.get('validationException') or event.get('internalServerException')
                       or event.get('runtimeClientError') or {})
                print('harness stream error: ' + json.dumps(err, default=str))
        except Exception as exc:
            # A malformed event must not lose the text already assembled.
            print(f'harness stream event skipped: {type(exc).__name__}: {exc}')

    usage['total'] = usage['total'] or (usage['input'] + usage['output'])
    return answer, tool_calls, rationales, usage


def handler(event, context):
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
    }

    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    body = json.loads(event.get('body', '{}'))
    prompt = body.get('prompt', '')
    session_id = body.get('sessionId', context.aws_request_id)

    if not prompt:
        return {'statusCode': 400, 'headers': headers, 'body': json.dumps({'error': 'No prompt'})}

    response = agentcore.invoke_harness(
        harnessArn=HARNESS_ARN,
        runtimeSessionId=_normalize_session_id(session_id),
        messages=[{'role': 'user', 'content': [{'text': prompt}]}],
    )

    result, tool_calls, rationales, usage = _parse_harness_stream(response.get('stream', []))

    # Readable per-chat reasoning + token record in CloudWatch Logs.
    print('=== FlowAMP chat trace ===')
    print('prompt: ' + prompt[:200])
    if rationales:
        print('reasoning: ' + ' | '.join(rationales[:3]))
    print('tool calls: ' + (', '.join(tool_calls) if tool_calls else '(none)'))
    print('tokens: in=%d out=%d total=%d' % (usage['input'], usage['output'], usage['total']))
    print('==========================')

    # Bump the representative agent's request counter. Cost comes from the finops-collector
    # (source='cost-explorer'); this handler writes no COST# row. Conditional so a clean catalog
    # never gains a phantom INFO row for REP_AGENT, and wrapped so a write failure cannot break chat.
    try:
        table.update_item(
            Key={'agentId': REP_AGENT, 'sk': 'INFO'},
            UpdateExpression='ADD requests :one',
            ConditionExpression='attribute_exists(agentId)',
            ExpressionAttributeValues={':one': 1},
        )
    except Exception:
        pass

    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({
            'response': result,
            'sessionId': session_id,
            # Per-chat trace, so the UI can show which registry tools the agent called and what the
            # turn cost in tokens.
            'trace': {
                'toolCalls': tool_calls,
                'tokens': usage,
            },
        }),
    }
