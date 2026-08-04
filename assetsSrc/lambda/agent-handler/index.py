# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import os
import boto3
from decimal import Decimal

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])

PREFIXES = ('compliance:', 'aop:', 'access:')

# Explicit field allowlists per record type so responses never expose the internal
# 'sk' key or unexpected attributes to the Bedrock Agent / LLM (least-exposure).
_AGENT_FIELDS = {
    'agentId', 'name', 'description', 'category', 'owner', 'system', 'platform',
    'platformAgentId', 'runtime', 'status', 'source', 'createdAt', 'updatedAt',
    'lastSyncedAt', 'lastSynced', 'monthlyCost', 'costPerInvocation', 'requests',
    'errors', 'avgResponseMs', 'utilization', 'score', 'fairness', 'transparency',
    'accountability', 'ethics', 'costCenter', 'businessUnit', 'tags',
}
_COMPLIANCE_FIELDS = {'agentId', 'name', 'complianceScore', 'status', 'lastAudit', 'controls'}
_AOP_FIELDS = {'agentId', 'aopId', 'name', 'status', 'agents', 'executions',
               'successRate', 'owner', 'entry'}
_ACCESS_FIELDS = {'agentId', 'userName', 'role', 'accessLevel', 'operations',
                  'assetMgmt', 'finance', 'security', 'customer'}

def _project(items, allowed):
    """Reduce each item to the allowed field set (drops 'sk' and anything else)."""
    return [{k: v for k, v in item.items() if k in allowed} for item in items]

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal): return float(o)
        return super().default(o)

def scan_info():
    """All canonical entity rows (sk='INFO'). Excludes COST#/EVENT# rows."""
    from boto3.dynamodb.conditions import Attr
    return table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])

def get_all_agents(platform=None):
    items = [i for i in scan_info() if not i['agentId'].startswith(PREFIXES)]
    if platform:
        items = [i for i in items if i.get('platform', 'native') == platform]
    return items

def scan_by_prefix(prefix):
    return [i for i in scan_info() if i['agentId'].startswith(prefix)]

# Maps each MCP tool name to the internal route it serves. An AgentCore Gateway
# identifies the tool by name in the Lambda *context*, not by an HTTP-ish path in the
# event, so this is how a tool call resolves to a branch below.
TOOL_ROUTES = {
    'listAgents': '/agents',
    'getAgent': '/agents/{agentId}',
    'getAgentMetrics': '/agents/{agentId}/metrics',
    'listCompliance': '/compliance',
    'listAOPs': '/aops',
    'listAccess': '/access',
    'listPlatforms': '/platforms',
    'getCrossPlatformSummary': '/agents/cross-platform-summary',
}

# The gateway prefixes the visible tool name with its target name, e.g.
# "agent-management___listAgents" — THREE underscores (the CDK README says two).
TOOL_NAME_DELIMITER = '___'


def _resolve_request(event, context):
    """Normalize an invocation into (route, params, is_gateway).

    Two callers are supported:
      - AgentCore Gateway (current): the tool name arrives on
        context.client_context.custom['bedrockAgentCoreToolName'], and the event IS
        the flat input-schema arguments.
      - Bedrock Agents Classic action group (legacy): the route arrives as
        event['apiPath'] with event['parameters'] as a list of {name, value} pairs.

    The legacy branch is kept so the handler stays independently testable and so a
    stack mid-migration cannot break the chat path.
    """
    custom = getattr(getattr(context, 'client_context', None), 'custom', None) or {}
    raw_name = custom.get('bedrockAgentCoreToolName', '')
    tool_name = raw_name.split(TOOL_NAME_DELIMITER)[-1] if raw_name else ''

    if tool_name:
        # The gateway passes the tool's arguments as the event itself.
        params = {k: v for k, v in (event or {}).items() if v is not None}
        return TOOL_ROUTES.get(tool_name, ''), params, True

    api_path = event.get('apiPath', '')
    params = {p['name']: p['value'] for p in event.get('parameters', [])}
    return api_path, params, False


def handler(event, context):
    api_path, params, is_gateway = _resolve_request(event, context)
    action = event.get('actionGroup', '') if isinstance(event, dict) else ''

    if api_path == '/agents':
        items = _project(get_all_agents(params.get('platform')), _AGENT_FIELDS)
        body = json.dumps(items, cls=DecimalEncoder)

    elif api_path == '/agents/cross-platform-summary':
        agents = get_all_agents()
        total_cost = sum(float(a.get('monthlyCost', 0)) for a in agents)
        total_req = sum(int(a.get('requests', 0)) for a in agents)
        total_err = sum(int(a.get('errors', 0)) for a in agents)
        scores = [float(a.get('score', 0)) for a in agents if float(a.get('score', 0)) > 0]
        breakdown = {}
        for a in agents:
            p = a.get('platform', 'native')
            if p not in breakdown:
                breakdown[p] = {'count': 0, 'active': 0, 'cost': 0}
            breakdown[p]['count'] += 1
            if a.get('status') == 'active':
                breakdown[p]['active'] += 1
            breakdown[p]['cost'] += float(a.get('monthlyCost', 0))
        body = json.dumps({
            'totalAgents': len(agents),
            'totalMonthlyCost': round(total_cost, 2),
            'avgRaiScore': round(sum(scores) / len(scores), 1) if scores else 0,
            'totalRequests': total_req,
            'totalErrors': total_err,
            'platformBreakdown': json.dumps(breakdown),
        })

    elif api_path == '/platforms':
        agents = get_all_agents()
        platforms = {}
        for a in agents:
            p = a.get('platform', 'native')
            if p not in platforms:
                platforms[p] = {'platform': p, 'agentCount': 0, 'activeCount': 0, 'totalMonthlyCost': 0, 'raiScores': [], 'lastSyncedAt': None}
            platforms[p]['agentCount'] += 1
            if a.get('status') == 'active':
                platforms[p]['activeCount'] += 1
            platforms[p]['totalMonthlyCost'] += float(a.get('monthlyCost', 0))
            s = float(a.get('score', 0))
            if s > 0:
                platforms[p]['raiScores'].append(s)
            ls = a.get('lastSyncedAt')
            if ls and (not platforms[p]['lastSyncedAt'] or ls > platforms[p]['lastSyncedAt']):
                platforms[p]['lastSyncedAt'] = ls
        result = []
        for v in platforms.values():
            scores = v.pop('raiScores')
            v['avgRaiScore'] = round(sum(scores) / len(scores), 1) if scores else 0
            v['totalMonthlyCost'] = round(v['totalMonthlyCost'], 2)
            result.append(v)
        body = json.dumps(result)

    elif api_path == '/agents/{agentId}':
        item = table.get_item(Key={'agentId': params['agentId'], 'sk': 'INFO'}).get('Item', {})
        body = json.dumps({k: v for k, v in item.items() if k in _AGENT_FIELDS}, cls=DecimalEncoder)

    elif api_path == '/agents/{agentId}/metrics':
        item = table.get_item(Key={'agentId': params['agentId'], 'sk': 'INFO'}).get('Item', {})
        body = json.dumps({k: item.get(k) for k in ['agentId', 'requests', 'errors', 'avgResponseMs', 'status', 'monthlyCost', 'costPerInvocation', 'utilization', 'platform']}, cls=DecimalEncoder)

    elif api_path == '/compliance':
        body = json.dumps(_project(scan_by_prefix('compliance:'), _COMPLIANCE_FIELDS), cls=DecimalEncoder)
    elif api_path == '/aops':
        body = json.dumps(_project(scan_by_prefix('aop:'), _AOP_FIELDS), cls=DecimalEncoder)
    elif api_path == '/access':
        body = json.dumps(_project(scan_by_prefix('access:'), _ACCESS_FIELDS), cls=DecimalEncoder)
    else:
        body = json.dumps({'message': 'Unknown action'})

    # A Gateway Lambda target returns its result DIRECTLY — the gateway wraps it as
    # the MCP tool result. Only the legacy action-group caller needs the
    # messageVersion/response envelope.
    if is_gateway:
        return json.loads(body)

    return {
        'messageVersion': '1.0',
        'response': {
            'actionGroup': action,
            'apiPath': api_path,
            'httpMethod': event.get('httpMethod', 'GET'),
            'httpStatusCode': 200,
            'responseBody': {'application/json': {'body': body}}
        }
    }
