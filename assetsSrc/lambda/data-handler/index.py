"""
Data Handler — REST backend for the demo UI (API Gateway proxy integration).

Separate from `agent-handler`, which speaks the Bedrock Agent action-group
response shape and stays read-only behind the Bedrock Agent. This handler is the
single REST surface the single-page UI calls directly (behind the same Cognito
authorizer as /chat).

Read routes: GET /agents, /compliance, /aops, /access, /events, /costs. Write routes:
POST /agents (register), PATCH /agents/{agentId} (field update),
POST /agents/{agentId}/lifecycle (state transition). Each write also appends an
append-only audit row (sk='EVENT#...') via write_event; GET /events reads them back.

Table is keyed agentId (PK) + sk (SK). Entity rows use sk='INFO'; cost rows use
sk='COST#<date>' and audit events use sk='EVENT#<ts>#<id>'. Read routes filter to
sk='INFO' so ledger/event rows never leak into entity listings.
"""
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])

# AgentCore Evaluations reads CloudWatch, not DynamoDB: results are structured JSON
# log events in a per-config results log group, plus per-evaluator EMF metrics. These
# clients back the /evaluations read path. Created at module load (mirrors ddb/table);
# unused on non-eval routes, cheap to instantiate.
logs = boto3.client('logs')
cw = boto3.client('cloudwatch')
xray = boto3.client('xray')

PREFIXES = ('compliance:', 'aop:', 'access:')

# Audit events get a 90-day TTL (DynamoDB TTL on the 'ttl' attribute auto-expires
# old rows when enabled on the table).
EVENT_TTL_DAYS = 90

# Five-state agent lifecycle. pending-review is the entry state for
# manually registered agents; rejected is terminal.
AGENT_LIFECYCLE_TRANSITIONS = {
    'pending-review': {'active', 'rejected', 'decommissioned'},
    'active':         {'inactive', 'decommissioned'},
    'inactive':       {'active', 'decommissioned'},
    'decommissioned': {'pending-review'},
    'rejected':       set(),
}

_VALID_LIFECYCLE_STATUSES = set(AGENT_LIFECYCLE_TRANSITIONS.keys())

# Allowlisted scalar fields a PATCH (or register) may write on the INFO row.
# The FinOps-derived fields (monthlyCost/costPerInvocation) are intentionally
# non-writable here — they are read-time derived.
_UPDATABLE_FIELDS = {
    'name', 'description', 'category', 'owner', 'system', 'platform',
    'platformAgentId', 'runtime', 'costCenter', 'businessUnit', 'tags',
}

CORS_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
}


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super().default(o)


# Explicit field allowlists per record type. Responses are projected to these
# fields so the internal 'sk' key and any future/unexpected attributes are never
# exposed through the API (least-exposure). Keep these as the superset of what the
# UI reads; add a field here when the UI needs it.
_AGENT_FIELDS = {
    'agentId', 'name', 'description', 'category', 'owner', 'system', 'platform',
    'platformAgentId', 'runtime', 'status', 'source', 'createdAt', 'updatedAt',
    'lastSyncedAt', 'lastSynced', 'monthlyCost', 'costPerInvocation', 'requests',
    'errors', 'avgResponseMs', 'utilization', 'score', 'fairness', 'transparency',
    'accountability', 'ethics', 'costCenter', 'businessUnit', 'tags',
    # Enrichment produced by the AgentCore discovery-scanner. Without these in the
    # allowlist the scanner's LLM classification is written to the table but
    # filtered out before reaching the UI — so surface them here. lastAuditedAt is
    # projected by the compliance-scanner; lastDiscoveredAt by discovery.
    'displayName', 'riskTier', 'capabilities', 'suggestedOwner', 'lifecycleStatus',
    'aiInferred', 'humanVerifiedFields', 'lastDiscoveredAt', 'lastAuditedAt', 'runtimeId',
    'platformId',
}
_COMPLIANCE_FIELDS = {'agentId', 'name', 'complianceScore', 'status', 'lastAudit', 'controls'}
# Per-agent compliance audit rows (sk='AUDIT#<ts>') written by the compliance-scanner.
# 'report' is the nested audit body (byFramework, compositeGrade, compositeScore,
# narrative, recommendations, escalatedWorkItems); 'sk' carries the ISO timestamp.
_AUDIT_FIELDS = {'agentId', 'sk', 'rowType', 'createdAt', 'report'}
_AOP_FIELDS = {'agentId', 'aopId', 'name', 'status', 'agents', 'executions',
               'successRate', 'owner', 'entry'}
_ACCESS_FIELDS = {'agentId', 'userName', 'role', 'accessLevel', 'operations',
                  'assetMgmt', 'finance', 'security', 'customer'}
# AgentCore Evaluations rows are read from CloudWatch (not the table), so no 'sk'.
# Fleet rows are the per-evaluator EMF-metric summary; per-agent rows are parsed from
# the results log group's structured JSON events. Kept as explicit allowlists to match
# the least-exposure projection pattern used for the DynamoDB record types above.
_EVAL_FLEET_FIELDS = {'serviceName', 'evaluatorName', 'score', 'label', 'sampleCount',
                      'lastUpdated'}
_EVAL_RESULT_FIELDS = {'agentId', 'serviceName', 'evaluatorName', 'score', 'label',
                       'explanation', 'sessionId', 'traceId', 'timestamp'}


def _project(items, allowed):
    """Return each item reduced to the allowed field set (drops 'sk' and anything
    not explicitly listed)."""
    return [{k: v for k, v in item.items() if k in allowed} for item in items]


def _resp(status, body):
    return {
        'statusCode': status,
        'headers': CORS_HEADERS,
        'body': json.dumps(body, cls=DecimalEncoder),
    }


def scan_info():
    """All canonical entity rows (sk='INFO'). Excludes COST#/EVENT# rows."""
    return table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])


def get_agents(platform=None):
    items = [i for i in scan_info() if not i['agentId'].startswith(PREFIXES)]
    if platform:
        items = [i for i in items if i.get('platform', 'native') == platform]
    return items


def get_by_prefix(prefix):
    return [i for i in scan_info() if i['agentId'].startswith(prefix)]


def get_agent_audits(agent_id, limit=10):
    """Return the compliance-scanner's AUDIT#<ts> rows for one agent, newest-first.

    The compliance-scanner writes each audit as {agentId, sk='AUDIT#<ts>', rowType,
    report{byFramework, compositeGrade, compositeScore, narrative, recommendations,
    escalatedWorkItems}, createdAt}. A single-partition Query on the composite key is
    cheap (no scan); ScanIndexForward=False sorts AUDIT#<ISO-ts> newest-first.
    """
    if not agent_id:
        return []
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 10
    resp = table.query(
        KeyConditionExpression=Key('agentId').eq(agent_id) & Key('sk').begins_with('AUDIT#'),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get('Items', [])


def get_all_latest_audits():
    """Latest compliance AUDIT# row per agent, for the fleet Compliance view.

    One table scan for AUDIT# rows (begins_with keeps it off INFO/COST/EVENT rows),
    then reduce to the newest row per agentId. sk = 'AUDIT#<ISO-ts>' sorts lexically,
    so a string max() picks the most recent. Single-table substitute for a per-agent
    GSI query fan-out — the audit corpus is small (one row per agent per daily run,
    TTL-free but low-volume), so a scan is acceptable here.
    """
    items, start_key = [], None
    while True:
        kwargs = {'FilterExpression': Attr('sk').begins_with('AUDIT#')}
        if start_key:
            kwargs['ExclusiveStartKey'] = start_key
        resp = table.scan(**kwargs)
        items.extend(resp.get('Items', []))
        start_key = resp.get('LastEvaluatedKey')
        if not start_key:
            break
    latest = {}
    for it in items:
        aid = it.get('agentId')
        if not aid:
            continue
        cur = latest.get(aid)
        if cur is None or it.get('sk', '') > cur.get('sk', ''):
            latest[aid] = it
    return list(latest.values())


def get_costs(days=30):
    """Raw COST# ledger rows for the last N days (sk='COST#<YYYY-MM-DD>').

    begins_with('COST#') keeps this off INFO/EVENT rows; the gte floor bounds it
    to the requested window (sk dates sort lexically, so a string compare works).
    Returns the raw rows; the UI aggregates the spend trend client-side (no
    server-side Athena/Cost Explorer per the single-table constraint).
    """
    try:
        days = max(1, int(days))
    except (TypeError, ValueError):
        days = 30
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days - 1)).strftime('%Y-%m-%d')
    flt = Attr('sk').begins_with('COST#') & Attr('sk').gte('COST#' + cutoff)
    items, start_key = [], None
    while True:
        kwargs = {'FilterExpression': flt}
        if start_key:
            kwargs['ExclusiveStartKey'] = start_key
        resp = table.scan(**kwargs)
        items.extend(resp.get('Items', []))
        start_key = resp.get('LastEvaluatedKey')
        if not start_key:
            break
    return items


# ── AgentCore Evaluations read path (CloudWatch, not DynamoDB) ──
#
# AgentCore online evaluations write results to CloudWatch: structured JSON log events
# in a per-config results log group (<prefix><config-id>) following OTEL GenAI eval
# semantic conventions, plus per-evaluator EMF metrics under EVAL_METRIC_NAMESPACE.
# This handler only reads CloudWatch here. The CDK agent sets the env-var contract
# below; everything degrades to []/an honest readiness dict on a cold account so the
# UI gets a 200 with explanatory notes instead of a 500.
#
# Field names in the JSON follow OTEL GenAI conventions (gen_ai.evaluation.score,
# gen_ai.evaluation.name/label, session.id, trace.id) but exact keys vary by evaluator
# and release, so every parse tries several likely key names and falls back gracefully.

# Candidate keys tried (in order) when pulling a field out of an eval result event or
# metric dimension. Parse defensively: the first present key wins.
_EVAL_SCORE_KEYS = ('gen_ai.evaluation.score', 'gen_ai.evaluation.score.value',
                    'evaluation.score', 'score', 'value')
_EVAL_LABEL_KEYS = ('gen_ai.evaluation.label', 'gen_ai.evaluation.result.label',
                    'evaluation.label', 'label', 'result')
_EVAL_NAME_KEYS = ('gen_ai.evaluation.name', 'evaluation.name', 'evaluator',
                   'evaluatorName', 'name')
_EVAL_EXPLANATION_KEYS = ('gen_ai.evaluation.explanation', 'evaluation.explanation',
                          'explanation', 'reasoning', 'rationale')
_EVAL_SESSION_KEYS = ('session.id', 'gen_ai.session.id', 'sessionId', 'session_id')
_EVAL_TRACE_KEYS = ('trace.id', 'gen_ai.trace.id', 'traceId', 'trace_id')
_EVAL_SERVICE_KEYS = ('service.name', 'serviceName', 'service_name')
_EVAL_TIMESTAMP_KEYS = ('timestamp', 'time', 'gen_ai.evaluation.timestamp')

_RUNTIME_LOG_GROUP_PREFIX = '/aws/bedrock-agentcore/runtimes/'


def _eval_env():
    """Parse the CDK-supplied env-var contract for the evaluations read path.

    Returns {prefix, namespace, services: [..]} with safe defaults so a missing/unset var
    never raises. `services` are the OTEL service.name values (= the agent runtime names)
    used to scope per-agent queries and match metric dimensions. Whether evaluations are
    actually ON is not an env flag — it's determined at read time by listing the online
    eval configs (they're created on demand via POST /evaluations/enable).
    """
    services = [s.strip() for s in (os.environ.get('EVAL_SERVICE_NAMES') or '').split(',')
                if s.strip()]
    return {
        'prefix': os.environ.get('EVAL_RESULTS_LOG_GROUP_PREFIX')
                  or '/aws/bedrock-agentcore/evaluations/results/',
        'namespace': os.environ.get('EVAL_METRIC_NAMESPACE') or 'Bedrock-AgentCore/Evaluations',
        'services': services,
    }


def list_eval_configs():
    """Existing online-eval configs (summaries), or [] on any failure. A config existing
    is the real 'evaluations are enabled' signal (they're provisioned on demand)."""
    try:
        client = boto3.client('bedrock-agentcore-control')
        out, token = [], None
        while True:
            kwargs = {'nextToken': token} if token else {}
            resp = client.list_online_evaluation_configs(**kwargs)
            out.extend(resp.get('onlineEvaluationConfigs',
                                resp.get('onlineEvaluationConfigSummaries', resp.get('items', []))))
            token = resp.get('nextToken')
            if not token:
                break
        return out
    except Exception:  # noqa: BLE001 — API absent/no perms/none created → treat as none
        return []


def _first(d, keys, default=None):
    """First present, non-None value among `keys` in dict `d` (defensive key probing)."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _as_float(val):
    """Coerce a score to float in a JSON-safe way, or None (labels like 'YES' -> None)."""
    if val is None or isinstance(val, bool):
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def check_eval_readiness():
    """Explain WHY the Evaluations page is empty — the account-level preflight.

    A cold account has none of this wired up, so each check is wrapped independently and
    degrades to an 'unknown'/False signal (never throws). `notes` carries human-readable
    blockers the UI renders verbatim. Signals:
      transactionSearch     — xray.get_trace_segment_destination(): 'active' only when
                              Destination=='CloudWatchLogs' and Status=='ACTIVE' (spans
                              indexed); 'XRay'/anything else means evals get no sessions.
      configPresent         — >=1 online-eval config exists (created on demand via POST
                              /evaluations/enable, not a deploy flag).
      resultsLogGroupPresent— >=1 log group under EVAL_RESULTS_LOG_GROUP_PREFIX.
      trafficPresent        — >=1 runtime trace log group under /aws/bedrock-agentcore/
                              runtimes/ (agents have run at all).
      spansPresent          — the aws/spans log group has data. AgentCore Evaluations
                              scores OTEL SPANS (not app logs) from aws/spans; if the
                              agents aren't OTEL-instrumented this stays empty and no
                              scores can ever be produced, regardless of traffic.
    """
    env = _eval_env()
    out = {
        'transactionSearch': 'unknown',
        'configPresent': len(list_eval_configs()) >= 1,
        'resultsLogGroupPresent': False,
        'trafficPresent': False,
        'spansPresent': False,
        'notes': [],
    }

    try:
        dest = xray.get_trace_segment_destination()
        active = dest.get('Destination') == 'CloudWatchLogs' and dest.get('Status') == 'ACTIVE'
        out['transactionSearch'] = 'active' if active else 'inactive'
    except Exception:
        out['transactionSearch'] = 'unknown'

    try:
        groups = logs.describe_log_groups(logGroupNamePrefix=env['prefix']).get('logGroups', [])
        out['resultsLogGroupPresent'] = len(groups) >= 1
    except Exception:
        out['resultsLogGroupPresent'] = False

    try:
        rt = logs.describe_log_groups(
            logGroupNamePrefix=_RUNTIME_LOG_GROUP_PREFIX).get('logGroups', [])
        out['trafficPresent'] = len(rt) >= 1
    except Exception:
        out['trafficPresent'] = False

    # aws/spans holds the OTEL spans the evaluator actually scores. Probe for RECENT
    # events, not storedBytes: the storedBytes metric lags by hours, so it can read 0
    # even when spans are actively landing. filter_log_events over a recent window
    # reflects the current state. Requires the group to exist first (else skip cleanly).
    try:
        groups = logs.describe_log_groups(logGroupNamePrefix='aws/spans').get('logGroups', [])
        if any(g.get('logGroupName') == 'aws/spans' for g in groups):
            start_ms = int((datetime.now(timezone.utc) - timedelta(hours=6)).timestamp() * 1000)
            evs = logs.filter_log_events(
                logGroupName='aws/spans', startTime=start_ms, limit=1).get('events', [])
            out['spansPresent'] = len(evs) >= 1
        else:
            out['spansPresent'] = False
    except Exception:
        out['spansPresent'] = False

    if out['transactionSearch'] != 'active':
        out['notes'].append(
            'Transaction Search is not enabled — AgentCore spans are not indexed, so no '
            'sessions can be evaluated. Enable it once per account (CloudWatch → '
            'Transaction Search).')
    if not out['trafficPresent']:
        out['notes'].append(
            'No agent traffic yet — evaluations run against completed sessions, so nothing '
            'is produced until the agents receive traffic (invoke an agent, e.g. run a scan).')
    elif not out['spansPresent']:
        out['notes'].append(
            'Agents are running but not emitting OpenTelemetry spans — aws/spans is empty, '
            'so AgentCore has no traces to evaluate. The agents must be OTEL-instrumented '
            '(aws-opentelemetry-distro + StrandsTelemetry); redeploy the instrumented agents '
            'and re-run them.')
    elif not out['configPresent']:
        out['notes'].append(
            'Evaluations are not enabled yet — click "Enable evaluations" to start scoring '
            'these agents\' sessions with AgentCore\'s built-in evaluators.')
    elif not out['resultsLogGroupPresent']:
        out['notes'].append(
            'No evaluation results yet — the online eval samples completed sessions; '
            'results appear a few minutes after the agents produce spans.')
    return out


def get_fleet_evaluations():
    """Latest average score per (serviceName, evaluatorName) from the EMF metrics.

    Per-evaluator scores are CloudWatch EMF metrics under EVAL_METRIC_NAMESPACE,
    dimensioned by evaluator name and the online-evaluation-config id (and typically
    service.name). ListMetrics enumerates the dimension combinations, then a single
    GetMetricData batch pulls the last ~24h average + sample count per metric. Dimension
    names vary by release, so service/evaluator are probed across several likely keys.
    Returns [] when the namespace has no metrics (or on any failure) — never throws.
    """
    env = _eval_env()
    try:
        metrics, token = [], None
        while True:
            kwargs = {'Namespace': env['namespace']}
            if token:
                kwargs['NextToken'] = token
            resp = cw.list_metrics(**kwargs)
            metrics.extend(resp.get('Metrics', []))
            token = resp.get('NextToken')
            if not token or len(metrics) >= 500:
                break
    except Exception:
        return []

    if not metrics:
        return []

    # Build one GetMetricData query per metric (bounded to CloudWatch's 500/call limit).
    queries, meta = [], {}
    for idx, m in enumerate(metrics[:500]):
        dims = {d.get('Name'): d.get('Value') for d in m.get('Dimensions', [])}
        service = _first(dims, _EVAL_SERVICE_KEYS)
        evaluator = _first(dims, _EVAL_NAME_KEYS) or m.get('MetricName')
        qid = 'm%d' % idx
        meta[qid] = {'serviceName': service, 'evaluatorName': evaluator}
        queries.append({
            'Id': qid,
            'MetricStat': {
                'Metric': {'Namespace': m.get('Namespace'), 'MetricName': m.get('MetricName'),
                           'Dimensions': m.get('Dimensions', [])},
                'Period': 86400,
                'Stat': 'Average',
            },
            'ReturnData': True,
        })

    now = datetime.now(timezone.utc)
    rows = []
    try:
        for chunk_start in range(0, len(queries), 500):
            chunk = queries[chunk_start:chunk_start + 500]
            resp = cw.get_metric_data(
                MetricDataQueries=chunk,
                StartTime=now - timedelta(days=1),
                EndTime=now,
                ScanBy='TimestampDescending',
            )
            for res in resp.get('MetricDataResults', []):
                info = meta.get(res.get('Id'), {})
                vals = res.get('Values') or []
                stamps = res.get('Timestamps') or []
                if not vals:
                    continue
                last_ts = stamps[0].strftime('%Y-%m-%dT%H:%M:%SZ') if stamps else None
                rows.append({
                    'serviceName': info.get('serviceName'),
                    'evaluatorName': info.get('evaluatorName'),
                    'score': _as_float(vals[0]),
                    'label': None,
                    'sampleCount': len(vals),
                    'lastUpdated': last_ts,
                })
    except Exception:
        return rows
    return rows


def get_agent_evaluations(service_name, limit=20):
    """Per-agent evaluation results (newest-first) from the CloudWatch results log group.

    Discovers the per-config results log group(s) via describe_log_groups(prefix), then
    runs a Logs Insights query scoped to the given service (matched defensively against
    the OTEL service.name keys) and parses each row into the friendly shape below. Polls
    start_query/get_query_results until Complete on a bounded ~10s loop (API GW caps the
    request at 29s). `limit` is clamped 1..50 like get_agent_audits. serviceName doubles
    as agentId (they're the same runtime names). Returns [] on any failure — never throws.
    """
    if not service_name:
        return []
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 20

    env = _eval_env()
    try:
        groups = [g.get('logGroupName') for g
                  in logs.describe_log_groups(logGroupNamePrefix=env['prefix']).get('logGroups', [])
                  if g.get('logGroupName')]
    except Exception:
        return []
    if not groups:
        return []

    try:
        start = logs.start_query(
            logGroupNames=groups[:20],  # StartQuery caps at 20 log groups per call
            startTime=int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp()),
            endTime=int(datetime.now(timezone.utc).timestamp()),
            queryString='fields @timestamp, @message | sort @timestamp desc | limit %d' % limit,
        )
        query_id = start.get('queryId')
    except Exception:
        return []
    if not query_id:
        return []

    # Bounded poll — well under the 29s API GW ceiling. Give up gracefully on timeout.
    result = None
    for _ in range(20):
        try:
            result = logs.get_query_results(queryId=query_id)
        except Exception:
            return []
        if result.get('status') in ('Complete', 'Failed', 'Cancelled', 'Timeout'):
            break
        time.sleep(0.5)  # nosemgrep: arbitrary-sleep - poll interval for async CloudWatch Logs Insights GetQueryResults; loop is iteration-bounded (<10s, under API GW's 29s) and exits on terminal status
    if not result or result.get('status') != 'Complete':
        return []

    rows = []
    for fields in result.get('results', []):
        try:
            cols = {f.get('field'): f.get('value') for f in fields}
            ts = cols.get('@timestamp')
            body = cols.get('@message')
            parsed = {}
            if body:
                try:
                    parsed = json.loads(body)
                except (ValueError, TypeError):
                    parsed = {}
            svc = _first(parsed, _EVAL_SERVICE_KEYS) or service_name
            # Scope to the requested service when the event carries one; keep unlabeled
            # rows (some evaluators omit service.name) rather than dropping data.
            if svc and service_name and svc != service_name and _first(parsed, _EVAL_SERVICE_KEYS):
                continue
            rows.append({
                'agentId': svc or service_name,
                'serviceName': svc or service_name,
                'evaluatorName': _first(parsed, _EVAL_NAME_KEYS),
                'score': _as_float(_first(parsed, _EVAL_SCORE_KEYS)),
                'label': _first(parsed, _EVAL_LABEL_KEYS),
                'explanation': _first(parsed, _EVAL_EXPLANATION_KEYS),
                'sessionId': _first(parsed, _EVAL_SESSION_KEYS),
                'traceId': _first(parsed, _EVAL_TRACE_KEYS),
                'timestamp': _first(parsed, _EVAL_TIMESTAMP_KEYS) or ts,
            })
        except Exception:
            continue
    return rows[:limit]


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _ttl_epoch():
    return int((datetime.now(timezone.utc) + timedelta(days=EVENT_TTL_DAYS)).timestamp())


def write_event(agent_id, event_type, payload, actor='system', severity='info'):
    """Append one EVENT# row to the table (inline audit write — no Streams/Pipes).

    The 'EVENT#' prefix on the sk is a single-table convention so audit rows never
    collide with INFO entity rows or COST# ledger rows
    (final sk = 'EVENT#<ISO-ts>#<eventId>').
    """
    event_id = str(uuid.uuid4())
    ts = _now_iso()
    item = {
        'agentId': agent_id or 'system',
        'sk': 'EVENT#' + ts + '#' + event_id,
        'eventId': event_id,
        'eventType': event_type,
        'timestamp': ts,
        'payload': payload or {},
        'ttl': _ttl_epoch(),
        'actor': actor,
        'severity': severity,
    }
    table.put_item(Item=item)
    return event_id


def get_events(event_type=None, agent_id=None, severity=None, limit=200):
    """Scan EVENT# rows, apply optional filters, return newest-first (capped).

    Single-table substitute for an eventType-timestamp GSI query and an Athena
    cross-agent path (both forbidden by the no-GSI/no-Athena constraint).
    """
    items = table.scan(FilterExpression=Attr('sk').begins_with('EVENT#')).get('Items', [])
    if event_type:
        items = [i for i in items if i.get('eventType') == event_type]
    if agent_id:
        items = [i for i in items if i.get('agentId') == agent_id]
    if severity:
        items = [i for i in items if i.get('severity') == severity]
    items.sort(key=lambda i: i.get('timestamp', ''), reverse=True)
    return items[:limit]


def _actor(event):
    """Cognito username from the authorizer claims, or 'system' when absent."""
    try:
        return event['requestContext']['authorizer']['claims']['cognito:username'] or 'system'
    except (KeyError, TypeError):
        return 'system'


def _slugify(name):
    """lowercase, non-alnum -> '-', collapse/strip dashes."""
    s = re.sub(r'[^a-z0-9]+', '-', (name or '').lower())
    return s.strip('-')


def _body(event):
    return json.loads(event.get('body') or '{}')


# ── Write routes ──

def create_agent(body, actor='system'):
    name = (body.get('name') or '').strip()
    if not name:
        return _resp(400, {'error': 'name is required'})

    agent_id = body.get('agentId') or _slugify(name) or str(uuid.uuid4())
    now = _now_iso()
    item = {
        'agentId': agent_id,
        'sk': 'INFO',
        'name': name,
        'platform': body.get('platform', 'native'),
        'category': body.get('category', ''),
        'system': body.get('system', ''),
        'owner': body.get('owner', ''),
        'runtime': body.get('runtime', ''),
        'status': 'pending-review',
        'source': 'manual',
        'createdAt': now,
        'updatedAt': now,
    }
    for field in _UPDATABLE_FIELDS:
        if field in body:
            item[field] = body[field]

    try:
        table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(agentId)',
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return _resp(409, {'error': 'Agent already exists', 'agentId': agent_id})
        raise
    write_event(agent_id, 'agent_registered',
                {'name': name, 'platform': item['platform'], 'category': item.get('category', '')},
                actor=actor, severity='info')
    return _resp(201, {k: v for k, v in item.items() if k in _AGENT_FIELDS})


def update_agent(agent_id, body, actor='system'):
    allowed = {k: v for k, v in body.items() if k in _UPDATABLE_FIELDS}
    if not allowed:
        return _resp(400, {'error': 'No updatable fields'})

    now = _now_iso()
    names = {'#updatedAt': 'updatedAt'}
    values = {':u': now}
    parts = ['#updatedAt = :u']
    for idx, (key, val) in enumerate(allowed.items()):
        names['#a%d' % idx] = key
        values[':v%d' % idx] = val
        parts.append('#a%d = :v%d' % (idx, idx))

    try:
        resp = table.update_item(
            Key={'agentId': agent_id, 'sk': 'INFO'},
            UpdateExpression='SET ' + ', '.join(parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ConditionExpression='attribute_exists(agentId)',
            ReturnValues='ALL_NEW',
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return _resp(404, {'error': 'Agent not found'})
        raise
    write_event(agent_id, 'agent_updated', {'changes': sorted(allowed.keys())},
                actor=actor, severity='info')
    return _resp(200, {k: v for k, v in resp['Attributes'].items() if k in _AGENT_FIELDS})


def update_lifecycle(agent_id, body, actor='system'):
    new_state = body.get('newState')
    if not new_state:
        return _resp(400, {'error': 'newState is required'})
    if new_state not in _VALID_LIFECYCLE_STATUSES:
        return _resp(400, {'error': 'Invalid lifecycleStatus value'})

    item = table.get_item(Key={'agentId': agent_id, 'sk': 'INFO'}).get('Item')
    if not item:
        return _resp(404, {'error': 'Agent not found'})

    current = item.get('status')
    allowed = AGENT_LIFECYCLE_TRANSITIONS.get(current, set())
    if new_state not in allowed:
        return _resp(409, {
            'error': "Transition from '%s' to '%s' is not allowed" % (current, new_state),
            'currentState': current,
            'allowedTransitions': sorted(allowed),
        })

    now = _now_iso()
    try:
        resp = table.update_item(
            Key={'agentId': agent_id, 'sk': 'INFO'},
            UpdateExpression='SET #status = :new, #updatedAt = :now',
            ConditionExpression='#status = :current',
            ExpressionAttributeNames={'#status': 'status', '#updatedAt': 'updatedAt'},
            ExpressionAttributeValues={':new': new_state, ':current': current, ':now': now},
            ReturnValues='ALL_NEW',
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return _resp(409, {'error': 'Agent status changed concurrently', 'agentId': agent_id})
        raise
    write_event(agent_id, 'lifecycle_change',
                {'from': current, 'to': new_state, 'reason': body.get('reason', '')},
                actor=actor,
                severity='warning' if new_state in ('inactive', 'rejected', 'decommissioned') else 'info')
    return _resp(200, {k: v for k, v in resp['Attributes'].items() if k in _AGENT_FIELDS})


def handler(event, context):
    method = event.get('httpMethod', 'GET')
    path = event.get('resource') or event.get('path', '')
    qs = event.get('queryStringParameters') or {}

    if method == 'OPTIONS':
        return {'statusCode': 200, 'headers': CORS_HEADERS, 'body': ''}

    # ── Read routes (Phase 0) ──
    if method == 'GET':
        if path.endswith('/agents/{agentId}/audit'):
            agent_id = (event.get('pathParameters') or {}).get('agentId', '')
            return _resp(200, _project(get_agent_audits(agent_id, qs.get('limit', 10)), _AUDIT_FIELDS))
        if path.endswith('/audits'):
            # Fleet-wide: latest audit per agent, for the Compliance dashboard view.
            return _resp(200, _project(get_all_latest_audits(), _AUDIT_FIELDS))
        if path.endswith('/agents'):
            return _resp(200, _project(get_agents(qs.get('platform')), _AGENT_FIELDS))
        if path.endswith('/compliance'):
            return _resp(200, _project(get_by_prefix('compliance:'), _COMPLIANCE_FIELDS))
        if path.endswith('/aops'):
            return _resp(200, _project(get_by_prefix('aop:'), _AOP_FIELDS))
        if path.endswith('/access'):
            return _resp(200, _project(get_by_prefix('access:'), _ACCESS_FIELDS))
        if path.endswith('/events'):
            return _resp(200, get_events(qs.get('eventType'), qs.get('agentId'), qs.get('severity')))
        if path.endswith('/costs'):
            return _resp(200, get_costs(qs.get('days', 30)))
        # AgentCore Evaluations (CloudWatch-backed). Match the SPECIFIC eval paths
        # before the generic '/evaluations' so the readiness/per-agent routes are not
        # shadowed (both end with '/evaluations' otherwise): '.../readiness' and
        # '/agents/{agentId}/evaluations' are checked first, '/evaluations' last.
        if path.endswith('/evaluations/readiness'):
            return _resp(200, check_eval_readiness())
        if path.endswith('/agents/{agentId}/evaluations'):
            agent_id = (event.get('pathParameters') or {}).get('agentId', '')
            return _resp(200, _project(get_agent_evaluations(agent_id, qs.get('limit', 20)),
                                       _EVAL_RESULT_FIELDS))
        if path.endswith('/evaluations'):
            # One-call bundle for the Evaluations page: account readiness (why it's empty)
            # + the fleet per-evaluator score summary. `enabled` mirrors configPresent —
            # a config existing is what "evaluations are on" means (created on demand).
            readiness = check_eval_readiness()
            return _resp(200, {
                'enabled': bool(readiness.get('configPresent')),
                'readiness': readiness,
                'fleet': _project(get_fleet_evaluations(), _EVAL_FLEET_FIELDS),
            })

    # ── Write routes (each appends an audit EVENT# row via write_event) ──
    actor = _actor(event)
    if method == 'POST' and path.endswith('/agents'):
        return create_agent(_body(event), actor)
    if method == 'PATCH' and path.endswith('/agents/{agentId}'):
        return update_agent((event.get('pathParameters') or {}).get('agentId', ''), _body(event), actor)
    if method == 'POST' and path.endswith('/agents/{agentId}/lifecycle'):
        return update_lifecycle((event.get('pathParameters') or {}).get('agentId', ''), _body(event), actor)

    return _resp(404, {'error': 'Not found', 'path': path, 'method': method})
