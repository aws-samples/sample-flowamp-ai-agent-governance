"""
Discovery Agent — discovers ALL agents, native and external, and upserts normalized records.

Supports: native AWS (Amazon Bedrock Agents + AgentCore runtimes), Microsoft Copilot
Studio, Okta Secure AI, MuleSoft Agent Fabric. Each connector returns a list of
normalized dicts that map to the AgentRecord schema.
Runs on a schedule (EventBridge) or on-demand via API Gateway.

Native-discovery ownership: the AgentCore `discovery-scanner` agent (deployed with
`-c deployAgentCore=true`) is the authoritative native discoverer — it enumerates AND
LLM-classifies AgentCore runtimes. When it is deployed, this Lambda's native pass is
DISABLED (env NATIVE_DISCOVERY_ENABLED=false) so the two never double-write the same
runtime under different keys/statuses. When the scanner is off (default), this Lambda
owns native discovery so a bare deploy still populates the catalog. Either way, native
rows are keyed by a clean agentId and enter at status 'pending-review' — the same
key/status convention the scanner uses, and a valid entry state in the data-handler
lifecycle state machine.
"""
import json, os, time, logging
from datetime import datetime, timezone
from decimal import Decimal
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])
secrets = boto3.client('secretsmanager')

# When false, the AgentCore discovery-scanner owns native discovery and this
# Lambda serves only the simulated external connectors. Set by the CDK stack.
NATIVE_DISCOVERY_ENABLED = os.environ.get('NATIVE_DISCOVERY_ENABLED', 'true') == 'true'

# Real cross-account org discovery. Default ON: alongside single-account (native)
# discovery, the aws-org connector enumerates the AWS Organization
# (organizations:ListAccounts, callable only from the management or a delegated-admin
# account), assumes ORG_DISCOVERY_ROLE_NAME in each member account, and lists Bedrock
# Agents + AgentCore runtimes per region. If FlowAMP is NOT in the management/
# delegated-admin account, ListAccounts fails and the connector returns [] with a
# warning surfaced to the UI (it does not fall back to simulated data). Set to false
# to disable. Controlled by the CDK enableOrgDiscovery flag.
ORG_DISCOVERY_ENABLED = os.environ.get('ORG_DISCOVERY_ENABLED', 'true') == 'true'
# Role assumed in each member account. Defaults to AWSControlTowerExecution — the
# role AWS Control Tower / Landing Zone provisions in every enrolled account, which
# trusts the management account. This is the common enterprise topology; for a plain
# (non-Control-Tower) org, override with OrganizationAccountAccessRole, or point at a
# scoped read-only role for least privilege.
ORG_DISCOVERY_ROLE_NAME = os.environ.get('ORG_DISCOVERY_ROLE_NAME', 'AWSControlTowerExecution')
# Regions to scan per member account (comma-separated). Bedrock Agents is regional,
# so we scan an explicit list rather than every region. Defaults to this Lambda's region.
ORG_DISCOVERY_REGIONS = [
    r.strip() for r in os.environ.get(
        'ORG_DISCOVERY_REGIONS', os.environ.get('AWS_REGION', 'us-east-1')
    ).split(',') if r.strip()
]

NOW = datetime.now(timezone.utc).isoformat()

# Per-run, per-connector warnings surfaced to the UI (e.g. accounts that could not be
# assumed during org discovery). Reset at the start of each connector run so the
# results dict can carry them back through POST /discovery/sync to the browser.
_CONNECTOR_WARNINGS: list = []


def demo_metrics(seed_key: str) -> dict:
    """Plausible non-zero operational metrics for a freshly discovered agent.

    Real Bedrock ListAgents returns no usage numbers, which leaves the agent's
    detail Overview empty in the demo. Derive stable, varied values from a hash
    of the agent id so each agent looks distinct and the numbers don't change on
    every sync. RAI score fields are intentionally left at 0 — the rai-scorer
    owns those, and "Not yet scored" is the honest governance story for a
    newly-discovered agent.
    """
    import hashlib
    h = int(hashlib.sha256(seed_key.encode()).hexdigest(), 16)
    requests = 800 + h % 9000
    errors = h % 25
    return {
        'requests': requests,
        'errors': errors,
        'avgResponseMs': 40 + h % 260,
        'utilization': 45 + h % 50,
        'monthlyCost': 120 + h % 700,
        'costPerInvocation': round(0.0001 + (h % 20) / 10000.0, 4),
    }

# Fields the discovery pipeline may fill in but a human can lock. If any is empty
# and not human-verified, the record is classified 'enrich'; otherwise 'refresh'.
ENRICHMENT_FIELDS = ('capabilities', 'category', 'riskTier', 'suggestedOwner')
# Never overwritten on an existing row by a discovery sync (carried forward from
# the stored record). 'status' is human/lifecycle-owned; 'discoveredAt' is the
# first-seen timestamp; 'agentId' is the key.
IMMUTABLE_FIELDS = frozenset({'agentId', 'discoveredAt', 'status'})

# ── Helpers ──

def _clean_native_id(name: str, fallback_id: str) -> str:
    """Return the agentId to use for a discovered native agent.

    Mirrors the AgentCore discovery-scanner's `_clean_agent_id`: prefer the
    operator-defined name when it is a clean identifier (no ':' or '/'), else
    fall back to the raw platform id. Using the name keeps the key stable across
    runtime redeploys and keeps /agents/{agentId}/... URLs free of reserved
    characters — and, critically, means the Lambda and the scanner converge on
    the SAME key for the same agent instead of double-writing it.
    """
    if name and ':' not in name and '/' not in name:
        return name
    return fallback_id


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def classify_record(agent, existing):
    """Decide what to do with a discovered agent: add / enrich / refresh.

    Keyed on the platform's agentId (no ARN cleaning needed):
      - 'add'     — no existing INFO row
      - 'enrich'  — exists but at least one of displayName/ENRICHMENT_FIELDS is
                    empty (on both the incoming and stored record) AND not locked
      - 'refresh' — exists and fully populated; only bump lastSyncedAt
    Returns (action, missing_fields).
    """
    existing = existing or {}
    verified = list(existing.get('humanVerifiedFields') or [])
    if not existing:
        return 'add', []
    missing = [
        f for f in ('displayName', *ENRICHMENT_FIELDS)
        if not (agent.get(f) or existing.get(f)) and f not in verified
    ]
    return ('enrich' if missing else 'refresh'), missing

def upsert_agent(agent: dict):
    """Write a normalized agent record, classifying add/enrich/refresh.

    Preserves RAI scores, immutable fields, and any human-verified fields so a
    discovery sync never clobbers operator decisions.
    """
    # Agent rows are the canonical "INFO" row for their agentId (table is keyed
    # agentId + sk; cost/event rows live under other sk values).
    agent['sk'] = 'INFO'
    existing = table.get_item(Key={'agentId': agent['agentId'], 'sk': 'INFO'}).get('Item', {})
    # Keep RAI scores from previous runs — discovery doesn't overwrite them
    for k in ('score', 'fairness', 'transparency', 'accountability', 'ethics'):
        if k not in agent or agent[k] == 0:
            agent[k] = existing.get(k, 0)

    action, _missing = classify_record(agent, existing)
    verified = list(existing.get('humanVerifiedFields') or [])
    agent['lastSyncedAt'] = NOW

    if action == 'add':
        # AgentRecord uses 'discovered' for a newly-found agent (the UI
        # badge set is active/warning/error/inactive/discovered).
        agent['status'] = agent.get('status') or 'discovered'
        agent['discoveredAt'] = NOW
        agent['aiInferred'] = False
        agent['humanVerifiedFields'] = []
    else:
        # enrich / refresh: carry immutable + verified fields forward from the
        # stored row so human-set status, the original discoveredAt, and locked
        # fields survive the sync.
        for f in IMMUTABLE_FIELDS:
            if f in existing:
                agent[f] = existing[f]
        for f in ('displayName', *ENRICHMENT_FIELDS):
            # Never overwrite a verified field, and never blank out an
            # already-populated field with an empty incoming value.
            if f in verified or (existing.get(f) and not agent.get(f)):
                agent[f] = existing.get(f)
        agent['humanVerifiedFields'] = existing.get('humanVerifiedFields', [])
        agent['aiInferred'] = existing.get('aiInferred', False)

    # Convert floats to Decimal for DynamoDB
    agent = json.loads(json.dumps(agent, default=decimal_default), parse_float=Decimal)
    table.put_item(Item=agent)


# ═══════════════════════════════════════════════════════════════
# Microsoft Copilot Studio connector
# ═══════════════════════════════════════════════════════════════

# Capped at 2 agents per connector: enough to demonstrate the external-platform
# discovery story without flooding the catalog. These are illustrative, not real.
MSFT_SIMULATED_AGENTS = [
    {"platformAgentId": "copilot-it-helpdesk", "name": "IT Helpdesk Copilot", "category": "IT Operations", "status": "active", "requests": 14200, "errors": 45, "avgResponseMs": 320, "utilization": 87, "monthlyCost": 1200, "costPerInvocation": 0.0015, "owner": "IT Department"},
    {"platformAgentId": "copilot-hr-onboarding", "name": "HR Onboarding Assistant", "category": "Human Resources", "status": "active", "requests": 3400, "errors": 8, "avgResponseMs": 450, "utilization": 62, "monthlyCost": 800, "costPerInvocation": 0.0020, "owner": "HR Team"},
]

def discover_microsoft(config: dict) -> list:
    """
    In production: call Microsoft Graph / Copilot Studio Management API.
    For demo: return simulated agents.
    """
    # TODO: real implementation would use:
    # endpoint = config.get('endpoint', 'https://graph.microsoft.com/v1.0')
    # creds = json.loads(secrets.get_secret_value(SecretId=config['credentialArn'])['SecretString'])
    agents = []
    for src in MSFT_SIMULATED_AGENTS:
        agents.append({
            'agentId': f"msft:{src['platformAgentId']}",
            'name': src['name'],
            'platform': 'microsoft',
            'platformAgentId': src['platformAgentId'],
            'category': src['category'],
            'system': 'Copilot Studio',
            # External connector agents are NOT Bedrock/AgentCore — label the runtime
            # with the platform's own runtime and mark the origin so the UI does not
            # show them as "Bedrock Agent".
            'runtime': 'Copilot Studio',
            'source': 'external-connector',
            'status': src['status'],
            'requests': src['requests'],
            'errors': src['errors'],
            'avgResponseMs': src['avgResponseMs'],
            'utilization': src['utilization'],
            'monthlyCost': src['monthlyCost'],
            'costPerInvocation': src['costPerInvocation'],
            'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
            'owner': src.get('owner', ''),
            'platformMetadata': {'source': 'copilot-studio', 'tenant': 'contoso'},
        })
    return agents


# ═══════════════════════════════════════════════════════════════
# Okta Secure AI connector
# ═══════════════════════════════════════════════════════════════

OKTA_SIMULATED_AGENTS = [
    {"platformAgentId": "okta-identity-governance", "name": "Identity Governance Agent", "category": "Security", "status": "active", "requests": 9800, "errors": 5, "avgResponseMs": 95, "utilization": 92, "monthlyCost": 450, "costPerInvocation": 0.0003, "owner": "IAM Team"},
    {"platformAgentId": "okta-threat-detector", "name": "Agent Threat Detector", "category": "Security", "status": "active", "requests": 22000, "errors": 18, "avgResponseMs": 42, "utilization": 96, "monthlyCost": 680, "costPerInvocation": 0.0001, "owner": "SOC"},
]

def discover_okta(config: dict) -> list:
    """
    In production: call Okta Admin API + Secure AI endpoints.
    For demo: return simulated agents.
    """
    agents = []
    for src in OKTA_SIMULATED_AGENTS:
        agents.append({
            'agentId': f"okta:{src['platformAgentId']}",
            'name': src['name'],
            'platform': 'okta',
            'platformAgentId': src['platformAgentId'],
            'category': src['category'],
            'system': 'Okta Secure AI',
            'runtime': 'Okta Secure AI',
            'source': 'external-connector',
            'status': src['status'],
            'requests': src['requests'],
            'errors': src['errors'],
            'avgResponseMs': src['avgResponseMs'],
            'utilization': src['utilization'],
            'monthlyCost': src['monthlyCost'],
            'costPerInvocation': src['costPerInvocation'],
            'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
            'owner': src.get('owner', ''),
            'platformMetadata': {'source': 'okta-secure-ai', 'org': 'contoso.okta.com'},
        })
    return agents


# ═══════════════════════════════════════════════════════════════
# MuleSoft Agent Fabric connector
# ═══════════════════════════════════════════════════════════════

MULESOFT_SIMULATED_AGENTS = [
    {"platformAgentId": "mule-sap-invoice", "name": "SAP Invoice Processor", "category": "Finance", "status": "active", "requests": 7800, "errors": 22, "avgResponseMs": 410, "utilization": 83, "monthlyCost": 1100, "costPerInvocation": 0.0010, "owner": "Finance Ops"},
    {"platformAgentId": "mule-servicenow-ticket", "name": "ServiceNow Ticket Router", "category": "IT Operations", "status": "active", "requests": 11400, "errors": 28, "avgResponseMs": 185, "utilization": 88, "monthlyCost": 760, "costPerInvocation": 0.0004, "owner": "IT Service Mgmt"},
]

def discover_mulesoft(config: dict) -> list:
    """
    In production: call MuleSoft Anypoint Platform API.
    For demo: return simulated agents.
    """
    agents = []
    for src in MULESOFT_SIMULATED_AGENTS:
        agents.append({
            'agentId': f"mule:{src['platformAgentId']}",
            'name': src['name'],
            'platform': 'mulesoft',
            'platformAgentId': src['platformAgentId'],
            'category': src['category'],
            'system': 'MuleSoft Agent Fabric',
            'runtime': 'MuleSoft Agent Fabric',
            'source': 'external-connector',
            'status': src['status'],
            'requests': src['requests'],
            'errors': src['errors'],
            'avgResponseMs': src['avgResponseMs'],
            'utilization': src['utilization'],
            'monthlyCost': src['monthlyCost'],
            'costPerInvocation': src['costPerInvocation'],
            'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
            'owner': src.get('owner', ''),
            'platformMetadata': {'source': 'anypoint-agent-fabric', 'org': 'contoso'},
        })
    return agents


# ═══════════════════════════════════════════════════════════════
# Native AWS connector — Amazon Bedrock Agents + AgentCore runtimes
# ═══════════════════════════════════════════════════════════════

def discover_native(config: dict) -> list:
    """
    Discover agents running natively in this AWS account: Amazon Bedrock Agents
    and (when present) Bedrock AgentCore runtimes. Unlike the external connectors,
    this reads real AWS APIs — no simulation. Best-effort: a missing API or
    permission for one source does not abort discovery of the others.
    """
    agents = []

    # Bedrock Agents
    try:
        bedrock_agent = boto3.client('bedrock-agent')
        paginator = bedrock_agent.get_paginator('list_agents')
        for page in paginator.paginate():
            for a in page.get('agentSummaries', []):
                agent_id = a['agentId']
                agent_name = a.get('agentName', agent_id)
                agents.append({
                    # Clean, human-readable key (the agent name) rather than a
                    # prefixed id — matches the AgentCore scanner's keying so the
                    # two discoverers never create duplicate rows for one agent,
                    # and keeps /agents/{agentId}/... URLs free of ':' / '/'.
                    'agentId': _clean_native_id(agent_name, agent_id),
                    'name': agent_name,
                    'platform': 'native',
                    'platformAgentId': agent_id,
                    'category': 'AWS Native',
                    'system': 'Amazon Bedrock Agents',
                    # Newly-discovered agents enter at 'pending-review' — a valid
                    # entry state in the data-handler lifecycle machine — so an
                    # operator can move them through the lifecycle in the UI.
                    'status': 'pending-review',
                    **demo_metrics(agent_id),
                    'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                    'owner': '',
                    'platformMetadata': {
                        'source': 'bedrock-agents',
                        'agentStatus': a.get('agentStatus', ''),
                        'updatedAt': str(a.get('updatedAt', '')),
                    },
                })
        logger.info(f"Native: found {len(agents)} Bedrock Agent(s)")
    except Exception as e:
        logger.error(f"Native Bedrock Agents discovery failed: {e}")

    # Bedrock AgentCore runtimes (only present when AgentCore is deployed)
    try:
        agentcore = boto3.client('bedrock-agentcore-control')
        resp = agentcore.list_agent_runtimes()
        for rt in resp.get('agentRuntimes', []):
            rt_id = rt.get('agentRuntimeId', rt.get('agentRuntimeName', ''))
            rt_name = rt.get('agentRuntimeName', rt_id)
            agents.append({
                'agentId': _clean_native_id(rt_name, rt_id),
                'name': rt_name,
                'platform': 'native',
                'platformAgentId': rt_id,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'status': 'pending-review',
                **demo_metrics(rt_id),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {'source': 'bedrock-agentcore', 'status': rt.get('status', '')},
            })
        logger.info(f"Native: found {len(resp.get('agentRuntimes', []))} AgentCore runtime(s)")
    except Exception as e:
        # AgentCore is gated off by default, so this is expected to be absent
        logger.info(f"Native AgentCore discovery skipped: {e}")

    return agents


# ═══════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════
# AWS Organization connector (cross-account) — SIMULATED
# ═══════════════════════════════════════════════════════════════
#
# The 'native' connector lists Bedrock agents in THIS account/region only. A real
# org-wide connector would, from a delegated-admin account: organizations:ListAccounts
# -> sts:AssumeRole into a read-only FlowAMPDiscoveryRole in each member account
# (rolled out org-wide via CloudFormation StackSets, service-managed) -> list_agents
# across each enabled region -> normalize. That needs a real AWS Organization, so this
# demo simulates the account list and the agents found in each, which illustrates the
# single-pane-across-accounts story and the account/region-scoped data model.
#
# Note the agentId carries accountId + region so identically-named agents in different
# accounts do not collide: native:<accountId>:<region>:bedrock-agent:<id>.

# Capped at 2 agents (one representative member account) to keep the cross-account
# story without flooding the catalog.
ORG_SIMULATED_ACCOUNTS = [
    {"accountId": "111111111111", "accountName": "Production", "region": "us-east-1", "agents": [
        {"platformAgentId": "prod-order-orchestrator", "name": "Order Orchestrator", "category": "Customer Operations", "status": "active", "requests": 18400, "errors": 12, "avgResponseMs": 120, "utilization": 93, "monthlyCost": 1180, "costPerInvocation": 0.0006, "owner": "Customer BU"},
        {"platformAgentId": "prod-fraud-screener", "name": "Fraud Screener", "category": "Finance & Trading", "status": "active", "requests": 9200, "errors": 7, "avgResponseMs": 210, "utilization": 81, "monthlyCost": 760, "costPerInvocation": 0.0011, "owner": "Finance BU"},
    ]},
]


def discover_aws_org(config: dict) -> list:
    """
    In production: from a delegated-admin account, organizations:ListAccounts then
    sts:AssumeRole into a read-only role in each member account (deployed org-wide via
    StackSets) and list_agents per enabled region.
    When ORG_DISCOVERY_ENABLED, performs the real cross-account scan; otherwise
    returns simulated agents so the sample still shows the cross-account story.
    """
    if ORG_DISCOVERY_ENABLED:
        return _discover_aws_org_real()

    agents = []
    for acct in ORG_SIMULATED_ACCOUNTS:
        for src in acct['agents']:
            agents.append({
                'agentId': f"native:{acct['accountId']}:{acct['region']}:bedrock-agent:{src['platformAgentId']}",
                'name': src['name'],
                'platform': 'aws-org',
                'platformAgentId': src['platformAgentId'],
                'accountId': acct['accountId'],
                'accountName': acct['accountName'],
                'region': acct['region'],
                'category': src['category'],
                'system': 'Amazon Bedrock Agents',
                # Cross-account org agents ARE Bedrock agents, so the runtime is
                # honest here; still marked external-connector as their origin.
                'runtime': 'Bedrock Agent',
                'source': 'external-connector',
                'status': src['status'],
                'requests': src['requests'],
                'errors': src['errors'],
                'avgResponseMs': src['avgResponseMs'],
                'utilization': src['utilization'],
                'monthlyCost': src['monthlyCost'],
                'costPerInvocation': src['costPerInvocation'],
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': src.get('owner', ''),
                'platformMetadata': {
                    'source': 'aws-organizations',
                    'accountId': acct['accountId'],
                    'accountName': acct['accountName'],
                    'region': acct['region'],
                },
            })
    return agents


def _org_account_map() -> dict:
    """Return {accountId: accountName} for ACTIVE accounts in the organization.

    organizations:ListAccounts is only callable from the management account or a
    registered delegated-administrator account. Paginates on NextToken (which can
    appear even on an empty page, per the API contract).
    """
    org = boto3.client('organizations')
    accounts = {}
    paginator = org.get_paginator('list_accounts')
    for page in paginator.paginate():
        for a in page.get('Accounts', []):
            if a.get('Status') == 'ACTIVE':
                accounts[a['Id']] = a.get('Name', a['Id'])
    return accounts


def _assume_discovery_session(account_id: str):
    """Assume ORG_DISCOVERY_ROLE_NAME in account_id; return a boto3 Session or None.

    Returns None (and logs) on failure so one unreachable account never aborts the
    whole org scan — e.g. an invited account without OrganizationAccountAccessRole,
    or a member account that hasn't rolled out a scoped discovery role.
    """
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{ORG_DISCOVERY_ROLE_NAME}"
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName='flowamp-discovery')
        c = resp['Credentials']
        return boto3.Session(
            aws_access_key_id=c['AccessKeyId'],
            aws_secret_access_key=c['SecretAccessKey'],
            aws_session_token=c['SessionToken'],
        )
    except Exception as e:
        code = type(e).__name__
        # AccessDenied usually means the discovery role isn't present in / doesn't
        # trust us for that account (e.g. non-enrolled account, or wrong role name).
        _CONNECTOR_WARNINGS.append(
            f"account {account_id}: could not assume {ORG_DISCOVERY_ROLE_NAME} ({code})"
        )
        logger.warning(f"Org discovery: cannot assume {role_arn}: {e}")
        return None


def _list_bedrock_agents_in(session, account_id: str, account_name: str, region: str) -> list:
    """List Amazon Bedrock Agents in one account+region via an assumed-role session."""
    found = []
    try:
        client = session.client('bedrock-agent', region_name=region)
        paginator = client.get_paginator('list_agents')
        logger.info(f"Org discovery: listing bedrock-agents in {account_id}/{region}")
        for page in paginator.paginate():
            for a in page.get('agentSummaries', []):
                platform_agent_id = a['agentId']
                # agentId carries accountId + region so identically-named agents in
                # different accounts never collide (matches the simulated shape).
                found.append({
                    'agentId': f"native:{account_id}:{region}:bedrock-agent:{platform_agent_id}",
                    'name': a.get('agentName', platform_agent_id),
                    'platform': 'aws-org',
                    'platformAgentId': platform_agent_id,
                    'accountId': account_id,
                    'accountName': account_name,
                    'region': region,
                    'category': 'AWS Native',
                    'system': 'Amazon Bedrock Agents',
                    'runtime': 'Bedrock Agent',
                    'source': 'external-connector',
                    'status': 'pending-review',
                    **demo_metrics(f"{account_id}:{platform_agent_id}"),
                    'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                    'owner': '',
                    'platformMetadata': {
                        'source': 'aws-organizations',
                        'accountId': account_id,
                        'accountName': account_name,
                        'region': region,
                        'agentStatus': a.get('agentStatus', ''),
                    },
                })
    except Exception as e:
        logger.warning(f"Org discovery: list_agents failed in {account_id}/{region}: {type(e).__name__}: {e}")
    logger.info(f"Org discovery: {account_id}/{region} bedrock-agents found={len(found)}")
    return found


def _list_agentcore_runtimes_in(session, account_id: str, account_name: str, region: str) -> list:
    """List Bedrock AgentCore runtimes in one account+region via an assumed session.

    Mirrors the single-account native connector, which scans BOTH Bedrock Agents and
    AgentCore runtimes — cross-account discovery must cover both too.
    """
    found = []
    try:
        client = session.client('bedrock-agentcore-control', region_name=region)
        resp = client.list_agent_runtimes()
        for rt in resp.get('agentRuntimes', resp.get('agentRuntimeSummaries', [])):
            rt_id = rt.get('agentRuntimeId', rt.get('agentRuntimeName', ''))
            rt_name = rt.get('agentRuntimeName', rt_id)
            found.append({
                'agentId': f"native:{account_id}:{region}:agentcore:{rt_id}",
                'name': rt_name,
                'platform': 'aws-org',
                'platformAgentId': rt_id,
                'accountId': account_id,
                'accountName': account_name,
                'region': region,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'runtime': 'AgentCore (Strands)',
                'source': 'external-connector',
                'status': 'pending-review',
                **demo_metrics(f"{account_id}:{rt_id}"),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {
                    'source': 'aws-organizations',
                    'accountId': account_id,
                    'accountName': account_name,
                    'region': region,
                    'status': rt.get('status', ''),
                },
            })
    except Exception as e:
        # AgentCore may not be available in every region — expected; log and move on.
        logger.info(f"Org discovery: list_agent_runtimes skipped in {account_id}/{region}: {e}")
    return found


def _discover_aws_org_real() -> list:
    """Real cross-account discovery: enumerate the org, assume a role per member
    account, and list BOTH Bedrock Agents and AgentCore runtimes across the
    configured regions (matching the single-account native connector).

    Runs from the management or delegated-admin account. Skips this Lambda's OWN
    account — those agents are covered by the single-account native connector /
    AgentCore scanner, so including them here would double-write under a different
    (native:<acct>:<region>:...) key.
    """
    try:
        own_account = boto3.client('sts').get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Org discovery: cannot resolve own account: {e}")
        return []

    try:
        account_map = _org_account_map()
    except Exception as e:
        # Almost always: not the management/delegated-admin account (AccessDenied).
        msg = (f"organizations:ListAccounts failed ({type(e).__name__}) — org discovery "
               f"must run from the management or a delegated-admin account")
        _CONNECTOR_WARNINGS.append(msg)
        logger.error(f"Org discovery: {msg}: {e}")
        return []

    logger.info(f"Org discovery: own={own_account} accounts={list(account_map.keys())} "
                f"regions={ORG_DISCOVERY_REGIONS} role={ORG_DISCOVERY_ROLE_NAME}")
    agents = []
    scanned = 0
    for account_id, account_name in account_map.items():
        if account_id == own_account:
            continue  # covered by single-account native discovery
        session = _assume_discovery_session(account_id)
        if session is None:
            continue
        scanned += 1
        for region in ORG_DISCOVERY_REGIONS:
            agents.extend(_list_bedrock_agents_in(session, account_id, account_name, region))
            agents.extend(_list_agentcore_runtimes_in(session, account_id, account_name, region))
    logger.info(f"Org discovery: scanned {scanned} member account(s) across "
                f"{len(ORG_DISCOVERY_REGIONS)} region(s); found {len(agents)} agent(s)")
    return agents


# ═══════════════════════════════════════════════════════════════

CONNECTORS = {
    'native': discover_native,
    'aws-org': discover_aws_org,
    'microsoft': discover_microsoft,
    'okta': discover_okta,
    'mulesoft': discover_mulesoft,
}

def _inactivate_missing_native(seen_ids: set) -> int:
    """Mark native agents absent from this scan as inactive.

    Only the native connector is authoritative for inactivation (it reads real
    AWS APIs); the simulated external connectors always re-return their lists and
    self-heal, so they are never inactivated here. Guards that skip rows where a
    human has locked 'status', and skip rows already inactive.
    """
    from boto3.dynamodb.conditions import Attr
    items = table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])
    removed = 0
    for i in items:
        if i.get('platform') != 'native':
            continue
        if i['agentId'] in seen_ids:
            continue
        if i.get('status') == 'inactive':
            continue
        # Respect a human lock on status.
        if 'status' in (i.get('humanVerifiedFields') or []):
            logger.info(f"Skipping inactivation of {i['agentId']}: status is human-verified")
            continue
        table.update_item(
            Key={'agentId': i['agentId'], 'sk': 'INFO'},
            UpdateExpression='SET #s = :inactive, lastSyncedAt = :now',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':inactive': 'inactive', ':now': NOW},
        )
        removed += 1
    return removed

def run_discovery(platforms: list[str] | None = None) -> list[dict]:
    """Run discovery for specified platforms (or all if None)."""
    targets = platforms or list(CONNECTORS.keys())
    results = []
    for p in targets:
        if p not in CONNECTORS:
            results.append({'platform': p, 'error': f'Unknown platform: {p}'})
            continue
        # Native discovery is ceded to the AgentCore scanner when it is deployed.
        # Skip it here so the two discoverers never double-write native agents.
        # An explicit `platforms=['native']` request (e.g. manual API call) still
        # reports the skip rather than silently doing nothing.
        if p == 'native' and not NATIVE_DISCOVERY_ENABLED:
            results.append({
                'platform': p,
                'skipped': 'native discovery is owned by the AgentCore discovery-scanner',
                'syncedAt': NOW,
            })
            continue
        try:
            config = {}  # In production: load from SSM Parameter Store
            _CONNECTOR_WARNINGS.clear()  # capture only this connector's warnings
            agents = CONNECTORS[p](config)
            updated = 0
            for agent in agents:
                upsert_agent(agent)
                updated += 1
            removed = 0
            # Native is the only authoritative source for inactivation. Only act
            # when the scan clearly succeeded (returned >0 agents); an empty/errored
            # ListAgents must not wrongly inactivate the whole fleet.
            if p == 'native' and agents:
                seen = {a['agentId'] for a in agents}
                removed = _inactivate_missing_native(seen)
            result = {
                'platform': p,
                'agentsDiscovered': len(agents),
                'agentsUpdated': updated,
                'agentsRemoved': removed,
                'syncedAt': NOW,
            }
            # Surface partial failures (e.g. org accounts we couldn't reach) so the
            # UI can warn instead of silently reporting 0 discovered.
            if _CONNECTOR_WARNINGS:
                result['warnings'] = list(_CONNECTOR_WARNINGS)
            results.append(result)
            # Log metadata only (counts + platform name) — never full agent records
            # or user-submitted fields, which may contain sensitive data.
            logger.info(f"Discovered {len(agents)} agents from {p}, inactivated {removed}")
        except Exception as e:
            logger.error(f"Discovery failed for {p}: {e}")
            results.append({'platform': p, 'error': str(e), 'syncedAt': NOW})
    return results


def handler(event, context):
    """
    Invoked by:
      - EventBridge schedule (no body → sync all platforms)
      - API Gateway POST /discovery/sync (body.platforms → selective sync)
      - API Gateway GET /discovery/status (return last sync info)
    """
    # Async worker invocation (fire-and-forget from the API path below). Runs the
    # actual scan out of band so a multi-account org sync isn't bound by API
    # Gateway's 29s limit. Payload: {"async_sync": true, "platforms": [...]|null}.
    if isinstance(event, dict) and event.get('async_sync'):
        results = run_discovery(event.get('platforms'))
        logger.info(f"Async discovery sync complete: {json.dumps(results, default=decimal_default)[:500]}")
        return {'ok': True, 'results': results}

    # EventBridge scheduled invocation
    if 'source' in event and event['source'] == 'aws.events':
        results = run_discovery()
        return {'statusCode': 200, 'body': json.dumps(results, default=decimal_default)}

    # API Gateway
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')

    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    }

    if http_method == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    if http_method == 'POST' and '/sync' in path:
        body = json.loads(event.get('body', '{}') or '{}')
        platforms = body.get('platforms')  # None = all
        # Fire-and-forget: an org sync (assume + list across many member accounts)
        # can exceed API Gateway's 29s limit and get cut off mid-scan. Kick off an
        # async copy of ourselves and return 202 immediately; the UI polls the
        # registry for results. Falls back to synchronous if the async invoke fails.
        self_fn = os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        try:
            boto3.client('lambda', region_name=os.environ.get('AWS_REGION', 'us-west-2')).invoke(
                FunctionName=self_fn,
                InvocationType='Event',
                Payload=json.dumps({'async_sync': True, 'platforms': platforms}).encode(),
            )
            return {'statusCode': 202, 'headers': headers, 'body': json.dumps({
                'status': 'started',
                'message': 'Discovery sync started; results appear in the registry shortly.',
            })}
        except Exception as e:
            logger.warning(f"async sync invoke failed, running inline: {e}")
            results = run_discovery(platforms)
            return {'statusCode': 200, 'headers': headers, 'body': json.dumps(results, default=decimal_default)}

    if http_method == 'GET' and '/status' in path:
        # Return counts per platform from DynamoDB (entity rows only — sk='INFO').
        from boto3.dynamodb.conditions import Attr
        items = table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])
        agents = [i for i in items if not i['agentId'].startswith(('compliance:', 'aop:', 'access:'))]
        summary = {}
        for a in agents:
            p = a.get('platform', 'native')
            if p not in summary:
                summary[p] = {'count': 0, 'active': 0, 'lastSynced': None}
            summary[p]['count'] += 1
            if a.get('status') == 'active':
                summary[p]['active'] += 1
            ls = a.get('lastSyncedAt')
            if ls and (not summary[p]['lastSynced'] or ls > summary[p]['lastSynced']):
                summary[p]['lastSynced'] = ls
        return {'statusCode': 200, 'headers': headers, 'body': json.dumps(summary, default=decimal_default)}

    if http_method == 'GET' and '/platforms' in path:
        return {
            'statusCode': 200, 'headers': headers,
            'body': json.dumps([
                {'platform': 'native', 'name': 'AWS Bedrock / Strands', 'status': 'connected'},
                {'platform': 'aws-org', 'name': 'AWS Organization (cross-account)', 'status': 'connected'},
                {'platform': 'microsoft', 'name': 'Microsoft Copilot Studio', 'status': 'connected'},
                {'platform': 'okta', 'name': 'Okta Secure AI', 'status': 'connected'},
                {'platform': 'mulesoft', 'name': 'MuleSoft Agent Fabric', 'status': 'connected'},
            ])
        }

    return {'statusCode': 404, 'headers': headers, 'body': json.dumps({'error': 'Not found'})}
