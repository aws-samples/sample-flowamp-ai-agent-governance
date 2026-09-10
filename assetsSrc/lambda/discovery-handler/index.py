# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Discovery Agent - discovers agents, native and external, and upserts normalized records.

Connectors:
  - `aws-org`   Real cross-account scan (Bedrock Agents + AgentCore) via assume-role.
  - `native`    Real single-account scan. `discover_native` is inactive unless
                NATIVE_DISCOVERY_ENABLED is true, which happens only with
                `-c deployGovernanceAgents=false`; otherwise the AgentCore
                `discovery-scanner` runtime owns native discovery (same control-plane calls
                plus LLM enrichment) and this pass is skipped, so the two never double-write
                one agent under different keys or statuses.
  - `microsoft` Real Microsoft Foundry Agent Service scan (Entra client-credentials plus
                the Foundry data-plane API). Reports 'skipped' until an operator configures
                credentials in the UI, rather than failing.
  - `okta` / `mulesoft`
                Demo only: hardcoded agent lists with no API call behind them, gated by
                SEED_SAMPLE_DATA so they never write to a real catalog.

This handler also serves the connector-configuration API (`/discovery/connectors`).
Non-secret settings live on the AgentTable platform sentinel row; the credential lives in
Secrets Manager and no read path returns it.

Each connector returns a list of normalized dicts matching the AgentRecord schema. Runs on
an EventBridge schedule or on demand via API Gateway. Native rows are keyed by a clean
agentId (see _clean_native_id) and enter at status 'pending-review', matching the scanner's
convention and a valid entry state in the data-handler lifecycle state machine.
"""
import hashlib, json, os, time, logging, re, urllib.error, urllib.parse, urllib.request
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

# Demo data gate. The okta/mulesoft connectors return hardcoded agents with no API call
# behind them, so they run only under the flag that gates the rest of the sample data.
# Default off, so a real deploy never puts invented agents in a customer's registry.
SEED_SAMPLE_DATA = os.environ.get('SEED_SAMPLE_DATA', 'false') == 'true'

# Connectors with no real backend, see SEED_SAMPLE_DATA. 'aws-org' and 'microsoft' are
# excluded: both call real APIs. 'aws-org' falls back to simulated data only when explicitly
# disabled, and 'microsoft' is gated on being configured rather than on demo data.
SIMULATED_CONNECTORS = frozenset({'okta', 'mulesoft'})

# Connectors that require operator-supplied credentials before they can run. An
# unconfigured one reports 'skipped' rather than erroring, so a default deploy is quiet.
CONFIGURABLE_CONNECTORS = frozenset({'microsoft'})

# Sentinel partition holding platform rows. Shared with the compliance-scanner, which
# queries the same PK for `auditable=true` platforms, so connector config and platform
# registration live in one place.
PLATFORM_SENTINEL_PK = 'FLOWAMP_PLATFORMS'

# Secrets Manager name prefix for connector credentials. One secret per connector; the
# value is a JSON object so a connector can carry more than one field later.
#
# A constant rather than an env var: CDK grants this Lambda Secrets Manager access scoped to
# `secret:flowamp/connectors/*`, so an override would move the secrets outside the IAM scope
# and every call would fail with AccessDenied at runtime while synth and deploy stayed green.
# Changing it means also changing the discoveryFn secretsmanager PolicyStatement in
# team-stack.ts.
CONNECTOR_SECRET_PREFIX = 'flowamp/connectors'

# Entra (Microsoft identity platform) client-credentials endpoint. Raw HTTP rather than
# azure-identity: this Lambda is packaged with Code.fromAsset and vendors no dependencies,
# and a form POST is the entire grant.
ENTRA_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
# Two token audiences from one app registration and one secret: the data plane reads agents,
# ARM enumerates what to read (subscriptions -> Foundry accounts -> projects).
FOUNDRY_SCOPE = 'https://ai.azure.com/.default'
ARM_SCOPE = 'https://management.azure.com/.default'
ARM_BASE = 'https://management.azure.com'
# 2024-10-01 rejects `accounts/projects` with InvalidResourceType; 2025-06-01 answers both
# calls. Pinned in one place so the two cannot drift apart.
ARM_SUBSCRIPTIONS_API_VERSION = '2020-01-01'
ARM_COGNITIVE_API_VERSION = '2025-06-01'
# The Foundry account resource advertises its own data-plane base URL under this key, so
# discovery never has to construct it or ask the operator to paste it.
FOUNDRY_ENDPOINT_KEY = 'AI Foundry API'
# Only this Cognitive Services kind hosts Foundry projects/agents; the same subscription
# may hold Speech, Vision or OpenAI accounts, which have no agents to enumerate.
FOUNDRY_ACCOUNT_KIND = 'AIServices'
# Foundry's agents API is versioned `v1`, not a date string. See the REST tab of
# learn.microsoft.com/azure/foundry/agents/quickstarts/prompt-agent.
FOUNDRY_API_VERSION = os.environ.get('FOUNDRY_API_VERSION', 'v1')
# The two persisted agent kinds. AgentDetails carries no `kind` field, so the kind comes from
# which filtered list call returned the agent: two paged calls, not a GetVersion per agent.
FOUNDRY_AGENT_KINDS = (
    ('prompt', 'Foundry Prompt Agent'),
    ('hosted', 'Foundry Hosted Agent'),
)
_HTTP_TIMEOUT = 20

# ── Normalized platform status ────────────────────────────────────────────────
# Every platform reports run state in its own vocabulary, and the registry shows it next to
# one governance lifecycle. The raw value is stored verbatim (`platformStatusRaw`) and mapped
# onto these four buckets for display and drift detection. Transitional values (CREATING /
# UPDATING / PREPARING / VERSIONING) map to 'unknown': they are neither running nor stopped,
# and forcing them into either bucket would make the drift matrix fire on every ordinary
# deploy.
#
# This map is duplicated in assetsSrc/agents/discovery-scanner/main.py, which owns native
# discovery on the default deploy path. The two asset directories are packaged separately
# and cannot import from each other, so a change here needs the same change there.
PLATFORM_STATUS_RUNNING = 'running'
PLATFORM_STATUS_STOPPED = 'stopped'
PLATFORM_STATUS_FAILED = 'failed'
PLATFORM_STATUS_UNKNOWN = 'unknown'

_PLATFORM_STATUS_BY_RAW = {
    # AgentCore Runtime `status`: CREATING, CREATE_FAILED, UPDATING, UPDATE_FAILED, READY,
    # DELETING. Harness `status` is the same set plus DELETE_FAILED.
    'READY': PLATFORM_STATUS_RUNNING,
    'CREATE_FAILED': PLATFORM_STATUS_FAILED,
    'UPDATE_FAILED': PLATFORM_STATUS_FAILED,
    'DELETE_FAILED': PLATFORM_STATUS_FAILED,
    'DELETING': PLATFORM_STATUS_STOPPED,
    # Bedrock Agents Classic `agentStatus`: CREATING, PREPARING, PREPARED, NOT_PREPARED,
    # FAILED, UPDATING, DELETING. NOT_PREPARED is a stopped state, not a transitional one:
    # the agent exists but no version has been prepared, so it cannot serve traffic.
    'PREPARED': PLATFORM_STATUS_RUNNING,
    'NOT_PREPARED': PLATFORM_STATUS_STOPPED,
    'FAILED': PLATFORM_STATUS_FAILED,
    # Microsoft Foundry (`state` on AgentDetails), for both prompt and hosted agents.
    'ENABLED': PLATFORM_STATUS_RUNNING,
    'DISABLED': PLATFORM_STATUS_STOPPED,
}


def normalize_platform_status(raw: str) -> str:
    """Map one platform's own run-state string onto a FlowAMP platform-status bucket.

    Anything unrecognized, including '', returns 'unknown'. The drift matrix treats 'unknown'
    as "no signal" rather than a finding, so a platform state newly added by AWS or Azure
    degrades to silence instead of a false alarm.
    """
    return _PLATFORM_STATUS_BY_RAW.get(str(raw or '').strip().upper(),
                                       PLATFORM_STATUS_UNKNOWN)


def platform_status_fields(raw: str, bucket: str | None = None) -> dict:
    """The three fields every discovered agent carries to describe its platform state.

    `bucket` overrides the mapping for platforms whose run state needs more than one field to
    determine (Foundry, where a failed version outranks an enabled agent).

    `platformStatusAt` marks this as a point-in-time sample, not a live read: discovery runs
    on a 6-hour schedule, so the UI needs the value's age to grey out a stale reading. It must
    not use the module-level `NOW`, which is fixed for the life of a warm container and would
    report an age of zero for an old sample.
    """
    return {
        'platformStatus': bucket or normalize_platform_status(raw),
        'platformStatusRaw': str(raw or ''),
        'platformStatusAt': datetime.now(timezone.utc).isoformat(),
    }
# Cached Entra tokens keyed by (tenant, client_id, scope) -> (token, expires_at_epoch), at
# module scope so a warm container reuses a token instead of re-minting one per run.
_token_cache: dict = {}
# Coverage from the most recent Foundry sweep: {project_key: 'ok'|'denied'|'throttled'}.
# Module-level because the CONNECTORS dispatch table types every connector as
# `config -> list`, and run_discovery needs the coverage to scope inactivation. Cleared and
# repopulated by each sweep, so a stale map cannot authorize inactivation in a project this
# run never read.
_FOUNDRY_COVERAGE: dict = {}
# Member accounts the last org sweep actually read, by account id. Same purpose as
# _FOUNDRY_COVERAGE: an account that could not be assumed into contributes no agents, so
# without this its agents would look deleted and be inactivated wholesale.
_ORG_ACCOUNTS_READ: set = set()

# Real cross-account org discovery, on by default (CDK enableOrgDiscovery). The aws-org
# connector enumerates the AWS Organization (organizations:ListAccounts, callable only from
# the management or a delegated-admin account), assumes ORG_DISCOVERY_ROLE_NAME in each
# member account, and lists Bedrock Agents plus AgentCore runtimes per region. Anywhere else
# ListAccounts fails and the connector returns [] with a warning surfaced to the UI, rather
# than falling back to simulated data.
ORG_DISCOVERY_ENABLED = os.environ.get('ORG_DISCOVERY_ENABLED', 'true') == 'true'
# Role assumed in each member account. AWSControlTowerExecution is provisioned by Control
# Tower / Landing Zone in every enrolled account and trusts the management account. For a
# plain org, override with OrganizationAccountAccessRole, or a scoped read-only role for
# least privilege.
ORG_DISCOVERY_ROLE_NAME = os.environ.get('ORG_DISCOVERY_ROLE_NAME', 'AWSControlTowerExecution')
# Regions to scan per member account (comma-separated). Bedrock Agents is regional, so an
# explicit list is scanned rather than every region. Defaults to this Lambda's region.
ORG_DISCOVERY_REGIONS = [
    r.strip() for r in os.environ.get(
        'ORG_DISCOVERY_REGIONS', os.environ.get('AWS_REGION', 'us-east-1')
    ).split(',') if r.strip()
]

NOW = datetime.now(timezone.utc).isoformat()

# Per-run, per-connector warnings surfaced to the UI, e.g. accounts that could not be assumed
# during org discovery. Reset at the start of each connector run so the results dict can carry
# them back through POST /discovery/sync to the browser.
_CONNECTOR_WARNINGS: list = []


def demo_metrics(seed_key: str) -> dict:
    """Plausible non-zero operational metrics for a freshly discovered agent.

    Bedrock ListAgents returns no usage numbers, which leaves the agent's detail Overview
    empty. Derived from a hash of the agent id so each agent looks distinct and the numbers
    stay stable across syncs. RAI score fields stay 0: the rai-scorer owns those, and
    "Not yet scored" is the accurate state for a new agent.
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

    Mirrors the AgentCore discovery-scanner's `_clean_agent_id`: prefer the operator-defined
    name when it is a clean identifier (no ':' or '/'), else the raw platform id. The name
    keeps the key stable across runtime redeploys, keeps /agents/{agentId}/... URLs free of
    reserved characters, and makes this Lambda and the scanner converge on one key for an
    agent instead of double-writing it.
    """
    if name and ':' not in name and '/' not in name:
        return name
    return fallback_id


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError


# ── Connector configuration (DynamoDB) + credentials (Secrets Manager) ──
#
# The split is required: non-secret settings live on the platform sentinel row so the UI can
# read them back and the compliance-scanner can see the platform, while the client secret lives
# only in Secrets Manager. Nothing writes the secret into DynamoDB, and no read path returns it.

def _connector_secret_name(platform: str) -> str:
    return f"{CONNECTOR_SECRET_PREFIX}/{platform}"


def load_connector_config(platform: str) -> dict:
    """Return the stored config for a connector, or {} when never configured."""
    try:
        item = table.get_item(
            Key={'agentId': PLATFORM_SENTINEL_PK, 'sk': f'PLATFORM#{platform}'},
        ).get('Item') or {}
        return item
    except Exception as e:
        logger.error(f"Unable to read connector config for {platform}: {e}")
        return {}


def save_connector_config(platform: str, body: dict) -> dict:
    """Upsert a connector's config, writing the secret to Secrets Manager.

    Returns the stored (redacted) config. The incoming clientSecret is optional on
    update: omitting it keeps the existing secret, so an operator can edit the endpoint
    without re-entering credentials.
    """
    secret_value = body.get('clientSecret') or ''
    secret_arn = ''
    if secret_value:
        secret_arn = _put_connector_secret(platform, secret_value)
    else:
        secret_arn = (load_connector_config(platform) or {}).get('secretArn', '')

    # Tenant and client only: the endpoint, accounts and projects are discovered from Azure at
    # sweep time, so nothing stored here can drift or be mistyped into re-keying a fleet.
    item = {
        'agentId': PLATFORM_SENTINEL_PK,
        'sk': f'PLATFORM#{platform}',
        'platformId': platform,
        'name': body.get('name') or 'Microsoft Foundry',
        'enabled': bool(body.get('enabled', True)),
        'tenantId': body.get('tenantId') or '',
        'clientId': body.get('clientId') or '',
        'secretArn': secret_arn,
        'updatedAt': NOW,
    }
    table.put_item(Item=item)
    return redact_connector_config(item)


def delete_connector_config(platform: str) -> None:
    """Remove a connector's config row and its secret. Best-effort on the secret."""
    table.delete_item(Key={'agentId': PLATFORM_SENTINEL_PK, 'sk': f'PLATFORM#{platform}'})
    try:
        secrets.delete_secret(
            SecretId=_connector_secret_name(platform),
            ForceDeleteWithoutRecovery=True,
        )
    except Exception as e:
        # A missing secret is not an error: the config may never have had one.
        logger.info(f"Connector secret delete skipped for {platform}: {type(e).__name__}")


def redact_connector_config(item: dict) -> dict:
    """Project a config row for the API. Never returns the secret, only whether a
    credential exists, so the UI can show 'configured' without reading it."""
    return {
        'platform': item.get('platformId') or item.get('sk', '').replace('PLATFORM#', ''),
        'name': item.get('name', ''),
        'enabled': bool(item.get('enabled', False)),
        'tenantId': item.get('tenantId', ''),
        'clientId': item.get('clientId', ''),
        'credentialSet': bool(item.get('secretArn')),
        # Whether this connector takes operator-supplied credentials at all, so the UI does
        # not offer Edit/Remove on connectors configured by CDK flags.
        'configurable': (item.get('platformId') or '') in CONFIGURABLE_CONNECTORS,
        'updatedAt': item.get('updatedAt', ''),
        'lastSyncAt': item.get('lastSyncAt', ''),
        'lastSyncStatus': item.get('lastSyncStatus', ''),
        'lastError': item.get('lastError', ''),
        # Coverage, so the UI can answer "what did the last sweep see?" and not only
        # "did it error?".
        'lastSyncSummary': item.get('lastSyncSummary', ''),
        # Per-connector telemetry the UI renders generically when the tile is clicked (org
        # id, accounts scanned, projects swept, ...). Written by _record_sync_outcome and
        # must contain nothing secret, since this projection is the public read path.
        'details': _decimals_to_native(item.get('details') or {}),
    }


def _decimals_to_native(obj):
    """DynamoDB returns every number as Decimal, which json.dumps cannot serialize.

    Converts rather than relying on the `decimal_default` encoder, because a couple of API
    paths call json.dumps without it.
    """
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: _decimals_to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decimals_to_native(v) for v in obj]
    return obj


def _put_connector_secret(platform: str, client_secret: str) -> str:
    """Create or rotate the connector's secret. Returns its ARN."""
    name = _connector_secret_name(platform)
    payload = json.dumps({'clientSecret': client_secret})
    try:
        resp = secrets.create_secret(
            Name=name,
            SecretString=payload,
            Description=f'FlowAMP connector credentials for {platform}',
        )
        return resp['ARN']
    except secrets.exceptions.ResourceExistsException:
        resp = secrets.put_secret_value(SecretId=name, SecretString=payload)
        return resp['ARN']


def _read_connector_secret(platform: str) -> str:
    """Read the connector's clientSecret. Returns '' when absent."""
    try:
        raw = secrets.get_secret_value(SecretId=_connector_secret_name(platform))
        return (json.loads(raw['SecretString']) or {}).get('clientSecret', '')
    except Exception as e:
        logger.error(f"Unable to read connector secret for {platform}: {type(e).__name__}")
        return ''


def _record_sync_outcome(platform: str, status: str, error: str = '',
                         summary: str = '', details: dict | None = None) -> None:
    """Stamp the connector row with the result of the last run, so the UI can show why a
    connector is quiet without the operator reading CloudWatch. Written for every connector
    that runs, including those taking no operator configuration (native, aws-org).

    `summary` carries one-line coverage ("14 project(s) synced, 2 unreadable: …"). An error
    string alone cannot answer "did we see everything?", which for a multi-scope sweep is the
    more important question: a sync that read 2 of 50 projects reports no error at all.

    `details` is per-connector telemetry the UI renders generically: a flat map of
    key -> str | int | list[str], so a connector can add a field without a UI change. It must
    contain nothing secret, since GET /discovery/connectors returns it, which is also why
    `secretArn` is the only credential-shaped value ever stored on this row.
    """
    try:
        expr = ('SET lastSyncAt = :t, lastSyncStatus = :s, lastError = :e, '
                'lastSyncSummary = :sum, platformId = :p')
        vals = {
            ':t': NOW, ':s': status, ':e': error[:500], ':sum': summary[:500],
            ':p': platform,
        }
        if details is not None:
            expr += ', details = :d'
            vals[':d'] = _sanitize_details(details)
        table.update_item(
            Key={'agentId': PLATFORM_SENTINEL_PK, 'sk': f'PLATFORM#{platform}'},
            UpdateExpression=expr,
            ExpressionAttributeValues=vals,
        )
    except Exception as e:
        logger.info(f"Could not stamp sync outcome for {platform}: {type(e).__name__}")


def _sanitize_details(details: dict) -> dict:
    """Coerce a details map into what DynamoDB stores and the UI can render generically.

    Keeps str / int / bool and lists of strings, stringifies anything else, drops empties.
    Lists are capped so a badly-scoped estate cannot bloat the row or the API response; the
    count lives in its own key, so truncating the list loses nothing.
    """
    clean: dict = {}
    for key, value in (details or {}).items():
        if value is None or value == '' or value == []:
            continue
        if isinstance(value, bool) or isinstance(value, int):
            clean[key] = value
        elif isinstance(value, (list, tuple, set)):
            items = [str(v) for v in value if str(v)]
            if items:
                clean[key] = items[:20]
        else:
            clean[key] = str(value)[:300]
    return clean


# ── Microsoft Entra auth + Foundry HTTP ──

def _entra_token(tenant_id: str, client_id: str, client_secret: str,
                 scope: str = FOUNDRY_SCOPE) -> str:
    """Mint (or reuse) an Entra access token for one Azure audience.

    Client-credentials grant via urllib rather than azure-identity, so this Lambda needs no
    vendored dependencies. `scope` selects the audience: the Foundry data plane (default) or
    ARM. Tokens are cached per (tenant, client, scope); the scope must be part of the key, or
    an ARM token gets handed to a data-plane call and fails as a 401.
    """
    cache_key = (tenant_id, client_id, scope)
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > time.time():
        return cached[0]

    body = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope,
    }).encode()
    req = urllib.request.Request(
        ENTRA_TOKEN_URL.format(tenant=urllib.parse.quote(tenant_id, safe='')),
        data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # Entra's JSON body names the cause (bad secret, wrong tenant, expired secret), which
        # is more useful than a bare 401 for the most common setup failure. The secret itself
        # is never echoed.
        detail = ''
        try:
            detail = (json.loads(e.read().decode()) or {}).get('error_description', '')[:200]
        except Exception:
            detail = f'HTTP {e.code}'
        raise RuntimeError(f'Entra token request failed: {detail}') from None

    token = payload.get('access_token') or ''
    if not token:
        raise RuntimeError('Entra token response contained no access_token')
    # Refresh a minute early so a long connector run cannot expire mid-pagination.
    _token_cache[cache_key] = (token, time.time() + int(payload.get('expires_in', 3600)) - 60)
    return token


class AzureDenied(RuntimeError):
    """Azure authenticated the caller but refused the operation (401/403).

    A distinct type because a denial is neither a failure to retry nor an empty result to act
    on: it means "unknown". Callers sweeping many scopes catch it to mark one scope `denied`
    and continue, so a denied scope is never mistaken for an empty one, which would inactivate
    its agents.
    """


class AzureThrottled(RuntimeError):
    """Azure throttled or errored past the retries. Also 'unknown', not 'empty'."""


def _azure_get(base: str, path: str, token: str, params: dict | None = None,
               api_version: str = FOUNDRY_API_VERSION) -> dict:
    """GET an Azure JSON endpoint (ARM or the Foundry data plane) and decode it.

    One helper for both planes so they share a retry policy and error taxonomy: the sweep must
    treat a denial identically whether it came from ARM enumeration or a data-plane read.
    Retries 429 and 5xx with backoff; 401/403 is not retried, because a missing role assignment
    is not a transient condition.
    """
    query = dict(params or {})
    query['api-version'] = api_version
    url = f"{base.rstrip('/')}/{path.lstrip('/')}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})

    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AzureDenied(
                    f'Azure returned {e.code}: authenticated but not authorized. Assign the '
                    f'app registration a Foundry role that can list agents (allow up to '
                    f'~30 minutes for it to take effect).'
                ) from None
            if e.code == 429 or e.code >= 500:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise AzureThrottled(f'Azure request failed after retries: HTTP {e.code}') from None
            raise RuntimeError(f'Azure request failed: HTTP {e.code}') from None
        except urllib.error.URLError as e:
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise AzureThrottled(f'Azure unreachable: {e.reason}') from None
    raise AzureThrottled('Azure request failed after retries')


def _foundry_get(endpoint: str, path: str, token: str, params: dict | None = None) -> dict:
    """GET a Foundry data-plane path. Thin wrapper over _azure_get for readability."""
    return _azure_get(endpoint, path, token, params, api_version=FOUNDRY_API_VERSION)


def _arm_get(resource_path: str, token: str, api_version: str,
             params: dict | None = None) -> dict:
    """GET an Azure Resource Manager path (resource IDs start with '/subscriptions/...')."""
    return _azure_get(ARM_BASE, resource_path, token, params, api_version=api_version)


_NON_KEY_CHARS = re.compile(r'[^A-Za-z0-9._-]+')


def _arm_list_subscriptions(arm_token: str) -> list:
    """Subscriptions the service principal can see. [] if it can see none.

    Inherent blind spot: a subscription the principal cannot enumerate does not appear here and
    nothing reveals that it exists, so this is "what is visible", not "what exists". Coverage
    is bounded by Azure role assignments made outside FlowAMP.
    """
    payload = _arm_get('/subscriptions', arm_token, ARM_SUBSCRIPTIONS_API_VERSION)
    return [
        {'id': s.get('subscriptionId', ''), 'name': s.get('displayName', '')}
        for s in (payload.get('value') or [])
        if s.get('subscriptionId') and str(s.get('state', '')).lower() != 'disabled'
    ]


def _arm_list_foundry_accounts(arm_token: str, subscription_id: str,
                               subscription_name: str = '') -> list:
    """Foundry accounts in one subscription, with the data-plane base URL each advertises.

    Filtered to kind=AIServices: the same subscription commonly holds Speech, Vision or OpenAI
    Cognitive Services accounts, none of which host agents. Each account publishes its own
    Foundry endpoint under properties.endpoints['AI Foundry API'], so the operator never pastes
    a URL and a renamed resource cannot silently break discovery.
    """
    payload = _arm_get(
        f'/subscriptions/{subscription_id}/providers/Microsoft.CognitiveServices/accounts',
        arm_token, ARM_COGNITIVE_API_VERSION,
    )
    accounts = []
    for acct in payload.get('value') or []:
        if str(acct.get('kind', '')) != FOUNDRY_ACCOUNT_KIND:
            continue
        endpoints = (acct.get('properties') or {}).get('endpoints') or {}
        base = endpoints.get(FOUNDRY_ENDPOINT_KEY) or ''
        if not base:
            # An AIServices account without a Foundry endpoint hosts no agents API. Skipped
            # rather than guessing a URL from the resource name.
            continue
        accounts.append({
            'id': acct.get('id', ''),
            'name': acct.get('name', ''),
            'endpointBase': base.rstrip('/'),
            'subscriptionId': subscription_id,
            # Carried through so an agent row can show "<id> - <name>", as the registry does
            # for an AWS account. The subscription is the AWS-account analogue (billing and
            # isolation boundary); a Foundry project is a sub-scope of it.
            'subscriptionName': subscription_name,
        })
    return accounts


def _arm_list_projects(arm_token: str, account: dict) -> list:
    """Project names in one Foundry account.

    ARM returns each project's `name` as '<account>/<project>', so only the child segment is
    taken; passing the compound form to the data plane returns 404.
    """
    payload = _arm_get(f"{account['id']}/projects", arm_token, ARM_COGNITIVE_API_VERSION)
    names = []
    for proj in payload.get('value') or []:
        raw = str(proj.get('name') or '')
        names.append(raw.split('/')[-1] if '/' in raw else raw)
    return [n for n in names if n]


def _foundry_project_key(account_name: str, project: str) -> str:
    """Stable identifier for one project within the sweep: '<account>/<project>'.

    Stored on every agent row as platformMetadata.projectKey and used to scope inactivation, so
    it must be derived the same way on the discovery and the inactivation side.
    """
    return f'{account_name}/{project}'


def _foundry_agent_key(agent_name: str, agent_id: str, project_key: str) -> str:
    """Build the AgentTable partition key for a Foundry agent: `<name>-<scope hash>`.

    The bare agent name is not usable as a key: Foundry enforces name uniqueness only within a
    project, and the normal enterprise topology is a project per environment, so one logical
    agent in dev, staging and prod is expected and a bare-name key would leave two of the three
    ungoverned. The key therefore carries a 6-hex-character digest of `project_key`
    (`<account>/<project>`), which is unique per scope, deterministic whatever order ARM returns
    subscriptions/accounts/projects in, and bounded at name + 7 characters so it stays readable
    in `/agents/{agentId}/lifecycle` URLs (agentId is a path parameter, hence the
    [A-Za-z0-9._-] sanitization). The full scope is not lost: it is stored in platformMetadata
    and shown on the detail page, and the Agent column still displays the bare `name`.

    Account names are globally unique in Azure (they form the endpoint's DNS label), so
    `<account>/<project>` needs no tenant or subscription component. sha256 is a stable
    non-cryptographic digest here; nothing security-relevant depends on it. Renaming a Foundry
    account or project changes the digest and re-keys its agents, which is inherent to putting
    scope in the key.
    """
    clean = _NON_KEY_CHARS.sub('-', agent_name or agent_id).strip('-')[:180]
    digest = hashlib.sha256((project_key or '').encode()).hexdigest()[:6]
    return f'{clean}-{digest}'

def classify_record(agent, existing):
    """Decide what to do with a discovered agent: add / enrich / refresh.

    Keyed on the platform's agentId (no ARN cleaning needed):
      - 'add':     no existing INFO row
      - 'enrich':  exists but at least one of displayName/ENRICHMENT_FIELDS is empty on
                   both the incoming and stored record, and is not locked
      - 'refresh': exists and fully populated; only bump lastSyncedAt
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

    Preserves RAI scores, immutable fields and any human-verified fields, so a discovery
    sync never overwrites operator decisions.
    """
    # Agent rows are the canonical "INFO" row for their agentId. The table is keyed
    # agentId + sk; cost and event rows live under other sk values.
    agent['sk'] = 'INFO'
    existing = table.get_item(Key={'agentId': agent['agentId'], 'sk': 'INFO'}).get('Item', {})
    # Keep RAI scores from previous runs; discovery does not own them.
    for k in ('score', 'fairness', 'transparency', 'accountability', 'ethics'):
        if k not in agent or agent[k] == 0:
            agent[k] = existing.get(k, 0)

    action, _missing = classify_record(agent, existing)
    verified = list(existing.get('humanVerifiedFields') or [])
    agent['lastSyncedAt'] = NOW

    if action == 'add':
        # AgentRecord uses 'discovered' for a newly-found agent; the UI badge set is
        # active/warning/error/inactive/discovered.
        agent['status'] = agent.get('status') or 'discovered'
        agent['discoveredAt'] = NOW
        agent['aiInferred'] = False
        agent['humanVerifiedFields'] = []
    else:
        # enrich / refresh: carry immutable and verified fields forward from the stored row,
        # so human-set status, the original discoveredAt and locked fields survive the sync.
        for f in IMMUTABLE_FIELDS:
            if f in existing:
                agent[f] = existing[f]
        for f in ('displayName', *ENRICHMENT_FIELDS):
            # Never overwrite a verified field, and never blank out an already-populated
            # field with an empty incoming value.
            if f in verified or (existing.get(f) and not agent.get(f)):
                agent[f] = existing.get(f)
        agent['humanVerifiedFields'] = existing.get('humanVerifiedFields', [])
        agent['aiInferred'] = existing.get('aiInferred', False)

    # Convert floats to Decimal for DynamoDB
    agent = json.loads(json.dumps(agent, default=decimal_default), parse_float=Decimal)
    table.put_item(Item=agent)


# ═══════════════════════════════════════════════════════════════
# Microsoft Foundry (Agent Service) connector - real API
# ═══════════════════════════════════════════════════════════════
#
# Two agent kinds are persisted and therefore discoverable:
#   prompt  - declarative (model + instructions + tools); Foundry runs the agent loop
#   hosted  - the customer's own container or zip, run by Foundry
#
# Not discoverable: an ephemeral agent built per-call through the Responses API persists no
# Foundry resource, so no API can enumerate it. An inherent platform blind spot, documented in
# the README.


def _foundry_latest_version(agent: dict) -> dict:
    """Return the agent's latest version object, or {}.

    `versions` is a dict, not a version string: `{"latest": {...}}`, where the nested object
    carries `version`, `description`, `definition` (kind + model + instructions),
    `instance_identity` and timestamps. Almost everything worth recording lives there rather
    than on the agent, whose only fields are id / name / state / configuration_state / versions.
    """
    versions = agent.get('versions') or {}
    if not isinstance(versions, dict):
        return {}
    latest = versions.get('latest') or versions.get('latestVersion') or {}
    return latest if isinstance(latest, dict) else {}


def _foundry_agent_identity(version: dict) -> str:
    """The agent's own Entra identity principal, recorded as platform metadata. Lives on the
    version, not the agent, hence the argument.

    Not used as `owner`: this is the identity the agent authenticates as, not the team
    accountable for it, and a bare GUID in the Owner column would read as accountability
    information while being the agent identifying itself. Resolving it to a display name would
    need Microsoft Graph (Directory.Read.All), a second token scope and separate admin consent,
    so it is stored as-is for a reviewer to look up.
    """
    for key in ('instance_identity', 'instanceIdentity', 'blueprint'):
        identity = version.get(key) or {}
        if isinstance(identity, dict):
            for field in ('principal_id', 'principalId', 'client_id', 'clientId', 'name'):
                if identity.get(field):
                    return str(identity[field])
    return ''


def _foundry_list_agents(endpoint: str, token: str, kind: str) -> list:
    """Page the Foundry agents collection for one kind. Returns raw agent dicts.

    Cursor pagination: the collection returns `data` plus `has_more`/`last_id`, so paging walks
    forward with `after`. `nextLink` is honoured too, since both shapes appear across Foundry API
    revisions and handling only one would silently truncate a fleet at the first page.
    """
    collected: list = []
    after = None
    for _ in range(50):  # hard stop: 50 pages is far beyond any real fleet
        params = {'kind': kind, 'limit': 100}
        if after:
            params['after'] = after
        payload = _foundry_get(endpoint, 'agents', token, params)
        page = payload.get('data') or payload.get('value') or []
        collected.extend(page)
        if not payload.get('has_more') and not payload.get('nextLink'):
            break
        after = payload.get('last_id') or (page[-1].get('id') if page else None)
        if not after:
            break
    return collected


def _normalize_foundry_agent(src: dict, kind: str, runtime_label: str,
                             account: dict, project: str) -> dict | None:
    """Map one raw Foundry agent onto the AgentRecord shape the catalog stores.

    Emits no metrics: Azure exposes token and request counts per model deployment, not per
    agent, so there is no accurate per-agent `requests`, `errors` or `monthlyCost`. Absent
    is correct here; zero would be a claim.
    """
    agent_id = str(src.get('id') or '')
    agent_name = str(src.get('name') or agent_id)
    if not (agent_id or agent_name):
        return None

    version = _foundry_latest_version(src)
    definition = version.get('definition') or {}
    metadata = version.get('metadata') or {}
    # Foundry's operational state, not the version's `status`: that describes the version's own
    # lifecycle and reads 'active' even for a disabled endpoint, so it would report a disabled
    # agent as live.
    state = str(src.get('state') or '').lower()
    account_name = account.get('name', '')
    project_key = _foundry_project_key(account_name, project)

    # Platform run state. `state` is the operational switch and drives the bucket, but a version
    # that is not `active` outranks it: an agent Foundry reports as enabled whose latest version
    # failed to deploy cannot serve traffic. Hosted agents contribute no session state, because
    # the sandbox lifecycle is Active/Idle/Resumed per session with a 15-minute default idle
    # timeout, so a 6-hourly sample would read 'idle' for a busy agent and flap.
    version_status = str(version.get('status') or '').lower()
    if version_status and version_status != 'active':
        status_bucket = PLATFORM_STATUS_FAILED
        status_raw = f'{state}/{version_status}'
    else:
        status_bucket = None
        status_raw = state

    return {
        'agentId': _foundry_agent_key(agent_name, agent_id, project_key),
        'name': agent_name,
        'platform': 'microsoft',
        'platformAgentId': agent_id,
        # A field copy off the version, not enrichment. Often empty, in which case the reviewer
        # fills it in.
        'description': version.get('description') or metadata.get('description') or '',
        # No enrichment on this path, so the category stays generic rather than guessing from
        # the agent's name.
        'category': 'External Platforms',
        'system': 'Microsoft Foundry',
        # Execution surface, shown in the registry's Runtime column. Prompt vs hosted is the
        # Foundry analogue of harness vs runtime on AgentCore.
        'runtime': runtime_label,
        'source': 'external-connector',
        # Every newly discovered agent enters pending-review, including one Foundry reports as
        # `disabled`. The FlowAMP lifecycle is a governance state, not a mirror of the platform's
        # operational state: mapping `disabled` to `inactive` would let an agent skip review. The
        # platform's own state is kept as `state` / `configurationState` in platformMetadata.
        'status': 'pending-review',
        # Foundry's own run state, alongside (not instead of) the governance status above.
        **platform_status_fields(status_raw, status_bucket),
        'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
        # Left unset: Foundry records no owner and no creator (the API carries only timestamps,
        # and agent CRUD does not reach the Azure Activity Log), so the registry shows
        # "Unassigned" until a reviewer assigns one.
        'owner': '',
        'platformMetadata': {
            'source': 'foundry-agent-service',
            'agentIdentity': _foundry_agent_identity(version),
            'kind': str(definition.get('kind') or kind),
            'state': state,
            # Distinct from `state`: Foundry reports both, and they can disagree.
            'configurationState': str(src.get('configuration_state') or ''),
            'latestVersion': str(version.get('version') or ''),
            # The foundation model behind the agent: governance-relevant on its own, and the only
            # capability metadata this API provides without extra calls.
            'model': str(definition.get('model') or ''),
            'agentGuid': str(version.get('agent_guid') or ''),
            'blueprintId': str(
                (version.get('blueprint_reference') or {}).get('blueprint_id') or ''
            ),
            'digitalWorkerType': str(
                src.get('digitalWorkerType') or src.get('digital_worker_type') or ''
            ),
            # Where this agent lives, so inactivation can be scoped to projects the sweep
            # actually read and the UI can show provenance.
            'subscriptionId': account.get('subscriptionId', ''),
            'subscriptionName': account.get('subscriptionName', ''),
            # Platform-agnostic account identity for the registry's Account column: for Azure the
            # subscription is the AWS-account equivalent. Identical key names across connectors
            # keep the column free of per-platform branching.
            'accountId': account.get('subscriptionId', ''),
            'accountLabel': account.get('subscriptionName', ''),
            # The Foundry resource name, under the same key the org connector uses for an
            # AWS account name.
            'accountName': account_name,
            'projectName': project,
            # What the agentId digest is derived from, so the key and the scope shown on the
            # detail page can never describe different projects.
            'projectKey': project_key,
            'projectEndpoint': f"{account.get('endpointBase', '')}/api/projects/{project}",
        },
    }


def sweep_foundry_tenant(cfg: dict) -> tuple:
    """Walk an Azure tenant and return (agents, coverage).

    subscriptions -> Foundry accounts -> projects -> agents, from one service principal.
    Coverage is `{project_key: 'ok' | 'denied' | 'throttled'}`: a project that could not be read
    is unknown, not empty, so its previously-discovered agents must not be inactivated. Only
    projects marked 'ok' are authoritative about what exists.

    A per-scope denial never raises out of here. A tenant where the principal can read two
    projects out of fifty discovers those two and leaves the rest alone.
    """
    tenant_id = cfg.get('tenantId') or ''
    client_id = cfg.get('clientId') or ''
    client_secret = _read_connector_secret('microsoft')

    coverage: dict = {}
    agents: list = []
    # agentId -> project_key of the row that claimed it. The key carries a digest of the project
    # scope, so a cross-project clash should be impossible; this is defence in depth against a
    # digest collision, or one name appearing twice within a project. Overwriting silently would
    # reassign one agent's COMPLIANCE#/EVENT# history to another.
    claimed: dict = {}

    arm_token = _entra_token(tenant_id, client_id, client_secret, scope=ARM_SCOPE)
    data_token = _entra_token(tenant_id, client_id, client_secret, scope=FOUNDRY_SCOPE)

    try:
        subscriptions = _arm_list_subscriptions(arm_token)
    except AzureDenied:
        _CONNECTOR_WARNINGS.append(
            'Microsoft Foundry: the app registration cannot list subscriptions. Grant it '
            'at least Reader on the subscriptions you want discovered.'
        )
        return [], coverage
    if not subscriptions:
        _CONNECTOR_WARNINGS.append(
            'Microsoft Foundry: no subscriptions are visible to the app registration.'
        )
        return [], coverage

    for sub in subscriptions:
        try:
            accounts = _arm_list_foundry_accounts(arm_token, sub['id'], sub.get('name', ''))
        except (AzureDenied, AzureThrottled) as e:
            _CONNECTOR_WARNINGS.append(
                f"Microsoft Foundry: could not list Foundry accounts in subscription "
                f"{sub.get('name') or sub['id']}: {e}"
            )
            continue

        for account in accounts:
            try:
                projects = _arm_list_projects(arm_token, account)
            except (AzureDenied, AzureThrottled) as e:
                _CONNECTOR_WARNINGS.append(
                    f"Microsoft Foundry: could not list projects in account "
                    f"{account['name']}: {e}"
                )
                continue

            for project in projects:
                key = _foundry_project_key(account['name'], project)
                endpoint = f"{account['endpointBase']}/api/projects/{project}"
                project_agents: list = []
                outcome = 'ok'
                for kind, runtime_label in FOUNDRY_AGENT_KINDS:
                    try:
                        raw = _foundry_list_agents(endpoint, data_token, kind)
                    except AzureDenied:
                        # The whole project is unreadable. Stop trying the other kind: a partial
                        # read of one project is still unknown.
                        outcome = 'denied'
                        break
                    except AzureThrottled:
                        outcome = 'throttled'
                        break
                    for src in raw:
                        record = _normalize_foundry_agent(
                            src, kind, runtime_label, account, project)
                        if record:
                            project_agents.append(record)

                coverage[key] = outcome
                if outcome == 'ok':
                    for record in project_agents:
                        prior = claimed.get(record['agentId'])
                        if prior and prior != key:
                            # Same agent name in two projects: keep the first and report it, since
                            # overwriting moves one agent's history onto another and dropping it
                            # silently hides an agent from governance.
                            _CONNECTOR_WARNINGS.append(
                                f"Microsoft Foundry: agent name '{record['agentId']}' exists in "
                                f"both {prior} and {key}; only the first is registered. Rename "
                                f"one agent, or the two cannot be governed separately."
                            )
                            logger.warning(
                                'Foundry agentId collision %s: %s vs %s',
                                record['agentId'], prior, key)
                            continue
                        claimed[record['agentId']] = key
                        agents.append(record)
                else:
                    # Discard a partial project's agents: upserting some while the project counts
                    # as unknown is a half-truth, and they are re-read on the next clean sweep.
                    logger.warning('Foundry project %s: %s', key, outcome)

    return agents, coverage


def _coverage_summary(coverage: dict) -> str:
    """One-line coverage string for the connector row, e.g.
    '14 projects swept, 2 denied: acct/proj-a, acct/proj-b'.

    From an agent count alone, a sync that read 2 of 50 projects and one that read all 50 both
    look like success.
    """
    ok = sorted(k for k, v in coverage.items() if v == 'ok')
    bad = sorted(k for k, v in coverage.items() if v != 'ok')
    summary = f'{len(ok)} project(s) synced'
    if bad:
        shown = ', '.join(bad[:5]) + (' …' if len(bad) > 5 else '')
        summary += f', {len(bad)} unreadable: {shown}'
    return summary


def discover_microsoft(config: dict) -> list:
    """Discover every Foundry agent an Azure tenant exposes to this service principal.

    Returns [] and records a warning when the connector is unconfigured or disabled, so a
    default deploy stays quiet.
    """
    cfg = config or load_connector_config('microsoft')
    if not cfg or not cfg.get('secretArn'):
        _CONNECTOR_WARNINGS.append(
            'Microsoft Foundry is not configured. Add the connector in Settings to discover agents.'
        )
        return []
    if not cfg.get('enabled', True):
        logger.info('Microsoft Foundry connector is disabled; skipping')
        return []
    if not (cfg.get('tenantId') and cfg.get('clientId')):
        _CONNECTOR_WARNINGS.append(
            'Microsoft Foundry config is incomplete (needs tenant ID and client ID).'
        )
        return []
    if not _read_connector_secret('microsoft'):
        _CONNECTOR_WARNINGS.append(
            'Microsoft Foundry credential is missing from Secrets Manager. Re-enter the client secret.'
        )
        return []

    try:
        agents, coverage = sweep_foundry_tenant(cfg)
    except Exception as e:
        # Sign-in failure, or anything the per-scope handling above did not absorb.
        _CONNECTOR_WARNINGS.append(f'Microsoft Foundry sweep failed: {e}')
        _record_sync_outcome('microsoft', 'error', str(e), '')
        return []

    # Hand the coverage map to run_discovery so inactivation is scoped to the readable projects.
    # Module-level rather than a return value because the CONNECTORS dispatch table types every
    # connector as `config -> list`.
    _FOUNDRY_COVERAGE.clear()
    _FOUNDRY_COVERAGE.update(coverage)

    summary = _coverage_summary(coverage)
    logger.info('Microsoft Foundry: %d agent(s); %s', len(agents), summary)
    # Status must reflect coverage, not just whether an exception surfaced: a per-project denial
    # is recorded in `coverage` without raising a warning, so keying status off warnings alone
    # would report a partial sweep as a clean 'ok'.
    unreadable = [k for k, v in coverage.items() if v != 'ok']
    status = 'partial' if (_CONNECTOR_WARNINGS or unreadable) else 'ok'
    readable = [k for k, v in coverage.items() if v == 'ok']
    _record_sync_outcome(
        'microsoft',
        status,
        _CONNECTOR_WARNINGS[0] if _CONNECTOR_WARNINGS else '',
        summary,
        details={
            'tenantId': cfg.get('tenantId', ''),
            'clientId': cfg.get('clientId', ''),
            # Distinct counts rather than one "projects" number: a single figure cannot express
            # "found 14, read 12".
            'subscriptionsVisible': len({
                (a.get('platformMetadata') or {}).get('subscriptionId', '') for a in agents
            } - {''}) or None,
            'foundryAccounts': len({k.split('/')[0] for k in coverage}) or None,
            'projectsFound': len(coverage),
            'projectsRead': len(readable),
            'projectsUnreadable': len(unreadable),
            'unreadableProjects': unreadable,
            'agentsDiscovered': len(agents),
            'agentKinds': [label for _kind, label in FOUNDRY_AGENT_KINDS],
        },
    )
    return agents


# ═══════════════════════════════════════════════════════════════
# Okta Secure AI connector
# ═══════════════════════════════════════════════════════════════

OKTA_SIMULATED_AGENTS = [
    {"platformAgentId": "okta-identity-governance", "name": "Identity Governance Agent", "category": "Security", "status": "active", "requests": 9800, "errors": 5, "avgResponseMs": 95, "utilization": 92, "monthlyCost": 450, "costPerInvocation": 0.0003, "owner": "IAM Team"},
    {"platformAgentId": "okta-threat-detector", "name": "Agent Threat Detector", "category": "Security", "status": "active", "requests": 22000, "errors": 18, "avgResponseMs": 42, "utilization": 96, "monthlyCost": 680, "costPerInvocation": 0.0001, "owner": "SOC"},
]

def discover_okta(config: dict) -> list:
    """Return the simulated Okta agent list.

    A real implementation would call the Okta Admin API and Secure AI endpoints.
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
            # `system` names the platform; `runtime` is the execution surface the UI filters on.
            'runtime': 'External API',
            'source': 'external-connector',
            # As with every connector, a discovered agent enters pending-review whatever the
            # source platform calls it: the fixtures say 'active', which would let a demo agent
            # skip the review gate the real ones go through.
            'status': 'pending-review',
            'platformStatus': src['status'],
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
    """Return the simulated MuleSoft agent list.

    A real implementation would call the MuleSoft Anypoint Platform API.
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
            # `system` names the platform; `runtime` is the execution surface the UI filters on.
            'runtime': 'External API',
            'source': 'external-connector',
            # As with every connector, a discovered agent enters pending-review whatever the
            # source platform calls it: the fixtures say 'active', which would let a demo agent
            # skip the review gate the real ones go through.
            'status': 'pending-review',
            'platformStatus': src['status'],
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
# Native AWS connector - Amazon Bedrock Agents + AgentCore runtimes
# ═══════════════════════════════════════════════════════════════

def discover_native(config: dict) -> list:
    """Discover agents running natively in this AWS account: AgentCore harnesses, AgentCore
    runtimes and any Bedrock Agents Classic agents.

    Inactive unless NATIVE_DISCOVERY_ENABLED is true; by default the AgentCore
    discovery-scanner owns native discovery and run_discovery skips this connector.

    Best-effort: a missing API or permission for one source does not abort the others.

    Bedrock Agents Classic is in maintenance mode (CreateAgent is blocked for accounts without
    prior usage), but existing agents keep working and the read APIs stay open to everyone, so a
    customer's Classic fleet still has to be discoverable: this is a governance plane, and it
    reports what exists rather than only what is current.
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
                    # The agent name rather than a prefixed id, matching the scanner's keying so
                    # the two discoverers never create duplicate rows for one agent, and keeping
                    # /agents/{agentId}/... URLs free of ':' and '/'.
                    'agentId': _clean_native_id(agent_name, agent_id),
                    'name': agent_name,
                    'platform': 'native',
                    'platformAgentId': agent_id,
                    'category': 'AWS Native',
                    'system': 'Amazon Bedrock Agents',
                    # Execution surface, shown in the registry's Runtime column. The connector
                    # must report it or the column renders empty.
                    'runtime': 'Bedrock Agent Classic',
                    # 'pending-review' is a valid entry state in the data-handler lifecycle
                    # machine, so an operator can move the agent on from the UI.
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

    # Bedrock AgentCore harnesses: the managed agent loop (model + prompt + tools declared as
    # configuration) that AgentCore runs for you.
    #
    # Enumerated before runtimes because AgentCore implements a harness as a runtime, so the same
    # logical agent is returned by both ListHarnesses and ListAgentRuntimes. Each harness's
    # backing runtime name is recorded here and skipped in the runtime pass below, or one agent
    # registers twice under two different names.
    harness_runtime_names = set()
    try:
        agentcore = boto3.client('bedrock-agentcore-control')
        harnesses = agentcore.list_harnesses().get('harnesses', [])
        for h in harnesses:
            h_id = h.get('harnessId', h.get('harnessName', ''))
            h_name = h.get('harnessName', h_id)
            # AgentCore names the backing runtime `harness_<harnessName>`.
            harness_runtime_names.add(f"harness_{h_name}")
            agents.append({
                'agentId': _clean_native_id(h_name, h_id),
                'name': h_name,
                'platform': 'native',
                'platformAgentId': h_id,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'runtime': 'AgentCore Harness',
                'status': 'pending-review',
                **demo_metrics(h_id),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {
                    'source': 'bedrock-agentcore-harness',
                    'status': h.get('status', ''),
                    'updatedAt': str(h.get('updatedAt', '')),
                },
            })
        logger.info(f"Native: found {len(harnesses)} AgentCore harness(es)")
    except Exception as e:
        # ListHarnesses needs a recent SDK and a region where harnesses are available.
        logger.info(f"Native AgentCore harness discovery skipped: {e}")

    # Bedrock AgentCore runtimes (containerized / direct-code agents), excluding
    # the runtimes that merely back a harness discovered above.
    try:
        agentcore = boto3.client('bedrock-agentcore-control')
        resp = agentcore.list_agent_runtimes()
        skipped = 0
        for rt in resp.get('agentRuntimes', []):
            rt_id = rt.get('agentRuntimeId', rt.get('agentRuntimeName', ''))
            rt_name = rt.get('agentRuntimeName', rt_id)
            if rt_name in harness_runtime_names:
                skipped += 1
                continue
            agents.append({
                'agentId': _clean_native_id(rt_name, rt_id),
                'name': rt_name,
                'platform': 'native',
                'platformAgentId': rt_id,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'runtime': 'AgentCore Runtime',
                'status': 'pending-review',
                **demo_metrics(rt_id),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {'source': 'bedrock-agentcore', 'status': rt.get('status', ''),
                                     'accountId': _own_account_id(),
                                     'region': os.environ.get('AWS_REGION', '')},
            })
        logger.info(
            f"Native: found {len(resp.get('agentRuntimes', []))} AgentCore runtime(s), "
            f"{skipped} skipped as harness-backing"
        )
    except Exception as e:
        logger.info(f"Native AgentCore runtime discovery skipped: {e}")

    # Per-surface counts: a single total hides which inventory the agents came from, and hides a
    # surface returning nothing (a missing permission, a region without harnesses).
    by_surface: dict = {}
    for a in agents:
        by_surface[a.get('runtime', 'unknown')] = by_surface.get(a.get('runtime', 'unknown'), 0) + 1
    _record_sync_outcome(
        'native',
        'partial' if _CONNECTOR_WARNINGS else 'ok',
        _CONNECTOR_WARNINGS[0] if _CONNECTOR_WARNINGS else '',
        f'{len(agents)} agent(s) in this account',
        details={
            'accountId': _own_account_id(),
            'region': os.environ.get('AWS_REGION', ''),
            'surfacesScanned': ['AgentCore Harness', 'AgentCore Runtime', 'Bedrock Agent Classic'],
            'agentCoreHarnesses': by_surface.get('AgentCore Harness', 0),
            'agentCoreRuntimes': by_surface.get('AgentCore Runtime', 0),
            'bedrockAgentsClassic': by_surface.get('Bedrock Agent Classic', 0),
            'agentsDiscovered': len(agents),
            'discoveryOwner': 'discovery-handler Lambda (no LLM enrichment)',
        },
    )
    return agents


def _own_account_id() -> str:
    """This Lambda's account id, for display. '' on failure: telemetry must never break a run."""
    try:
        return boto3.client('sts').get_caller_identity()['Account']
    except Exception:
        return ''


# ═══════════════════════════════════════════════════════════════
# AWS Organization connector (cross-account) - simulated fallback
# ═══════════════════════════════════════════════════════════════
#
# The real cross-account path is _discover_aws_org_real below. This fixture list is the fallback
# used when org discovery is disabled and seedSampleData is on, so the cross-account data model
# can be demonstrated without an AWS Organization. Capped at one member account.
#
# The agentId carries accountId and region so identically-named agents in different accounts do
# not collide: native:<accountId>:<region>:harness:<id>.
ORG_SIMULATED_ACCOUNTS = [
    {"accountId": "111111111111", "accountName": "Production", "region": "us-east-1", "agents": [
        {"platformAgentId": "prod-order-orchestrator", "name": "Order Orchestrator", "category": "Customer Operations", "status": "active", "requests": 18400, "errors": 12, "avgResponseMs": 120, "utilization": 93, "monthlyCost": 1180, "costPerInvocation": 0.0006, "owner": "Customer BU"},
        {"platformAgentId": "prod-fraud-screener", "name": "Fraud Screener", "category": "Finance & Trading", "status": "active", "requests": 9200, "errors": 7, "avgResponseMs": 210, "utilization": 81, "monthlyCost": 760, "costPerInvocation": 0.0011, "owner": "Finance BU"},
    ]},
]


def discover_aws_org(config: dict) -> list:
    """Cross-account discovery, real or simulated.

    With ORG_DISCOVERY_ENABLED, runs the real scan: organizations:ListAccounts from the management
    or delegated-admin account, then sts:AssumeRole into a read-only role in each member account
    and list_agents per enabled region. When disabled, returns simulated agents only under
    seedSampleData, so invented agents never land in a catalog a customer trusts.
    """
    if ORG_DISCOVERY_ENABLED:
        return _discover_aws_org_real()
    if not SEED_SAMPLE_DATA:
        _record_sync_outcome('aws-org', 'skipped', '', 'Cross-account discovery is disabled',
                             details={
                                 'reason': 'enableOrgDiscovery is false, and the simulated fallback is gated behind seedSampleData.',
                                 'enableWith': '-c enableOrgDiscovery=true',
                             })
        return []

    agents = []
    for acct in ORG_SIMULATED_ACCOUNTS:
        for src in acct['agents']:
            agents.append({
                'agentId': f"native:{acct['accountId']}:{acct['region']}:harness:{src['platformAgentId']}",
                'name': src['name'],
                'platform': 'aws-org',
                'platformAgentId': src['platformAgentId'],
                'accountId': acct['accountId'],
                'accountName': acct['accountName'],
                'accountLabel': acct['accountName'],
                'region': acct['region'],
                'category': src['category'],
                'system': 'Amazon Bedrock AgentCore',
                # A member account would be building on AgentCore rather than Classic, whose
                # CreateAgent is closed to accounts without prior usage.
                'runtime': 'AgentCore Harness',
                'source': 'external-connector',
            # As with every connector, a discovered agent enters pending-review whatever the
            # source platform calls it: the fixtures say 'active', which would let a demo agent
            # skip the review gate the real ones go through.
            'status': 'pending-review',
            'platformStatus': src['status'],
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
                    'accountLabel': acct['accountName'],
                    'region': acct['region'],
                },
            })
    return agents


def _org_account_map() -> dict:
    """Return {accountId: accountName} for ACTIVE accounts in the organization.

    organizations:ListAccounts is only callable from the management account or a registered
    delegated-administrator account. NextToken can appear even on an empty page.
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

    Returns None and logs on failure, so one unreachable account never aborts the whole org scan:
    an invited account without OrganizationAccountAccessRole, or one that has not rolled out a
    scoped discovery role.
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
        # AccessDenied usually means the role is absent from that account or does not trust this
        # one: a non-enrolled account, or a wrong role name.
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
                # agentId carries accountId and region so identically-named agents in different
                # accounts never collide.
                found.append({
                    'agentId': f"native:{account_id}:{region}:bedrock-agent:{platform_agent_id}",
                    'name': a.get('agentName', platform_agent_id),
                    'platform': 'aws-org',
                    'platformAgentId': platform_agent_id,
                    'accountId': account_id,
                    'accountName': account_name,
                    'accountLabel': account_name,
                    'region': region,
                    'category': 'AWS Native',
                    'system': 'Amazon Bedrock Agents',
                    'runtime': 'Bedrock Agent Classic',
                    'source': 'external-connector',
                    'status': 'pending-review',
                    **platform_status_fields(a.get('agentStatus', '')),
                    **demo_metrics(f"{account_id}:{platform_agent_id}"),
                    'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                    'owner': '',
                    'platformMetadata': {
                        'source': 'aws-organizations',
                        'accountId': account_id,
                        'accountName': account_name,
                        'accountLabel': account_name,
                        'region': region,
                        'agentStatus': a.get('agentStatus', ''),
                    },
                })
    except Exception as e:
        logger.warning(f"Org discovery: list_agents failed in {account_id}/{region}: {type(e).__name__}: {e}")
    logger.info(f"Org discovery: {account_id}/{region} bedrock-agents found={len(found)}")
    return found


def _list_agentcore_harnesses_in(session, account_id: str, account_name: str, region: str):
    """List Bedrock AgentCore harnesses in one account+region via an assumed session.

    Returns (records, backing_runtime_names). The second value feeds the runtime lister so a
    harness is not also registered as its own backing runtime, as in discover_native().
    """
    found = []
    backing = set()
    try:
        client = session.client('bedrock-agentcore-control', region_name=region)
        for h in client.list_harnesses().get('harnesses', []):
            h_id = h.get('harnessId', h.get('harnessName', ''))
            h_name = h.get('harnessName', h_id)
            backing.add(f"harness_{h_name}")
            found.append({
                'agentId': f"native:{account_id}:{region}:harness:{h_id}",
                'name': h_name,
                'platform': 'aws-org',
                'platformAgentId': h_id,
                'accountId': account_id,
                'accountName': account_name,
                'accountLabel': account_name,
                'region': region,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'runtime': 'AgentCore Harness',
                'source': 'external-connector',
                'status': 'pending-review',
                **platform_status_fields(h.get('status', '')),
                **demo_metrics(f"{account_id}:{h_id}"),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {
                    'source': 'aws-organizations',
                    'accountId': account_id,
                    'accountName': account_name,
                    'accountLabel': account_name,
                    'region': region,
                    'status': h.get('status', ''),
                },
            })
    except Exception as e:
        # Harnesses are not available in every region; log and move on.
        logger.info(f"Org discovery: list_harnesses skipped in {account_id}/{region}: {e}")
    logger.info(f"Org discovery: {account_id}/{region} harnesses found={len(found)}")
    return found, backing


def _list_agentcore_runtimes_in(session, account_id: str, account_name: str, region: str,
                                skip_names=None) -> list:
    """List Bedrock AgentCore runtimes in one account+region via an assumed session.

    Cross-account discovery covers the same three surfaces as the single-account native
    connector. `skip_names` carries the harness-backing runtime names to exclude.
    """
    found = []
    skip_names = skip_names or set()
    skipped = 0
    try:
        client = session.client('bedrock-agentcore-control', region_name=region)
        resp = client.list_agent_runtimes()
        for rt in resp.get('agentRuntimes', resp.get('agentRuntimeSummaries', [])):
            rt_id = rt.get('agentRuntimeId', rt.get('agentRuntimeName', ''))
            rt_name = rt.get('agentRuntimeName', rt_id)
            if rt_name in skip_names:
                skipped += 1
                continue
            found.append({
                'agentId': f"native:{account_id}:{region}:agentcore:{rt_id}",
                'name': rt_name,
                'platform': 'aws-org',
                'platformAgentId': rt_id,
                'accountId': account_id,
                'accountName': account_name,
                'accountLabel': account_name,
                'region': region,
                'category': 'AWS Native',
                'system': 'Amazon Bedrock AgentCore',
                'runtime': 'AgentCore Runtime',
                'source': 'external-connector',
                'status': 'pending-review',
                **platform_status_fields(rt.get('status', '')),
                **demo_metrics(f"{account_id}:{rt_id}"),
                'score': 0, 'fairness': 0, 'transparency': 0, 'accountability': 0, 'ethics': 0,
                'owner': '',
                'platformMetadata': {
                    'source': 'aws-organizations',
                    'accountId': account_id,
                    'accountName': account_name,
                    'accountLabel': account_name,
                    'region': region,
                    'status': rt.get('status', ''),
                },
            })
    except Exception as e:
        # AgentCore is not available in every region; log and move on.
        logger.info(f"Org discovery: list_agent_runtimes skipped in {account_id}/{region}: {e}")
    logger.info(f"Org discovery: {account_id}/{region} runtimes found={len(found)}, "
                f"{skipped} skipped as harness-backing")
    return found


def _discover_aws_org_real() -> list:
    """Real cross-account discovery: enumerate the org, assume a role per member account, and list
    both Bedrock Agents and AgentCore runtimes across the configured regions.

    Runs from the management or delegated-admin account, and skips this Lambda's own account:
    those agents are covered by native discovery or the AgentCore scanner, so including them here
    would double-write them under a different native:<acct>:<region>:... key.
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
        # An operator can only fix this by moving the deployment, so say so on the tile rather
        # than leaving it silently empty.
        _record_sync_outcome('aws-org', 'error', msg, 'Cannot enumerate the organization',
                             details={
                                 'reason': 'organizations:ListAccounts was refused. Cross-account discovery must run from the organization management account or a delegated administrator.',
                                 'deployedInAccount': own_account,
                                 'assumedRole': ORG_DISCOVERY_ROLE_NAME,
                             })
        return []

    logger.info(f"Org discovery: own={own_account} accounts={list(account_map.keys())} "
                f"regions={ORG_DISCOVERY_REGIONS} role={ORG_DISCOVERY_ROLE_NAME}")
    agents = []
    scanned = 0
    unreachable: list = []
    scanned_accounts: set = set()
    for account_id, account_name in account_map.items():
        if account_id == own_account:
            continue  # covered by single-account native discovery
        session = _assume_discovery_session(account_id)
        if session is None:
            # Named, not just counted: "3 accounts skipped" is not actionable, whereas the account
            # ids point straight at the missing role.
            unreachable.append(f'{account_name or account_id} ({account_id})')
            continue
        scanned += 1
        scanned_accounts.add(account_id)
        for region in ORG_DISCOVERY_REGIONS:
            agents.extend(_list_bedrock_agents_in(session, account_id, account_name, region))
            # Harnesses first: their backing runtimes are then skipped below so one
            # logical agent is not registered twice.
            harnesses, backing = _list_agentcore_harnesses_in(
                session, account_id, account_name, region)
            agents.extend(harnesses)
            agents.extend(_list_agentcore_runtimes_in(
                session, account_id, account_name, region, skip_names=backing))
    logger.info(f"Org discovery: scanned {scanned} member account(s) across "
                f"{len(ORG_DISCOVERY_REGIONS)} region(s); found {len(agents)} agent(s)")

    # Hand the successfully-read accounts to run_discovery so inactivation is limited to them.
    # Cleared every run, so a stale set cannot authorize inactivation in an unreached account.
    _ORG_ACCOUNTS_READ.clear()
    _ORG_ACCOUNTS_READ.update(scanned_accounts)

    summary = f'{scanned} member account(s) scanned'
    if unreachable:
        summary += f', {len(unreachable)} unreachable'
    _record_sync_outcome(
        'aws-org',
        'partial' if (unreachable or _CONNECTOR_WARNINGS) else 'ok',
        _CONNECTOR_WARNINGS[0] if _CONNECTOR_WARNINGS else '',
        summary,
        details={
            'organizationId': _org_id(),
            'managementAccountId': own_account,
            'assumedRole': ORG_DISCOVERY_ROLE_NAME,
            'regionsScanned': list(ORG_DISCOVERY_REGIONS),
            # `accountsInOrg` counts the whole org; `accountsScanned` excludes this account
            # (covered by native discovery) and any that could not be assumed into. The gap
            # between the two is the operator's coverage question.
            'accountsInOrg': len(account_map),
            'accountsScanned': scanned,
            'accountsUnreachable': len(unreachable),
            'unreachableAccounts': unreachable,
            'agentsDiscovered': len(agents),
            'ownAccountExcluded': own_account,
        },
    )
    return agents


def _org_id() -> str:
    """The AWS Organization id, for display. '' when it cannot be read.

    DescribeOrganization is a separate permission from ListAccounts, so a role scoped only to the
    latter still discovers agents and simply shows no org id.
    """
    try:
        return boto3.client('organizations').describe_organization()['Organization']['Id']
    except Exception as e:
        logger.info(f'Org discovery: DescribeOrganization unavailable: {type(e).__name__}')
        return ''


# ═══════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════

CONNECTORS = {
    'native': discover_native,
    'aws-org': discover_aws_org,
    'microsoft': discover_microsoft,
    'okta': discover_okta,
    'mulesoft': discover_mulesoft,
}

# Connectors that read a real API and can therefore prove an agent is gone. Only these may
# inactivate rows: the simulated okta/mulesoft connectors re-return a fixed list every run, so
# absence there proves nothing.
AUTHORITATIVE_PLATFORMS = frozenset({'native', 'microsoft', 'aws-org'})


def _inactivate_missing(platform: str, seen_ids: set, scopes_read: set | None = None,
                        scope_field: str = 'projectKey') -> int:
    """Mark agents on `platform` that were absent from this scan as inactive.

    Only connectors reading a real API may call this (see AUTHORITATIVE_PLATFORMS), and only when
    the scan is known to have succeeded. A denied or throttled listing is indistinguishable from
    an empty one, so treating it as empty would inactivate a live fleet wholesale.

    `scopes_read` narrows authority to the scopes actually read this run, keyed by
    `platformMetadata[scope_field]`. For a tenant-wide sweep this is essential: a project the
    service principal could not read contributes no agents, so without the narrowing every one of
    its agents would look deleted. None means the caller asserts authority over the whole platform
    (single-scope connectors).

    Rows where a human has locked 'status', and rows already inactive, are skipped.
    """
    from boto3.dynamodb.conditions import Attr
    items = table.scan(FilterExpression=Attr('sk').eq('INFO')).get('Items', [])
    removed = 0
    for i in items:
        if i.get('platform') != platform:
            continue
        if scopes_read is not None:
            # `scope_field` differs per connector: Foundry scopes by project (`projectKey`), org
            # discovery by member account (`accountId`).
            scope = ((i.get('platformMetadata') or {}).get(scope_field)) or ''
            if scope not in scopes_read:
                # Either the scope was unreadable this run, or the row predates scope
                # tracking. Both mean the agent cannot be proven gone.
                continue
        if i['agentId'] in seen_ids:
            continue
        if i.get('status') == 'inactive':
            continue
        # Respect a human lock on status.
        if 'status' in (i.get('humanVerifiedFields') or []):
            logger.info(f"Skipping inactivation of {i['agentId']}: status is human-verified")
            continue
        # Clear the platform status as well as setting the governance one: the agent is gone from a
        # scope that was provably read, so leaving 'running' on the row would make the drift matrix
        # report "inactive but still serving traffic" for a deleted agent. 'not-found' is recorded
        # raw so the detail view can say why the status is unknown.
        table.update_item(
            Key={'agentId': i['agentId'], 'sk': 'INFO'},
            UpdateExpression=(
                'SET #s = :inactive, lastSyncedAt = :now, platformStatus = :pstatus, '
                'platformStatusRaw = :praw, platformStatusAt = :now'
            ),
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':inactive': 'inactive',
                ':now': NOW,
                ':pstatus': PLATFORM_STATUS_UNKNOWN,
                ':praw': 'not-found',
            },
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
        # Native discovery is ceded to the AgentCore scanner when it is deployed, so the two never
        # double-write native agents. An explicit `platforms=['native']` request still reports the
        # skip rather than doing nothing.
        if p == 'native' and not NATIVE_DISCOVERY_ENABLED:
            results.append({
                'platform': p,
                'skipped': 'native discovery is owned by the AgentCore discovery-scanner',
                'syncedAt': NOW,
            })
            # A tile that never runs still has to explain itself, or it reads as broken.
            _record_sync_outcome(p, 'skipped', '', 'Owned by the AgentCore discovery-scanner',
                                 details={
                                     'discoveryOwner': 'discovery-scanner (AgentCore runtime, with LLM enrichment)',
                                     'reason': 'This Lambda cedes native discovery to the scanner so the two never double-write the same agent.',
                                     'reEnableWith': '-c deployGovernanceAgents=false',
                                 })
            continue
        # Demo-only connectors stay out of a real catalog. Reported rather than silently absent, so
        # a per-connector Discover click explains itself instead of returning zero.
        if p in SIMULATED_CONNECTORS and not SEED_SAMPLE_DATA:
            results.append({
                'platform': p,
                'skipped': 'simulated connector; deploy with -c seedSampleData=true to load demo agents',
                'syncedAt': NOW,
            })
            _record_sync_outcome(p, 'skipped', '', 'Simulated connector, not enabled',
                                 details={
                                     'mode': 'simulated - returns hardcoded illustrative agents, no API call',
                                     'reason': 'Gated off so a real deployment never contains agents you do not have.',
                                     'enableWith': '-c seedSampleData=true',
                                 })
            continue
        # A connector needing operator-supplied credentials is inert until configured, and reported
        # as skipped rather than failed: unconfigured is the expected state on a default deploy.
        if p in CONFIGURABLE_CONNECTORS and not load_connector_config(p).get('secretArn'):
            results.append({
                'platform': p,
                'skipped': 'connector is not configured; add credentials in the FlowAMP UI',
                'syncedAt': NOW,
            })
            _record_sync_outcome(p, 'skipped', '', 'Not configured',
                                 details={
                                     'reason': 'No credentials stored. Configure the connector in the FlowAMP UI to start discovering.',
                                 })
            continue
        try:
            # Connector settings live on the platform sentinel row (credentials in
            # Secrets Manager); connectors that need none simply ignore an empty dict.
            _CONNECTOR_WARNINGS.clear()  # capture only this connector's warnings
            config = load_connector_config(p) if p in CONFIGURABLE_CONNECTORS else {}
            agents = CONNECTORS[p](config)
            updated = 0
            for agent in agents:
                upsert_agent(agent)
                updated += 1
            removed = 0
            # Inactivation needs an authoritative source and proof of what was read. For a
            # tenant-wide sweep, "the run had no warnings" is the wrong test: partial access is the
            # normal case, and one unreadable project out of fifty would freeze inactivation for the
            # whole estate. Foundry therefore narrows authority to the projects it read.
            if p == 'microsoft':
                scopes_read = {k for k, v in _FOUNDRY_COVERAGE.items() if v == 'ok'}
                if scopes_read:
                    seen = {a['agentId'] for a in agents}
                    removed = _inactivate_missing(p, seen, scopes_read=scopes_read)
            elif p == 'aws-org':
                # Scoped to the member accounts this run could assume into: a locked-out account must
                # never look like one whose agents were deleted.
                if _ORG_ACCOUNTS_READ:
                    seen = {a['agentId'] for a in agents}
                    removed = _inactivate_missing(p, seen,
                                                  scopes_read=set(_ORG_ACCOUNTS_READ),
                                                  scope_field='accountId')
            elif p in AUTHORITATIVE_PLATFORMS and agents and not _CONNECTOR_WARNINGS:
                # Single-scope connectors: a non-empty result proves the API answered, and no
                # warnings proves nothing was silently dropped.
                seen = {a['agentId'] for a in agents}
                removed = _inactivate_missing(p, seen)
            result = {
                'platform': p,
                'agentsDiscovered': len(agents),
                'agentsUpdated': updated,
                'agentsRemoved': removed,
                'syncedAt': NOW,
            }
            # Surface partial failures, e.g. unreachable org accounts, so the UI can warn instead of
            # silently reporting 0 discovered.
            if _CONNECTOR_WARNINGS:
                result['warnings'] = list(_CONNECTOR_WARNINGS)
            results.append(result)
            # Metadata only (counts and platform name), never full agent records or user-submitted
            # fields, which may contain sensitive data.
            logger.info(f"Discovered {len(agents)} agents from {p}, inactivated {removed}")
        except Exception as e:
            logger.error(f"Discovery failed for {p}: {e}")
            results.append({'platform': p, 'error': str(e), 'syncedAt': NOW})
    return results


def _test_connector(platform: str) -> dict:
    """Prove the stored credentials reach the tenant, and report how far they see.

    Runs the same sweep discovery does but writes nothing to the catalog, so an operator can tell
    "credentials wrong" from "no agents yet" from "only part of the estate is visible". Breadth
    (subscriptions, accounts, projects) is reported rather than a bare agent count, because 0
    agents across 14 projects and 0 agents because nothing was reachable look identical otherwise.
    """
    cfg = load_connector_config(platform)
    if not cfg.get('secretArn'):
        return {'ok': False, 'error': 'Connector is not configured.'}
    if not _read_connector_secret(platform):
        return {'ok': False, 'error': 'Stored credential could not be read from Secrets Manager.'}

    _CONNECTOR_WARNINGS.clear()
    try:
        agents, coverage = sweep_foundry_tenant(cfg)
    except Exception as e:
        return {'ok': False, 'error': str(e)}

    denied = sorted(k for k, v in coverage.items() if v != 'ok')
    accounts = {k.split('/')[0] for k in coverage}
    subscriptions = {
        (a.get('platformMetadata') or {}).get('subscriptionId', '') for a in agents
    }
    # A tenant can hold readable projects with no agents, in which case `agents` yields no
    # subscription ids. Falls back to "at least one" rather than reporting 0 subscriptions next to a
    # positive project count, which would read as a contradiction.
    sub_count = len({s for s in subscriptions if s}) or (1 if coverage else 0)

    result = {
        'ok': True,
        'subscriptions': sub_count,
        'accounts': len(accounts),
        'projects': len(coverage),
        'agentCount': len(agents),
        'denied': denied,
    }
    # `ok` means something was read, not merely that sign-in worked: finding projects and then being
    # refused by every one of them is a failed test, since the connector will discover nothing.
    if not any(v == 'ok' for v in coverage.values()):
        result['ok'] = False
        result['error'] = (
            _CONNECTOR_WARNINGS[0] if _CONNECTOR_WARNINGS else
            (f'Signed in and found {len(coverage)} project(s), but could not read any of '
             f'them. Check the app registration\'s Azure role assignment, and allow up to '
             f'~30 minutes for a new one to take effect.') if coverage else
            'Signed in, but no Foundry projects are visible to this app registration. '
            'Check its Azure role assignment, and allow up to ~30 minutes for a new one '
            'to take effect.'
        )
    return result


def _handle_connector_route(event: dict, http_method: str, path: str, headers: dict) -> dict:
    """Serve the connector-configuration API.

    The client secret is write-only: it arrives in a PUT body, goes straight to Secrets Manager, and
    no response echoes it (GET reports only `credentialSet: true/false`). The request body is never
    logged, since Lambda logs are readable by anyone with CloudWatch access.
    """
    platform = (event.get('pathParameters') or {}).get('platform', '')

    if http_method == 'GET':
        from boto3.dynamodb.conditions import Key
        try:
            rows = table.query(
                KeyConditionExpression=Key('agentId').eq(PLATFORM_SENTINEL_PK),
            ).get('Items', [])
        except Exception as e:
            logger.error(f'Connector list failed: {e}')
            return {'statusCode': 500, 'headers': headers,
                    'body': json.dumps({'error': 'Could not read connector config'})}
        configs = [
            redact_connector_config(r) for r in rows
            if str(r.get('sk', '')).startswith('PLATFORM#')
        ]
        return {'statusCode': 200, 'headers': headers,
                'body': json.dumps({'connectors': configs}, default=decimal_default)}

    if not platform:
        return {'statusCode': 400, 'headers': headers,
                'body': json.dumps({'error': 'Missing platform in path'})}
    if platform not in CONFIGURABLE_CONNECTORS:
        return {'statusCode': 400, 'headers': headers,
                'body': json.dumps({'error': f'Connector {platform} is not configurable'})}

    if http_method == 'POST' and path.rstrip('/').endswith('/test'):
        result = _test_connector(platform)
        # 200 even for a failed credential check: the request itself succeeded, and the UI needs the
        # message body to tell the operator what to fix.
        return {'statusCode': 200, 'headers': headers,
                'body': json.dumps(result, default=decimal_default)}

    if http_method == 'PUT':
        try:
            body = json.loads(event.get('body') or '{}')
        except json.JSONDecodeError:
            return {'statusCode': 400, 'headers': headers,
                    'body': json.dumps({'error': 'Body is not valid JSON'})}
        # No endpoint or project: the connector discovers those from the tenant itself.
        missing = [
            f for f in ('tenantId', 'clientId')
            if not (body.get(f) or '').strip()
        ]
        if missing:
            return {'statusCode': 400, 'headers': headers,
                    'body': json.dumps({'error': f"Missing required field(s): {', '.join(missing)}"})}
        # A first-time save must carry a secret; an edit may omit it to keep the stored one.
        if not body.get('clientSecret') and not load_connector_config(platform).get('secretArn'):
            return {'statusCode': 400, 'headers': headers,
                    'body': json.dumps({'error': 'clientSecret is required when first configuring a connector'})}
        try:
            stored = save_connector_config(platform, body)
        except Exception as e:
            # Log the exception type only: the message could contain the request payload.
            logger.error(f'Connector save failed for {platform}: {type(e).__name__}')
            return {'statusCode': 500, 'headers': headers,
                    'body': json.dumps({'error': 'Could not save connector config'})}
        return {'statusCode': 200, 'headers': headers,
                'body': json.dumps({'connector': stored}, default=decimal_default)}

    if http_method == 'DELETE':
        try:
            delete_connector_config(platform)
        except Exception as e:
            logger.error(f'Connector delete failed for {platform}: {type(e).__name__}')
            return {'statusCode': 500, 'headers': headers,
                    'body': json.dumps({'error': 'Could not delete connector config'})}
        return {'statusCode': 200, 'headers': headers, 'body': json.dumps({'deleted': True})}

    return {'statusCode': 405, 'headers': headers,
            'body': json.dumps({'error': f'{http_method} not supported on {path}'})}


def handler(event, context):
    """Invoked by:
      - EventBridge schedule (no body: sync all platforms)
      - API Gateway POST /discovery/sync (body.platforms: selective sync)
      - API Gateway GET /discovery/status (return last sync info)
    """
    # Async worker invocation, fire-and-forget from the API path below, so a multi-account org sync
    # is not bound by API Gateway's 29s limit. Payload: {"async_sync": true, "platforms": [...]|null}.
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
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    }

    if http_method == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    # ── Connector configuration ──
    # Checked before /sync and /status: '/discovery/connectors/{p}/test' is a POST that must not be
    # mistaken for a sync.
    if '/connectors' in path:
        return _handle_connector_route(event, http_method, path, headers)

    if http_method == 'POST' and '/sync' in path:
        body = json.loads(event.get('body', '{}') or '{}')
        platforms = body.get('platforms')  # None = all
        # Fire-and-forget: an org sync (assume plus list across many member accounts) can exceed API
        # Gateway's 29s limit and be cut off mid-scan. Invokes an async copy of this function and
        # returns 202; the UI polls the registry. Falls back to inline if the async invoke fails.
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
        # Counts per platform from DynamoDB (entity rows only, sk='INFO').
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
        # Demo connectors report 'available' when their data is gated off, so nothing claims an Okta
        # or MuleSoft integration that is not there.
        simulated_status = 'connected' if SEED_SAMPLE_DATA else 'available'
        # Foundry is a real connector, so its status reflects whether credentials are configured.
        foundry_status = (
            'connected' if load_connector_config('microsoft').get('secretArn') else 'available'
        )
        return {
            'statusCode': 200, 'headers': headers,
            'body': json.dumps([
                {'platform': 'native', 'name': 'AWS Bedrock Local Account', 'status': 'connected'},
                {'platform': 'aws-org', 'name': 'AWS Organization (cross-account)', 'status': 'connected'},
                {'platform': 'microsoft', 'name': 'Microsoft Foundry', 'status': foundry_status},
                {'platform': 'okta', 'name': 'Okta Secure AI', 'status': simulated_status},
                {'platform': 'mulesoft', 'name': 'MuleSoft Agent Fabric', 'status': simulated_status},
            ])
        }

    return {'statusCode': 404, 'headers': headers, 'body': json.dumps({'error': 'Not found'})}
