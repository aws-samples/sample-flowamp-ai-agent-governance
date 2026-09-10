# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Discovery Scanner - Strands agent that discovers this account's agents and maintains
the Agent Catalog.

Covers the three native execution surfaces: AgentCore harnesses, AgentCore runtimes and
Bedrock Agents Classic. Cross-account discovery belongs to the discovery-handler Lambda,
which assumes a role per member account and skips this one.

Must stay an AgentCore Runtime rather than a harness: it runs custom Python tools, writes
to DynamoDB and calls control-plane APIs, and a harness executes no code of its own (it
supplies only a model, a prompt and tool declarations).

Single-table data model: agent, audit, work-item and compliance rows share the AgentTable
named by ``AGENT_TABLE_NAME``, separated by sk prefix (INFO / EVENT# / REVIEW# /
COMPLIANCE# / MODEL#). ``list_active_agents`` (``flowamp_tools.agent_catalog``) Scans it
with a ``sk='INFO'`` FilterExpression; the table has no GSI.
"""
# ---------------------------------------------------------------------------
# OTEL bootstrap - must run before any other import (boto3, strands, etc.).
#
# Spans export only under `opentelemetry-instrument`, which reads the
# OTEL_*/AGENT_OBSERVABILITY_ENABLED env vars and installs the global TracerProvider
# plus the OTLP exporter wired to aws/spans. Direct-code deploy launches a bare
# `python main.py`, so this module re-execs itself under the auto-instrumentation
# entry point; _OTEL_REEXEC makes that one-shot and any failure is swallowed so a
# missing wrapper never crashes the scanner.
# Docs: bedrock-agentcore/observability-configure, "Enabling observability in
# agent code for AgentCore-hosted agents".
import os as _os
import sys as _sys

if (
    _os.environ.get("AGENT_OBSERVABILITY_ENABLED") == "true"
    and not _os.environ.get("_OTEL_REEXEC")
):
    _os.environ["_OTEL_REEXEC"] = "1"
    # Call auto_instrumentation.run() rather than the `opentelemetry-instrument` console
    # script: `uv pip install --target` puts that script in <bundle>/bin, off the runtime
    # PATH, with a shebang pointing at the build machine's Python. run() sets up
    # PYTHONPATH (loading the ADOT sitecustomize) and re-execs `python main.py`
    # instrumented.
    _bundle_dir = _os.path.dirname(_os.path.abspath(__file__))
    # Let the re-exec'd `python -c` process import the vendored ADOT modules
    # regardless of the runtime's CWD.
    _os.environ["PYTHONPATH"] = (
        _bundle_dir + _os.pathsep + _os.environ.get("PYTHONPATH", "")
    ).rstrip(_os.pathsep)
    try:
        # Safe: the exec target and argv are the process's own values (sys.executable,
        # sys.argv), so no external input reaches this call.
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
        # Auto-instrumentation unavailable (e.g. local dev without ADOT vendored):
        # continue uninstrumented rather than crash.
        print(f"otel auto-instrument re-exec skipped: {_reexec_exc}")

import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from strands import Agent, tool
from strands.models.bedrock import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# Enable AgentCore Evaluations tracing: the OpenInference span processor translates
# Strands' native OTEL spans into the GenAI semantic conventions Evaluations reads.
#
# Do not call StrandsTelemetry(): it calls set_tracer_provider() with an exporter-less
# provider and OTEL is first-caller-wins, so it would take precedence over AgentCore's
# ADOT provider (the one wired to aws/spans). Attach to the existing global provider
# instead, and do it lazily on first invoke (_ensure_otel_processor): on launch paths
# where the re-exec above was skipped, get_tracer_provider() returns a
# ProxyTracerProvider, which has no add_span_processor.
_otel_processor_attached = False


def _ensure_otel_processor():
    """Attach the OpenInference span processor to the runtime's global TracerProvider.

    Idempotent; called on first invoke (not at import) so AgentCore's ADOT provider is
    already installed. Guarded so any resolution/timing issue never breaks the scan.
    """
    global _otel_processor_attached
    if _otel_processor_attached:
        return
    try:
        from opentelemetry.trace import get_tracer_provider
        from openinference.instrumentation.strands_agents import StrandsAgentsToOpenInferenceProcessor
        provider = get_tracer_provider()
        if hasattr(provider, 'add_span_processor'):
            provider.add_span_processor(StrandsAgentsToOpenInferenceProcessor())
            _otel_processor_attached = True
            logger.info("otel: OpenInference span processor attached to runtime TracerProvider")
        else:
            logger.warning("otel: global TracerProvider still has no add_span_processor at invoke "
                           "(type=%s) — spans will not be transformed", type(provider).__name__)
    except Exception as exc:  # noqa: BLE001
        logger.warning("otel processor attach skipped: %s", exc)

from flowamp_tools import (
    log_agent_decision,
    log_decision_trace,
    log_lifecycle_change,
    invoke_agent,
    close_assigned_work_item,
    add_work_item_note,
    add_work_item_task,
    update_work_item_task,
    update_work_item_info,
    list_active_agents as _list_active_agents,
)
from flowamp_tools.config import get_model_config

logging.basicConfig(level=logging.INFO, force=True)
logger = logging.getLogger(__name__)

_region = os.environ.get('AWS_REGION', 'us-west-2')
# Single-table data model: audit, work-item, AOP, and compliance data share one
# physical table, so every direct DDB access below uses AGENT_TABLE_NAME.
_agent_table_name = os.environ.get('AGENT_TABLE_NAME', '')
_agent_id = os.environ.get('FLOWAMP_AGENT_ID', 'flowamp_discovery_scanner_dev')
_ssm_namespace = os.environ.get('SSM_NAMESPACE', 'flowamp')
_environment = os.environ.get('ENVIRONMENT', 'dev')
_ENRICHMENT_FIELDS = ('capabilities', 'category', 'riskTier', 'suggestedOwner')
_BACKOFF_CAP = 30.0
_BACKOFF_BASE = 1.0

# Canonical platformId (FLOWAMP_PLATFORMS sentinel id) for Amazon Bedrock AgentCore.
# Every runtime returned by list_agent_runtimes is stamped with this value. The env
# var lets operators swap the id; the default mirrors scripts/seed_sentinels.py.
_BEDROCK_PLATFORM_ID = os.environ.get(
    'AMAZON_BEDROCK_AGENTCORE_PLATFORM_ID',
    'amazon-bedrock-agentcore',
)

# Baseline framework auto-assigned to every newly discovered agent; mirrors the
# FLOWAMP_BASELINE row seeded into the AgentTable. agent_compliance_service.
# add_agent_framework writes the same COMPLIANCE# row, so there are two write paths.
_BASELINE_FRAMEWORK_ID = 'FLOWAMP_BASELINE'

# ---------------------------------------------------------------------------
# Singleton scan state, held at module scope across the three stages of a scan (see
# THREE-STAGE DISCOVERY PIPELINE below). It lives for the life of the runtime container
# and resets on cold start. This is the guardrail surface: all agent metadata flows
# through these tools, and the LLM never writes to DynamoDB directly.
# ---------------------------------------------------------------------------
_scan_state: dict = {
    'records': {},          # agentId -> working record (see schema below)
    'inactivate': [],       # catalog rows missing from the live scan. Only
                            # Bedrock-platform rows qualify: the scanner owns
                            # Bedrock lifecycle only.
    'stamp_invocable_false': [],  # non-Bedrock catalog rows whose invocable flag
                                  # must be false so the UI and agent tools do
                                  # not try to invoke them.
    'started_at': '',
    'completed_scan': False,
    'work_item_id': '',     # captured in start_discovery_scan and reused by
                            # commit, so the LLM passes it only once
}

# A working record (one entry in _scan_state['records']) carries: agentId / runtimeId
# (canonical id and ARN, immutable); name / description / runtimeVersion / costCenter
# from AgentCore at scan time; _action ('add' | 'enrich' | 'refresh'); _existed_before,
# _existing (snapshot of the existing INFO row) and _humanVerified (fields the portal
# locked); and the LLM-filled enrichment slots displayName / category / riskTier /
# capabilities / suggestedOwner.

# Fields the agent may not mutate via set_enrichment_fields: either AgentTable key
# attributes, or lifecycle/audit fields only a human or a lifecycle hook may set.
_IMMUTABLE_FIELDS = frozenset({
    'agentId', 'runtimeId', 'discoveredAt', 'status', 'lifecycleStatus',
    'humanVerifiedFields', 'aiInferred',
})

# Fields the agent may set on the in-memory record. Anything outside this set is
# rejected by set_enrichment_fields.
_ENRICHABLE_FIELDS = frozenset({
    'displayName', 'category', 'riskTier', 'capabilities', 'suggestedOwner',
    'description', 'invocable',
})

# Fallback category ids, used only when the FLOWAMP_CATEGORIES sentinel row is
# unreadable (e.g. unit tests where it has not been seeded). The sentinel is the
# source of truth; set_enrichment_fields prefers whatever it returns.
_FALLBACK_CATEGORY_IDS = frozenset({
    'grid-ops', 'safety', 'finance', 'asset-mgmt',
    'trading', 'platform', 'customer-ops', 'other',
})

# Cached sentinel response: entries are the dicts from
# AgentTable[FLOWAMP_CATEGORIES][CONFIG].categories, typically {id, name, icon?,
# color?}. Populated lazily by get_agent_categories.
_categories_cache: list[dict] | None = None

_VALID_RISK_TIERS = frozenset({'low', 'medium', 'high', 'critical'})


def _read_categories_sentinel() -> list[dict]:
    """Read the FLOWAMP_CATEGORIES sentinel row. Returns [] on any failure
    so callers can fall back to the hardcoded list."""
    try:
        dynamodb = boto3.resource('dynamodb', region_name=_region)
        table = dynamodb.Table(_agent_table_name)
        item = table.get_item(
            Key={'agentId': 'FLOWAMP_CATEGORIES', 'sk': 'CONFIG'},
        ).get('Item') or {}
        cats = item.get('categories') or []
        return [c for c in cats if isinstance(c, dict) and c.get('id')]
    except Exception:
        logger.warning('Unable to read FLOWAMP_CATEGORIES sentinel')
        return []


def _valid_category_ids() -> frozenset[str]:
    """Return the accepted category ids: sentinel first, hardcoded fallback second.

    Caches the sentinel read so later set_enrichment_fields calls cost nothing."""
    global _categories_cache
    if _categories_cache is None:
        _categories_cache = _read_categories_sentinel()
    if _categories_cache:
        return frozenset(c['id'] for c in _categories_cache)
    return _FALLBACK_CATEGORY_IDS

# Tokens stripped when deriving a human-friendly displayName from a raw runtime
# name: title-case nouns, no env suffix, no trailing '_runtime'/'_lambda'/etc.
_NAMING_STRIP_TOKENS = ('runtime', 'lambda', 'function', 'service', 'agent')
_NAMING_ENV_SUFFIXES = ('-dev', '-prod', '-staging', '-test', '_dev', '_prod', '_staging', '_test')


def _jitter_delay(base: float, attempt: int, cap: float = _BACKOFF_CAP) -> float:
    """Return jittered exponential backoff delay. Returns actual sleep duration."""
    delay = min(cap, base * (2 ** attempt)) * random.uniform(0.5, 1.0)
    time.sleep(delay)
    return delay

_GENERIC_NAME_TOKENS = {'agent', 'runtime', 'service', 'lambda', 'function', 'dev', 'prod', 'staging'}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


_AGENTCORE_RUNTIME_SUFFIX_RE = re.compile(r'-[A-Za-z0-9]{10}$')

# Execution surfaces this scanner can discover. The registry renders the stored
# string verbatim, so these must match the vocabulary the rest of the platform emits
# (discovery-handler, the UI's registration dropdown).
_CLASSIC_RUNTIME_LABEL = 'Bedrock Agent Classic'
_RUNTIME_LABELS = ('AgentCore Harness', 'AgentCore Runtime', _CLASSIC_RUNTIME_LABEL)

# The `system` string stored alongside each runtime label. The registry groups on
# this field, and Classic agents live in the separate Bedrock Agents inventory, so a
# Classic agent must not be labelled AgentCore.
_SYSTEM_BY_RUNTIME_LABEL = {
    'AgentCore Harness': 'Amazon Bedrock AgentCore',
    'AgentCore Runtime': 'Amazon Bedrock AgentCore',
    _CLASSIC_RUNTIME_LABEL: 'Amazon Bedrock Agents',
}

# Per-scan health of the best-effort inventory passes in list_agent_runtimes.
# `classic_ok` goes False when bedrock-agent:ListAgents failed, which suppresses
# inactivation of Classic rows: an errored listing is indistinguishable from an
# empty one, and treating it as empty would inactivate a live fleet.
_scan_health = {'classic_ok': True}

# ── Normalised platform status ────────────────────────────────────────────────
# Each execution surface reports run state in its own vocabulary, and the registry shows
# it next to one governance lifecycle. The raw value is stored verbatim in
# `platformStatusRaw` and mapped onto these buckets for display and drift detection.
# Transitional values (CREATING / UPDATING / PREPARING / VERSIONING) are left unmapped and
# fall through to 'unknown': they are neither running nor stopped, and forcing them into
# either bucket would make the drift matrix fire on every ordinary deploy.
#
# This map is duplicated in assetsSrc/lambda/discovery-handler/index.py. The two asset
# directories are packaged separately and cannot import from each other, so a change here
# needs the same change there. Foundry's `enabled`/`disabled` exist only in that copy,
# since this scanner never sees a Foundry agent.
_PLATFORM_STATUS_UNKNOWN = 'unknown'
_PLATFORM_STATUS_BY_RAW = {
    # AgentCore Runtime `status`: CREATING, CREATE_FAILED, UPDATING, UPDATE_FAILED,
    # READY, DELETING. Harness `status` is the same set plus DELETE_FAILED.
    'READY': 'running',
    'CREATE_FAILED': 'failed',
    'UPDATE_FAILED': 'failed',
    'DELETE_FAILED': 'failed',
    'DELETING': 'stopped',
    # Bedrock Agents Classic `agentStatus`: CREATING, PREPARING, PREPARED, NOT_PREPARED,
    # FAILED, UPDATING, DELETING. NOT_PREPARED is a real stopped state, not a transitional
    # one: the agent exists but no version has been prepared, so it cannot serve traffic.
    'PREPARED': 'running',
    'NOT_PREPARED': 'stopped',
    'FAILED': 'failed',
}


def _normalize_platform_status(raw: str) -> str:
    """Map a platform's own run-state string onto a FlowAMP platform-status bucket.

    Anything unrecognised, including the empty string, returns 'unknown'. The drift
    matrix treats 'unknown' as "no signal" rather than a finding, so a status newly
    added by AWS degrades to silence instead of a false alarm.
    """
    return _PLATFORM_STATUS_BY_RAW.get(str(raw or '').strip().upper(),
                                       _PLATFORM_STATUS_UNKNOWN)


def _is_agentcore_runtime_arn(arn: str) -> bool:
    """True for an AgentCore runtime ARN (arn:...:bedrock-agentcore:...:runtime/x).

    AgentCore control-plane calls (tagging, GetAgentRuntime) accept only these, so
    Bedrock Agents Classic ARNs (arn:...:bedrock:...:agent/x) must skip those calls
    rather than fail them once per agent per scan.
    """
    return ':runtime/' in (arn or '')


_account_context: dict | None = None


def _account_context_lookup() -> dict:
    """Resolve {partition, account} once per container, for ARN construction.

    sts:GetCallerIdentity needs no IAM permission and its caller ARN carries the
    partition, so constructed ARNs stay correct outside the commercial partition
    rather than hardcoding `aws`.
    """
    global _account_context
    if _account_context is None:
        ident = boto3.client('sts', region_name=_region).get_caller_identity()
        parts = (ident.get('Arn') or '').split(':')
        _account_context = {
            'partition': parts[1] if len(parts) > 2 and parts[1] else 'aws',
            'account': ident['Account'],
        }
    return _account_context


def _account_alias() -> str:
    """This account's IAM alias, or '' when none is set.

    The alias is the closest thing to an account name available from inside the account
    (organizations:DescribeAccount needs management-account permissions this runtime may
    not have). With no alias the registry shows the bare account id, as the console does.
    Errors are swallowed: a display label must never break a discovery commit.
    """
    try:
        aliases = boto3.client('iam', region_name=_region).list_account_aliases()
        return (aliases.get('AccountAliases') or [''])[0]
    except Exception:
        return ''


def _own_account_id() -> str:
    """This account's id for display, or '' if it cannot be resolved.

    Errors are swallowed because this only feeds the registry's Account column.
    `_account_context_lookup` raises instead, since ARN construction cannot proceed
    without the account id.
    """
    try:
        return _account_context_lookup().get('account', '')
    except Exception:
        return ''


def _classic_agent_arn(agent_id: str) -> str:
    """Build the ARN for a Bedrock Agents Classic agent from its agentId.

    ListAgents' AgentSummary carries no ARN field, so the ARN must be constructed.
    GetAgent would return a real `agentArn`, at the cost of one extra call per agent per
    scan for a fully determined value.
    """
    ctx = _account_context_lookup()
    return f"arn:{ctx['partition']}:bedrock:{_region}:{ctx['account']}:agent/{agent_id}"


def _runtime_id_from_arn(arn: str) -> str:
    """Extract the agentRuntimeId (the AWS-side identifier, including the
    AgentCore-appended 10-char suffix) from a runtime ARN.

    This is what ``bedrock-agentcore-control:GetAgentRuntime`` expects in its
    ``agentRuntimeId`` parameter. Passing the full ARN fails with AccessDenied,
    AWS's privacy-preserving "not found" response."""
    if not arn:
        return arn
    return arn.split(':runtime/', 1)[1] if ':runtime/' in arn else arn


def _agent_id_from_arn(arn: str) -> str:
    """Derive the AgentTable partition key (agentId) from a runtime ARN or ID.

    Runtime ARNs look like
    ``arn:aws:bedrock-agentcore:<region>:<account>:runtime/{runtimeName}-{10-char-suffix}``,
    where AWS appends the suffix for uniqueness across versions. AgentTable rows are keyed
    by the operator-chosen name instead, so agentIds survive redeploys (which regenerate
    the suffix) and URL paths like ``/agents/{agentId}/approve`` need no escaping of ``:``
    or ``/``. The full ARN stays on each row's ``runtimeId`` for InvokeAgentRuntime /
    GetAgentRuntime; inputs that do not match the runtime-ARN shape are returned unchanged.
    """
    if not arn:
        return arn
    runtime_id = arn.split(':runtime/', 1)[1] if ':runtime/' in arn else arn
    return _AGENTCORE_RUNTIME_SUFFIX_RE.sub('', runtime_id)


def _clean_agent_id(arn: str, name: str) -> str:
    """Return the agentId to use for an AgentTable row.

    Prefers ``name`` (``agentRuntimeName`` from the AgentCore API) when it is a clean
    identifier with no ``:`` or ``/``, meaning it is the operator-defined name rather than
    an ARN fragment, and so does not depend on suffix length or ARN shape. Falls back to
    ``_agent_id_from_arn`` for callers holding only an ARN.
    """
    if name and ':' not in name and '/' not in name:
        return name
    return _agent_id_from_arn(arn)


def _sanitize_for_ddb(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _sanitize_for_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_ddb(v) for v in obj]
    return obj


def _is_generic_name(name: str) -> bool:
    """Return True if the name looks like an auto-generated identifier rather than a human label."""
    parts = set(name.lower().replace('_', ' ').replace('-', ' ').split())
    return len(parts - _GENERIC_NAME_TOKENS) == 0 or len(name) > 60


def _read_cost_center_tag(runtime_arn: str) -> str:
    """Read the flowamp:cost-center tag from an AgentCore runtime. Returns '' on any error."""
    # Classic agents are not AgentCore resources, so this API rejects their ARN.
    # Returning '' leaves costCenter unset; see _write_agent_tags for why Classic
    # carries no FlowAMP tags at all.
    if not _is_agentcore_runtime_arn(runtime_arn):
        return ''
    try:
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        resp = ctrl.list_tags_for_resource(resourceArn=runtime_arn)
        value = resp.get('tags', {}).get('flowamp:cost-center', '')
        return value if isinstance(value, str) else ''
    except Exception:
        logger.warning('Unable to read tags')
        return ''


def _write_agent_tags(runtime_arn: str, agent_id: str, cost_center: str) -> None:
    """Write flowamp:agentId and (if set) flowamp:cost-center tags to the runtime."""
    # Classic agents are tagged through bedrock:TagResource, which this role does not hold:
    # discovery stays read-only on the Classic inventory. A Classic agent therefore gets no
    # flowamp:agentId tag and so no Cost Explorer attribution, though it is still audited.
    if not _is_agentcore_runtime_arn(runtime_arn):
        return
    try:
        tags = {'flowamp:agentId': agent_id}
        if cost_center:
            tags['flowamp:cost-center'] = cost_center
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        ctrl.tag_resource(resourceArn=runtime_arn, tags=tags)
    except Exception:
        logger.warning('Unable to write tags')


def _extract_model_id_from_runtime(runtime_info: dict) -> str | None:
    """Best-effort extraction of an agent's foundation model from runtime metadata.

    AgentCore has no canonical "foundationModel" field (unlike bedrock-agent), so
    signals are inspected in priority order: environment variables
    (FLOWAMP_MODEL_ID / MODEL_ID / BEDROCK_MODEL_ID, then any name containing MODEL),
    then the `flowamp:model-id` tag convention. Returns the first non-empty match,
    or None.
    """
    env_vars = runtime_info.get('environmentVariables') or {}
    if isinstance(env_vars, dict):
        for k in ('FLOWAMP_MODEL_ID', 'MODEL_ID', 'BEDROCK_MODEL_ID', 'FOUNDATION_MODEL_ID'):
            v = env_vars.get(k)
            if v:
                return str(v)
        # Fallback: any env var whose name contains MODEL_ID
        for k, v in env_vars.items():
            if isinstance(k, str) and 'MODEL' in k.upper() and v:
                return str(v)

    tags = runtime_info.get('tags') or {}
    if isinstance(tags, dict):
        for k in ('flowamp:model-id', 'flowamp:modelId', 'modelId'):
            if tags.get(k):
                return str(tags[k])

    return None


def _attach_model_to_agent(table, agent_id: str, model_id: str) -> None:
    """Add `model_id` to the agent's `modelIds` list (idempotent) and ensure a
    matching row exists on AgentTable so the Model Registry surfaces it.

    A model unknown to the registry gets a minimal placeholder row that the nightly
    model sync enriches on its next pass."""
    try:
        existing = table.get_item(Key={'agentId': agent_id, 'sk': 'INFO'}).get('Item') or {}
        current = list(existing.get('modelIds') or [])
        if model_id not in current:
            current.append(model_id)
            table.update_item(
                Key={'agentId': agent_id, 'sk': 'INFO'},
                UpdateExpression='SET modelIds = :ids, modelInferredAt = :ts',
                ExpressionAttributeValues={
                    ':ids': current,
                    ':ts': _now_iso(),
                },
            )
    except Exception as exc:
        logger.warning(f'Unable to attach model to agent: {exc}')
        return

    # Ensure a MODEL# row exists so the Model Registry shows the inferred model
    # immediately. Best-effort; the nightly sync is authoritative.
    try:
        # Parse provider/name#version from e.g. "anthropic/claude-3-sonnet#1";
        # otherwise treat the whole string as both modelId and display name.
        provider = model_id.split('/')[0] if '/' in model_id else 'unknown'
        name = model_id.split('/')[-1].split('#')[0] if '/' in model_id else model_id
        version = model_id.split('#')[-1] if '#' in model_id else '1'
        sk = f"MODEL#{provider}/{name}#{version}"
        # Conditional put: never overwrite an existing registry row, which may carry
        # richer Bedrock metadata from the nightly sync. Registry rows share the
        # FLOWAMP_MODELS sentinel partition (as FLOWAMP_PLATFORMS / FLOWAMP_CATEGORIES
        # do) so list_models() is a single Query rather than a Scan.
        table.put_item(
            Item={
                'agentId': 'FLOWAMP_MODELS',
                'sk': sk,
                'modelId': model_id,
                'name': name,
                'provider': provider,
                'version': version,
                'status': 'active',
                'lastSyncSource': 'discovery-scanner',
                'lastSyncedAt': _now_iso(),
                'createdAt': _now_iso(),
            },
            ConditionExpression='attribute_not_exists(sk)',
        )
    except Exception:
        # ConditionalCheckFailedException is expected for already-known models.
        # Other errors are non-fatal here.
        pass


# =============================================================================
# TOOLS - each is an atomic operation callable by the Strands Agent
# =============================================================================

@tool
def list_agent_runtimes() -> str:
    """List every live agent in this account/region across all three surfaces.

    Covers:
      - harnesses (model + prompt + declared tools; AgentCore runs the loop)
      - runtimes (your own containerized or direct-code program)
      - Bedrock Agents Classic (the separate, maintenance-mode inventory)

    AgentCore implements a harness as a runtime, so ListAgentRuntimes also returns the
    runtime backing each harness, named `harness_<harnessName>`. Those are skipped here;
    without the skip the same logical agent is registered twice, once under its harness
    name and once under the backing-runtime name.

    Returns a JSON list of summaries including ARN, name, version, and the
    `flowampRuntimeLabel` each record should be stored with.
    """
    agentcore_client = boto3.client('bedrock-agentcore-control', region_name=_region)
    agents = []
    next_token = None
    # Reset per call: a scan that succeeds must clear a previous scan's failure.
    _scan_health['classic_ok'] = True

    # ── Harnesses first, so their backing runtimes can be excluded below ──
    harness_backing_names = set()
    try:
        harness_token = None
        while True:
            kwargs = {} if not harness_token else {'nextToken': harness_token}
            resp = agentcore_client.list_harnesses(**kwargs)
            for h in resp.get('harnesses', []):
                h_name = h.get('harnessName') or h.get('harnessId', '')
                harness_backing_names.add(f"harness_{h_name}")
                agents.append({
                    'agentRuntimeArn': h.get('harnessArn', h.get('arn', '')),
                    'agentRuntimeId': h.get('harnessId', h_name),
                    'agentRuntimeName': h_name,
                    'agentRuntimeVersion': str(h.get('harnessVersion', '') or ''),
                    'status': h.get('status', ''),
                    'flowampRuntimeLabel': 'AgentCore Harness',
                })
            harness_token = resp.get('nextToken')
            if not harness_token:
                break
        logger.info("list_harnesses: %d harness(es) returned", len(agents))
    except Exception as exc:
        # ListHarnesses needs a recent SDK and a region where harnesses exist. A
        # failure here must not prevent runtime discovery below.
        logger.info("list_harnesses skipped: %s: %s", type(exc).__name__, exc)

    # ── Bedrock Agents Classic: a separate service and inventory ──
    # Best-effort like the harness pass, but a failure is recorded rather than merely
    # logged: `classic_ok=False` suppresses inactivation of Classic rows in
    # start_discovery_scan, because an errored ListAgents looks identical to an empty one
    # and treating it as empty would inactivate a live Classic fleet wholesale.
    classic_count = 0
    try:
        bedrock_agent_client = boto3.client('bedrock-agent', region_name=_region)
        paginator = bedrock_agent_client.get_paginator('list_agents')
        for page in paginator.paginate():
            for summary in page.get('agentSummaries', []):
                classic_id = summary.get('agentId', '')
                if not classic_id:
                    continue
                classic_name = summary.get('agentName') or classic_id
                agents.append({
                    'agentRuntimeArn': _classic_agent_arn(classic_id),
                    'agentRuntimeId': classic_id,
                    'agentRuntimeName': classic_name,
                    'agentRuntimeVersion': str(summary.get('latestAgentVersion', '') or ''),
                    'description': summary.get('description', '') or '',
                    'status': summary.get('agentStatus', ''),
                    'flowampRuntimeLabel': _CLASSIC_RUNTIME_LABEL,
                })
                classic_count += 1
        logger.info("list_agents (Classic): %d agent(s) returned", classic_count)
    except Exception as exc:
        _scan_health['classic_ok'] = False
        logger.warning(
            "list_agents (Classic) failed, Classic rows will not be inactivated this scan: %s: %s",
            type(exc).__name__, exc,
        )

    for attempt in range(4):
        try:
            kwargs = {} if not next_token else {'nextToken': next_token}
            response = agentcore_client.list_agent_runtimes(**kwargs)
            for rt in response.get('agentRuntimes', response.get('agentRuntimeSummaries', [])):
                rt_name = rt.get('agentRuntimeName') or ''
                if not rt_name and rt.get('agentRuntimeId'):
                    rt_name = _AGENTCORE_RUNTIME_SUFFIX_RE.sub('', rt['agentRuntimeId'])
                # Skip the runtime that merely backs a harness discovered above.
                if rt_name in harness_backing_names:
                    logger.info("skipping harness-backing runtime %s", rt_name)
                    continue
                rt['flowampRuntimeLabel'] = 'AgentCore Runtime'
                agents.append(rt)
            next_token = response.get('nextToken')
            if not next_token:
                break
            attempt = 0
        except Exception as exc:
            if 'Throttling' in type(exc).__name__ and attempt < 3:
                _jitter_delay(_BACKOFF_BASE, attempt)
                continue
            # Log the real exception (it reaches the runtime's CloudWatch log group)
            # so control-plane failures are diagnosable rather than paraphrased by the
            # LLM as "service not available".
            logger.error("list_agent_runtimes failed: %s: %s", type(exc).__name__, exc)
            return json.dumps({'error': f'{type(exc).__name__}: {exc}', 'agents': []})

    logger.info("list_agent_runtimes: %d runtime(s) returned", len(agents))

    # Ensure every item exposes a clean 'agentRuntimeName' (no AWS-appended suffix)
    # so callers can pass it straight to upsert_agent without re-deriving it.
    for item in agents:
        if 'agentRuntimeName' not in item and 'agentRuntimeId' in item:
            item['agentRuntimeName'] = _AGENTCORE_RUNTIME_SUFFIX_RE.sub('', item['agentRuntimeId'])
        elif 'agentRuntimeName' not in item and 'agentRuntimeArn' in item:
            item['agentRuntimeName'] = _agent_id_from_arn(item['agentRuntimeArn'])

    return json.dumps(agents, default=str)


@tool
def get_agent_catalog(status_filter: str = 'all') -> str:
    """Read all agents currently tracked in AgentTable.

    Args:
        status_filter: Filter by status ('active', 'inactive', or 'all'). Defaults to 'all'.

    Returns a JSON list of agent records.
    """

    logger.info('Getting agent catalog')
    status = None if status_filter == 'all' else status_filter
    items = _list_active_agents(status=status)
    return json.dumps(items, default=str)


@tool
def get_agent_categories() -> str:
    """Return the canonical agent categories from the FLOWAMP_CATEGORIES sentinel row.

    This is the live source of truth, managed via the Governance UI. Always call it
    before set_enrichment_fields so you pass a current `id` rather than a guess.
    Returns JSON: {"items": [{id, name, icon?, color?}, ...], "count": N}.
    """
    global _categories_cache
    cats = _read_categories_sentinel()
    _categories_cache = cats  # refresh cache so set_enrichment_fields agrees
    return json.dumps({'items': cats, 'count': len(cats)}, default=str)


def _assign_baseline_framework(table, agent_id: str, now: str) -> None:
    """Write a COMPLIANCE#FLOWAMP_BASELINE row for a freshly discovered agent.

    Idempotent via attribute_not_exists, so re-running discovery on an already
    baselined agent is a no-op. Failures are logged, never raised: the INFO row is
    written first, and a missing baseline row is benign (the dashboard treats baseline
    as implicit and a user can re-trigger via the Manage Frameworks UI).
    """
    try:
        table.put_item(
            Item={
                'agentId': agent_id,
                'sk': f'COMPLIANCE#{_BASELINE_FRAMEWORK_ID}',
                'frameworkId': _BASELINE_FRAMEWORK_ID,
                'assignedBy': _agent_id,
                'assignedAt': now,
            },
            ConditionExpression='attribute_not_exists(agentId)',
        )
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        return
    except Exception as exc:
        logger.warning('Failed to assign baseline framework to %s: %s', agent_id, exc)


@tool
def upsert_agent(agent_runtime_arn: str, agent_runtime_name: str,
                 description: str = '', runtime_version: str = '', work_item_id: str = '',
                 skip_fields: set | None = None, runtime_label: str = '') -> str:
    """Upsert a single discovered agent into AgentTable.

    New records get lifecycleStatus='pending-review' so a human reviewer approves them
    before they enter the active pool. Re-scans preserve the current lifecycleStatus
    (stored as 'status') by omitting it from the UpdateExpression: callers may pass
    skip_fields, but 'status' is always skipped on the update path.

    `runtime_label` is the execution surface to store ('AgentCore Harness', 'AgentCore
    Runtime' or 'Bedrock Agent Classic'), as reported by list_agent_runtimes in
    `flowampRuntimeLabel`. The registry shows this string verbatim, so it must match
    the vocabulary the rest of the platform emits.

    Returns JSON with {'isNew': bool, 'agentId': str}.
    """
    # Default rather than guess: an unlabelled call is most likely a runtime, and a
    # blank value renders as an empty Runtime column in the registry.
    runtime_label = runtime_label if runtime_label in _RUNTIME_LABELS else 'AgentCore Runtime'

    logger.info(
            'Upserting agent %s',
            agent_runtime_name
        )
    skip_fields = (skip_fields or set()) | {'status'}  # status is always preserved on update

    dynamodb = boto3.resource('dynamodb', region_name=_region)
    table = dynamodb.Table(_agent_table_name)
    now = _now_iso()

    # Prefer the operator-defined agentRuntimeName when it is a clean identifier (no
    # ':' or '/'), falling back to ARN stripping. The full ARN is kept in runtimeId;
    # agentId must be the stable friendly name so URL paths (/agents/{agentId}/...)
    # stay clean across runtime redeploys.
    agent_id_key = _clean_agent_id(agent_runtime_arn, agent_runtime_name)
    resp = table.get_item(Key={'agentId': agent_id_key, 'sk': 'INFO'})
    existing = resp.get('Item')

    cost_center = _read_cost_center_tag(agent_runtime_arn)
    _write_agent_tags(agent_runtime_arn, agent_runtime_name, cost_center)

    if existing is None:
        # New record: enter pending-review so a reviewer can approve before activation.
        #
        # Do not default `owner` or `escalationGroup`. The `owner-populated` and
        # `escalation-group-assigned` compliance checks read exactly those two fields, so
        # any placeholder makes both pass on every discovered agent by construction. Blank
        # means unowned until a human takes ownership, which is the signal those checks
        # exist to detect and what the registry renders as "Unassigned".
        item = _sanitize_for_ddb({
            'agentId': agent_id_key,
            'sk': 'INFO',
            'status': 'pending-review',
            'lastDiscoveredAt': now,
            'discoveredAt': now,
            'name': agent_runtime_name,
            'runtimeId': agent_runtime_arn,
            'description': description,
            'runtimeVersion': runtime_version,
            # FinOps tag taxonomy defaults; operators update these via PATCH /agents/{id}
            # after reviewing the record. Unlike owner, 'external' is a real neutral bucket
            # in that taxonomy rather than a stand-in for a named team, and no compliance
            # check reads it.
            'agentClass': 'external',
            'businessUnit': 'external',
        })
        if cost_center:
            item['costCenter'] = cost_center
        table.put_item(Item=item)
        _assign_baseline_framework(table, agent_id_key, now)
        # Write a REVIEW# row so the Review History tab shows the scanner's first
        # observation alongside reviewer approvals / rejections / decommissions.
        try:
            table.put_item(Item={
                'agentId':            agent_id_key,
                'sk':                 f'REVIEW#{now}',
                'reviewer':           _agent_id,
                'decision':           'status-change',
                'previousStatus':     'none',
                'newStatus':          'pending-review',
                'frameworksAssigned': [],
                'createdAt':          now,
                'notes':              'Newly discovered via AgentCore list-agents',
            })
        except Exception as exc:
            logger.error('add_or_update_agent: REVIEW# row write failed agent=%s: %s', agent_id_key, exc)
        log_lifecycle_change(
            entity_type='agent',
            entity_id=agent_id_key,
            previous_state='none',
            new_state='pending-review',
            reason='Newly discovered via AgentCore list-agents',
            operator_id=_agent_id,
        )
        if work_item_id:
            add_work_item_task(
                work_item_id=work_item_id,
                instructions=f'Added agent to Catalog: {agent_id_key}',
                status='success',
            )
        return json.dumps({'isNew': True, 'agentId': agent_id_key})
    else:
        # Existing record: update lastDiscoveredAt only; never overwrite lifecycleStatus.
        update_expr = 'SET lastDiscoveredAt = :now'
        expr_vals: dict = {':now': now}
        kwargs: dict = {
            'Key': {'agentId': agent_id_key, 'sk': 'INFO'},
            'UpdateExpression': update_expr,
            'ExpressionAttributeValues': expr_vals,
        }
        if cost_center:
            update_expr += ', costCenter = :cc'
            expr_vals[':cc'] = cost_center
            kwargs['UpdateExpression'] = update_expr
        table.update_item(**kwargs)
        if work_item_id:
            add_work_item_task(
                work_item_id=work_item_id,
                instructions=f'Updated agent in Catalog: {agent_id_key}',
                status='success',
            )
        return json.dumps({'isNew': False, 'agentId': agent_id_key})


@tool
def mark_agent_inactive(agent_id: str, previous_status: str = 'active', work_item_id: str = '') -> str:
    """Mark an agent inactive in AgentTable because it was absent from the live scan.

    Refuses when the agent's ``platformId`` is not Amazon Bedrock AgentCore: those
    agents live on platforms this scanner cannot see (manual registration, other
    connectors), so absence from this scan is no evidence they are gone. Returns error
    JSON in that case so the LLM sees the refusal rather than retrying blindly.

    Args:
        agent_id: The agentId (canonical runtime ARN) of the agent to mark inactive.
        previous_status: The agent's status before going inactive (for audit trail).

    Returns JSON confirmation, or {'error': ...} when refused.
    """

    logger.info('Marking inactive agent %s', agent_id)
    dynamodb = boto3.resource('dynamodb', region_name=_region)
    table = dynamodb.Table(_agent_table_name)

    # Guard: only Bedrock-platform agents are inactivatable by this scanner.
    existing = table.get_item(Key={'agentId': agent_id, 'sk': 'INFO'}).get('Item')
    if existing is None:
        return json.dumps({
            'agentId': agent_id,
            'error': 'Agent not found',
        })
    existing_platform = existing.get('platformId') or ''
    if existing_platform and existing_platform != _BEDROCK_PLATFORM_ID:
        msg = (
            f'Cannot inactivate {agent_id}: platformId={existing_platform!r} '
            f'is not {_BEDROCK_PLATFORM_ID!r}. The discovery scanner only '
            f'manages Bedrock-platform agents; non-Bedrock rows are owned '
            f'elsewhere.'
        )
        logger.info(msg)
        return json.dumps({
            'agentId': agent_id,
            'platformId': existing_platform,
            'error': msg,
        })

    # Clear the platform status alongside the governance one: the agent is absent from a
    # scan known to have succeeded, so leaving 'running' would make the drift matrix report
    # "inactive but still serving traffic" for a deleted agent. 'not-found' is recorded raw
    # so the detail view can explain why the status is unknown.
    table.update_item(
        Key={'agentId': agent_id, 'sk': 'INFO'},
        UpdateExpression=(
            'SET #s = :inactive, platformStatus = :pstatus, platformStatusRaw = :praw, '
            'platformStatusAt = :pat'
        ),
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={
            ':inactive': 'inactive',
            ':pstatus': _PLATFORM_STATUS_UNKNOWN,
            ':praw': 'not-found',
            ':pat': _now_iso(),
        },
    )
    # Write a REVIEW# row so the Review History tab shows this scanner-driven
    # inactivation alongside reviewer actions and admin decommissions.
    now = _now_iso()
    try:
        table.put_item(Item={
            'agentId':            agent_id,
            'sk':                 f'REVIEW#{now}',
            'reviewer':           _agent_id,
            'decision':           'status-change',
            'previousStatus':     previous_status,
            'newStatus':          'inactive',
            'frameworksAssigned': [],
            'createdAt':          now,
            'notes':              'Agent absent from AgentCore list-agents response',
        })
    except Exception as exc:
        logger.error('mark_agent_inactive: REVIEW# row write failed agent=%s: %s', agent_id, exc)
    log_lifecycle_change(
        entity_type='agent',
        entity_id=agent_id,
        previous_state=previous_status,
        new_state='inactive',
        reason='Agent absent from AgentCore list-agents response',
        operator_id=_agent_id,
    )

    if work_item_id:
        add_work_item_task(
            work_item_id=work_item_id,
            instructions=f'Agent absent from scan. Marking agent as inactive: {agent_id}',
            status='failure',
        )
    return json.dumps({'agentId': agent_id, 'newStatus': 'inactive'})


@tool
def enrich_agent(agent_id: str, work_item_id: str = '') -> str:
    """Enrich an agent record with a human-friendly displayName.

    Steps:
    1. Skip if displayName is already set.
    2. Fetch metadata from the AgentCore control plane (GetAgentRuntime).
    3. If the runtime name/description is generic or missing, invoke the agent
       directly and ask what it does.
    4. Synthesize a human-friendly displayName via Bedrock and write it to AgentTable.

    Args:
        agent_id: The agentId (ARN) of the agent to enrich.

    Returns JSON with {'agentId': str, 'displayName': str, 'skipped': bool}.
    """
    dynamodb = boto3.resource('dynamodb', region_name=_region)
    table = dynamodb.Table(_agent_table_name)

    item = table.get_item(Key={'agentId': agent_id, 'sk': 'INFO'}).get('Item')
    if not item:
        return json.dumps({'agentId': agent_id, 'skipped': True, 'reason': 'not found'})

    if item.get('displayName'):
        return json.dumps({'agentId': agent_id, 'displayName': item['displayName'], 'skipped': True})

    runtime_name = item.get('name', '')
    description = item.get('description', '')
    runtime_arn = item.get('runtimeId', agent_id)

    # Try to get richer metadata from the control plane
    runtime_info: dict = {}
    try:
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        runtime_info = ctrl.get_agent_runtime(agentRuntimeId=runtime_arn) or {}
        runtime_name = runtime_info.get('agentRuntimeName', runtime_name) or runtime_name
        description = runtime_info.get('description', description) or description
    except Exception:
        logger.warning('Metadata unavailable')
        pass  # fall through to ask the agent

    # Extract the underlying foundation model from runtime metadata so it lands on the
    # agent's modelIds list, and in the Model Registry if not already registered.
    inferred_model_id = _extract_model_id_from_runtime(runtime_info)
    if inferred_model_id:
        _attach_model_to_agent(table, agent_id, inferred_model_id)

    # If name is generic or description is empty, ask the agent what it does
    self_description = ''
    if _is_generic_name(runtime_name) or not description:
        try:
            agentcore_client = boto3.client('bedrock-agentcore', region_name=_region)
            response = agentcore_client.invoke_agent_runtime(
                agentRuntimeArn=runtime_arn,
                qualifier='DEFAULT',
                runtimeSessionId=f'discovery-{int(time.time())}',
                payload=json.dumps({
                    'messages': [{'role': 'user', 'content': 'In one sentence, what do you do?'}],
                }),
            )
            body = response.get('response', b'{}')
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='replace')
            parsed = json.loads(body) if isinstance(body, str) else {}
            self_description = (
                parsed.get('result') or
                parsed.get('content') or
                parsed.get('output', {}).get('text', '') or
                ''
            )
        except Exception:
            logger.warning('Unable to invoke agent')
            pass  # agent may be unreachable; fall through

    # Build prompt for Bedrock to synthesize a human-friendly display name
    context_parts = [f'Runtime name: {runtime_name}']
    if description:
        context_parts.append(f'Description: {description}')
    if self_description:
        context_parts.append(f'Self-description: {self_description}')
    context = '\n'.join(context_parts)

    prompt = (
        f'Based on the following information about an AI agent, write a short, human-friendly '
        f'display name (3-6 words, title case, no jargon). Return only the display name, nothing else.\n\n'
        f'{context}'
    )

    try:
        bedrock = boto3.client('bedrock-runtime', region_name=_region)
        # Always the configured model, never a hardcoded id: the runtime's IAM policy
        # scopes bedrock:InvokeModel to exactly one foundation-model ARN (the configured
        # base model) plus this account's inference profiles, so any other model is denied
        # and the surrounding `except` would swallow that denial silently.
        resp = bedrock.invoke_model(
            modelId=get_model_config()['defaultModel'],
            body=json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 32,
                'messages': [{'role': 'user', 'content': prompt}],
            }),
        )
        result = json.loads(resp['body'].read())
        display_name = result['content'][0]['text'].strip().strip('"')
    except Exception as exc:
        logger.warning('Unable to invoke agent for enrichment')
        display_name = runtime_name  # fall back to technical name
        log_decision_trace(
            trace_steps=[
                {
                    "step": "enrich_agent_bedrock_error",
                    "agentId": agent_id,
                    "error": str(exc)[:500],
                    "fallback": "runtime_name",
                },
            ],
            trace_id=agent_id,
        )
        log_agent_decision(
            action_type='enrich_agent_bedrock_error',
            input_summary=f'Bedrock enrichment failed for {agent_id}',
            output_summary=str(exc),
            trace_id=agent_id,
        )

    table.update_item(
        Key={'agentId': agent_id, 'sk': 'INFO'},
        UpdateExpression='SET displayName = :dn',
        ExpressionAttributeValues={':dn': display_name},
    )

    log_decision_trace(
        trace_steps=[
            {
                "step": "agent_enriched",
                "agentId": agent_id,
                "displayName": display_name,
            },
        ],
        trace_id=agent_id,
    )
    log_agent_decision(
        action_type='agent_enriched',
        input_summary=f'Enriched displayName for {agent_id}',
        output_summary=f'displayName = {display_name}',
        trace_id=agent_id,
    )

    return json.dumps({'agentId': agent_id, 'displayName': display_name, 'skipped': False})


def _probe_invocable(runtime_arn: str) -> bool | None:
    """Return True if the runtime uses IAM auth, False if JWT-only, None on lookup error.

    Reads authorizerConfiguration via the control-plane GetAgentRuntime; no model
    invocation needed. IAM-auth runtimes have no customJwtAuthorizer field, so they are
    reachable via SigV4 SDK calls (boto3 / API Lambda).

    ``GetAgentRuntime`` expects the bare ``agentRuntimeId`` (the suffixed runtime name,
    e.g. ``flowamp_orchestration_agent_dev-ofYZpKEzg8``), not the full ARN. Passing the
    ARN fails with AccessDeniedException regardless of IAM permissions.
    """
    # Classic agents have no AgentCore authorizer config to probe. None rather than
    # False leaves whatever the row already carried; new Classic rows are created with
    # invocable=False, the safe default for a surface FlowAMP never invokes.
    if not _is_agentcore_runtime_arn(runtime_arn):
        return None
    try:
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        info = ctrl.get_agent_runtime(agentRuntimeId=_runtime_id_from_arn(runtime_arn))
        auth_cfg = info.get('authorizerConfiguration') or {}
        return 'customJwtAuthorizer' not in auth_cfg
    except Exception as exc:
        logger.error('Unable to read agentcore config for %s: %s', runtime_arn, exc)
        return None


def _write_invocable(agent_id: str, invocable: bool) -> None:
    dynamodb = boto3.resource('dynamodb', region_name=_region)
    table = dynamodb.Table(_agent_table_name)
    table.update_item(
        Key={'agentId': agent_id, 'sk': 'INFO'},
        UpdateExpression='SET invocable = :v',
        ExpressionAttributeValues={':v': invocable},
    )


# =============================================================================
# THREE-STAGE DISCOVERY PIPELINE
#
# Stage 1  start_discovery_scan: list live agents, load the catalog, classify into
#          add / enrich / refresh / inactivate, populate _scan_state. No DDB writes.
# Stage 2  LLM-driven enrichment: get_pending_enrichments, then any of the enrich_*
#          tools for signal, then set_enrichment_fields to apply changes in memory.
# Stage 3  commit_discovery_scan: flush _scan_state to AgentTable, mark inactives,
#          emit metrics, clear state.
# =============================================================================

def _classify_record(arn: str, live_data: dict, existing: dict | None) -> dict:
    """Build the working record for one runtime and decide its action.

    Action rules:
      - 'add'      no existing INFO row
      - 'enrich'   exists, but an enrichment field is empty and not in
                   humanVerifiedFields
      - 'refresh'  fully populated; nothing for the LLM to do
    """
    existing = existing or {}
    verified = list(existing.get('humanVerifiedFields') or [])

    _live_name = live_data.get('agentRuntimeName', '')
    _derived_id = _clean_agent_id(arn, _live_name)
    record = {
        'agentId': _derived_id,
        'runtimeId': arn,
        'name': _live_name or _derived_id,
        'description': live_data.get('description', '') or existing.get('description', ''),
        'runtimeVersion': live_data.get('agentRuntimeVersion', ''),
        # Execution surface, set by list_agent_runtimes from whichever control-plane API
        # returned this agent. Carried through so commit can store it as-is.
        'runtimeLabel': live_data.get('flowampRuntimeLabel', 'AgentCore Runtime'),
        # The platform's own run state, carried verbatim and normalized at commit.
        # Distinct from the governance `status`, which records whether a human has
        # accepted responsibility for the agent.
        'platformStatusRaw': str(live_data.get('status') or ''),
        # The LLM may fill any of these via set_enrichment_fields. Pre-seeded from the
        # existing row so the LLM can see current values.
        'displayName': existing.get('displayName', ''),
        'category': existing.get('category', ''),
        'riskTier': existing.get('riskTier', ''),
        'capabilities': existing.get('capabilities', ''),
        'suggestedOwner': existing.get('suggestedOwner', ''),
        # Stamped here, not enrichable, so the LLM cannot influence it. invocable is
        # hydrated from the existing row; commit re-probes for a fresh value.
        'platformId': _BEDROCK_PLATFORM_ID,
        'invocable': existing.get('invocable'),
        '_existed_before': bool(existing),
        '_existing': existing,
        '_humanVerified': verified,
    }

    if not existing:
        record['_action'] = 'add'
    else:
        # enrich if any required field is missing AND not portal-locked
        missing = [
            f for f in ('displayName', *_ENRICHMENT_FIELDS)
            if not record.get(f) and f not in verified
        ]
        record['_action'] = 'enrich' if missing else 'refresh'
        record['_missing'] = missing
    return record


@tool
def start_discovery_scan(work_item_id: str = '') -> str:
    """Stage 1 - scan AgentCore and analyze the catalog.

    Lists live agents, loads existing AgentTable rows, and classifies every agent:
      - add:        new runtime, not in catalog
      - enrich:     existing row missing displayName/category/riskTier/etc.
      - refresh:    existing row complete; will only bump lastDiscoveredAt
      - inactivate: catalog row absent from the live scan

    Populates _scan_state and returns a JSON summary so the LLM can decide what to
    enrich next. **Does not write to AgentTable yet.** Call `commit_discovery_scan`
    after enrichment to persist results.
    """
    _scan_trace_id = work_item_id or 'discovery-scan'
    log_decision_trace(
        trace_steps=[
            {
                "step": "discovery_scan_start",
                "workItemId": work_item_id,
                "stage": 1,
            },
        ],
        trace_id=_scan_trace_id,
    )
    log_agent_decision(
        action_type='discovery_scan_start',
        input_summary='Discovery scan triggered',
        output_summary='Stage 1: scanning AgentCore + analyzing catalog',
        trace_id=_scan_trace_id,
    )
    if work_item_id:
        add_work_item_note(
            work_item_id=work_item_id,
            text='Starting Stage 1: AgentCore scan + catalog analysis',
        )

    # TODO(DISC-BEHAVIOR-001): scope is this account's native AWS surfaces only. When
    # multi-platform connectors land, dispatch by platform here.
    live_runtimes_json = list_agent_runtimes()
    live_data = json.loads(live_runtimes_json)
    if isinstance(live_data, dict) and 'error' in live_data:
        return json.dumps({
            'stage': 1, 'error': live_data.get('error'),
            'timestamp': _now_iso(),
        })

    live_agents = live_data if isinstance(live_data, list) else []
    catalog_json = get_agent_catalog(status_filter='all')
    existing = {item['agentId']: item for item in json.loads(catalog_json)}

    # Reset state: module scope outlives a single invocation, so a fresh scan must
    # clear leftovers from any prior run. The work_item_id is captured so
    # commit_discovery_scan can reuse it without the LLM passing it twice.
    _scan_state['records'] = {}
    _scan_state['inactivate'] = []
    _scan_state['stamp_invocable_false'] = []
    _scan_state['started_at'] = _now_iso()
    _scan_state['completed_scan'] = False
    _scan_state['work_item_id'] = work_item_id

    # `live_agent_ids` holds AgentTable PKs (runtime names), not ARNs; `existing` and
    # the `live_*` checks below all work in PK space. `_classify_record` still receives
    # the full ARN because it stamps `runtimeId` from it.
    live_agent_ids = set()
    # ARNs of every agent returned by this scan. Guards against inactivating a row whose
    # `agentId` predates the current key format but whose `runtimeId` still points at a
    # live runtime.
    live_runtime_arns = set()
    stage1_invocable_writes = 0
    for agent_data in live_agents:
        arn = agent_data.get('agentRuntimeArn') or agent_data.get('agentRuntimeId')  or agent_data.get('runtimeId')
        if not arn:
            continue
        agent_id = _clean_agent_id(arn, agent_data.get('agentRuntimeName', ''))
        live_agent_ids.add(agent_id)
        live_runtime_arns.add(arn)
        existing_row = existing.get(agent_id)
        record = _classify_record(arn, agent_data, existing_row)
        # Probe invocability now so get_pending_enrichments can expose it; otherwise
        # the LLM may try enrich_via_agent_self_description on a JWT-auth runtime that
        # cannot answer. Best-effort: on lookup error keep the existing row's value.
        probed = _probe_invocable(arn)
        if probed is not None:
            record['invocable'] = probed
            # Persist immediately for agents that already have a row, so the flag reflects
            # the live authorizer config even if the commit phase never runs. New agents
            # get their initial value when commit creates the row.
            if existing_row and existing_row.get('invocable') is not probed:
                try:
                    _write_invocable(agent_id, probed)
                    stage1_invocable_writes += 1
                except Exception:
                    logger.warning('Stage-1 invocable write failed for %s', agent_id)
        # Key by the canonical agentId so the enrichment tools look records up with the
        # same id get_pending_enrichments exposes. The full ARN stays on
        # record['runtimeId'].
        _scan_state['records'][record['agentId']] = record

    # Inactivation candidates: catalog rows missing from the live scan, except demo
    # agents in dev so seeded data survives re-scans. Non-Bedrock rows are never
    # inactivated here (the scanner owns Bedrock lifecycle only) but do get invocable
    # stamped false so nothing attempts a SigV4 invocation against them.
    for agent_id, record in existing.items():
        if agent_id in live_agent_ids:
            continue
        # Guard against agentId key drift: a row whose runtimeId matches a runtime in
        # this scan is not orphaned, its agentId just predates the current format.
        # Re-keying it is a separate dedupe concern.
        if record.get('runtimeId') and record.get('runtimeId') in live_runtime_arns:
            continue
        if record.get('status') == 'inactive':
            continue
        if _environment == 'dev' and 'DEMO' in (record.get('description') or ''):
            continue
        # A failed Classic listing is indistinguishable from an empty one, so a Classic
        # row missing from this scan proves nothing when that pass errored.
        if not _scan_health['classic_ok'] and record.get('runtime') == _CLASSIC_RUNTIME_LABEL:
            logger.info('Not inactivating Classic agent %s: ListAgents failed this scan', agent_id)
            continue
        if record.get('platformId') == _BEDROCK_PLATFORM_ID:
            _scan_state['inactivate'].append(agent_id)
        else:
            # Only queue a write when the flag is missing or True, to avoid no-op
            # writes when invocable is already false.
            if record.get('invocable') is not False:
                _scan_state['stamp_invocable_false'].append(agent_id)

    _scan_state['completed_scan'] = True

    by_action = {'add': 0, 'enrich': 0, 'refresh': 0}
    for r in _scan_state['records'].values():
        by_action[r['_action']] = by_action.get(r['_action'], 0) + 1

    summary = {
        'stage': 1,
        'discovered': len(live_agent_ids),
        'toAdd': by_action['add'],
        'toEnrich': by_action['enrich'],
        'toRefresh': by_action['refresh'],
        'toInactivate': len(_scan_state['inactivate']),
        'nonBedrockToStamp': len(_scan_state['stamp_invocable_false']),
        # Existing catalog rows whose `invocable` flag this stage refreshed from a
        # fresh GetAgentRuntime probe.
        'invocableRefreshed': stage1_invocable_writes,
        'startedAt': _scan_state['started_at'],
        'note': (
            'Stage 1 complete. Use get_pending_enrichments to see records '
            'needing attention, then call enrich_* tools and '
            'set_enrichment_fields. Finish with commit_discovery_scan.'
        ),
    }
    if work_item_id:
        add_work_item_note(
            work_item_id=work_item_id,
            text=(
                f'Scan complete. {summary["toAdd"]} to add, '
                f'{summary["toEnrich"]} to enrich, '
                f'{summary["toRefresh"]} to refresh, '
                f'{summary["toInactivate"]} to inactivate.'
            ),
        )
    return json.dumps(summary)


@tool
def get_pending_enrichments() -> str:
    """Return the in-memory records flagged 'add' or 'enrich'.

    Each entry includes the runtime metadata, the existing-record snapshot,
    the list of missing fields, and the humanVerifiedFields the LLM is not
    allowed to overwrite. Use this to drive the enrichment loop.
    """
    if not _scan_state.get('completed_scan'):
        return json.dumps({'error': 'No active scan. Call start_discovery_scan first.'})
    pending = [
        {
            'agentId': r['agentId'],
            'name': r['name'],
            'description': r['description'],
            'runtimeVersion': r['runtimeVersion'],
            'action': r['_action'],
            'missingFields': r.get('_missing', []),
            'humanVerifiedFields': r['_humanVerified'],
            'currentDisplayName': r['displayName'],
            'currentCategory': r['category'],
            'currentRiskTier': r['riskTier'],
            'currentCapabilities': r['capabilities'],
            'currentSuggestedOwner': r['suggestedOwner'],
            # invocable=false means enrich_via_agent_self_description will refuse;
            # use the metadata or naming-convention path instead.
            'platformId': r.get('platformId'),
            'invocable': r.get('invocable'),
        }
        for r in _scan_state['records'].values()
        if r['_action'] in ('add', 'enrich')
    ]
    return json.dumps({'pending': pending, 'count': len(pending)})


@tool
def enrich_from_runtime_metadata(agent_id: str) -> str:
    """Pull one runtime's name and description from the AgentCore control plane.

    Returns the raw metadata as JSON; decide how to use it (pass a derived
    displayName to set_enrichment_fields, copy the description verbatim, etc.).
    """
    if agent_id not in _scan_state.get('records', {}):
        return json.dumps({'error': f'Unknown agentId {agent_id} — not in current scan'})
    try:
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        info = ctrl.get_agent_runtime(agentRuntimeId=agent_id)
    except Exception as exc:
        return json.dumps({'agentId': agent_id, 'error': str(exc)})
    return json.dumps({
        'agentId': agent_id,
        'runtimeName': info.get('agentRuntimeName', ''),
        'description': info.get('description', ''),
        'tags': info.get('tags', {}),
    })


@tool
def enrich_via_agent_self_description(agent_id: str) -> str:
    """Invoke the discovered agent and ask "in one sentence, what do you do?".

    Returns the agent's self-description, usable for capabilities / displayName. Best
    effort: fall back to another enrichment path on failure.

    Refuses unless the working record's ``invocable`` flag is True. Non-invocable
    agents (JWT-only, or non-Bedrock rows with no SigV4-callable runtime) would only
    return AccessDenied, so this short-circuits with a clear message instead.
    """
    if agent_id not in _scan_state.get('records', {}):
        return json.dumps({'error': f'Unknown agentId {agent_id} — not in current scan'})
    record = _scan_state['records'][agent_id]
    if record.get('invocable') is not True:
        return json.dumps({
            'agentId': agent_id,
            'invocable': record.get('invocable'),
            'platformId': record.get('platformId'),
            'error': (
                'Agent is not invocable — skip self-description and use '
                'enrich_from_runtime_metadata or enrich_with_naming_convention '
                'instead.'
            ),
        })
    try:
        agentcore_client = boto3.client('bedrock-agentcore', region_name=_region)
        response = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=agent_id,
            qualifier='DEFAULT',
            runtimeSessionId=f'discovery-{int(time.time())}',
            payload=json.dumps({
                'messages': [{'role': 'user', 'content': 'In one sentence, what do you do?'}],
            }),
        )
        body = response.get('response', b'{}')
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='replace')
        parsed = json.loads(body) if isinstance(body, str) else {}
        text = (
            parsed.get('result') or
            parsed.get('content') or
            parsed.get('output', {}).get('text', '') or
            ''
        )
        return json.dumps({'agentId': agent_id, 'selfDescription': text})
    except Exception as exc:
        return json.dumps({'agentId': agent_id, 'error': str(exc)})


@tool
def enrich_with_naming_convention(agent_id: str) -> str:
    """Apply the FlowAMP naming convention to a raw runtime name and return a
    candidate displayName.

    Rules:
      - Strip env suffix (-dev / -prod / _staging / etc.)
      - Strip generic trailing nouns (runtime, lambda, function, service, agent)
      - Replace _ and - with spaces, title-case, cap at 6 words

    Deterministic, with no model call. Use it when the raw name is already
    descriptive enough to clean up directly.
    """
    if agent_id not in _scan_state.get('records', {}):
        return json.dumps({'error': f'Unknown agentId {agent_id} — not in current scan'})
    raw = _scan_state['records'][agent_id]['name']
    name = raw
    # strip env suffix once
    for suffix in _NAMING_ENV_SUFFIXES:
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    tokens = name.replace('_', ' ').replace('-', ' ').split()
    # drop trailing generic tokens (e.g. "...runtime", "...service")
    while tokens and tokens[-1].lower() in _NAMING_STRIP_TOKENS:
        tokens.pop()
    if not tokens:
        # nothing left — fall back to the raw name title-cased
        candidate = raw.replace('_', ' ').replace('-', ' ').title()
    else:
        candidate = ' '.join(t.capitalize() for t in tokens[:6])
    return json.dumps({'agentId': agent_id, 'candidateDisplayName': candidate})


def _validate_enrichment_value(field: str, value) -> tuple[bool, str]:
    """Return (ok, message) for a single field/value pair."""
    if field == 'category':
        valid = _valid_category_ids()
        if value not in valid:
            return False, f"category must be one of {sorted(valid)}"
    elif field == 'riskTier':
        if value not in _VALID_RISK_TIERS:
            return False, f"riskTier must be one of {sorted(_VALID_RISK_TIERS)}"
    elif field == 'displayName':
        if not isinstance(value, str) or not value.strip() or len(value) > 80:
            return False, "displayName must be a non-empty string ≤ 80 chars"
    elif field in ('capabilities', 'suggestedOwner', 'description'):
        if not isinstance(value, str):
            return False, f"{field} must be a string"
    else:
        return False, f"unknown field {field}"
    return True, ''


@tool
def set_enrichment_fields(
    agent_id: str,
    displayName: str = '',
    category: str = '',
    riskTier: str = '',
    capabilities: str = '',
    suggestedOwner: str = '',
    description: str = '',
) -> str:
    """Apply enrichment to one in-memory record.

    Empty-string args are ignored, so you can update one field at a time.

    Guardrails (rejected with no partial write):
      - agent_id must be in the current scan state
      - any field listed in humanVerifiedFields is skipped silently
      - immutable fields (agentId, runtimeId, status, etc.) cannot be passed
      - category and riskTier are checked against the canonical enums
    """
    if agent_id not in _scan_state.get('records', {}):
        return json.dumps({'error': f'Unknown agentId {agent_id} — not in current scan'})

    record = _scan_state['records'][agent_id]
    proposed = {
        'displayName': displayName,
        'category': category,
        'riskTier': riskTier,
        'capabilities': capabilities,
        'suggestedOwner': suggestedOwner,
        'description': description,
    }
    # Filter empties and immutables.
    proposed = {k: v for k, v in proposed.items() if v != '' and k in _ENRICHABLE_FIELDS}

    # Validate every proposed value before applying any, so errors never half-apply.
    for field, value in proposed.items():
        ok, msg = _validate_enrichment_value(field, value)
        if not ok:
            return json.dumps({'agentId': agent_id, 'error': msg, 'field': field})

    applied = {}
    skipped = []
    for field, value in proposed.items():
        if field in record['_humanVerified']:
            skipped.append(field)
            continue
        record[field] = value
        applied[field] = value

    # Recompute _missing so the next get_pending_enrichments reflects progress.
    record['_missing'] = [
        f for f in ('displayName', *_ENRICHMENT_FIELDS)
        if not record.get(f) and f not in record['_humanVerified']
    ]
    if not record['_missing'] and record['_action'] == 'enrich':
        # Keep _action as 'enrich' so commit still treats this as an update.
        pass

    return json.dumps({
        'agentId': agent_id,
        'applied': applied,
        'skippedHumanVerified': skipped,
        'remainingMissing': record['_missing'],
    })


@tool
def commit_discovery_scan(work_item_id: str = '') -> str:
    """Stage 3 - flush _scan_state to AgentTable.

    For each in-memory record:
      - 'add'      write a new INFO row with status='pending-review' and
                   aiInferred=True for any LLM-set field
      - 'enrich'   UpdateItem with the LLM-set fields, never overwriting
                   humanVerifiedFields
      - 'refresh'  bump lastDiscoveredAt only

    The inactivation list is processed last; demo rows in dev were already excluded at
    scan time. Also re-probes invocability for every live runtime, emits the
    AgentsDiscovered CloudWatch metric, and clears state.
    """
    if not _scan_state.get('completed_scan'):
        return json.dumps({'error': 'No active scan to commit. Call start_discovery_scan first.'})

    # Fall back to the work_item_id captured in start_discovery_scan so the work item
    # still gets its tasks and is closed.
    if not work_item_id:
        work_item_id = _scan_state.get('work_item_id', '')

    # Outcome tracking for the finally-block close. close_status flips to 'failure' on
    # the first unhandled exception so the dispatch work item is never left
    # in-progress until backlog_sweep retries it.
    close_status = 'done'
    close_error_message: str | None = None
    new_count = 0
    enriched_count = 0
    refreshed_count = 0
    inactive_count = 0
    summary_json = ''
    try:
        dynamodb = boto3.resource('dynamodb', region_name=_region)
        table = dynamodb.Table(_agent_table_name)
        now = _now_iso()

        for agent_id, record in _scan_state['records'].items():
            action = record['_action']
            verified = set(record['_humanVerified'])
            # runtimeId is the full ARN; agent_id is the canonical clean name
            # (AgentTable PK) used as the records dict key.
            arn = record['runtimeId']
            # Execution surface, set in stage 1. Validated rather than trusted, since
            # rows carried over from an earlier scanner version may not carry it.
            runtime_label = record.get('runtimeLabel')
            if runtime_label not in _RUNTIME_LABELS:
                runtime_label = 'AgentCore Runtime'
            # Classic agents belong to the Bedrock Agents inventory, not AgentCore.
            system_label = _SYSTEM_BY_RUNTIME_LABEL[runtime_label]

            cost_center = _read_cost_center_tag(arn)
            _write_agent_tags(arn, record['name'], cost_center)

            if action == 'add':
                item = _sanitize_for_ddb({
                    'agentId': agent_id,
                    'sk': 'INFO',
                    'runtimeId': arn,
                    'status': 'pending-review',
                    'discoveredAt': now,
                    'lastDiscoveredAt': now,
                    'name': record['name'],
                    'description': record['description'],
                    'runtimeVersion': record['runtimeVersion'],
                    # invocable starts False; the probe loop below flips it to True for
                    # IAM-auth runtimes once the row exists.
                    'platformId': _BEDROCK_PLATFORM_ID,
                    # Display fields the UI registry renders. The runtime label
                    # distinguishes a harness from a runtime and must not be blank, or
                    # the registry shows an empty Runtime column.
                    'runtime': runtime_label,
                    'platform': 'native',
                    'system': system_label,
                    # Default category so the registry never shows a blank; the
                    # enrichment loop below overwrites it when it derives one.
                    'category': 'AWS Native',
                    'invocable': False,
                    # The platform's run state, shown alongside the governance status
                    # above. `platformStatusAt` lets the UI say how old the sample is:
                    # discovery runs on a schedule, so this is point-in-time, not live.
                    'platformStatus': _normalize_platform_status(record.get('platformStatusRaw')),
                    'platformStatusRaw': record.get('platformStatusRaw') or '',
                    'platformStatusAt': now,
                    # Account identity for the registry's Account column, which would
                    # otherwise be blank for the most common case.
                    'platformMetadata': {
                        'source': 'discovery-scanner',
                        'accountId': _own_account_id(),
                        # The IAM account alias when set, '' otherwise, in which case the
                        # registry shows the bare account id as the console does.
                        'accountLabel': _account_alias(),
                        'region': _region,
                        'runtimeLabel': runtime_label,
                    },
                    # `owner` and `escalationGroup` are left unset: the `owner-populated`
                    # and `escalation-group-assigned` checks read those fields, so a
                    # placeholder makes them pass by construction (see upsert_agent). The
                    # LLM's guess belongs in `suggestedOwner`.
                })
                # Apply any LLM-set enrichment fields. aiInferred=True tells the portal
                # these came from automation, not a human edit.
                ai_set = False
                for field in ('displayName', *_ENRICHMENT_FIELDS, 'description'):
                    value = record.get(field)
                    if value:
                        item[field] = _sanitize_for_ddb(value)
                        if field != 'description':
                            ai_set = True
                if ai_set:
                    item['aiInferred'] = True
                if cost_center:
                    item['costCenter'] = cost_center
                table.put_item(Item=item)
                _assign_baseline_framework(table, agent_id, now)
                log_lifecycle_change(
                    entity_type='agent',
                    entity_id=arn,
                    previous_state='none',
                    new_state='pending-review',
                    reason='Newly discovered via AgentCore list-agents',
                    operator_id=_agent_id,
                )
                new_count += 1
                if work_item_id:
                    add_work_item_task(
                        work_item_id=work_item_id,
                        instructions=f'Added agent to Catalog: {agent_id}',
                        status='success',
                    )
                continue

            # action == 'enrich' or 'refresh': always update lastDiscoveredAt.
            update_parts = ['lastDiscoveredAt = :now']
            expr_vals: dict = {':now': now}
            # Platform run state is refreshed unconditionally, unlike the backfills below
            # which only fire when a field is missing: its whole value is its freshness,
            # so an agent that has since failed must not keep reporting 'running'.
            update_parts.append('platformStatus = :pstatus')
            update_parts.append('platformStatusRaw = :praw')
            update_parts.append('platformStatusAt = :now')
            expr_vals[':pstatus'] = _normalize_platform_status(record.get('platformStatusRaw'))
            expr_vals[':praw'] = record.get('platformStatusRaw') or ''
            if cost_center:
                update_parts.append('costCenter = :cc')
                expr_vals[':cc'] = cost_center

            # Backfill platformId on rows that predate the platform stamp: the agent
            # appeared in this scan, so it belongs to the Bedrock platform regardless of
            # what the row says.
            existing_platform = record['_existing'].get('platformId')
            if existing_platform != _BEDROCK_PLATFORM_ID:
                update_parts.append('platformId = :platform_id')
                expr_vals[':platform_id'] = _BEDROCK_PLATFORM_ID

            # Backfill the display fields (platform/runtime/system) on refresh/enrich too:
            # rows written by a bare upsert may lack them, and without them the UI cannot
            # group them as native AgentCore agents. runtimeId is refreshed as well, so a
            # redeploy (which regenerates the ARN suffix) leaves no stale ARN.
            if record['_existing'].get('platform') != 'native':
                update_parts.append('platform = :platform')
                expr_vals[':platform'] = 'native'
            if record['_existing'].get('runtime') != runtime_label:
                update_parts.append('runtime = :runtime')
                expr_vals[':runtime'] = runtime_label
            if record['_existing'].get('system') != system_label:
                update_parts.append('#sys = :system')
                expr_vals[':system'] = system_label
            if record.get('runtimeId') and record['_existing'].get('runtimeId') != record['runtimeId']:
                update_parts.append('runtimeId = :rid')
                expr_vals[':rid'] = record['runtimeId']
            # Backfill platformMetadata for the same reason as the fields above: a row
            # first written without it keeps the registry's Account column blank for
            # agents in this account, the most common case.
            if not (record['_existing'].get('platformMetadata') or {}).get('accountId'):
                update_parts.append('platformMetadata = :pmeta')
                expr_vals[':pmeta'] = _sanitize_for_ddb({
                    'source': 'discovery-scanner',
                    'accountId': _own_account_id(),
                    'accountLabel': _account_alias(),
                    'region': _region,
                    'runtimeLabel': runtime_label,
                })
            # Backfill a default category on rows that have none so the registry is not
            # blank. Skipped when the enrich loop below will set category itself:
            # two 'category =' clauses in one UpdateExpression are rejected by DynamoDB.
            enrich_will_set_category = (
                action == 'enrich'
                and 'category' not in verified
                and record.get('category')
                and record.get('category') != record['_existing'].get('category')
            )
            if not record['_existing'].get('category') and not enrich_will_set_category:
                update_parts.append('category = :cat')
                expr_vals[':cat'] = 'AWS Native'

            if action == 'enrich':
                ai_applied = False
                for field in ('displayName', *_ENRICHMENT_FIELDS):
                    if field in verified:
                        continue
                    value = record.get(field)
                    if not value:
                        continue
                    # Skip no-op writes.
                    if value == record['_existing'].get(field):
                        continue
                    placeholder = f':{field}'
                    update_parts.append(f'{field} = {placeholder}')
                    expr_vals[placeholder] = _sanitize_for_ddb(value)
                    ai_applied = True
                if ai_applied:
                    update_parts.append('aiInferred = :ai')
                    expr_vals[':ai'] = True
                    enriched_count += 1
                else:
                    refreshed_count += 1
            else:
                refreshed_count += 1

            update_kwargs = {
                'Key': {'agentId': agent_id, 'sk': 'INFO'},
                'UpdateExpression': 'SET ' + ', '.join(update_parts),
                'ExpressionAttributeValues': expr_vals,
            }
            # 'system' is a DynamoDB reserved word, so alias it when present.
            if '#sys = :system' in update_parts:
                update_kwargs['ExpressionAttributeNames'] = {'#sys': 'system'}
            table.update_item(**update_kwargs)
            if work_item_id:
                add_work_item_task(
                    work_item_id=work_item_id,
                    instructions=f'Updated agent in Catalog: {agent_id}',
                    status='success',
                )

        for agent_id in _scan_state['inactivate']:
            try:
                mark_agent_inactive(agent_id=agent_id, previous_status='active', work_item_id=work_item_id)
                inactive_count += 1
            except Exception:
                logger.error('Failed to mark inactive %s', agent_id)

        # Stamp invocable=false on non-Bedrock catalog rows outside this scan's working
        # set: the scanner cannot reach those agents, so they must never be reported as
        # invocable.
        stamped_invocable_false = 0
        for agent_id in _scan_state['stamp_invocable_false']:
            try:
                _write_invocable(agent_id, False)
                stamped_invocable_false += 1
            except Exception:
                logger.error('Failed to stamp invocable=false on %s', agent_id)

        # Invocability probe, only for agents just touched. The probe takes the ARN
        # (the AgentCore-side identifier); the write is keyed on the runtime-name-based
        # agentId (the AgentTable PK).
        invocable_count = 0
        for _cid, _crec in _scan_state['records'].items():
            _carn = _crec['runtimeId']
            result = _probe_invocable(_carn)
            if result is not None:
                _write_invocable(_cid, result)
                if result:
                    invocable_count += 1

        # Metric.
        try:
            boto3.client('cloudwatch', region_name=_region).put_metric_data(
                Namespace='FlowAMP/DiscoveryScanner',
                MetricData=[{'MetricName': 'AgentsDiscovered', 'Value': float(new_count), 'Unit': 'Count'}],
            )
        except Exception:
            logger.warning('Unable to emit AgentsDiscovered metric')

        _commit_trace_id = _scan_state.get('work_item_id') or 'discovery-scan-commit'
        log_decision_trace(
            trace_steps=[
                {
                    "step": "discovery_scan_complete",
                    "recordsCommitted": len(_scan_state["records"]),
                    "newAgents": new_count,
                    "enriched": enriched_count,
                    "refreshed": refreshed_count,
                    "markedInactive": inactive_count,
                    "invocable": invocable_count,
                    "startedAt": _scan_state.get("started_at"),
                },
            ],
            trace_id=_commit_trace_id,
        )
        log_agent_decision(
            action_type='discovery_scan_complete',
            input_summary=f'Committed {len(_scan_state["records"])} records',
            output_summary=(
                f'{new_count} new; {enriched_count} enriched; '
                f'{refreshed_count} refreshed; {inactive_count} inactivated'
            ),
            trace_id=_commit_trace_id,
        )

        summary = {
            'stage': 3,
            'agentsDiscovered': len(_scan_state['records']),
            'newAgents': new_count,
            'enriched': enriched_count,
            'refreshed': refreshed_count,
            'markedInactive': inactive_count,
            'invocable': invocable_count,
            'nonBedrockStampedInvocableFalse': stamped_invocable_false,
            'startedAt': _scan_state.get('started_at'),
            'completedAt': _now_iso(),
        }
        summary_json = json.dumps(summary)

        # Clear state, ready for the next scan.
        _scan_state['records'] = {}
        _scan_state['inactivate'] = []
        _scan_state['stamp_invocable_false'] = []
        _scan_state['completed_scan'] = False
        _scan_state['work_item_id'] = ''
        return summary_json
    except Exception as exc:
        # Capture the cause so `finally` can close the dispatch work item as 'failure'
        # with a useful note, then re-raise so the LLM sees the error.
        close_status = 'failure'
        close_error_message = f'{type(exc).__name__}: {exc}'
        logger.exception('commit_discovery_scan: aborted - %s', exc)
        raise
    finally:
        # Always close the dispatch work item so a partial scan never leaves it stuck
        # in-progress until backlog_sweep retries it. Best-effort: a close failure is
        # logged but never masks the original exception.
        if work_item_id:
            if close_status == 'done':
                close_note = (
                    f'Discovery scan complete: {new_count} new, '
                    f'{enriched_count} enriched, {inactive_count} inactivated.'
                )
            else:
                close_note = (
                    f'Discovery scan aborted before commit: '
                    f'{close_error_message or "unknown error"}'
                )
            try:
                close_assigned_work_item(
                    work_item_id=work_item_id,
                    status=close_status,
                    note=close_note,
                )
            except Exception as close_exc:
                logger.error(
                    'commit_discovery_scan: close_assigned_work_item failed for %s (status=%s): %s',
                    work_item_id, close_status, close_exc,
                )


@tool
def run_discovery_scan(work_item_id: str = '') -> str:
    """Run stage 1 and stage 3 back-to-back with no enrichment in between.

    Use only when there is no time or budget to enrich; prefer the staged tools so
    display names and categories get filled in.
    """
    start_result = json.loads(start_discovery_scan(work_item_id=''))
    if 'error' in start_result:
        return json.dumps(start_result)
    return commit_discovery_scan(work_item_id=work_item_id)


# =============================================================================
# STRANDS AGENT
# =============================================================================

_model_id = get_model_config()["defaultModel"]
_guardrail_id = os.environ.get('BEDROCK_GUARDRAIL_ID', '')
_guardrail_version = os.environ.get('BEDROCK_GUARDRAIL_VERSION', 'DRAFT')

if _guardrail_id:
    _model = BedrockModel(
        model_id=_model_id,
        guardrail_id = _guardrail_id,
        guardrail_version = _guardrail_version
    )
else:
    _model = BedrockModel(model_id=_model_id)

_DISCOVERY_TOOLS = [
    # Three-stage pipeline
    start_discovery_scan, get_pending_enrichments,
    enrich_from_runtime_metadata, enrich_via_agent_self_description,
    enrich_with_naming_convention, set_enrichment_fields,
    commit_discovery_scan,
    # One-shot fallback (no enrichment in the middle)
    run_discovery_scan,
    # Direct catalog reads / single-agent ops
    list_agent_runtimes, get_agent_catalog, get_agent_categories,
    upsert_agent, mark_agent_inactive, enrich_agent, invoke_agent,
    # Work-item lifecycle tools — used when invoked with a workItemId in the payload
    add_work_item_note, add_work_item_task, update_work_item_task,
    close_assigned_work_item,
]

SYSTEM_PROMPT = """You are the FlowAMP Discovery Scanner Agent. You discover and maintain the
Agent Catalog by scanning all AgentCore runtimes deployed in the AWS account.

## Three-stage discovery workflow (preferred for full scans)

### Stage 1 — Scan + analyze (deterministic)

Call `start_discovery_scan` once. It enumerates live AgentCore runtimes,
loads the existing catalog, and classifies every agent into:
  - **add**: a new runtime not yet in the catalog
  - **enrich**: an existing row missing displayName / category / riskTier /
    capabilities / suggestedOwner (where the field is not in
    humanVerifiedFields)
  - **refresh**: existing row complete; nothing to do beyond bumping
    lastDiscoveredAt
  - **inactivate**: catalog row absent from the live scan

The scan does NOT write to AgentTable. It builds an in-memory working set
that you operate on in stage 2.

### Stage 2 — Enrich (your job)

Call `get_pending_enrichments` to see records flagged 'add' or 'enrich' and
their `missingFields`. For each one, choose ONE OR MORE of these tools to
gather signal:

  - `enrich_from_runtime_metadata(agentId)` — pull the description/name from
    the AgentCore control plane. Cheap; try this first.
  - `enrich_via_agent_self_description(agentId)` — invoke the runtime and ask
    "what do you do?". Use when the runtime metadata is generic or empty.
    Each pending record carries an `invocable` field: when it's not True
    (JWT-only runtime, or a non-Bedrock platform), this tool refuses
    immediately — pick a different enrichment path.
  - `enrich_with_naming_convention(agentId)` — deterministic title-case +
    suffix-strip for displayName. Cheap; useful when the raw runtime name is
    already descriptive.
  - Or if the runtime name is simple to decipher, you can just transform it
    into a human readable form yourself (e.g. "customer_service_dev" => "Customer Service")

Once you've gathered enough signal, call `set_enrichment_fields` once or
multiple times per record. Empty-string args are ignored, so you can update
one field at a time. Allowed fields:
  - **displayName** (≤ 80 chars, human-friendly, e.g. "Grid Stability Monitor")
  - **category** — call `get_agent_categories` once per scan to fetch the
    live category list, then pass one of the returned `id` values (NOT the
    `name`). Categories are managed in the Governance UI and may change
    over time, so always read them rather than guessing.
  - **riskTier** (one of: low, medium, high, critical). Operational risk
    to the company.
  - **capabilities** (short sentence or comma separated list describing what the agent can do)
  - **suggestedOwner** (a team or person)
  - **description** (longer free text)

**Guardrails**: any field already locked in `humanVerifiedFields` is skipped
silently. Immutable fields (agentId, runtimeId, status, etc.) cannot be set.
Invalid enum values are rejected with no partial write.

### Stage 3 — Save (deterministic)

Once you're satisfied with every record's enrichment, call
`commit_discovery_scan`. This flushes the in-memory state to AgentTable:
  - 'add' records become INFO rows with status='pending-review'
  - 'enrich' records get UpdateItem with your fields, never overwriting
    humanVerifiedFields
  - 'refresh' records just bump lastDiscoveredAt
  - inactivate list is processed last
  - the Work Item is marked as `done`

State is cleared after commit; a new scan starts fresh.

IF THERE ARE ANY NEW OR ENRICHED RECORDS, YOU MUST RUN COMMIT_DISCOVERY_SCAN!!!!

## Other tools

- `run_discovery_scan` — one-shot wrapper that runs stage 1 + stage 3 with
  NO enrichment. Use only when you have no time/budget to enrich. Prefer
  the staged tools.
- `list_agent_runtimes` — raw AgentCore list (no catalog comparison).
- `get_agent_catalog` — read current AgentTable rows (filter by status).
- `get_agent_categories` — fetch the canonical category list from the
  FLOWAMP_CATEGORIES sentinel. Use the returned `id` values for the
  `category` field on set_enrichment_fields.
- `invoke_agent` — research only; do not use to trigger actions.
- `enrich_agent` — legacy single-agent Bedrock-driven enrichment; the
  three-stage workflow above is preferred.
- `mark_agent_inactive`, `upsert_agent` — single-row ops; commit_discovery_scan
  handles these in bulk.

### Work-item lifecycle (when dispatched with a workItemId)

- `add_work_item_note` — free-form progress notes; pass
  `documents_decision=True` for judgment calls so an agent_decision event is
  auto-emitted.
- `add_work_item_task` / `update_work_item_task` — break complex work into
  checkable steps.
- `close_assigned_work_item` — finalise with `done` / `failure` / `blocked`.
  REQUIRES a `note` argument. agent_decision is auto-emitted on close.

When dispatched with a work item:
1. Add a note describing what you're about to do.
2. Run the three-stage discovery (stage 1 → enrichment loop → stage 3).
3. Add a note summarising the result.
4. Call `close_assigned_work_item` with status='done' (or 'failure' /
   'blocked' on error). Never leave the work item in 'in-progress'. /
   (committing a scan will complete the work item)

## Reporting rules (important)

- The `list_agent_runtimes` and `start_discovery_scan` tools call the AWS AgentCore
  control plane and it IS available — never claim the service is unavailable,
  unreachable, or missing. If a tool returns a JSON list (even empty), that is a
  SUCCESS: report the count and names exactly as returned.
- Only report a failure if a tool result actually contains an `"error"` field, and
  in that case quote that error verbatim — do not invent or paraphrase a cause.
- Never fabricate, guess, or editorialize about infrastructure state. Report only
  what the tools returned.

Always use tools to fetch real data before answering. Be honest, and think carefully!"""

agent = Agent(model=_model, tools=_DISCOVERY_TOOLS, system_prompt=SYSTEM_PROMPT)

# =============================================================================
# AGENTCORE RUNTIME ENTRY POINT
# =============================================================================

app = BedrockAgentCoreApp()


@app.entrypoint
async def invoke(payload):
    """Entry point for AgentCore invocations.

    Accepts two payload shapes:
    1. Work-item dispatch: `workItemId`, `workItem` (full snapshot) and `messages`
       whose first user message is the work-item prompt. The work-item tools
       (add_work_item_note, add_work_item_task, update_work_item_task,
       update_work_item_info, close_assigned_work_item) record progress and finalise
       the item; in this repo they are safe no-ops because there is no AOP runtime.
    2. Direct conversation (no workItemId): the latest user message is used as-is,
       defaulting to a generic discovery-scan instruction. This is the one-shot path.
    """
    _ensure_otel_processor()  # the ADOT provider exists by now
    logger.info(
            'Discovery Scanner Agent Invoked!'
        )
    logger.info(f"Starting invoke with payload: {json.dumps(payload)[:150]}...")
    messages = payload.get("messages", [])
    user_message = next(
        (msg.get("content", "") for msg in reversed(messages) if msg.get("role") == "user"),
        "Run a discovery scan and report results.",
    )
    session_id = payload.get("sessionId", f"session-{id(payload)}")

    logger.info(f"Starting invoke with message: {user_message[:150]}...")
    logger.info(f"Session ID: {session_id}")

    complete_response = ''
    async for event in agent.stream_async(user_message):
        if 'data' in event:
            chunk = event['data']
            complete_response += chunk
            yield {'type': 'text', 'result': chunk, 'sessionId': session_id}

    yield {'type': 'output', 'result': complete_response, 'sessionId': session_id}


if __name__ == "__main__":
    app.run()
