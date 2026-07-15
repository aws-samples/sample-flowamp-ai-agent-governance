"""Discovery Scanner — Strands agent that discovers AgentCore runtimes and maintains the Agent Catalog.

Single-table data model. Audit, work-item, and compliance data all live in the
one AgentTable named by the ``AGENT_TABLE_NAME`` env var: the audit/work-item/
compliance rows are sub-collection rows (EVENT#/REVIEW#/COMPLIANCE#/MODEL#)
under the same partition key. The catalog-read helper (``list_active_agents``
in ``flowamp_tools.agent_catalog``) scans the AgentTable with a ``sk='INFO'``
FilterExpression; the table has no GSI.
"""
# ---------------------------------------------------------------------------
# OTEL bootstrap — MUST run before any other import (boto3, strands, etc.).
#
# AgentCore Runtime does not auto-wrap the direct-code entrypoint with the
# OpenTelemetry auto-instrumentation command. Per the AWS docs
# (bedrock-agentcore/observability-configure §"Enabling observability in agent
# code for AgentCore-hosted agents"), the agent must be launched as
# `opentelemetry-instrument python main.py` — that wrapper reads the
# OTEL_*/AGENT_OBSERVABILITY_ENABLED env vars and installs the global
# TracerProvider + OTLP exporter wired to aws/spans. Direct-code deploy launches
# a bare `python main.py`, so aws-opentelemetry-distro is not invoked and
# Strands' spans have no exporter.
#
# Because the launch command is fixed in direct-code deploy, this module
# re-execs itself under opentelemetry-instrument on startup. The _OTEL_REEXEC
# guard makes this a one-shot: the re-exec'd process sees the flag set, skips
# the branch, and proceeds to the real imports below (now fully instrumented).
# The re-exec is guarded by AGENT_OBSERVABILITY_ENABLED so local/
# non-observability runs (where opentelemetry-instrument may be absent) are
# unaffected. Any failure to re-exec is swallowed so a missing wrapper never
# crashes the scanner.
import os as _os
import sys as _sys

if (
    _os.environ.get("AGENT_OBSERVABILITY_ENABLED") == "true"
    and not _os.environ.get("_OTEL_REEXEC")
):
    _os.environ["_OTEL_REEXEC"] = "1"
    # Invoke the auto-instrumentation via its Python entry point rather than the
    # `opentelemetry-instrument` console script: the bundle is built with
    # `uv pip install --target`, so that script lands in <bundle>/bin (not on the
    # runtime PATH) and its shebang points at the build machine's Python (invalid
    # in the arm64 runtime container). Re-exec the container's own interpreter
    # (sys.executable) and call the script's public entry point,
    # `opentelemetry.instrumentation.auto_instrumentation.run()`, which is
    # importable from the vendored packages in the bundle root. run() sets up
    # PYTHONPATH (to load the ADOT sitecustomize) and execs `python main.py` again,
    # this time fully instrumented. The _OTEL_REEXEC guard makes it one-shot.
    _bundle_dir = _os.path.dirname(_os.path.abspath(__file__))
    # Ensure the re-exec'd `python -c` process can import the vendored ADOT modules
    # regardless of the runtime's CWD.
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
        # Auto-instrumentation unavailable (e.g. local dev without ADOT vendored) —
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
# Strands' native OTEL spans into the GenAI semantic conventions AgentCore Evaluations
# reads.
#
# Two requirements govern how the processor is attached:
#   1. Do NOT call StrandsTelemetry(): it calls set_tracer_provider() with an
#      exporter-less provider. OTEL is first-caller-wins, so that provider would
#      take precedence over AgentCore's ADOT provider (the one wired to aws/spans).
#      Attach the OpenInference processor to the EXISTING global provider instead.
#   2. Attach LAZILY on first invoke (see _ensure_otel_processor), not at import
#      time. The re-exec at the top of this module launches under
#      opentelemetry-instrument, which installs the ADOT global TracerProvider
#      before imports run. Lazy attach is a defensive guard for launch paths where
#      the provider is not ready at import (e.g. the re-exec was skipped locally):
#      in that case get_tracer_provider() returns the ProxyTracerProvider (no
#      add_span_processor). By first invoke the real provider exists, so attachment
#      is reliable in every launch path.
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

# Canonical platformId (FLOWAMP_PLATFORMS sentinel id) for the AWS Bedrock
# AgentCore platform — every runtime returned by list_agent_runtimes is
# automatically stamped with this value. The env var lets ops swap the id
# (e.g. when seeding a custom platform). Default mirrors the value seeded by
# scripts/seed_sentinels.py.
_BEDROCK_PLATFORM_ID = os.environ.get(
    'AMAZON_BEDROCK_AGENTCORE_PLATFORM_ID',
    'amazon-bedrock-agentcore',
)

# Canonical baseline framework auto-assigned to every newly discovered agent.
# Mirrors the FLOWAMP_BASELINE row seeded into the AgentTable; the
# agent_compliance_service.add_agent_framework helper auto-creates the same
# COMPLIANCE# row when a user assigns any non-baseline framework, so the
# discovery scanner side is just the earlier of the two write paths.
_BASELINE_FRAMEWORK_ID = 'FLOWAMP_BASELINE'

# ---------------------------------------------------------------------------
# Singleton scan state — held in the strands runtime across the three stages
# of a discovery scan. The agent (LLM) is expected to call them in order:
#
#   Stage 1 — start_discovery_scan: list runtimes + catalog, classify every
#             agent into add / enrich / refresh / inactivate, populate state.
#   Stage 2 — LLM enriches the records flagged 'add' or 'enrich' using the
#             enrich_* tools, then calls set_enrichment_fields to commit
#             changes to the in-memory record.
#   Stage 3 — commit_discovery_scan: flush the state to AgentTable with
#             guardrails, mark inactivates, emit metrics, clear state.
#
# Holding state at module scope means it persists for the lifetime of the
# AgentCore runtime, but resets each cold start. That's the intended
# guardrail surface: every read/write of agent metadata flows through these
# tools, never directly into DDB from the LLM.
# ---------------------------------------------------------------------------
_scan_state: dict = {
    'records': {},          # ARN -> working record (see schema below)
    'inactivate': [],       # Bedrock-platform ARNs in catalog but missing
                            # from live scan; the discovery scanner only
                            # owns Bedrock lifecycle, so non-Bedrock rows
                            # are excluded from this list.
    'stamp_invocable_false': [],  # Non-Bedrock catalog ARNs that need their
                                  # invocable flag set to false so other
                                  # subsystems (UI, agent tools) know not
                                  # to invoke them.
    'started_at': '',
    'completed_scan': False,
    'work_item_id': '',     # set in start_discovery_scan; commit reuses it
                            # so the LLM only has to pass it once
}

# A working record (one entry in _scan_state['records']) carries:
#   agentId / runtimeId       — canonical ARN; immutable
#   name / description /
#   runtimeVersion / costCenter — pulled from AgentCore at scan time
#   _action                   — 'add' | 'enrich' | 'refresh'
#   _existed_before           — True if there was an INFO row before this scan
#   _existing                 — snapshot of the existing INFO row (or {})
#   _humanVerified            — list[str] of fields the portal locked
#   displayName / category /
#   riskTier / capabilities /
#   suggestedOwner            — enrichment slots filled by the LLM

# Fields the agent is forbidden to mutate via set_enrichment_fields. These are
# either keyed by AgentTable PK (agentId, runtimeId) or are lifecycle/audit
# fields that only humans (portal) or automated lifecycle hooks may set.
_IMMUTABLE_FIELDS = frozenset({
    'agentId', 'runtimeId', 'discoveredAt', 'status', 'lifecycleStatus',
    'humanVerifiedFields', 'aiInferred',
})

# Fields the agent IS allowed to set on the in-memory record. Anything outside
# this set is rejected by set_enrichment_fields.
_ENRICHABLE_FIELDS = frozenset({
    'displayName', 'category', 'riskTier', 'capabilities', 'suggestedOwner',
    'description', 'invocable',
})

# Fallback category ids used only when the FLOWAMP_CATEGORIES sentinel row is
# unreadable (e.g. in unit tests where the sentinel hasn't been seeded). The
# live source of truth is the sentinel — see get_agent_categories() — and
# set_enrichment_fields prefers whatever the sentinel returns.
_FALLBACK_CATEGORY_IDS = frozenset({
    'grid-ops', 'safety', 'finance', 'asset-mgmt',
    'trading', 'platform', 'customer-ops', 'other',
})

# Cached sentinel response. Each entry is the full dict from
# AgentTable[FLOWAMP_CATEGORIES][CONFIG].categories — typically
# {id, name, icon?, color?}. Populated lazily by get_agent_categories.
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
    """Return the set of accepted category ids — sentinel first, fallback
    second. Caches the sentinel read on the module so subsequent
    set_enrichment_fields calls are zero-cost."""
    global _categories_cache
    if _categories_cache is None:
        _categories_cache = _read_categories_sentinel()
    if _categories_cache:
        return frozenset(c['id'] for c in _categories_cache)
    return _FALLBACK_CATEGORY_IDS

# Suffixes/tokens we strip when deriving a human-friendly displayName from a
# raw runtime name (matches the seed_demo.py naming style: title-case nouns,
# no env suffix, no '_runtime'/'_lambda'/etc. trailing tokens).
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


def _runtime_id_from_arn(arn: str) -> str:
    """Extract the agentRuntimeId (the AWS-side identifier, *with* the
    AgentCore-appended 10-char suffix) from a runtime ARN. This is what
    ``bedrock-agentcore-control:GetAgentRuntime`` expects in its
    ``agentRuntimeId`` parameter — passing the full ARN there fails with
    AccessDenied (AWS's privacy-preserving "not found" response)."""
    if not arn:
        return arn
    return arn.split(':runtime/', 1)[1] if ':runtime/' in arn else arn


def _agent_id_from_arn(arn: str) -> str:
    """Derive the AgentTable partition key (agentId) from a runtime ARN or ID.

    Bedrock AgentCore runtime ARNs look like::

        arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/{agentRuntimeId}

    where ``{agentRuntimeId}`` is ``{runtimeName}-{10-char-AWS-suffix}``. The
    runtime *name* is what the operator/CDK chose (e.g.
    ``flowamp_orchestration_agent_dev``); AWS appends the 10-character
    alphanumeric suffix to guarantee global uniqueness across versions.

    AgentTable rows are keyed by the operator-friendly *name* — not the
    suffixed runtime id, and not the full ARN. Two reasons:

      1. Stable agentIds across runtime redeploys (a redeploy regenerates
         the suffix; the name does not change).
      2. URL paths like ``/agents/{agentId}/approve`` stay free of ``:`` and
         ``/`` characters that would otherwise need URL-encoding.

    The full ARN is preserved on each row's ``runtimeId`` field for
    InvokeAgentRuntime / GetAgentRuntime calls that genuinely need it.

    Falls back gracefully on inputs that don't match the runtime-ARN shape so
    callers operating on legacy data are never silently mangled.
    """
    if not arn:
        return arn
    runtime_id = arn.split(':runtime/', 1)[1] if ':runtime/' in arn else arn
    return _AGENTCORE_RUNTIME_SUFFIX_RE.sub('', runtime_id)


def _clean_agent_id(arn: str, name: str) -> str:
    """Return the agentId to use for an AgentTable row.

    Priority:
      1. ``name`` (``agentRuntimeName`` from the AgentCore API) when it is a
         clean identifier — no ``:`` or ``/`` characters — meaning it is the
         operator-defined name rather than a full ARN or ARN fragment.
      2. ``_agent_id_from_arn(arn)`` as the regex-based fallback for callers
         that only have an ARN.

    Using the API-supplied name directly is more reliable than ARN regex
    stripping: the name is always the exact operator-defined string and never
    varies based on suffix length or ARN shape changes.
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
    try:
        tags = {'flowamp:agentId': agent_id}
        if cost_center:
            tags['flowamp:cost-center'] = cost_center
        ctrl = boto3.client('bedrock-agentcore-control', region_name=_region)
        ctrl.tag_resource(resourceArn=runtime_arn, tags=tags)
    except Exception:
        logger.warning('Unable to write tags')


def _extract_model_id_from_runtime(runtime_info: dict) -> str | None:
    """Best-effort extraction of an agent's foundation model from AgentCore
    runtime metadata. AgentCore agents don't have a single canonical
    "foundationModel" field (unlike bedrock-agent), so we inspect signals in
    priority order:

      1. environmentVariables — many agents read FLOWAMP_MODEL_ID / MODEL_ID /
         BEDROCK_MODEL_ID at startup.
      2. agentArtifact.containerConfig.containerUri tag — image tags often
         encode the model name (e.g., `myrepo/agent:claude-3-sonnet`).
      3. tags — `flowamp:model-id` is a convention some runtimes set
         explicitly.

    Returns the first non-empty match or None if nothing usable is found.
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
    """Add `model_id` to the agent's `modelIds` list (idempotent) and ensure
    a corresponding row exists on AgentTable so the Model Registry view
    surfaces it. If the model is unknown to the registry, we drop a minimal
    placeholder row that the AC-6 nightly sync (or a manual scan) will
    enrich on the next pass."""
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

    # Ensure a MODEL# row exists so the Model Registry shows the inferred
    # model immediately. Best-effort; the nightly sync (AC-6) is authoritative.
    try:
        # Parse provider/name#version from "anthropic/claude-3-sonnet#1" if
        # present; otherwise treat the whole string as both the modelId and
        # the displayed name and infer the provider from the first segment.
        provider = model_id.split('/')[0] if '/' in model_id else 'unknown'
        name = model_id.split('/')[-1].split('#')[0] if '/' in model_id else model_id
        version = model_id.split('#')[-1] if '#' in model_id else '1'
        sk = f"MODEL#{provider}/{name}#{version}"
        # Conditional put — never overwrite an existing registry row, which
        # may carry richer Bedrock metadata from the AC-6 sync. Registry rows
        # share the FLOWAMP_MODELS sentinel partition (mirrors the
        # FLOWAMP_PLATFORMS / FLOWAMP_CATEGORIES pattern) so list_models() is
        # a single Query rather than a GSI scan.
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
        # ConditionalCheckFailedException is the expected case for known
        # models — silently skip. Other errors are non-fatal here.
        pass


# =============================================================================
# TOOLS — each is an atomic operation callable by the Strands Agent
# =============================================================================

@tool
def list_agent_runtimes() -> str:
    """List all live AgentCore runtimes from the AgentCore control plane.

    Returns a JSON list of runtime summaries including ARN, name, and version.
    """
    agentcore_client = boto3.client('bedrock-agentcore-control', region_name=_region)
    agents = []
    next_token = None

    for attempt in range(4):
        try:
            kwargs = {} if not next_token else {'nextToken': next_token}
            response = agentcore_client.list_agent_runtimes(**kwargs)
            agents.extend(response.get('agentRuntimes', response.get('agentRuntimeSummaries', [])))
            next_token = response.get('nextToken')
            if not next_token:
                break
            attempt = 0
        except Exception as exc:
            if 'Throttling' in type(exc).__name__ and attempt < 3:
                _jitter_delay(_BACKOFF_BASE, attempt)
                continue
            # Log the real exception to stdout (reaches the runtime CloudWatch log
            # group) so control-plane failures are diagnosable, not just paraphrased
            # by the LLM as "service not available".
            logger.error("list_agent_runtimes failed: %s: %s", type(exc).__name__, exc)
            return json.dumps({'error': f'{type(exc).__name__}: {exc}', 'agents': []})

    logger.info("list_agent_runtimes: %d runtime(s) returned", len(agents))

    # Normalize: ensure every item exposes a clean 'agentRuntimeName' field
    # (without the AWS-appended suffix) so callers can pass it directly to
    # upsert_agent without re-deriving it from the ARN.
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
    """Return the canonical agent categories from the FLOWAMP_CATEGORIES
    sentinel row.

    This is the live source of truth (managed via the Governance UI).
    Always call this before set_enrichment_fields so you use a current
    `id` rather than a guess. Returns JSON: {"items": [{id, name, icon?,
    color?}, ...], "count": N}.
    """
    global _categories_cache
    cats = _read_categories_sentinel()
    _categories_cache = cats  # refresh cache so set_enrichment_fields agrees
    return json.dumps({'items': cats, 'count': len(cats)}, default=str)


def _assign_baseline_framework(table, agent_id: str, now: str) -> None:
    """Write a COMPLIANCE#FLOWAMP_BASELINE row for a freshly discovered agent.

    Idempotent via attribute_not_exists — re-running discovery against an
    already-baselined agent is a no-op. Failures are logged but never raised:
    AgentTable INFO write succeeds first, and a missing baseline row is
    benign (the dashboard treats baseline as implicit and the user can
    re-trigger via the Manage Frameworks UI).
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
                 skip_fields: set | None = None) -> str:
    """Upsert a single discovered runtime into AgentTable.

    New records receive lifecycleStatus='pending-review' so a human reviewer
    can approve them before they enter the active pool.  Re-scans of existing
    records preserve the current lifecycleStatus (stored as 'status') by
    omitting it from the UpdateExpression — callers may pass an explicit
    skip_fields set, but 'status' is always skipped on the update path.

    Returns JSON with {'isNew': bool, 'agentId': str}.
    """

    logger.info(
            'Upserting agent %s',
            agent_runtime_name
        )
    skip_fields = (skip_fields or set()) | {'status'}  # status is always preserved on update

    dynamodb = boto3.resource('dynamodb', region_name=_region)
    table = dynamodb.Table(_agent_table_name)
    now = _now_iso()

    # Prefer the operator-defined agentRuntimeName when it is a clean identifier
    # (no ':' or '/' characters). Fall back to ARN regex stripping only when the
    # name is absent or looks like an ARN itself. The full ARN is preserved in
    # runtimeId; agentId must be the stable friendly name so URL paths
    # (/agents/{agentId}/...) stay clean across runtime redeploys.
    agent_id_key = _clean_agent_id(agent_runtime_arn, agent_runtime_name)
    resp = table.get_item(Key={'agentId': agent_id_key, 'sk': 'INFO'})
    existing = resp.get('Item')

    cost_center = _read_cost_center_tag(agent_runtime_arn)
    _write_agent_tags(agent_runtime_arn, agent_runtime_name, cost_center)

    if existing is None:
        # New record: enter pending-review so a reviewer can approve before activation.
        # Default governance fields (`owner`, `escalationGroup`) so the
        # rai-scorer's `owner-populated` and `escalation-group-assigned`
        # checks see something on first scan. The reviewer can change them
        # via the catalog before approval; on re-scan these are preserved
        # rather than overwritten with whatever the operator set.
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
            'owner': 'platform-engineering',
            'escalationGroup': 'platform-engineering',
            # FinOps tag taxonomy defaults (U-094 CNTR-PLATFORM-018 §tags snapshot).
            # Operators update these via PATCH /agents/{id} after reviewing the record.
            'agentClass': 'external',
            'businessUnit': 'external',
        })
        if cost_center:
            item['costCenter'] = cost_center
        table.put_item(Item=item)
        _assign_baseline_framework(table, agent_id_key, now)
        # Write a REVIEW# row so the unified Review History tab surfaces
        # the scanner's first observation of this agent alongside reviewer
        # approvals / rejections / decommissions.
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
    """Mark an agent as inactive in AgentTable because it was absent from the
    live scan.

    Refuses to inactivate an agent whose ``platformId`` is not the AWS Bedrock
    AgentCore platform — those agents live on platforms (manual registration,
    future connectors) the discovery scanner cannot see, so absence from THIS
    scan is not evidence the agent is gone. Returns an error JSON in that
    case so the LLM gets visible feedback and doesn't blindly retry.

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

    table.update_item(
        Key={'agentId': agent_id, 'sk': 'INFO'},
        UpdateExpression='SET #s = :inactive',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':inactive': 'inactive'},
    )
    # Write a REVIEW# row so the Review History tab surfaces the
    # scanner-driven inactivation alongside reviewer actions and admin
    # decommissions.
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

    # AC-7: extract the underlying foundation model from runtime metadata so
    # it lands on the agent's modelIds list (and into the Model Registry via
    # the AC-6 sync helper if not yet registered). The model identifier may
    # live in several places depending on how the runtime was built — check
    # each in priority order and take the first non-empty match.
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
        resp = bedrock.invoke_model(
            modelId='anthropic.claude-3-haiku-20240307-v1:0',
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

    Uses the control-plane GetAgentRuntime to check authorizerConfiguration —
    no model invocation required. IAM-auth runtimes have no customJwtAuthorizer
    field, so they are reachable via SigV4 SDK calls (boto3 / API Lambda).

    Note: ``GetAgentRuntime`` expects the bare ``agentRuntimeId`` (the
    suffixed runtime name like ``flowamp_orchestration_agent_dev-ofYZpKEzg8``),
    NOT the full ARN. Passing the ARN fails with AccessDeniedException
    regardless of IAM permissions (AWS-side privacy-preserving "not found").
    """
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
# Stage 1: start_discovery_scan
#   - List live AgentCore runtimes; load existing catalog
#   - Classify every agent into add / enrich / refresh / inactivate
#   - Populate _scan_state. No DDB writes.
#
# Stage 2: LLM-driven enrichment (zero, one, or many calls per record)
#   - get_pending_enrichments — what still needs work
#   - enrich_from_runtime_metadata / enrich_via_agent_self_description /
#     enrich_with_naming_convention — gather raw signal
#   - set_enrichment_fields — apply changes to the in-memory record (guardrails)
#
# Stage 3: commit_discovery_scan
#   - Flush _scan_state to AgentTable, marking inactives
#   - Emit metrics, clear state
# =============================================================================

def _classify_record(arn: str, live_data: dict, existing: dict | None) -> dict:
    """Build the working record for one runtime + decide its action.

    Action rules:
      - 'add'    — no existing INFO row
      - 'enrich' — existed, but at least one enrichment field is missing /
                   empty AND not in humanVerifiedFields
      - 'refresh'— fully populated; nothing for the LLM to do
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
        # The LLM may fill in any of these via set_enrichment_fields. Pre-seed
        # with whatever the existing row already has so the LLM sees them.
        'displayName': existing.get('displayName', ''),
        'category': existing.get('category', ''),
        'riskTier': existing.get('riskTier', ''),
        'capabilities': existing.get('capabilities', ''),
        'suggestedOwner': existing.get('suggestedOwner', ''),
        # Every runtime returned by list_agent_runtimes lives on the AWS
        # Bedrock AgentCore platform — stamp the canonical platformId here so
        # the LLM cannot influence it via enrichment. invocable is hydrated
        # from the existing row (commit re-probes for fresh values).
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
    """Stage 1 — scan AgentCore + analyze the catalog.

    Lists live runtimes, loads existing AgentTable rows, and classifies every
    agent into one of four buckets:
      - add:        new runtime, not in catalog
      - enrich:     existing row missing displayName/category/riskTier/etc.
      - refresh:    existing row complete; will only bump lastDiscoveredAt
      - inactivate: catalog row absent from the live scan

    Populates the singleton _scan_state and returns a JSON summary so the LLM
    can decide what to enrich next. **Does not write to AgentTable yet.** Call
    `commit_discovery_scan` after enrichment to persist results.
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

    # TODO(DISC-BEHAVIOR-001): Scope intentionally limited to AgentCore runtimes.
    # When multi-platform connectors land, dispatch by platform here.
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

    # Reset state. Module scope outlives a single invocation, so a fresh scan
    # must clear leftovers from any prior run. Capture the work_item_id so
    # commit_discovery_scan can reuse it without the LLM having to pass it
    # twice.
    _scan_state['records'] = {}
    _scan_state['inactivate'] = []
    _scan_state['stamp_invocable_false'] = []
    _scan_state['started_at'] = _now_iso()
    _scan_state['completed_scan'] = False
    _scan_state['work_item_id'] = work_item_id

    # `live_agent_ids` is the set of AgentTable PKs (runtime names) currently
    # discoverable on AgentCore. Both `existing` (DDB lookups) and `live_*`
    # checks below operate in PK space, NOT ARN space — `_classify_record`
    # still receives the full ARN because it stamps `runtimeId` from it.
    live_agent_ids = set()
    # ARNs of every runtime returned by this scan — used to defend against
    # inactivating a seeded/legacy row whose `agentId` doesn't match the
    # current schema but whose `runtimeId` field still points at a live
    # runtime. Without this guard, an agentId-format migration (e.g. ARN →
    # suffixed name → bare name) leaves seeded platform rows orphaned and
    # the next scan inactivates them.
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
        # Probe invocability NOW so the value is exposed to the LLM via
        # get_pending_enrichments — otherwise the LLM might attempt
        # enrich_via_agent_self_description on a JWT-auth runtime that's
        # guaranteed to fail. probe is best-effort; on lookup error we keep
        # whatever the existing row carried.
        probed = _probe_invocable(arn)
        if probed is not None:
            record['invocable'] = probed
            # Persist immediately for any agent that already has a DDB row.
            # Defers nothing to commit_discovery_scan: even if the LLM-driven
            # commit phase never runs (standalone scan trigger, partial
            # failure, etc.), the catalog's invocable flag still reflects
            # the live AgentCore authorizer config. New agents (not yet in
            # `existing`) get their initial invocable value in commit when
            # the row is created. Skip rewriting when the value is unchanged.
            if existing_row and existing_row.get('invocable') is not probed:
                try:
                    _write_invocable(agent_id, probed)
                    stage1_invocable_writes += 1
                except Exception:
                    logger.warning('Stage-1 invocable write failed for %s', agent_id)
        # Key by the canonical agentId (clean name) so that enrichment tools
        # can look up records using the same id that get_pending_enrichments
        # exposes to the LLM. The full ARN is preserved on record['runtimeId'].
        _scan_state['records'][record['agentId']] = record

    # Inactivation candidates: catalog rows missing from the live scan, except
    # demo agents in dev (so seeded data survives re-scans). The discovery
    # scanner only owns Bedrock-platform lifecycle, so non-Bedrock rows are
    # NEVER inactivated by this scan — they live on platforms (manual,
    # future connectors) the scanner doesn't see. Those rows do, however,
    # get their `invocable` flag stamped to false so the LLM and other
    # consumers know not to attempt SigV4 invocations against them.
    for agent_id, record in existing.items():
        if agent_id in live_agent_ids:
            continue
        # Defense against agentId schema drift: if the row's runtimeId field
        # points at a runtime returned by this scan, the agent is NOT
        # orphaned — its agentId just predates the current schema. Skip
        # inactivation. (Re-keying to the canonical agentId is out of scope
        # here; it's a separate dedupe concern.)
        if record.get('runtimeId') and record.get('runtimeId') in live_runtime_arns:
            continue
        if record.get('status') == 'inactive':
            continue
        if _environment == 'dev' and 'DEMO' in (record.get('description') or ''):
            continue
        if record.get('platformId') == _BEDROCK_PLATFORM_ID:
            _scan_state['inactivate'].append(agent_id)
        else:
            # Only queue a write when the flag is missing or already True —
            # avoid no-op writes when invocable is already false.
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
        # Number of existing catalog rows whose `invocable` flag was refreshed
        # in this stage from a fresh GetAgentRuntime probe.
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
            # Platform + invocability surface the immutable platform stamp
            # and the latest invocability snapshot. invocable=false means
            # enrich_via_agent_self_description WILL refuse — pick a
            # different enrichment path (metadata / naming convention).
            'platformId': r.get('platformId'),
            'invocable': r.get('invocable'),
        }
        for r in _scan_state['records'].values()
        if r['_action'] in ('add', 'enrich')
    ]
    return json.dumps({'pending': pending, 'count': len(pending)})


@tool
def enrich_from_runtime_metadata(agent_id: str) -> str:
    """Pull the description + name from the AgentCore control plane for one
    runtime. Returns the raw metadata as JSON; the LLM can decide how to use
    it (call set_enrichment_fields with a derived displayName, copy description
    verbatim, etc.).
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
    """Invoke the discovered agent and ask 'in one sentence, what do you do?'.
    Returns the agent's self-description so the LLM can use it to fill in
    capabilities/displayName etc. Best effort — may fail for JWT-only
    runtimes; the LLM should fall back to other enrichment paths.

    Refuses when the working record's ``invocable`` flag is anything other
    than True — non-invocable agents (JWT-only, or non-Bedrock platform
    rows that never expose a SigV4-callable runtime) would just throw an
    AccessDenied at the AgentCore control plane, so we short-circuit and
    surface a clear message to the LLM instead.
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
    """Apply the FlowAMP naming convention to the raw runtime name and return
    a candidate displayName.

    Rules (mirrors seed_demo.py style):
      - Strip env suffix (-dev / -prod / _staging / etc.)
      - Strip generic trailing nouns (runtime, lambda, function, service, agent)
      - Replace _ and - with spaces
      - Title-case
      - Cap at 6 words

    Pure deterministic — no LLM call. The agent picks this when the raw name
    is descriptive enough to clean up directly.
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
    """Apply enrichment to one in-memory record. Empty-string args are ignored
    so the LLM can update one field at a time.

    Guardrails (rejected with no partial write):
      - agent_id must be in the current scan state
      - any field listed in humanVerifiedFields is silently skipped
      - immutable fields (agentId, runtimeId, status, etc.) cannot be passed
      - category and riskTier values are checked against the canonical enums
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
    # Filter empties + immutables.
    proposed = {k: v for k, v in proposed.items() if v != '' and k in _ENRICHABLE_FIELDS}

    # Validate every proposed value first so we don't half-apply on error.
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

    # Recompute _missing so subsequent get_pending_enrichments reflects progress.
    record['_missing'] = [
        f for f in ('displayName', *_ENRICHMENT_FIELDS)
        if not record.get(f) and f not in record['_humanVerified']
    ]
    if not record['_missing'] and record['_action'] == 'enrich':
        # Optional micro-state: keep _action so commit knows it's an update.
        # Nothing else to do here.
        pass

    return json.dumps({
        'agentId': agent_id,
        'applied': applied,
        'skippedHumanVerified': skipped,
        'remainingMissing': record['_missing'],
    })


@tool
def commit_discovery_scan(work_item_id: str = '') -> str:
    """Stage 3 — flush _scan_state to AgentTable.

    For each in-memory record:
      - 'add'     — write a new INFO row with status='pending-review' and
                    aiInferred=True for any LLM-set field (capabilities/
                    category/riskTier/suggestedOwner)
      - 'enrich'  — UpdateItem with the LLM-set fields, never overwriting
                    humanVerifiedFields
      - 'refresh' — bump lastDiscoveredAt only

    Inactivation list is processed last; demo rows in dev were already
    excluded at scan time. Probes invocability for every live runtime.
    Emits the AgentsDiscovered CloudWatch metric and clears state.
    """
    if not _scan_state.get('completed_scan'):
        return json.dumps({'error': 'No active scan to commit. Call start_discovery_scan first.'})

    # If the LLM didn't pass work_item_id explicitly, reuse the one captured
    # in start_discovery_scan so the work item still gets tasks + closed.
    if not work_item_id:
        work_item_id = _scan_state.get('work_item_id', '')

    # Outcome tracking for the finally-block close. close_status flips to
    # 'failure' on the first unhandled exception so the dispatch WI never
    # gets stuck in-progress until backlog_sweep retries it.
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
            # runtimeId is the full ARN stored on the record; agent_id is the
            # canonical clean name (AgentTable PK) stored as the records dict key.
            arn = record['runtimeId']

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
                    # Bedrock-discovered → stamp the canonical platformId. invocable
                    # starts as False; the probe loop below flips it to True for
                    # IAM-auth runtimes after the row exists.
                    'platformId': _BEDROCK_PLATFORM_ID,
                    # Human-facing display fields the UI registry renders. These are
                    # AgentCore runtimes (NOT plain Bedrock Agents), so label the
                    # runtime/platform/system accordingly rather than leaving them
                    # blank (which the UI would show as an empty runtime column).
                    'runtime': 'AgentCore (Strands)',
                    'platform': 'native',
                    'system': 'Amazon Bedrock AgentCore',
                    # Default category so the registry list never shows a blank —
                    # the LLM enrichment loop below overwrites it if it derives a
                    # more specific one (only when a value is produced).
                    'category': 'AWS Native',
                    'invocable': False,
                    # Default governance fields so the rai-scorer's registry
                    # checks have something to evaluate on first scan. The
                    # reviewer can override via the catalog before approval.
                    'owner': 'platform-engineering',
                    'escalationGroup': 'platform-engineering',
                })
                # Apply any LLM-set enrichment fields. aiInferred=True signals to
                # the portal that these came from automation, not a human edit.
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
            if cost_center:
                update_parts.append('costCenter = :cc')
                expr_vals[':cc'] = cost_center

            # Backfill platformId on legacy rows that pre-date the platform stamp.
            # The agent appeared in this Bedrock scan, so it belongs to the
            # Bedrock platform regardless of what (if anything) is in the row.
            existing_platform = record['_existing'].get('platformId')
            if existing_platform != _BEDROCK_PLATFORM_ID:
                update_parts.append('platformId = :platform_id')
                expr_vals[':platform_id'] = _BEDROCK_PLATFORM_ID

            # Backfill the human-facing display fields (platform/runtime/system) on
            # refresh/enrich too — the 'add' path sets these, but rows first written
            # by an earlier scan (or a bare upsert) may lack them, without which the
            # UI cannot group them as native AgentCore agents. Also refresh the
            # runtimeId so a redeploy (which regenerates the ARN suffix) updates the
            # stored ARN instead of leaving a stale one that looks inactive.
            if record['_existing'].get('platform') != 'native':
                update_parts.append('platform = :platform')
                expr_vals[':platform'] = 'native'
            if record['_existing'].get('runtime') != 'AgentCore (Strands)':
                update_parts.append('runtime = :runtime')
                expr_vals[':runtime'] = 'AgentCore (Strands)'
            if record['_existing'].get('system') != 'Amazon Bedrock AgentCore':
                update_parts.append('#sys = :system')
                expr_vals[':system'] = 'Amazon Bedrock AgentCore'
            if record.get('runtimeId') and record['_existing'].get('runtimeId') != record['runtimeId']:
                update_parts.append('runtimeId = :rid')
                expr_vals[':rid'] = record['runtimeId']
            # Backfill a default category on existing rows that have none, so the
            # registry list isn't blank. Skip when the enrich loop below will set
            # category itself (record carries a value) — otherwise we'd emit two
            # 'category =' clauses in one UpdateExpression, which DynamoDB rejects.
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
                    # Skip when the value equals the existing value (no-op write).
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
            # 'system' is a DynamoDB reserved word — alias it when present.
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

        # Stamp invocable=false on non-Bedrock catalog rows that aren't in this
        # scan's working set. The discovery scanner can't reach those agents, so
        # they must never be reported as invocable by the platform.
        stamped_invocable_false = 0
        for agent_id in _scan_state['stamp_invocable_false']:
            try:
                _write_invocable(agent_id, False)
                stamped_invocable_false += 1
            except Exception:
                logger.error('Failed to stamp invocable=false on %s', agent_id)

        # Invocability probe — only for agents we just touched. Probe takes the
        # ARN (the AgentCore-side identifier), but the DDB write is keyed on the
        # runtime-name-based agentId (the AgentTable PK).
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

        # Clear state — ready for the next scan.
        _scan_state['records'] = {}
        _scan_state['inactivate'] = []
        _scan_state['stamp_invocable_false'] = []
        _scan_state['completed_scan'] = False
        _scan_state['work_item_id'] = ''
        return summary_json
    except Exception as exc:
        # Capture cause so the `finally` block can close the dispatch WI as
        # 'failure' with a useful note. Re-raise so the LLM sees the error.
        close_status = 'failure'
        close_error_message = f'{type(exc).__name__}: {exc}'
        logger.exception('commit_discovery_scan: aborted — %s', exc)
        raise
    finally:
        # Always close the dispatch work item so a partial scan never leaves
        # the WI stuck in-progress until backlog_sweep retries it. Close is
        # best-effort: a close failure is logged but never masks the original
        # exception (which has already propagated above).
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
    """Convenience wrapper — run all three stages back-to-back with no
    LLM-driven enrichment in the middle. Equivalent to calling
    start_discovery_scan + commit_discovery_scan in sequence.

    Use this only when the LLM is dispatched without time/budget to enrich;
    prefer the staged tools so display names and categories get filled in.
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

    Accepts both shapes:
    1. Work-item-driven dispatch (from aop_dispatch_handler / work_item_handler):
       payload includes `workItemId`, `workItem` (full snapshot), and `messages`
       whose first user message is the work-item prompt produced by
       _readiness.build_dispatch_prompt(). The agent uses the work-item
       flowamp_tools (add_work_item_note, add_work_item_task,
       update_work_item_task, update_work_item_info, close_assigned_work_item)
       to record progress and finalise the item. In this repo those work-item
       tools are safe no-ops (no AOP runtime), so this path runs harmlessly.
    2. Direct conversation (no workItemId): the latest user message is used
       as-is, defaulting to a generic discovery-scan instruction. This is the
       default one-shot path and works without the AOP runtime.
    """
    _ensure_otel_processor()  # attach OTEL span processor now that ADOT provider exists
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
