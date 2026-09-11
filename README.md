# FlowAMP: AI Agent Governance on AWS

FlowAMP is an **Agent Management Platform** - a single pane of glass to discover, monitor, score,
control, and cost-account AI agents across an AWS organization. It deploys with AWS CDK into your
own account and governs the agents already running there.

**Use this as a starting point for a production deployment.** It is a working control plane, but it
ships with demo-grade defaults - see [Production hardening](#production-hardening) before you rely
on it. Fork it, harden the items called out there, and extend the connectors and policies for your
environment.

## Architecture

A single DynamoDB table is the spine. Governance is **agent-driven**: AgentCore (Strands) agents
discover, classify, and audit the account's other agents, writing normalized records to the table.
An AgentCore harness answers natural-language questions over it, scheduled Lambdas keep the
inventory / Responsible-AI scores / cost current, and a static UI (S3 + CloudFront) talks to the
backend through a Cognito-authorized API Gateway.

![FlowAMP architecture - chat flows from the CloudFront UI through API Gateway to the AgentCore harness, which reaches the agent-handler Lambda as MCP tools through an AgentCore Gateway; a single DynamoDB table is the data spine, written by the governance agents and by scheduled discovery, RAI-scoring and FinOps Lambdas](static/images/flowamp-architecture.png)

## Prerequisites

- **Node.js 20+** and npm; **[`uv`](https://docs.astral.sh/uv/)** (vendors the agents' arm64 deps).
- **AWS CLI v2**, used for the preflight checks below and for the optional cost-allocation tag and
  CloudFront invalidation steps.
- **AWS credentials** for the target account. For **org discovery**, that account must be the
  organization **management or a delegated-admin** account.
- **Amazon Bedrock model access** for `us.anthropic.claude-sonnet-5` (Console → Bedrock → Model
  access). See [Which model is used, and where](#which-model-is-used-and-where) for what stops
  working without it. Because that is a **cross-region inference profile** (the `us.` prefix), the
  entitlement is needed for the underlying model in the profile's regions, not only your deploy
  region.

## Deploy

All commands run from [`cdk/`](cdk/). See [`cdk/README.md`](cdk/README.md) for details.

FlowAMP takes its **account and region from your environment** - neither is pinned in
the code - so set them explicitly and confirm what you get before deploying:

```bash
export AWS_PROFILE=<your-profile>    # omit if you use the default profile
export AWS_REGION=<your-region>      # must match the region where you granted model access
aws sts get-caller-identity          # confirm the account you are about to deploy into
```

Then:

```bash
cd cdk
npm install
npx cdk bootstrap      # one-time per account AND region
npx cdk deploy
```

Stack outputs include `DemoUrl` (CloudFront UI), `ApiUrl`, `LoginUsername`/`LoginPassword` (seeded),
`AgentTableName`, `ManagementHarnessArn`, `AgentManagementGatewayArn`, `UserPoolId`, and
`DiscoveryScannerRuntimeArn` / `ComplianceScannerRuntimeArn`.

## What deploys by default

A bare `npx cdk deploy` is **live-only, no seed data**. It deploys:

- the platform (table, API, Cognito, UI) and the **three core AgentCore agents** (management,
  discovery-scanner, compliance-scanner);
- **discovery** - single-account native (via the scanner) and cross-account **org discovery**
  (on by default);
- the **Cost Explorer FinOps collector** (on by default);
- the **Microsoft Foundry connector**, which stays inert until you configure one Azure tenant's
  credentials in the UI ([setup](#connect-microsoft-foundry)).

The agent registry shows discovered and registered agents, and the FinOps dashboard shows Cost
Explorer spend. No demo catalog and no synthetic cost unless you opt in.

## First run

`cdk deploy` prints everything you need. Open the **`DemoUrl`** output and sign in with
**`LoginUsername`** / **`LoginPassword`**.

The catalog starts empty, because FlowAMP only ever shows agents that actually exist in your
account. To populate it, go to **Agent Discovery** and choose **Discover agents** - one button that
runs the native scanner and every configured connector. Allow a couple of minutes: the scanner
classifies each agent with an LLM, so rows appear progressively, and the page refreshes itself every
minute.

What you should see once it finishes:

- Every discovered agent at **pending-review**, with the platform's own run state beneath it. That
  pairing is the point: an agent that is already running but has not been reviewed is the finding.
- **Unassigned** in the Owner column. Activating an agent requires naming an owner - the API refuses
  otherwise - which you can do from the agent's detail panel or as part of approving it.
- **Compliance** and **FinOps** empty. No audit has run yet (use **Run audit** on an agent), and
  Cost Explorer needs the cost-allocation tag activated plus 24 to 48 hours to backfill.
- **Responsible AI** mostly empty. An agent with no guardrail activity and no CloudTrail events is
  reported as not scored rather than given a number, so scores appear once agents carry real traffic.

FlowAMP will also list **itself** - its management agent and two scanners are agents in your account,
and it does not exempt them.

## Configuration flags

Flags are CDK context values, passed as `-c <flag>=value`. The common ones:

```bash
npx cdk deploy -c deploySampleAgents=true       # 3 sample agents (adds SampleAgentHarnessArns)
npx cdk deploy -c seedSampleData=true           # demo catalog + simulated Okta/MuleSoft connectors
npx cdk deploy -c enableOrgDiscovery=false      # turn OFF cross-account org discovery
npx cdk deploy -c enableCostExplorer=false      # turn OFF the FinOps collector
```

**Sample agents in a separate account** (e.g. an org member account, to exercise cross-account
discovery) can be deployed standalone - no platform, just the 3 runtimes:

```bash
npx cdk deploy --app "npx ts-node --prefer-ts-exts bin/sample-agents.ts" SampleAgentsStack --profile <that-account>
```

Full reference:

| Flag | Default | Effect |
|---|---|---|
| `enableOrgDiscovery` | **`true`** | Cross-account org discovery: `organizations:ListAccounts` → assume a role per member account → list Bedrock Agents + AgentCore runtimes per region. **Requires FlowAMP to run in the org management or a delegated-admin account** (otherwise it returns nothing and surfaces a UI warning). Assumed role defaults to `AWSControlTowerExecution` - override with `-c orgDiscoveryRoleName=…`; regions with `-c orgDiscoveryRegions=us-east-1,us-west-2` (defaults to the stack region). |
| `enableCostExplorer` | **`true`** | Deploys `finops-collector` + the cost-allocation-tag activator. Real spend appears only after the `flowamp:agentId` tag is activated in Billing and CE backfills (~24-48h) - see [FinOps](#finops-real-cost-from-cost-explorer). |
| `deploySampleAgents` | `false` | Deploy 3 sample workload agents as real, discoverable AgentCore harnesses. |
| `seedSampleData` | `false` | Load a demo agent catalog (`source: demo-seed`) and enable the **still-simulated** Okta / MuleSoft connectors, plus the simulated org fallback, for a populated UI without real agents. **Off by default so the catalog only ever contains agents that actually exist in your account** - those connectors return hardcoded illustrative data, not API results. The **Microsoft Foundry** connector is *not* gated by this flag: it makes real API calls and stays inert until you give it credentials ([setup](#connect-microsoft-foundry)). |
| `enableTransactionSearch` | `false` | Adds distributed **traces** for the Gateway's tool calls, on top of the request/response logs that are delivered either way. Off by default because enabling it is an **account-wide** change that moves span ingestion onto CloudWatch pricing (1% of spans indexed free) - see [Enable Transaction Search](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Enable-TransactionSearch.html). Safe to re-run where it is already on, and never disabled on stack delete. |
| `deployGovernanceAgents` | **`true`** | The `discovery-scanner` + `compliance-scanner` runtimes. Setting `=false` **disables the features they provide, not just their provisioning**: compliance auditing stops and discovery loses its agentic half (see below). It is the only way to drop the `uv` prerequisite, since these are the only components needing a code bundle. |

> **Turning off `deployGovernanceAgents` removes capability, not just cost.** With
> `-c deployGovernanceAgents=false`:
>
> - **Discovery still runs, but stops being agentic.** The `discovery-handler` Lambda takes native
>   discovery back and makes the same three control-plane calls (`ListHarnesses`,
>   `ListAgentRuntimes`, `bedrock-agent:ListAgents`), so the catalog is still populated. What is lost
>   is the LLM classification: nothing infers `displayName`, `category`, `riskTier`, `capabilities`
>   or `suggestedOwner`, so rows arrive sparse at `pending-review` for a human to complete. Exactly
>   one component ever owns native discovery, so the two never double-write an agent.
> - **Compliance auditing stops.** No `AUDIT#` / `RAI#` rows are ever written, so the Compliance view
>   and each agent's audit history stay empty, and the daily rotation audit does not run.
> - **Those two agents cannot be evaluated.** Their online-evaluation configs cannot be created; the
>   management harness's still can.
>
> Chat, the registry, FinOps, Responsible-AI scoring, AOPs and the access matrix are unaffected. The
> UI detects both cases and routes the Discover button to the Lambda sync while disabling the Run
> audit controls, rather than calling routes that
> do not exist. Deploy without the flag (or `=true`) to get the full platform.

> **Packaging - `uv` required.** The two scanner *runtimes* deploy on every `cdk deploy`, so
> [`uv`](https://docs.astral.sh/uv/) must be on the machine that runs synth/deploy. They use
> AgentCore **direct code deployment** (Lambda-style shared responsibility: AWS provides the Python
> runtime, you package the deps). At synth time `cdk/lib/agent-bundle.ts` vendors each one's
> `requirements.txt` for linux/arm64 + cp312 (`uv pip install --python-platform aarch64-manylinux2014
> --target <bundle>`) and copies in the shared `flowamp_tools` / `flowamp_compliance_checks`
> packages, so the uploaded zip is self-contained. **Docker is not required.**
>
> The *harnesses* (management agent, sample agents) need no packaging at all - they are pure
> configuration - so nothing is bundled for them. Watch the bundle size if you add dependencies to a
> scanner: direct-code packages are capped at
> [250 MB compressed / 750 MB uncompressed](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html),
> neither adjustable, and the uncompressed limit is the one that binds in practice (the current
> bundles sit near 170 MB unzipped, mostly ADOT and the Strands tool extras).

## Connect Microsoft Foundry

The `microsoft` connector is a client for **Microsoft Foundry Agent Service** (formerly Azure AI
Foundry). It is scoped to **one Azure tenant, not one project**: you supply a tenant ID, a client ID
and a client secret, and nothing else. FlowAMP discovers downward from those credentials - the
subscriptions the service principal can see, the Foundry accounts in each of them
(`Microsoft.CognitiveServices/accounts` with `kind == AIServices`), the projects in each account, and
the agents in each project. It registers what it finds beside your AWS agents with
`system: Microsoft Foundry` and a Runtime of `Foundry Prompt Agent` (declarative config, Foundry runs
the loop) or `Foundry Hosted Agent` (your own container or zip). It is **inert until you configure
it**: a deploy with no Azure credentials calls nothing and reports the connector as not configured.

This mirrors how FlowAMP's `aws-org` connector sweeps an AWS Organization, and it is simpler: there
is no per-account role to assume, just one service principal whose Azure RBAC defines its reach.

1. **Register an application in Microsoft Entra ID.** Entra portal → **App registrations** → **New
   registration**, then add a **client secret** under *Certificates & secrets*. FlowAMP authenticates
   with the OAuth 2.0 client-credentials grant against
   `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`. One app registration and one
   secret cover both Azure planes; only the requested token scope differs -
   `https://management.azure.com/.default` for the Azure Resource Manager enumeration
   (subscriptions, Foundry accounts, projects) and `https://ai.azure.com/.default` for reading the
   agents themselves. Keep the **tenant ID**, **client ID** and secret value.
2. **Assign `Foundry User` to that application, at the Foundry resource (account) scope.**
   Listing agents requires the data action
   `Microsoft.CognitiveServices/accounts/AIServices/agents/read`; `Foundry User`
   (`53ca6127-db72-4b80-b1b0-d745d6d5456d`) is the narrowest built-in role that carries it. Account
   scope inherits to every project, so one assignment covers all of them. Azure portal → your
   Foundry resource → **Access control (IAM)** → **Add role assignment** → `Foundry User` → your
   app registration. For an estate spanning several Foundry resources, assign at the resource
   group, subscription or management group scope instead.

   > **Allow up to 30 minutes for the assignment to take effect.** Data-plane authorization is
   > cached, so `GET /agents` can return **403** well after a correct assignment. If it persists
   > beyond that, confirm the role reached the **service principal's** object ID - a distinct value
   > from both the application (client) ID and the app registration's object ID, and the one the
   > portal does *not* show in its IAM list: `az ad sp show --id <client-id> --query id -o tsv`.

   For tighter privilege than `Foundry User` (which can also create, update and delete agents - more
   than a governance plane should hold over the agents it audits), a custom role works and is the
   better production answer. It needs `Microsoft.Authorization/roleDefinitions/write`, so an Azure
   Owner has to create it:

   ```json
   {
     "properties": {
       "roleName": "FlowAMP Agent Discovery (read-only)",
       "description": "Lists Foundry agents for governance discovery. No write access.",
       "assignableScopes": ["/subscriptions/<subscription-id>"],
       "permissions": [{
         "actions": ["Microsoft.CognitiveServices/*/read"],
         "notActions": [],
         "dataActions": ["Microsoft.CognitiveServices/accounts/AIServices/agents/read"],
         "notDataActions": []
       }]
     }
   }
   ```
3. **There is no endpoint to paste.** FlowAMP reads each Foundry account's own data-plane endpoint
   from its `properties.endpoints["AI Foundry API"]` value, then calls
   `GET <endpoint>/agents?api-version=v1` per project, following the paging cursor and filtering by
   agent `kind`. That is why the connector needs credentials only.
4. **Configure it in the FlowAMP UI**, in the **Agent Discovery** view's **Platform Integrations**
   panel. On the Microsoft Foundry tile choose **Edit**, enter the tenant ID, client ID and client
   secret, and then, in this order:

   1. **Save** - stores the configuration.
   2. **Test connection** - sweeps the tenant and reports how much of it the credentials reach
      (subscriptions, Foundry accounts, projects, agents found, and any project it was refused).
      The test runs against the *stored* configuration, so it has nothing to check until you have
      saved.
   3. **Discover** - syncs the agents into the catalog.

   The non-secret settings are stored in `AgentTable`; the client secret goes only to AWS Secrets
   Manager under `flowamp/connectors/microsoft` and is never returned by the API, which reports only
   *whether* a credential is set. After the first sync, agents refresh on the 6-hour schedule and
   whenever you trigger a sync by hand.

What Foundry agents do **not** get, and where the connector's coverage stops, is covered under
[production hardening](#production-hardening): no per-agent cost, no traffic metrics, no
Responsible-AI score, no compliance audit, and a discovery reach bounded by the Azure role
assignments you make outside FlowAMP.

## How FlowAMP works

Agents are deployed two ways, and the distinction matters when adding your own:

- **Harness** (`AWS::BedrockAgentCore::Harness`) - model, system prompt and tools declared as
  configuration; AgentCore runs the agent loop. No container, no code bundle. Used for the
  management agent and the sample workloads.
- **Runtime** (`agentcore.Runtime`, direct-code deploy) - your own Python program, packaged as a
  zip with its arm64 dependencies vendored in at synth time by `cdk/lib/agent-bundle.ts`. Used for
  the two scanners, which have custom tools, DynamoDB writes and cross-account calls that a
  harness cannot host.

> **Bedrock Agents Classic is not used.** It [entered maintenance mode on 2026-07-30](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html):
> `CreateAgent` is refused in any account without prior Bedrock Agents usage, so a stack that
> created one could not deploy into a new account. FlowAMP still **discovers and audits** Classic
> agents you already run, since the read APIs remain available and existing agents keep working -
> in this account via the `discovery-scanner`, and in member accounts via org discovery.

| Component | Purpose |
|---|---|
| **DynamoDB** `AgentTable` | Single table (PK `agentId`, SK `sk`, PAY_PER_REQUEST, 90-day TTL on `EVENT#` rows). Row types by `sk`: `INFO` (entity), `EVENT#`/`AUDIT#`/`RAI#`/`COST#`/`REVIEW#`/`MODEL#`/`COMPLIANCE#`. |
| **AgentCore harness: management agent** | Managed agent loop that answers questions over the table, calling the registry tools through the Gateway below. Model via an inference profile (`us.anthropic.claude-sonnet-5`). **Core - always deployed.** |
| **AgentCore: `discovery-scanner`** | Governance agent that enumerates AND LLM-classifies the account's agents across all three surfaces (AgentCore harnesses, AgentCore runtimes, Bedrock Agents Classic), writing enriched catalog rows. **Owns single-account native discovery. Core - always deployed.** |
| **AgentCore: `compliance-scanner`** | Governance agent that runs a deterministic compliance-checks framework (baseline / NIST AI RMF / ISO 27001 / SOC 2 / NERC-CIP) plus LLM judgment, writing `AUDIT#` / `RAI#` rows. **Core - always deployed.** |
| **AgentCore: 3 sample agents** | Optional customer-use-case harnesses (insurance claims triage, supply-chain analyst, service request intake) that give discovery genuine agents to find. Defined in `cdk/lib/sample-agents.ts`, shared with `SampleAgentsStack`. `deploySampleAgents=true`. |
| **AgentCore Gateway** | Exposes the `agent-handler` Lambda's eight read operations to the harness as MCP tools, with SigV4 inbound auth. Replaces what was a Bedrock Agent action group. |
| **Lambda `agent-handler`** | Registry read API behind the Gateway. Speaks both the Gateway/MCP shape and the legacy action-group shape, so it stays independently testable. |
| **Lambda `discovery-handler`** | Cross-account **org discovery**; the **Microsoft Foundry** connector, which sweeps one **Azure tenant** from a single service principal - subscriptions → Foundry accounts → projects → agents (live API calls, inert until you configure credentials - see [Connect Microsoft Foundry](#connect-microsoft-foundry)); the still-simulated Okta/MuleSoft connectors (**off unless `seedSampleData=true`**, so a default deploy never writes agents you do not have); and the connector configuration API. Runs every 6h and on API routes. Async fire-and-forget for multi-account scans. |
| **Lambda `discovery-scan-invoker`** | Bridges the UI **Discover** button to the `discovery-scanner` runtime (which has no API of its own). Backs `POST /discovery/scan`. |
| **Lambda `compliance-scan-invoker`** | Bridges the UI **Run audit** / daily schedule to the `compliance-scanner` runtime. Fire-and-forget (202 + async self-invoke) since an audit exceeds API Gateway's 29s. Backs `POST /compliance/scan`. |
| **Lambda `eval-provisioner`** | Creates/enables/disables AgentCore **online evaluation** configs at runtime (one per core agent) via `bedrock-agentcore` control APIs, discovering each agent's live trace log group. Backs `POST /evaluations/enable` / `/disable`. |
| **Lambda `finops-collector`** | Daily Cost Explorer pull, per-agent spend by the `flowamp:agentId` tag → `COST#` rows. |
| **Lambda `cost-tag-activator`** | CFN custom resource that best-effort activates the `flowamp:agentId` cost-allocation tag (management/payer account only). |
| **Lambda `rai-scorer`** | Daily job computing Responsible-AI scores from CloudWatch + CloudTrail signals. |
| **Lambda `api-handler`** | API Gateway `POST /chat` → `InvokeHarness`. Returns the answer plus a per-chat trace (which tools the agent called, real token counts). |
| **Lambda `data-handler`** | REST backend for the UI's data/read + write routes (register, lifecycle, events, costs, compliance audits, evaluation scores + readiness). |
| **Lambda `seed-data`** | CFN custom resource that seeds a demo catalog. Gated off by default (`seedSampleData`). |
| **Lambda `cognito-seed-user`** | Seeds the single demo UI user (`flowadmin`) - replace for production (see hardening). |
| **API Gateway** REST (Cognito-authorized) | `POST /chat`; data routes `/agents` (+`{id}` PATCH, `/lifecycle`, `/audit`, `/evaluations`), `/compliance`, `/aops`, `/access`, `/events`, `/costs`, `/audits`, `/evaluations` (+`/readiness`); `POST /rai/score`; `POST /compliance/scan`; `POST /evaluations/enable`, `POST /evaluations/disable`; `POST /discovery/sync`, `POST /discovery/scan`, `GET /discovery/status`, `GET /discovery/platforms`; connector config `GET /discovery/connectors`, `PUT`/`DELETE /discovery/connectors/{platform}`, `POST /discovery/connectors/{platform}/test`. |
| **S3 + CloudFront** | Hosts the static UI (`assetsSrc/site/agent-management.html`). |

## Agentic discovery

Discovery is *agent-driven* - the **`discovery-scanner`** is itself an AI agent that governs your
other agents:

1. **Trigger.** The UI **Discover** button → `POST /discovery/scan` → `discovery-scan-invoker`
   invokes the scanner runtime (`InvokeAgentRuntime`).
2. **Discover.** The scanner enumerates all three execution surfaces in the account — harnesses
   (`ListHarnesses`), runtimes (`ListAgentRuntimes`) and legacy Bedrock Agents Classic agents
   (`bedrock-agent:ListAgents`) — and classifies each as new / enrich / refresh / inactivate.
   AgentCore implements a harness *as* a runtime, so each harness also appears
   in `ListAgentRuntimes` under a `harness_<name>` backing name; those are skipped so one logical
   agent yields one registry row under its real name. The Classic pass is best-effort: if it fails,
   Classic rows are left alone rather than inactivated, since an errored listing is indistinguishable
   from an empty one.
3. **Classify (the agentic part).** For new/under-described agents it uses an LLM to infer
   `displayName`, `category`, `riskTier`, `capabilities`, `suggestedOwner` - and can invoke an agent
   to ask what it does. Machine-inferred rows are flagged `aiInferred: true` and land as
   `pending-review` for a human to approve.
4. **Commit.** Writes normalized `INFO` rows + a baseline compliance assignment + `REVIEW#`/`MODEL#`
   rows to the single `AgentTable`.

### Governance status vs platform status

The registry's Status column answers two different questions at once, on two lines.

The badge is the **governance status** - FlowAMP's own lifecycle, recording whether a human has
accepted responsibility for the agent (`pending-review`, `active`, `rejected`, `inactive`,
`decommissioned`). The dimmed line under it is the **platform status** - whether the agent is
actually running, according to the platform that hosts it.

Every platform reports run state in its own vocabulary, so discovery normalizes it to four buckets
and keeps the platform's own string for the tooltip:

| Bucket | AgentCore runtime / harness (`status`) | Bedrock Agents Classic (`agentStatus`) | Microsoft Foundry (`state`) |
|---|---|---|---|
| `running` | `READY` | `PREPARED` | `enabled` |
| `stopped` | `DELETING` | `NOT_PREPARED` | `disabled` |
| `failed` | `CREATE_FAILED`, `UPDATE_FAILED`, `DELETE_FAILED` | `FAILED` | latest version not `active` |
| `unknown` | `CREATING`, `UPDATING` | `CREATING`, `PREPARING`, `UPDATING` | anything else |

Transitional states map to `unknown` deliberately. `CREATING` is neither running nor stopped, and
forcing it into either bucket would raise a finding on every ordinary deploy.

**Drift** is where the two disagree in a way somebody should look at. The `⚠️ Drift` filter and its
count surface exactly those rows:

| Governance | Platform | Why it matters |
|---|---|---|
| `pending-review` | `running` | Serving traffic before anyone approved it. The highest-value finding here. |
| `rejected` | `running` | Rejected, still running. |
| `decommissioned` | `running` | Meant to be gone. |
| `inactive` | `running` | Believed retired, but the platform disagrees. |
| `active` | `failed` | An approved agent is broken. |
| `active` | `stopped` | An approved agent is not running - stale inventory. |

`unknown` is never drift: absence of a reading is not evidence of a problem, so a connector that
reports no run state - or a status a platform adds in future - degrades to silence rather than
flagging the whole fleet.

Two limits worth knowing. First, **platform status is a sample, not a live read**: it refreshes on
discovery, so on the 6-hour schedule a reading can be hours old. The UI shows its age and greys it
out past 12 hours, and activating an agent re-reads its state live first - for same-account AWS
agents only, since cross-account and Foundry agents sit behind credentials the read path does not
hold. Second, FlowAMP is **read-only** here: it reports drift and links to the platform's console,
and never starts, stops or deletes an agent to resolve it.

> **Foundry hosted agents' session state is deliberately not reported.** Foundry's sandbox lifecycle
> is Active / Idle / Resumed **per session**, with a configurable idle timeout defaulting to 15
> minutes - so a value sampled every 6 hours would read idle for a busy agent and flap for reasons
> unrelated to governance. Only agent-level `state` is used. See
> [Hosted agents in Foundry Agent Service](https://learn.microsoft.com/azure/ai-foundry/agents/concepts/hosted-agents?view=foundry).

**Cross-account org discovery** (the `discovery-handler` Lambda) applies the same idea across the
organization: enumerate accounts, assume a role in each, list AgentCore harnesses and runtimes plus
any legacy Bedrock Agents Classic agents per region, and upsert them keyed
`native:<account>:<region>:<harness|agentcore|bedrock-agent>:<name>`. Because a
multi-account scan can exceed API Gateway's 29 s limit, the sync is **fire-and-forget** (returns
`202`, runs in a background self-invoke) and the UI polls the registry for results.

The **`compliance-scanner`** follows the same pattern for governance: it runs the deterministic
`flowamp_compliance_checks` framework plus LLM judgment and writes `AUDIT#` / `RAI#` rows that the
compliance and Responsible-AI surfaces read back. It audits **one agent per invocation** - triggered
on demand (the UI **Run audit** / **Audit all agents** buttons → `POST /compliance/scan`, via the
`compliance-scan-invoker`) or on a daily EventBridge schedule (rotation: the oldest-audited agent).
Rotation considers every eligible agent by default; add `FLOWAMP_PLATFORMS` rows flagged
`auditable=true` to restrict it to specific platforms.

## Which model is used, and where

FlowAMP uses exactly **one** foundation model: **`us.anthropic.claude-sonnet-5`**, a cross-region
inference profile. Nothing in the stack can enable access to it - Bedrock model access is an
account-level setting with no CloudFormation resource - so **you must enable it yourself before the
agentic features work** (Console → Bedrock → Model access). Because the `us.` prefix denotes a
cross-region inference profile, the entitlement is required for the underlying model in the profile's
regions, not only the region you deploy into.

Three components invoke it, and each stops working entirely without access:

| Component | What it uses the model for |
|---|---|
| **Management harness** | Answers natural-language questions over the registry. Backs `POST /chat`. |
| **`discovery-scanner`** | Classifies and enriches discovered agents (`displayName`, `category`, `riskTier`, `capabilities`, `suggestedOwner`). |
| **`compliance-scanner`** | LLM judgment layered on the deterministic compliance checks. |

The three optional sample workload agents (`deploySampleAgents=true`) use the same model.

Both scanners are Strands agents whose every invocation runs through the model's tool-calling loop,
so a missing entitlement is not a partial degradation of them - **native agent discovery and
compliance auditing do not run at all**, and the registry stays empty of natively discovered agents.

`cdk deploy` still succeeds without the entitlement, because access is only checked when a model is
invoked. The failure appears later as `AccessDeniedException` in the agents' CloudWatch logs. These
features are unaffected and need no model access:

- the agent registry, manual registration, lifecycle and review workflow, and the whole UI;
- the **Microsoft Foundry** connector and the connector configuration API (plain Lambdas over HTTPS);
- cross-account **org discovery** (boto3 control-plane reads only);
- the **FinOps** collector (Cost Explorer) and the **Responsible-AI scorer** (CloudWatch + CloudTrail).

## Evaluations: AgentCore-native agent scoring

The **Evaluations** page surfaces **Amazon Bedrock AgentCore Evaluations** - LLM-as-a-Judge scoring
of live agent sessions (goal success, tool-selection accuracy, correctness, helpfulness, and more).

- **Provisioning is runtime, not deploy-time.** The `eval-provisioner` Lambda creates one online
  evaluation config per core agent (`POST /evaluations/enable`), discovering each agent's live
  `-DEFAULT` trace log group at call time (its name carries a runtime-id suffix that only exists
  once the agent has run, so a deploy-time CFN resource can't reference it). `POST /evaluations/disable`
  pauses them.
- **Agents must emit OpenTelemetry spans.** AgentCore Evaluations scores OTEL spans (from `aws/spans`,
  via CloudWatch **Transaction Search**), not application logs. Because AgentCore direct-code deploy
  launches a bare `python main.py` (no `opentelemetry-instrument` wrapper), each agent's `main.py`
  re-execs itself under the ADOT auto-instrumentation entry point on startup (guarded by
  `AGENT_OBSERVABILITY_ENABLED`, set on every runtime); the OpenInference processor then translates
  Strands' native spans into the GenAI semantic conventions the evaluator reads.
- **Reading results.** `GET /evaluations` returns per-agent scores + a readiness preflight (Transaction
  Search active? spans present? config present?), so an empty page explains *why*. Scores appear after
  a covered agent runs a new session and AgentCore's recurring sampler grades it.
- **Prerequisite:** enable CloudWatch **Transaction Search** once per account/region (Console →
  CloudWatch → Application Signals → Transaction search, or the X-Ray `UpdateTraceSegmentDestination`
  API). Evaluations are **per-account** - scored in whatever account the agents run in.

## FinOps: real cost from Cost Explorer

FinOps shows **real per-agent AWS spend** (no synthetic fallback):

- Every stack resource carries the **`flowamp:agentId`** cost-allocation tag - each AgentCore runtime
  with its own agent id, other resources with `platform`.
- `finops-collector` runs daily (03:00 UTC) and calls Cost Explorer (`GetCostAndUsage`, grouped by
  `flowamp:agentId`; four queries: total + agentCompute / toolExecution / storage by service),
  writing one `COST#<date>` row per agent with `source: cost-explorer`. The UI renders the total, the
  trend chart, a **Cost by Component** panel, and a **● Live · Cost Explorer** badge.

### One-time setup: activate the cost-allocation tag

Cost Explorer only groups by a user-defined tag once the key is **activated** in Billing - a
**management/payer-account** action with AWS-side propagation delay:

1. Deploy (collector + tags + activator included by default). The activator best-effort-activates the
   key, but only succeeds once AWS has *discovered* it (up to ~24 h after first tagging); otherwise it
   logs an "activate manually" message and never fails the stack.
2. Once discovered, activate it (Billing console → **Cost allocation tags** → *User-defined* →
   `flowamp:agentId` → **Activate**, or CLI, always `us-east-1`):
   ```bash
   aws ce list-cost-allocation-tags --region us-east-1 \
     --query "CostAllocationTags[?TagKey=='flowamp:agentId']" --output table
   aws ce update-cost-allocation-tags-status --region us-east-1 \
     --cost-allocation-tags-status '[{"TagKey":"flowamp:agentId","Status":"Active"}]'
   ```
3. Allow **~24-48 h** after activation, and spend to accrue, before CE returns tag-grouped data.
   Until then the collector runs cleanly and writes nothing. This latency is normal AWS billing
   behavior, not a bug.

## Production hardening

This deploys real infrastructure, but the defaults are demo-grade. Before production:

- **Data durability:** every stateful resource (DynamoDB table, S3 buckets) uses
  `RemovalPolicy.DESTROY` - `cdk destroy` deletes your data. Switch to `RETAIN` + enable
  point-in-time recovery on the table.
- **Authentication:** the UI uses one seeded Cognito user (`flowadmin`, self-signup disabled).
  Replace with your corporate IdP / SSO federation and remove the seeded user.
- **Edge protection:** no WAF is attached to CloudFront or API Gateway - add AWS WAF for a
  public-facing deployment.
- **Org discovery least privilege:** the default assumed role is `AWSControlTowerExecution` (broad).
  Roll out a scoped, read-only discovery role to member accounts (e.g. via a service-managed
  StackSet) and set `-c orgDiscoveryRoleName=…`.
- **The Okta and MuleSoft connectors are still simulated, and therefore disabled by default:** they
  return illustrative data (capped, tagged `source: external-connector`), not API results, and run
  only under `-c seedSampleData=true`, so a normal deploy never puts an agent you do not own into the
  catalog. Implement the real API calls (marked `TODO` in `discovery-handler`) for platforms you use,
  then remove the gate for those. The Microsoft Foundry connector is already real and is not gated
  this way.
- **Microsoft Foundry agents are governed as registry entries only.** Discovery, lifecycle and review
  work; the AWS-specific analytics do not, because the underlying signals do not exist for an
  Azure-hosted agent. Note also that **Foundry records no owner for an agent**, so discovered agents
  arrive as `Unassigned` for a reviewer to assign. Each agent's own Entra identity is captured as
  platform metadata, but it is the identity the agent authenticates as, not an accountable owner, so
  it is deliberately not shown in the Owner column.
  - **No per-agent cost, so Foundry agents are absent from the FinOps views** (absent, not zero).
    Azure's usage metrics (`InputTokens`, `TotalTokens`, `ModelRequests`) are dimensioned by *model
    deployment*, not by agent, and Cost Management attributes spend to the resource, so there is no
    per-agent figure to import.
  - **No traffic metrics in this version.** Per-agent invocations, errors and latency exist only in
    Application Insights traces, which need extra setup and RBAC on the Azure side. Not implemented.
  - **Not Responsible-AI scored.** RAI scoring reads Bedrock Guardrails and CloudTrail, neither of
    which exists for an Azure agent, so such agents are marked *not scored* rather than shown as zero.
  - **Not compliance-audited.** Most of the 25 compliance checks read CloudWatch and CloudTrail, so
    they have nothing to evaluate for a Foundry agent.
- **Partial access across a tenant is expected, and is handled per project.** A project the service
  principal cannot read is skipped and named in the connector's coverage summary (`N project(s)
  swept, M unreadable: …`, listing the first few by name), and discovery continues normally in every
  other project. Agents already discovered in a project that has become
  unreadable are **not** marked inactive, because "denied" and "empty" are different things and only
  one of them means the agent is gone.
- **A subscription the service principal cannot enumerate is an invisible gap.** Nothing in the
  results reveals that the subscription exists, so FlowAMP will look complete when it is not. The
  connector's coverage is bounded by Azure role assignments made outside FlowAMP: if a Foundry
  account sits in a subscription your service principal has no assignment in, its agents are absent
  from the catalog with no warning. Reconcile the subscription list against Azure yourself before
  treating the Foundry inventory as whole.
- **Ephemeral Foundry agents are undiscoverable.** An agent assembled per call through the Foundry
  Responses API persists no resource, so no API can enumerate it - not FlowAMP's, not Microsoft's.
  This is an inherent blind spot of any inventory-based approach, not a gap FlowAMP can close.
- **Classic agents are discovered but not cost-attributed.** Per-agent spend is keyed on the
  `flowamp:agentId` resource tag, which the scanner writes through the AgentCore control plane.
  Tagging a Classic agent needs `bedrock:TagResource`, which discovery deliberately does not hold
  (it is read-only on the Classic inventory), so Classic agents appear in the registry and are
  audited but show no `COST#` rows.
- **Compliance frameworks are code-defined** (`flowamp_compliance_checks/frameworks`) - runtime
  editing is not supported; extend/adjust the definitions in code and redeploy.
- **RAI / history-dependent checks:** `rai-scorer` and some compliance checks derive from CloudWatch /
  CloudTrail; in a fresh account they return **skip** and scores sit at base values until traffic
  accrues.
- **FinOps needs the cost-allocation tag activated.** Until `flowamp:agentId` is activated in Billing
  and Cost Explorer backfills (~24-48h), `finops-collector` runs cleanly and writes nothing
  (`reason: ce-empty`). The FinOps view is empty until then; it is not a failure.
- **Guardrail-dependent RAI signals need a `guardrailArn`.** Fairness and ethics read
  `AWS/Bedrock/Guardrails` → `InvocationsIntervened`, which is dimensioned by guardrail, not by agent.
  An agent with no attached guardrail produces no datapoints, so the scorer preserves its existing
  score rather than inventing one.

## Tear down

```bash
cd cdk
npx cdk destroy
```

Stateful resources use `RemovalPolicy.DESTROY`, so `destroy` removes everything - including the
DynamoDB table and its data. (Change this before production; see [hardening](#production-hardening).)

## Repository layout

```
.
├── cdk/                          # CDK app (TypeScript)
│   ├── bin/cdk.ts                # Main app → the FLOWAMP stack (TeamStack class)
│   ├── bin/sample-agents.ts      # Standalone app → SampleAgentsStack (samples only, no platform)
│   ├── lib/team-stack.ts         # The full FlowAMP stack
│   ├── lib/sample-agents-stack.ts# Standalone 3-sample-agent stack (for a separate account)
│   ├── lib/sample-agents.ts      # The 3 sample harness definitions (shared by both stacks)
│   ├── lib/agent-bundle.ts       # Synth-time uv vendoring of the scanner runtimes' arm64 deps
│   ├── lib/index.ts              # Barrel export of the two stack classes
│   └── README.md                 # Deploy details
├── assetsSrc/                    # Sources packaged as CDK assets
│   ├── lambda/                   # agent-handler, api-handler, data-handler, discovery-handler,
│   │                             #   discovery-scan-invoker, compliance-scan-invoker, eval-provisioner,
│   │                             #   finops-collector, cost-tag-activator, rai-scorer, seed-data,
│   │                             #   cognito-seed-user
│   ├── agents/                   # Source for the AgentCore RUNTIME agents only — the
│   │                             #   harnesses (management, samples) are pure config in CDK
│   │   ├── discovery-scanner/         # Governance: discover + classify agents
│   │   ├── compliance-scanner/        # Governance: deterministic checks + RAI grading
│   │   └── _shared/                   # flowamp_tools + flowamp_compliance_checks (vendored at synth)
│   └── site/                     # The static UI served via CloudFront
├── docs/developer-guides/        # Standalone HTML deep-dives per subsystem (NOT deployed)
├── docs/diagrams/                # Editable draw.io source for the architecture diagram
└── static/images/                # Rendered architecture diagram (PNG + SVG)
```

## Developer guides

Deep-dive, self-contained HTML guides for each major subsystem live in
[`docs/developer-guides/`](docs/developer-guides/) - AgentCore, OpenTelemetry / Observability,
Risk & Compliance, FinOps, Responsible-AI scoring, and Agent Operating Policies. Each is grounded in the current code
(it cites the real source files) and keeps an honest "what is real now vs. what you would
still harden" framing.

They are **reference material for anyone who clones this repo**, and are intentionally
**not** bundled into the deployed UI or served from CloudFront. Read them locally, e.g.
`open docs/developer-guides/finops-developer-guide.html`. See
[`docs/developer-guides/README.md`](docs/developer-guides/README.md) for the index. If you
change a subsystem, update its guide alongside the code.

## Notes

- The `discovery-scanner` / `compliance-scanner` use a single-table data model. Their AOP / work-item
  orchestration is not implemented in this deployment (no work-item runtime), so those tools are safe no-ops.
- AgentCore discovery requires a recent `boto3` (the `bedrock-agentcore-control` API postdates
  `boto3 1.35`); the agent bundles vendor a current version automatically.
