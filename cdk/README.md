# FlowAMP deployable stack (CDK)

This `cdk/` workspace is the AWS CDK app that deploys the FlowAMP Agent Management Platform into
your own AWS account. It uses only public npm packages and the standard `cdk bootstrap` +
`cdk deploy` flow.

## What's here

| Path | Purpose |
|---|---|
| `bin/cdk.ts` | App entrypoint - instantiates the `TeamStack` class as the CloudFormation stack **`FLOWAMP`**. |
| `lib/team-stack.ts` | The full FlowAMP stack: DynamoDB, Lambdas, the management **harness** + **Gateway**, the two scanner **runtimes**, API Gateway, Cognito, the S3 + CloudFront UI (optional, see `deployUi`), plus the seed / discovery / rai-scorer / FinOps jobs. Extends the standard `cdk.Stack`. |
| `lib/agent-bundle.ts` | Assembles each scanner **runtime's** direct-code bundle at synth time: copies the agent source + shared packages and vendors arm64/cp312 pip deps with `uv` (no Docker). Harnesses need no bundle. |
| `lib/sample-agents.ts` | The 3 sample workload **harness** definitions, shared by `TeamStack` and `SampleAgentsStack` so they cannot drift. |
| `lib/sample-agents-stack.ts` + `bin/sample-agents.ts` | Standalone app that deploys ONLY the 3 sample harnesses, for a separate account. |
| `cdk.json` | CDK app config. Context flags: `deploySampleAgents` (default off) adds 3 sample harnesses; `seedSampleData` (default off) adds the demo catalog + enables the still-simulated Okta/MuleSoft connectors, which write nothing without it (the real Microsoft Foundry connector is not gated by this flag; it stays inert until credentials are configured in the UI); `enableOrgDiscovery` (default **on**) cross-account discovery; `enableCostExplorer` (default **on**) real FinOps; `enableTransactionSearch` (default off) adds Gateway trace delivery, an **account-wide** change; `deployGovernanceAgents` (default **on**) the 2 scanner runtimes; `=false` **stops compliance auditing and drops the LLM enrichment half of discovery** (the `discovery-handler` Lambda takes native discovery back), and is the only way to drop the `uv` prerequisite; `deployUi` (default **on**) the S3 + CloudFront UI, `=false` for an API-only deployment in an account where CloudFront is unavailable. See the root README. |
| `../assetsSrc/` | Source inputs the stack packages as CDK assets — `lambda/` (handlers), `agents/` (the two scanner runtimes + `_shared/` packages; harnesses have no source here, they are config in CDK), `site/` (the UI HTML). Must sit alongside this `cdk/` directory. |

## Prerequisites

- **Node.js 20+**
- **AWS credentials** for the target account and a default region
  (`aws configure`, or `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` / `AWS_REGION`)
- **Amazon Bedrock model access** for `us.anthropic.claude-sonnet-5`. It is the only model the
  stack uses, and the stack cannot grant access to it (there is no CloudFormation resource for
  Bedrock model access). Without it `cdk deploy` still succeeds, but chat, native agent discovery
  and compliance auditing all fail at invocation time - see
  [Which model is used, and where](../README.md#which-model-is-used-and-where)
- **[`uv`](https://docs.astral.sh/uv/)** — required, because the two scanner runtimes deploy by
  default; it vendors their arm64 Python dependencies into the bundles at synth time. **No
  Docker.** Only `-c deployGovernanceAgents=false` removes this requirement, at the cost of
  native discovery and compliance auditing.

## Deploy

The stack takes its account and region from the environment; neither is pinned in the code.
Set them explicitly first, so you know which account and region you are deploying into:

```bash
export AWS_PROFILE=<your-profile>    # omit if you use the default profile
export AWS_REGION=<your-region>      # must match where Bedrock model access was granted
aws sts get-caller-identity
```

```bash
# 1. Install dependencies (public npm only)
npm install

# 2. Bootstrap the account/region for CDK assets (one time per account AND region)
npx cdk bootstrap

# 3. Synthesize (optional — inspect the CloudFormation) and deploy
npx cdk synth
npx cdk deploy
```

Two failures that happen before any resource is created, and are about the environment rather than
the stack:

| Message | Cause |
|---|---|
| `Unable to resolve AWS account to use` | No credentials could be resolved. The CLI leaves the account and region unset when it cannot authenticate, so the error names the stack even though the session is at fault. Re-authenticate. |
| `SSM parameter /cdk-bootstrap/hnb659fds/version not found`, usually after several `could not be used to assume ...-role-<account>-<region>` warnings | The target region is not bootstrapped. Bootstrap it, or set `AWS_REGION` to one you did. The region inside those role names is the one CDK actually resolved, which is the quickest way to see the mismatch. |

`cdk deploy` prints the stack outputs: `DemoUrl`, `ApiUrl`, `LoginUsername`, `LoginPassword`,
`AgentTableName`, `ManagementHarnessArn`, `AgentManagementGatewayArn`, `UserPoolId`,
`DiscoveryScannerRuntimeArn`, `ComplianceScannerRuntimeArn`
(+ `SampleAgentHarnessArns` when `deploySampleAgents=true`). With `-c deployUi=false` there is no
`DemoUrl`; `ApiAllowedOrigin` and `UserPoolClientId` take its place.

### Redeploying a UI change

The stack does not invalidate the CloudFront cache on deploy, so that it never needs
`cloudfront:CreateInvalidation` on `*`. A deploy that changes `assetsSrc/site/` therefore uploads the
new file while viewers keep the cached one, which looks exactly like a deploy that did not take
effect. Invalidate it yourself, using the distribution behind the `DemoUrl` output:

```bash
aws cloudfront create-invalidation --distribution-id <id> \
  --paths "/agent-management.html" "/"
```

### Deploying without the UI (no CloudFront)

```bash
npx cdk deploy -c deployUi=false
```

Some accounts cannot create CloudFront resources at all. A service control policy that denies
`cloudfront:CreateOriginAccessControl`, for example, fails the whole stack rather than just the UI.
`-c deployUi=false` drops the site bucket, the distribution, the origin access control, the UI
upload and the site-bucket drain, and leaves everything else exactly as it is: the API, Cognito,
the agents, discovery, compliance and the scheduled jobs all still deploy and work.

What changes:

- **`DemoUrl` is not output.** `ApiUrl` is the entry point, and `ApiAllowedOrigin` plus
  `UserPoolClientId` are output instead, which is what you need to configure a front end yourself.
- **The API's CORS preflight allows any origin.** The distribution domain is the only origin the
  stack can name, and without a distribution there is nothing to name, so it falls back to `*`
  rather than guessing. CORS is not what protects this API: every data route carries the Cognito
  authorizer, and the UI authenticates with a bearer token rather than a cookie, so a page on
  another origin still has no credential to call with. If you host the UI at a known address,
  scope the preflight to it in `lib/team-stack.ts`.

To serve the UI yourself, copy `assetsSrc/site/agent-management.html` to your own host and add a
`config.js` next to it with the values the stack normally generates:

```js
window.CHAT_API_URL = "<ApiUrl>chat";
window.COGNITO = { userPoolId: "<UserPoolId>", clientId: "<UserPoolClientId>", region: "<region>" };
window.DISCOVERY_SCAN_ENABLED = true;   // false with -c deployGovernanceAgents=false
window.COMPLIANCE_SCAN_ENABLED = true;  // false with -c deployGovernanceAgents=false
```

### Core AgentCore agents (always deployed)

Every `cdk deploy` includes three core agents, deployed two different ways:

- **Management agent — a HARNESS** (`AWS::BedrockAgentCore::Harness`). Model, system prompt and
  tools are declared as configuration and AgentCore runs the agent loop, so there is no container
  and no code bundle. Its tools are the `agent-handler` Lambda's read operations, exposed as MCP
  tools through an AgentCore **Gateway**.
- **`discovery-scanner` + `compliance-scanner` — RUNTIMES**, via **direct code deployment** (a zip
  of code + arm64 dependencies, vendored by `lib/agent-bundle.ts` using `uv`). No Docker, no ECR —
  but **`uv` is required** on the machine running `cdk deploy`. They stay runtimes because they are
  real Python programs with custom tools, DynamoDB writes and cross-account calls, which a harness
  cannot host.

Bedrock Agents Classic is deliberately not used: it entered maintenance mode on 2026-07-30 and
`CreateAgent` is refused in any account without prior usage, so a stack that created one could not
deploy into a new account. FlowAMP does still **read** that inventory - the `discovery-scanner`
lists Classic agents in this account and org discovery lists them in member accounts - because a
governance plane has to report what you actually run.

### Sample agents (optional, off by default)

```bash
npx cdk deploy -c deploySampleAgents=true   # 3 sample workload harnesses
```

### Sample data (optional, off by default)

`seedSampleData=true` loads the demo agent catalog and enables the still-simulated Okta/MuleSoft
connectors, plus the simulated org fallback, for a populated UI without any real agents. It is off by
default because those connectors return hardcoded illustrative agents rather than API results, and a
real deployment's catalog must contain only agents that actually exist:

```bash
npx cdk deploy -c seedSampleData=true
```

See the root [`README.md`](../README.md) (Configuration flags + Agentic discovery) for the full
behavior of both flags.

### External connectors

The **Microsoft Foundry** connector is real, is deployed on every `cdk deploy`, and is deliberately
*not* tied to `seedSampleData`. It is scoped to an **Azure tenant**, not a single Foundry project: it
has nothing to call until an operator configures a tenant ID, client ID and client secret through the
UI, so a default deploy is quiet. From those credentials it discovers downward - the subscriptions
the service principal can see, the Foundry accounts in each (`Microsoft.CognitiveServices/accounts`
with `kind == AIServices`), the projects in each account, and the agents in each project - reading
each account's data-plane endpoint from its own `properties.endpoints["AI Foundry API"]` value, so no
endpoint is ever pasted in. The stack provisions the pieces that configuration needs: the connector
routes on API Gateway (`GET /discovery/connectors`, `PUT`/`DELETE /discovery/connectors/{platform}`,
`POST /discovery/connectors/{platform}/test`) and a Secrets Manager grant scoped to
`flowamp/connectors/*`, where the client secret is stored. The client secret never goes into CDK
context or into the DynamoDB table; only the non-secret settings (tenant ID, client ID) are stored
there. Okta and MuleSoft remain simulated and remain behind `seedSampleData`. See
[Connect Microsoft Foundry](../README.md#connect-microsoft-foundry) in the root README for the Entra
app registration, the Azure role assignment (`Foundry User` at the Foundry resource scope or higher -
note data-plane authorization can take up to ~30 minutes to take effect), the two limits on how far
discovery reaches (an unreadable project is skipped and reported; an unenumerable subscription is an
invisible gap), and what Foundry agents are and are not governed for.

## Tear down

```bash
npx cdk destroy
```

The stack sets `RemovalPolicy.DESTROY` on stateful resources (this is a demo/starter kit), so
`destroy` removes everything it created, including the DynamoDB table.
