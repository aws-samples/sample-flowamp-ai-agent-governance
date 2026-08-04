# FlowAMP deployable stack (CDK)

This `cdk/` workspace is the AWS CDK app that deploys the FlowAMP Agent Management Platform into
your own AWS account. It uses only public npm packages and the standard `cdk bootstrap` +
`cdk deploy` flow.

## What's here

| Path | Purpose |
|---|---|
| `bin/cdk.ts` | App entrypoint — instantiates `TeamStack`. |
| `lib/team-stack.ts` | The full FlowAMP stack: DynamoDB, Lambdas, the management **harness** + **Gateway**, the two scanner **runtimes**, API Gateway, Cognito, S3 + CloudFront UI, plus the seed / discovery / rai-scorer / FinOps jobs. Extends the standard `cdk.Stack`. |
| `lib/agent-bundle.ts` | Assembles each scanner **runtime's** direct-code bundle at synth time: copies the agent source + shared packages and vendors arm64/cp312 pip deps with `uv` (no Docker). Harnesses need no bundle. |
| `lib/sample-agents.ts` | The 3 sample workload **harness** definitions, shared by `TeamStack` and `SampleAgentsStack` so they cannot drift. |
| `lib/sample-agents-stack.ts` + `bin/sample-agents.ts` | Standalone app that deploys ONLY the 3 sample harnesses, for a separate account. |
| `cdk.json` | CDK app config. Context flags: `deploySampleAgents` (default off) adds 3 sample harnesses; `seedSampleData` (default off) adds the demo catalog + simulated connectors; `enableOrgDiscovery` (default **on**) cross-account discovery; `enableCostExplorer` (default **on**) real FinOps; `enableTransactionSearch` (default off) adds Gateway trace delivery — an **account-wide** change; `deployGovernanceAgents` (default **on**) the 2 scanner runtimes — `=false` also **disables native discovery and compliance auditing**, and is the only way to drop the `uv` prerequisite. See the root README. |
| `../assetsSrc/` | Source inputs the stack packages as CDK assets — `lambda/` (handlers), `agents/` (the two scanner runtimes + `_shared/` packages; harnesses have no source here, they are config in CDK), `site/` (the UI HTML). Must sit alongside this `cdk/` directory. |

## Prerequisites

- **Node.js 20+**
- **AWS credentials** for the target account and a default region
  (`aws configure`, or `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` / `AWS_REGION`)
- **Amazon Bedrock model access** for the Anthropic Claude model in your region
- **[`uv`](https://docs.astral.sh/uv/)** — required, because the two scanner runtimes deploy by
  default; it vendors their arm64 Python dependencies into the bundles at synth time. **No
  Docker.** Only `-c deployGovernanceAgents=false` removes this requirement, at the cost of
  native discovery and compliance auditing.

## Deploy

```bash
# 1. Install dependencies (public npm only)
npm install

# 2. Bootstrap the account/region for CDK assets (one time)
npx cdk bootstrap

# 3. Synthesize (optional — inspect the CloudFormation) and deploy
npx cdk synth
npx cdk deploy
```

`cdk deploy` prints the stack outputs: `DemoUrl`, `ApiUrl`, `LoginUsername`, `LoginPassword`,
`AgentTableName`, `ManagementHarnessArn`, `AgentManagementGatewayArn`, `UserPoolId`,
`DiscoveryScannerRuntimeArn`, `ComplianceScannerRuntimeArn`
(+ `SampleAgentHarnessArns` when `deploySampleAgents=true`).

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
deploy into a new account.

### Sample agents (optional, off by default)

```bash
npx cdk deploy -c deploySampleAgents=true   # 3 sample workload harnesses
```

### Sample data (optional, off by default)

`seedSampleData=true` loads the demo agent catalog and the simulated external connectors, for a
populated UI without any real agents:

```bash
npx cdk deploy -c seedSampleData=true
```

See the root [`README.md`](../README.md) (Configuration flags + Agentic discovery) for the full
behavior of both flags.

## Tear down

```bash
npx cdk destroy
```

The stack sets `RemovalPolicy.DESTROY` on stateful resources (this is a demo/starter kit), so
`destroy` removes everything it created, including the DynamoDB table.
