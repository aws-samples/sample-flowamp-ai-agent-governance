# FlowAMP deployable stack (CDK)

This `cdk/` workspace is the AWS CDK app that deploys the FlowAMP Agent Management Platform into
your own AWS account. It uses only public npm packages and the standard `cdk bootstrap` +
`cdk deploy` flow.

## What's here

| Path | Purpose |
|---|---|
| `bin/cdk.ts` | App entrypoint — instantiates `TeamStack`. |
| `lib/team-stack.ts` | The full FlowAMP stack: DynamoDB, Lambdas, Bedrock Agent + action group, API Gateway, Cognito, S3 + CloudFront UI, plus the seed / discovery / rai-scorer jobs and (gated) AgentCore runtimes. Extends the standard `cdk.Stack`. |
| `lib/agent-bundle.ts` | Assembles each AgentCore agent's direct-code bundle at synth time: copies the agent source + shared packages and vendors arm64/cp312 pip deps with `uv` (no Docker). |
| `cdk.json` | CDK app config. Context flags: `deploySampleAgents` (default off) adds 3 sample agents; `seedSampleData` (default off) adds the demo catalog + simulated connectors; `enableOrgDiscovery` (default **on**) cross-account discovery; `enableCostExplorer` (default **on**) real FinOps. |
| `../assetsSrc/` | Source inputs the stack packages as CDK assets — `lambda/` (handlers), `agents/` (AgentCore Strands agents + `_shared/` packages, gated), `site/` (the UI HTML). Must sit alongside this `cdk/` directory. |

## Prerequisites

- **Node.js 20+**
- **AWS credentials** for the target account and a default region
  (`aws configure`, or `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` / `AWS_REGION`)
- **Amazon Bedrock model access** for the Anthropic Claude model in your region
- **[`uv`](https://docs.astral.sh/uv/)** — required (core AgentCore agents deploy on every deploy);
  it vendors the agents' arm64 Python dependencies into their bundles at synth time. **No Docker.**

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
`AgentTableName`, `BedrockAgentId`, `UserPoolId`, `DiscoveryScannerRuntimeArn`,
`ComplianceScannerRuntimeArn` (+ `SampleAgentRuntimeArns` when `deploySampleAgents=true`).

### Core AgentCore agents (always deployed)

Every `cdk deploy` includes the management agent + the `discovery-scanner` + `compliance-scanner`
governance agents, via **direct code deployment** (a zip of code + arm64 dependencies, vendored by
`lib/agent-bundle.ts` using `uv`). No Docker, no ECR — but **`uv` is required** on the machine
running `cdk deploy`.

### Sample agents (optional, off by default)

```bash
npx cdk deploy -c deploySampleAgents=true   # 3 sample workload agents
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
