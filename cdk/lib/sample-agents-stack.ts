import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import * as path from "path";
import { assembleAgentBundle } from "./agent-bundle";

/**
 * SampleAgentsStack — deploys ONLY the three standalone sample AgentCore agents
 * (insurance claims triage, supply-chain analyst, service request intake). No FlowAMP
 * platform: no DynamoDB, API Gateway, Cognito, UI, or governance agents.
 *
 * Use this to stand up just the sample workload agents in a separate account for
 * testing — e.g. so the FlowAMP org-discovery/scanner running elsewhere has real
 * cross-account agents to find. Each agent is self-contained (strands + boto3 only)
 * and deployed via direct-code (uv-vendored arm64 deps, no Docker).
 */
export class SampleAgentsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const assetsSrc = path.join(__dirname, "..", "..", "assetsSrc");
    const sharedDir = path.join(assetsSrc, "agents", "_shared");
    const bundleStagingRoot = path.join(__dirname, "..", "cdk.out", "sample-agent-bundles");

    // Model the sample agents invoke. Same model the rest of the repo pins.
    const inferenceProfileId = "us.anthropic.claude-sonnet-4-6";
    const baseModelId = "anthropic.claude-sonnet-4-6";
    const inferenceProfileArn = `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${inferenceProfileId}`;

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const agentcore = require("@aws-cdk/aws-bedrock-agentcore-alpha");

    const modelInvokeStatement = new iam.PolicyStatement({
      actions: [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:GetInferenceProfile",
      ],
      resources: [
        inferenceProfileArn,
        `arn:aws:bedrock:*::foundation-model/${baseModelId}`,
        `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
      ],
    });

    // Observability env: activates the AgentCore ADOT pipeline so each runtime
    // exports spans to aws/spans (Transaction Search). AGENT_OBSERVABILITY_ENABLED
    // also gates the in-agent re-exec bootstrap (main.py) that launches the process
    // under `opentelemetry-instrument` — without it AgentCore's direct-code runtime
    // runs a bare `python main.py` and no spans are produced.
    const observabilityEnv: Record<string, string> = {
      AGENT_OBSERVABILITY_ENABLED: "true",
      OTEL_PYTHON_DISTRO: "aws_distro",
      OTEL_PYTHON_CONFIGURATOR: "aws_configurator",
      OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
    };

    // RESPONSIBLE AI / GUARDRAIL GUIDANCE
    // These are illustrative, non-production sample workloads used to give the
    // FlowAMP governance platform real deployed agents to discover and govern.
    // They are NOT production decision-makers. Each agent carries an in-prompt
    // responsible-use disclaimer instructing the model to behave as a
    // non-authoritative assistant (preliminary/administrative suggestions only).
    // One of these operates in a regulated domain (insurance claims triage); its
    // outputs are not coverage/claims decisions. A production deployment should
    // attach an Amazon Bedrock Guardrail (set guardrailId/guardrailVersion on the
    // BedrockModel in each agent) and keep a qualified human in the loop for all
    // final decisions.
    const sampleAgents = [
      { id: "SampleClaimsTriageRuntime", runtimeName: "sampleClaimsTriage", dir: "sample-claims-triage",
        description: "Sample agent: insurance claims triage assistant" },
      { id: "SampleSupplyChainRuntime", runtimeName: "sampleSupplyChain", dir: "sample-supply-chain",
        description: "Sample agent: supply-chain disruption analyst" },
      { id: "SampleRequestIntakeRuntime", runtimeName: "sampleRequestIntake", dir: "sample-request-intake",
        description: "Sample agent: service request intake assistant" },
    ];

    const arns: string[] = [];
    for (const s of sampleAgents) {
      const runtime = new agentcore.Runtime(this, s.id, {
        runtimeName: s.runtimeName,
        // Direct-code deploy (no Docker): assembleAgentBundle vendors the agent's
        // arm64/cp312 deps (strands, boto3) into the bundle via `uv pip install`.
        agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromCodeAsset({
          path: assembleAgentBundle({
            agentDir: path.join(assetsSrc, "agents", s.dir),
            sharedDir,
            sharedPackages: [],
            stagingRoot: bundleStagingRoot,
            bundleName: s.dir,
          }),
          runtime: agentcore.AgentCoreRuntime.PYTHON_3_12,
          entrypoint: ["main.py"],
        }),
        environmentVariables: { PORT: "8080", ...observabilityEnv },
        description: s.description,
      });
      runtime.addToRolePolicy(modelInvokeStatement);
      // Cost-allocation tag so a FlowAMP running elsewhere can attribute spend and
      // discovery can key on it.
      cdk.Tags.of(runtime).add("flowamp:agentId", s.runtimeName);
      arns.push(runtime.agentRuntimeArn);
    }

    new cdk.CfnOutput(this, "SampleAgentRuntimeArns", { value: cdk.Fn.join(",", arns) });
  }
}
