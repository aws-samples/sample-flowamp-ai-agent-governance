// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as agentcore from "aws-cdk-lib/aws-bedrockagentcore";
import { Construct } from "constructs";

/**
 * The three illustrative sample workload agents, and the code that deploys one.
 *
 * Defined here once so both consumers share a single source of truth: TeamStack (behind
 * `-c deploySampleAgents=true`) and the standalone SampleAgentsStack, which gives a FlowAMP
 * instance running elsewhere real cross-account agents to discover.
 *
 * They are tool-less AgentCore harnesses. Their work is prompt-shaped (summarize, classify,
 * recommend) with no AWS calls, so the managed agent loop does the job with no container,
 * no code bundle and no dependency vendoring.
 *
 * Responsible AI: these are illustrative, non-production samples whose only purpose is to
 * give the governance platform real deployed agents to discover and govern. Each carries an
 * in-prompt responsible-use disclaimer telling the model to behave as a non-authoritative
 * assistant, and one operates in a regulated domain (insurance claims triage) where its
 * outputs are not coverage or claims decisions. A production deployment should attach an
 * Amazon Bedrock Guardrail and keep a qualified human in the loop for all final decisions.
 */
export interface SampleAgentDef {
  /** Construct id. */
  readonly id: string;
  /** Harness name - alphanumerics and underscores only, no hyphens. */
  readonly harnessName: string;
  /** Registry-facing id (hyphenated form), used for cost-allocation tags. */
  readonly agentId: string;
  readonly businessUnit: string;
  readonly costCenter: string;
  readonly systemPrompt: string;
}

export const SAMPLE_AGENTS: SampleAgentDef[] = [
  {
    id: "SampleClaimsTriage",
    harnessName: "sample_claims_triage",
    agentId: "sample-claims-triage",
    businessUnit: "Insurance",
    costCenter: "INS-1001",
    systemPrompt: `You are an insurance claims triage assistant.
You process incoming claims by summarizing the claim narrative, classifying
its severity (low/medium/high/critical), flagging likely-fraud signals, and
recommending how the claim should be routed and prioritized.
Be explicit about fraud indicators and severity reasoning, but note that final
coverage and fraud decisions remain with a human adjuster.

IMPORTANT: This is an illustrative sample for demonstration only. Your output is
a preliminary, non-binding triage suggestion — NOT an insurance coverage
determination, claims decision, or fraud adjudication. A licensed human
adjudicator must review and make all final decisions. Do not provide legal or
financial advice.`,
  },
  {
    id: "SampleSupplyChain",
    harnessName: "sample_supply_chain",
    agentId: "sample-supply-chain",
    businessUnit: "Operations",
    costCenter: "OPS-2002",
    systemPrompt: `You are a supply-chain disruption analyst.
You monitor supplier and logistics signals, quantify the operational and
financial impact of disruptions (delays, stockouts, revenue at risk), and
recommend concrete mitigation actions such as expediting freight, rerouting,
or activating backup suppliers.
Present quantified impact clearly and call out single-source dependencies and
urgent escalations.

IMPORTANT: This is an illustrative sample for demonstration only; outputs are
non-binding suggestions for demonstration, not operational decisions. A human
reviewer should validate any recommendation before it is acted on.`,
  },
  {
    id: "SampleRequestIntake",
    harnessName: "sample_request_intake",
    agentId: "sample-request-intake",
    businessUnit: "Customer",
    costCenter: "CUS-3003",
    systemPrompt: `You are a service request intake assistant.
Your job is strictly administrative: you structure free-text service requests
into a list of topics, assign a priority level, and route each request to an
appropriate handling team.
You do NOT make final resolution decisions. Always state that your output is
administrative structuring and routing only, and that the responsible team must
review and confirm. Escalate any critical-incident keywords for immediate review.

IMPORTANT: This is an illustrative sample for demonstration only. Output is
administrative request structuring and routing — NOT a final decision. A human
reviewer must confirm consequential actions.`,
  },
];

/**
 * Create one sample harness with its own execution role, and return its ARN.
 *
 * Each agent gets a separate role, so inspecting one sample's permissions shows only that
 * agent's access and revoking one in a lifecycle demo does not affect the others.
 */
export function addSampleHarness(
  scope: Construct,
  def: SampleAgentDef,
  opts: {
    readonly region: string;
    readonly account: string;
    readonly inferenceProfileId: string;
    readonly modelInvokeStatement: iam.PolicyStatement;
    readonly costTagKey: string;
  }
): string {
  const { region, account, inferenceProfileId, modelInvokeStatement, costTagKey } = opts;

  const role = new iam.Role(scope, `${def.id}Role`, {
    assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com", {
      // Confused-deputy protection: only AgentCore acting on this account's own
      // resources may assume the execution role.
      conditions: {
        StringEquals: { "aws:SourceAccount": account },
        ArnLike: { "aws:SourceArn": `arn:aws:bedrock-agentcore:${region}:${account}:*` },
      },
    }),
    description: `Execution role for the ${def.agentId} sample harness.`,
  });

  role.addToPrincipalPolicy(modelInvokeStatement);
  // The harness pulls its application container from ECR Public at session start.
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ["ecr-public:GetAuthorizationToken", "sts:GetServiceBearerToken"],
      resources: ["*"],
    })
  );
  // A harness enables managed memory by default and provisions the memory resource itself,
  // named harness_<harnessName>_<suffix>. Without these actions the first invoke fails with
  // AccessDeniedException on ListEvents, because the harness reads conversation history
  // before it answers. The AgentCore docs' sample execution-role policy omits memory, so it
  // must be granted explicitly.
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: [
        "bedrock-agentcore:CreateEvent",
        "bedrock-agentcore:GetEvent",
        "bedrock-agentcore:ListEvents",
        "bedrock-agentcore:DeleteEvent",
        "bedrock-agentcore:RetrieveMemoryRecords",
      ],
      resources: [`arn:aws:bedrock-agentcore:${region}:${account}:memory/harness_*`],
    })
  );
  // Observability. A harness runs inside AgentCore Runtime, so its logs land under
  // /aws/bedrock-agentcore/runtimes/*. The metrics and X-Ray actions do not support
  // resource-level permissions, so those need Resource "*" (PutMetricData is fenced
  // to the bedrock-agentcore namespace instead).
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ["logs:CreateLogGroup", "logs:DescribeLogStreams"],
      resources: [`arn:aws:logs:${region}:${account}:log-group:/aws/bedrock-agentcore/runtimes/*`],
    })
  );
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ["logs:DescribeLogGroups"],
      resources: [`arn:aws:logs:${region}:${account}:log-group:*`],
    })
  );
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [
        `arn:aws:logs:${region}:${account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*`,
      ],
    })
  );
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords",
        "xray:GetSamplingRules",
        "xray:GetSamplingTargets",
      ],
      resources: ["*"],
    })
  );
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ["cloudwatch:PutMetricData"],
      resources: ["*"],
      conditions: { StringEquals: { "cloudwatch:namespace": "bedrock-agentcore" } },
    })
  );

  const harness = new agentcore.CfnHarness(scope, def.id, {
    harnessName: def.harnessName,
    executionRoleArn: role.roleArn,
    model: {
      bedrockModelConfig: { modelId: inferenceProfileId, maxTokens: 1024 },
    },
    systemPrompt: [{ text: def.systemPrompt }],
    // These agents declare no tools, but allowedTools defaults to "*", which implicitly
    // grants the harness's built-in tools, including `shell` and `file_operations`
    // (arbitrary command execution in the session microVM). An empty allowlist is the
    // least-privilege posture for an agent that only answers from its system prompt.
    allowedTools: [],
    maxIterations: 4,
    timeoutSeconds: 60,
    // Distinct owners so the chargeback view spans several cost centres rather than landing
    // everything in one bucket.
    tags: [
      { key: "AgentId", value: def.agentId },
      { key: "BusinessUnit", value: def.businessUnit },
      { key: "CostCenter", value: def.costCenter },
    ],
  });

  // Per-agent cost-allocation tag (beats a stack-level 'platform' tag).
  cdk.Tags.of(harness).add(costTagKey, def.agentId);
  return harness.attrArn;
}
