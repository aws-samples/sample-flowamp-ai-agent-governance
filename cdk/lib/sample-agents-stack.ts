// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { SAMPLE_AGENTS, addSampleHarness } from "./sample-agents";

/**
 * Deploys only the three standalone sample agents (insurance claims triage, supply-chain
 * analyst, service request intake), with no FlowAMP platform: no DynamoDB, API Gateway,
 * Cognito, UI, or governance agents.
 *
 * Use this to stand up just the sample workloads in a separate account, for example so a
 * FlowAMP instance running elsewhere has real cross-account agents to discover. The agent
 * definitions live in ./sample-agents, shared with TeamStack.
 */
export class SampleAgentsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Model the sample agents invoke. Keep this in step with team-stack.ts, since the two
    // stacks can deploy into the same account.
    const inferenceProfileId = "us.anthropic.claude-sonnet-5";
    const baseModelId = "anthropic.claude-sonnet-5";
    const inferenceProfileArn = `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${inferenceProfileId}`;

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

    const arns = SAMPLE_AGENTS.map((def) =>
      addSampleHarness(this, def, {
        region: this.region,
        account: this.account,
        inferenceProfileId,
        modelInvokeStatement,
        // Lets a FlowAMP running elsewhere attribute spend and key discovery on it.
        costTagKey: "flowamp:agentId",
      })
    );

    new cdk.CfnOutput(this, "SampleAgentHarnessArns", {
      value: cdk.Fn.join(",", arns),
      description: "ARNs of the 3 sample workload harnesses.",
    });
  }
}
