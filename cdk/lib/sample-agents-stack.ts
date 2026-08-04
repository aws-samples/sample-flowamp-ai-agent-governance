// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { SAMPLE_AGENTS, addSampleHarness } from "./sample-agents";

/**
 * SampleAgentsStack — deploys ONLY the three standalone sample agents (insurance
 * claims triage, supply-chain analyst, service request intake). No FlowAMP platform:
 * no DynamoDB, API Gateway, Cognito, UI, or governance agents.
 *
 * Use this to stand up just the sample workloads in a separate account for testing —
 * e.g. so a FlowAMP instance running elsewhere has real cross-account agents to
 * discover. The agent definitions live in ./sample-agents, shared with TeamStack.
 */
export class SampleAgentsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Model the sample agents invoke. Same model the rest of the repo pins.
    const inferenceProfileId = "us.anthropic.claude-sonnet-4-6";
    const baseModelId = "anthropic.claude-sonnet-4-6";
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
        // So a FlowAMP running elsewhere can attribute spend and discovery can key on it.
        costTagKey: "flowamp:agentId",
      })
    );

    new cdk.CfnOutput(this, "SampleAgentHarnessArns", {
      value: cdk.Fn.join(",", arns),
      description: "ARNs of the 3 sample workload harnesses.",
    });
  }
}
