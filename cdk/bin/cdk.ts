#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { AwsSolutionsChecks, NagSuppressions } from "cdk-nag";
import { TeamStack } from "../lib";

const app = new cdk.App();

// Deploys into any account/region via the standard `cdk bootstrap` + `cdk deploy` flow.
// env resolves from the ambient AWS credentials/region (CDK_DEFAULT_* set by the CLI).
//
// The construct id is also the CloudFormation stack name. Renaming it does not rename an
// existing deployment: CDK treats the new id as a different stack and creates it alongside
// the old one, and several resources carry fixed account-unique names that do not move with
// the stack name (the AgentCore gateway, the management harness, the two scanner runtimes),
// so the parallel deploy fails on those collisions. Delete the previous stack before renaming.
const teamStack = new TeamStack(app, "FLOWAMP", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});

// Security scanning (cdk-nag AwsSolutions ruleset): enable with `-c cdkNag=true`. Off by
// default so it never affects normal deploys. Findings that are accepted risks for a sample
// are documented as stack-level suppressions below; genuine hardening (for example S3
// enforceSSL) is fixed in the stack rather than suppressed.
if (app.node.tryGetContext("cdkNag") === "true") {
  cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

  NagSuppressions.addStackSuppressions(teamStack, [
    {
      id: "AwsSolutions-IAM4",
      reason:
        "Sample uses the AWS-managed AWSLambdaBasicExecutionRole for baseline Lambda " +
        "logging. Acceptable for a demonstration control plane; production adopters " +
        "should replace it with a scoped customer-managed policy (see README 'Production hardening').",
    },
    {
      id: "AwsSolutions-IAM5",
      reason:
        "Wildcards are limited to AWS actions that do not support resource-level " +
        "permissions (e.g. bedrock:ListAgents, bedrock-agentcore:ListAgentRuntimes, " +
        "ce:GetCostAndUsage, logs:DescribeLogGroups, cloudwatch:*Metric*) or to " +
        "account+region-scoped runtime-id wildcards for agents the scanners discover " +
        "at runtime and cannot enumerate at synth time. Each occurrence is justified " +
        "inline in team-stack.ts.",
    },
    {
      id: "AwsSolutions-L1",
      reason:
        "Lambdas pin Python 3.12 deliberately: it is a current, supported runtime and " +
        "matches the AgentCore direct-code cp312 target the agents require. Left pinned " +
        "for reproducibility of this sample rather than tracking 'latest'.",
    },
    {
      id: "AwsSolutions-APIG2",
      reason:
        "The REST API is Cognito-authorized and every backend Lambda validates its own " +
        "input; API Gateway request-body validation is not layered on to avoid rejecting " +
        "the proxy/action-group payloads. Acceptable for a sample.",
    },
    {
      id: "AwsSolutions-APIG3",
      reason: "No AWS WAF on the demo API. Documented as a production-hardening item in the README.",
    },
    {
      id: "AwsSolutions-APIG6",
      reason: "Method-level CloudWatch execution logging is not enabled; stage-level JSON access logging is configured on the deployment stage.",
    },
    {
      id: "AwsSolutions-COG2",
      reason: "MFA is not enforced on the single seeded demo user. Adopters should require MFA in production (README 'Production hardening').",
    },
    {
      id: "AwsSolutions-COG8",
      reason: "Cognito advanced-security (plus tier) is not enabled for this demo user pool; a production deployment should enable it.",
    },
    {
      id: "AwsSolutions-CFR1",
      reason: "No CloudFront geo restrictions on the demo distribution; not applicable to a public sample UI.",
    },
    {
      id: "AwsSolutions-CFR2",
      reason: "No AWS WAF integration on the demo CloudFront distribution. Documented as a production-hardening item.",
    },
    {
      id: "AwsSolutions-CFR3",
      reason: "CloudFront access logging is not enabled for the demo distribution to avoid provisioning a second log bucket; the origin S3 bucket has server access logging enabled.",
    },
    {
      id: "AwsSolutions-CFR4",
      reason: "The demo distribution uses the default CloudFront viewer certificate (TLSv1 minimum policy). A production deployment should attach an ACM certificate enforcing TLSv1.2+.",
    },
    {
      id: "AwsSolutions-DDB3",
      reason: "Point-in-time recovery is off for the demo table (RemovalPolicy.DESTROY, disposable sample data). Adopters should enable PITR in production.",
    },
  ]);
}
