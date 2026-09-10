#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { SampleAgentsStack } from "../lib";

// Standalone app that deploys only the 3 sample AgentCore agents, with no FlowAMP
// platform. Intended for a separate account, for example to give a FlowAMP instance
// running elsewhere real cross-account agents to discover.
//
// Deploy with the sample-agents app named explicitly, so it never touches TeamStack:
//   npx cdk deploy --app "npx ts-node --prefer-ts-exts bin/sample-agents.ts" SampleAgentsStack
const app = new cdk.App();

new SampleAgentsStack(app, "SampleAgentsStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
