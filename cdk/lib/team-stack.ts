// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import * as cdk from "aws-cdk-lib";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as logs from "aws-cdk-lib/aws-logs";
// Harness + Gateway are stable L1/L2s in aws-cdk-lib. The alpha agentcore package is
// needed only for the two scanner runtimes (which run real Python, so a harness cannot
// host them) and is imported lazily where they are defined.
import * as agentcore from "aws-cdk-lib/aws-bedrockagentcore";
// AgentCore online-evaluation configs are created at runtime by the eval-provisioner
// Lambda, not as a CFN resource: the control plane validates at create time that the
// runtime-id-suffixed trace log groups already exist, and those names only exist once
// an agent has run. See the eval-provisioner block below.
import { Construct } from "constructs";
import * as path from "path";
import { assembleAgentBundle } from "./agent-bundle";
import { SAMPLE_AGENTS, addSampleHarness } from "./sample-agents";

/**
 * FlowAMP ("Agent Management Platform").
 *
 * Deploys into any account via the normal `cdk bootstrap` + `cdk deploy` flow. Lambda,
 * agent and site assets are sourced from ../assetsSrc.
 *
 * The management agent is an AgentCore harness (model, prompt and gateway tools supplied
 * as configuration) and always deploys. The discovery-scanner and compliance-scanner are
 * AgentCore runtimes, because they are Python programs and a harness runs no custom code.
 * The discovery-scanner owns single-account native discovery; the discovery-handler Lambda
 * owns external and cross-account discovery, and takes native discovery back when the
 * scanners are not deployed.
 *
 * Context flags:
 *   - `deploySampleAgents=true` (default off) adds 3 sample workload harnesses.
 *   - `seedSampleData=true` (default off) loads a demo catalog and the simulated
 *     external connectors.
 *   - `enableCostExplorer` (default on) deploys the Cost Explorer FinOps collector.
 *   - `enableOrgDiscovery` (default on) cross-account discovery; requires the
 *     organization management or delegated-admin account.
 *   - `enableTransactionSearch=true` (default off) adds Gateway trace delivery. This is
 *     an account-wide setting that moves span ingestion onto CloudWatch pricing; Gateway
 *     request/response logs are delivered either way.
 *   - `deployGovernanceAgents` (default on) the two scanner runtimes. Setting `=false`
 *     stops compliance auditing and drops the LLM enrichment from discovery, and is the
 *     only way to remove the `uv` synth prerequisite.
 */
export class TeamStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const assetsSrc = path.join(__dirname, "..", "..", "assetsSrc");
    const sharedDir = path.join(assetsSrc, "agents", "_shared");
    const bundleStagingRoot = path.join(__dirname, "..", "cdk.out", "agent-bundles");

    // ─── Deploy-time context flags ───
    const seedSampleData = this.node.tryGetContext("seedSampleData") === "true";
    // The 3 optional sample workload harnesses.
    const deploySampleAgents = this.node.tryGetContext("deploySampleAgents") === "true";
    // Cost Explorer collector (daily) plus activation of the flowamp:agentId
    // cost-allocation tag. Cost data appears once the tag is activated in Billing (up to
    // ~48h) and spend accrues; until then the collector runs and writes nothing.
    const enableCostExplorer = this.node.tryGetContext("enableCostExplorer") !== "false";
    const COST_TAG_KEY = "flowamp:agentId";
    // Cross-account discovery via the aws-org connector. Requires the organization
    // management or delegated-admin account: organizations:ListAccounts plus assuming a
    // role in each member account. Elsewhere the connector returns nothing and surfaces a
    // warning in the UI rather than falling back to simulated data.
    const enableOrgDiscovery = this.node.tryGetContext("enableOrgDiscovery") !== "false";
    // Control Tower's execution role, present in enrolled accounts and trusting the
    // management account. For an organization without Control Tower, pass
    // `-c orgDiscoveryRoleName=OrganizationAccountAccessRole`.
    const orgDiscoveryRoleName = this.node.tryGetContext("orgDiscoveryRoleName") || "AWSControlTowerExecution";
    const orgDiscoveryRegions = this.node.tryGetContext("orgDiscoveryRegions") || "";
    // The discovery-scanner and compliance-scanner runtimes.
    //
    // `-c deployGovernanceAgents=false` removes features, not just resources: discovery
    // still populates the catalog but loses its LLM enrichment, compliance auditing stops
    // and the Compliance view stays empty, and the scanner evaluation configs cannot be
    // created. The UI routes around the absent API routes via
    // window.DISCOVERY_SCAN_ENABLED / window.COMPLIANCE_SCAN_ENABLED. Chat, the registry,
    // FinOps, RAI scoring, AOPs and access are unaffected. These are also the only
    // components needing a direct-code bundle, so this is the only way to drop the `uv`
    // synth prerequisite.
    const deployGovernanceAgents =
      this.node.tryGetContext("deployGovernanceAgents") !== "false";
    // CloudWatch Transaction Search, required for the Gateway's trace delivery. Off by
    // default because it is an account-wide setting that moves span ingestion onto
    // CloudWatch pricing (1% of spans indexed free). Gateway request/response logs are
    // delivered either way; only distributed traces need this.
    const enableTransactionSearch =
      this.node.tryGetContext("enableTransactionSearch") === "true";

    // Set inside the core-agents block; wired to API routes below so the UI can
    // trigger the discovery-scanner and compliance-scanner directly.
    let discoveryScanInvokerFn: lambda.Function | undefined;
    let complianceScanInvokerFn: lambda.Function | undefined;
    let evalProvisionerFn: lambda.Function | undefined;

    // ─── DynamoDB ───
    // Single table for the whole platform. Composite key: agentId (PK) + sk (SK).
    //   - Agent / compliance: / aop: / access: records use sk = "INFO" (one row per entity).
    //   - Live cost ledger rows use sk = "COST#<YYYY-MM-DD>" under their agentId.
    //   - Append-only audit events use sk = "EVENT#<ISO-ts>#<eventId>"
    //     (agentId = the subject agent, or "system" for non-agent events).
    // Readers that want only entity rows filter sk = "INFO" so cost/event rows never
    // leak into agent/compliance/aop/access listings.
    const agentTable = new dynamodb.Table(this, "AgentTable", {
      partitionKey: { name: "agentId", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      // Audit EVENT# rows carry a 90-day epoch "ttl" attribute; DynamoDB TTL
      // auto-expires them so the append-only log stays bounded.
      timeToLiveAttribute: "ttl",
    });

    // ─── Lambda: registry read API (served to the harness as MCP tools) ───
    const agentHandlerFn = new lambda.Function(this, "AgentHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "agent-handler")),
      environment: { AGENT_TABLE_NAME: agentTable.tableName },
      timeout: cdk.Duration.seconds(30),
    });
    agentTable.grantReadData(agentHandlerFn);

    // ─── Seed DynamoDB (demo catalog) - off by default ───
    // Loads ~30 demo agent rows so the UI has content in a sandbox. Left off, the catalog
    // starts empty and is populated only by discovery of the account's own agents. Opt in
    // with `-c seedSampleData=true`.
    if (seedSampleData) {
      const seedFn = new lambda.Function(this, "SeedDataFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "seed-data")),
        environment: { AGENT_TABLE_NAME: agentTable.tableName },
        timeout: cdk.Duration.seconds(60),
      });
      agentTable.grantWriteData(seedFn);

      const seedProvider = new cr.Provider(this, "SeedProvider", { onEventHandler: seedFn });
      new cdk.CustomResource(this, "SeedData", { serviceToken: seedProvider.serviceToken });
    }

    // ─── Cognito ───
    // Authenticates the demo UI and gates the API. Self-signup is disabled: the
    // single demo user ("flowadmin") is seeded by a custom resource below and
    // its generated password is surfaced as a CfnOutput. Corporate SSO in the UI is
    // a placeholder only, so no UserPoolDomain / hosted UI is provisioned.
    const userPool = new cognito.UserPool(this, "UserPool", {
      signInAliases: { username: true, email: true },
      selfSignUpEnabled: false,
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const userPoolClient = new cognito.UserPoolClient(this, "UserPoolClient", {
      userPool,
      generateSecret: false,
      authFlows: { userPassword: true, userSrp: true },
    });

    // Seed the single demo user and reset its password on every deploy. The
    // generated password is returned to CloudFormation and exposed via CfnOutput.
    const cognitoSeedUserFn = new lambda.Function(this, "CognitoSeedUserFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "cognito-seed-user")),
      environment: { USER_POOL_ID: userPool.userPoolId, USER_NAME: "flowadmin" },
      timeout: cdk.Duration.seconds(60),
    });
    cognitoSeedUserFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "cognito-idp:AdminCreateUser",
          "cognito-idp:AdminSetUserPassword",
          "cognito-idp:AdminGetUser",
        ],
        resources: [userPool.userPoolArn],
      })
    );

    const cognitoSeedProvider = new cr.Provider(this, "CognitoSeedProvider", {
      onEventHandler: cognitoSeedUserFn,
    });
    const seedUser = new cdk.CustomResource(this, "CognitoSeedUser", {
      serviceToken: cognitoSeedProvider.serviceToken,
    });

    // ─── Discovery Agent (multi-platform sync) ───
    // The Lambda connector handles external connectors + cross-account ORG discovery.
    // Native discovery is owned by exactly one component: the discovery-scanner when it
    // is deployed, this Lambda when it is not. NATIVE_DISCOVERY_ENABLED tells the Lambda
    // which, so the two never double-write the same agent under different keys.
    const nativeDiscoveryOwnedByLambda = !deployGovernanceAgents;
    // Fixed name so the function can grant itself invoke via a constructed ARN
    // (referencing .functionArn in its own role policy is a circular dependency).
    const discoveryFnName = `${cdk.Stack.of(this).stackName}-DiscoveryHandler`;
    const discoveryFn = new lambda.Function(this, "DiscoveryHandlerFn", {
      functionName: discoveryFnName,
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "discovery-handler")),
      environment: {
        AGENT_TABLE_NAME: agentTable.tableName,
        NATIVE_DISCOVERY_ENABLED: nativeDiscoveryOwnedByLambda ? "true" : "false",
        // The okta/mulesoft connectors are hardcoded demo data, not API clients, so they
        // must stay gated or a default deploy writes invented agents into the catalog. The
        // microsoft connector is not gated here: it calls the real Microsoft Foundry API
        // and stays inert until an operator supplies credentials via /discovery/connectors.
        SEED_SAMPLE_DATA: seedSampleData ? "true" : "false",
        ORG_DISCOVERY_ENABLED: enableOrgDiscovery ? "true" : "false",
        ORG_DISCOVERY_ROLE_NAME: orgDiscoveryRoleName,
        ...(orgDiscoveryRegions ? { ORG_DISCOVERY_REGIONS: orgDiscoveryRegions } : {}),
      },
      timeout: cdk.Duration.seconds(300),
    });
    agentTable.grantReadWriteData(discoveryFn);
    // Self-invoke: POST /discovery/sync fires an async copy of this function so a
    // multi-account org scan runs out of band (API Gateway's 29s cap would cut it
    // off). Constructed ARN avoids a circular dependency on .functionArn.
    discoveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["lambda:InvokeFunction"],
        resources: [`arn:aws:lambda:${this.region}:${this.account}:function:${discoveryFnName}`],
      })
    );
    // Native discovery reads real AWS agents: AgentCore harnesses, AgentCore
    // runtimes, and any legacy Bedrock Agents Classic agents the customer still
    // runs. List/Get only - discovery never invokes or mutates the agents it
    // governs. Granted regardless of the flag so the handler can enumerate when it
    // owns native discovery.
    discoveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock:ListAgents",
          "bedrock:GetAgent",
          "bedrock-agentcore:ListAgentRuntimes",
          // Harnesses are the execution surface FlowAMP's own agents run on, so
          // the registry must enumerate them and not just raw runtimes.
          "bedrock-agentcore:ListHarnesses",
          "bedrock-agentcore:GetHarness",
        ],
        resources: ["*"],
      })
    );
    // Connector credentials live in Secrets Manager, never in AgentTable: the platform
    // config row holds only the tenant/client ids plus the secret ARN, so no read path can
    // return the credential. This handler writes the secret (via the configuration API)
    // and reads it back on the scheduled sync.
    //
    // One path-scoped statement covers every action: CreateSecret accepts a name-prefix
    // ARN for a secret that does not exist yet, and the trailing `*` also absorbs the
    // random suffix Secrets Manager appends to every ARN. DescribeSecret lets an "is a
    // credential set?" check read metadata instead of decrypting the value. ListSecrets is
    // not granted: it cannot be resource-scoped, and the platform is always known from the
    // {platform} path parameter.
    discoveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:DeleteSecret",
        ],
        resources: [
          `arn:aws:secretsmanager:${this.region}:${this.account}:secret:flowamp/connectors/*`,
        ],
      })
    );
    // Real cross-account org discovery: enumerate the org + assume a read role in
    // each member account. Granted only when enabled so a normal single-account
    // deploy carries no cross-account privileges.
    if (enableOrgDiscovery) {
      discoveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          // DescribeOrganization is only for display - the connector shows the org id in
          // its sync telemetry. It is a separate permission from ListAccounts, and
          // discovery works without it (the id renders empty), so it is granted but never
          // depended on.
          actions: [
            "organizations:ListAccounts",
            "organizations:DescribeOrganization",
            "sts:GetCallerIdentity",
          ],
          resources: ["*"],
        })
      );
      // Assume only the named discovery role, in any account (org-wide) - scoped to
      // the role name, not "*", so it can't assume arbitrary roles.
      discoveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["sts:AssumeRole"],
          resources: [`arn:aws:iam::*:role/${orgDiscoveryRoleName}`],
        })
      );
    }

    new events.Rule(this, "DiscoverySyncSchedule", {
      schedule: events.Schedule.rate(cdk.Duration.hours(6)),
      description: nativeDiscoveryOwnedByLambda
        ? "Sync agents from native AWS, Microsoft Foundry and the cross-account org connector every 6 hours"
        : "Sync Microsoft Foundry + the cross-account org connector every 6 hours (native discovery owned by the AgentCore scanner)",
    }).addTarget(new targets.LambdaFunction(discoveryFn));

    // ─── RAI Scorer (daily) ───
    const raiScorerFn = new lambda.Function(this, "RaiScorerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "rai-scorer")),
      environment: { AGENT_TABLE_NAME: agentTable.tableName },
      timeout: cdk.Duration.seconds(120),
    });
    agentTable.grantReadWriteData(raiScorerFn);
    raiScorerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"],
        resources: ["*"],
      })
    );
    raiScorerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["cloudtrail:LookupEvents"],
        resources: ["*"],
      })
    );
    new events.Rule(this, "RaiScorerSchedule", {
      schedule: events.Schedule.rate(cdk.Duration.days(1)),
    }).addTarget(new targets.LambdaFunction(raiScorerFn));

    // ─── FinOps: Cost Explorer collector (daily) ───
    // Pulls per-agent spend from AWS Cost Explorer, grouped by the flowamp:agentId
    // cost-allocation tag, and writes the COST#<date> rows the UI reads. Gated because
    // CE-grouped-by-tag data requires the tag to be activated in Billing (up to ~48h)
    // and real spend to accrue.
    if (enableCostExplorer) {
      const finopsCollectorFn = new lambda.Function(this, "FinopsCollectorFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "finops-collector")),
        environment: { AGENT_TABLE_NAME: agentTable.tableName, COST_TAG_KEY },
        timeout: cdk.Duration.seconds(120),
      });
      agentTable.grantReadWriteData(finopsCollectorFn);
      // Cost Explorer is account-wide; ce:* actions do not support resource scoping.
      finopsCollectorFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["ce:GetCostAndUsage"],
          resources: ["*"],
        })
      );
      // Run daily at 03:00 UTC - a few hours after CE finalizes the prior UTC day.
      new events.Rule(this, "FinopsCollectorSchedule", {
        schedule: events.Schedule.cron({ minute: "0", hour: "3" }),
        description: "Collect real per-agent spend from Cost Explorer (flowamp:agentId tag)",
      }).addTarget(new targets.LambdaFunction(finopsCollectorFn));

      // Best-effort activation of the cost-allocation tag (management account only;
      // fails gracefully elsewhere - see README for the manual Billing-console step).
      const costTagActivatorFn = new lambda.Function(this, "CostTagActivatorFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "cost-tag-activator")),
        environment: { COST_TAG_KEY },
        timeout: cdk.Duration.seconds(60),
      });
      costTagActivatorFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["ce:UpdateCostAllocationTagsStatus", "ce:ListCostAllocationTags"],
          // Cost Explorer actions are account-scoped and do not support resource-level
          // permissions, so "*" is required here.
          resources: ["*"],
        })
      );
      const costTagProvider = new cr.Provider(this, "CostTagActivatorProvider", {
        onEventHandler: costTagActivatorFn,
      });
      new cdk.CustomResource(this, "CostTagActivation", { serviceToken: costTagProvider.serviceToken });

      new cdk.CfnOutput(this, "FinopsCollectorFnName", { value: finopsCollectorFn.functionName });
    }

    // Cost-allocation tag on every taggable resource so Cost Explorer can attribute
    // spend. The stack-level value is "platform"; the discovery-scanner overrides it per
    // agent runtime. Applied regardless of enableCostExplorer, which gates activation and
    // collection rather than tagging, so tag history accrues from the first deploy.
    cdk.Tags.of(this).add(COST_TAG_KEY, "platform");

    // ─── Reasoning agent: AgentCore Harness + Gateway ───
    // A harness declares the model, system prompt and tools as configuration and lets
    // AgentCore run the agent loop, so it needs no container and no code bundle.
    //
    // Bedrock Agents Classic is not used: it is in maintenance mode, and CreateAgent is
    // refused in any account without Bedrock Agents usage in the prior 12 months, so it
    // cannot deploy into a fresh account. FlowAMP still discovers and audits Classic
    // agents that already exist.
    // https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html
    //
    // Both ids are required. The harness invokes the cross-region inference profile (`us.`
    // prefix), and invoking through a profile also authorizes against the underlying base
    // model, so the IAM policy below scopes to both ARNs. They must name the same model
    // version or the grant and the call disagree.
    const inferenceProfileId = "us.anthropic.claude-sonnet-5";
    const baseModelId = "anthropic.claude-sonnet-5";
    const inferenceProfileArn = `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${inferenceProfileId}`;

    // A Gateway fronts the agent-handler Lambda and exposes each operation as an MCP
    // tool, which the harness discovers and calls during its reasoning loop.
    //
    // Inbound auth is AWS IAM (SigV4), since the only caller is the harness in the same
    // account. Under SigV4 the harness does not propagate per-user identity into tool
    // calls, so FlowAMP authorizes per user at the API Gateway and Cognito edge.
    const gateway = new agentcore.Gateway(this, "AgentManagementGateway", {
      gatewayName: "flowamp-agent-management",
      description: "Read-only FlowAMP registry tools (agents, compliance, AOPs, access).",
      authorizerConfiguration: agentcore.GatewayAuthorizer.usingAwsIam(),
    });

    // One MCP tool per registry operation. The `description` is what the model reasons
    // over when choosing a tool, so keep these descriptive rather than terse restatements
    // of the name. addLambdaTarget grants the gateway role lambda:InvokeFunction on
    // agentHandlerFn and adds the aws:SourceAccount / aws:SourceArn confused-deputy
    // conditions.
    const agentIdProperty = {
      agentId: {
        type: agentcore.SchemaDefinitionType.STRING,
        description: "The unique identifier of the agent, for example service-health-monitor.",
      },
    };
    const noInput = { type: agentcore.SchemaDefinitionType.OBJECT, properties: {} };

    gateway.addLambdaTarget("AgentManagementTarget", {
      gatewayTargetName: "agent-management",
      description: "FlowAMP registry read API backed by the agent-handler Lambda.",
      lambdaFunction: agentHandlerFn,
      toolSchema: agentcore.ToolSchema.fromInline([
        {
          name: "listAgents",
          description:
            "List all registered AI agents across all platforms. Returns agents from " +
            "native (AWS), Microsoft, Okta, and MuleSoft platforms. Optionally filter by platform.",
          inputSchema: {
            type: agentcore.SchemaDefinitionType.OBJECT,
            properties: {
              platform: {
                type: agentcore.SchemaDefinitionType.STRING,
                description:
                  "Filter by platform: native, microsoft, okta, mulesoft. Omit for all platforms.",
              },
            },
          },
        },
        {
          name: "getAgent",
          description: "Get full details for one agent by its ID.",
          inputSchema: {
            type: agentcore.SchemaDefinitionType.OBJECT,
            properties: agentIdProperty,
            required: ["agentId"],
          },
        },
        {
          name: "getAgentMetrics",
          description:
            "Get performance and cost metrics for one agent: requests, errors, " +
            "response time, monthly cost, cost per invocation, and utilization.",
          inputSchema: {
            type: agentcore.SchemaDefinitionType.OBJECT,
            properties: agentIdProperty,
            required: ["agentId"],
          },
        },
        {
          name: "listCompliance",
          description:
            "List all compliance frameworks and scores, such as ISO 27001, GDPR, SOC 2, " +
            "and NIST AI RMF, with score, status, last audit date, and control details.",
          inputSchema: noInput,
        },
        {
          name: "listAOPs",
          description:
            "List all Agent Operating Policies with ID, name, status, assigned agents, " +
            "execution count, success rate, owner, and trigger condition.",
          inputSchema: noInput,
        },
        {
          name: "listAccess",
          description:
            "List the access control matrix: user roles and their permissions across the " +
            "agent categories Operations, Asset & Infrastructure, Finance, Security, and Customer.",
          inputSchema: noInput,
        },
        {
          name: "listPlatforms",
          description:
            "List all connected agent platforms with agent count, active count, " +
            "total monthly cost, and average Responsible AI score.",
          inputSchema: noInput,
        },
        {
          name: "getCrossPlatformSummary",
          description:
            "Get aggregated metrics across all platforms: total agent count, total cost, " +
            "average Responsible AI score, error totals, and per-platform breakdown. " +
            "This is the single-pane-of-glass summary.",
          inputSchema: noInput,
        },
      ]),
    });

    // ─── Gateway observability (logs, and traces when opted in) ───
    // A Gateway emits no application logs or spans until vended log delivery is wired up,
    // unlike the harness, which AgentCore Runtime instruments automatically. Without this
    // the tool-call layer is invisible: you see that the agent chose a tool, but not
    // whether the gateway dispatched it, with what arguments, or why it failed. Logs are
    // therefore delivered by default.
    //
    // CloudWatch vended logs take three resources: a delivery source per log type on the
    // gateway ARN, a delivery destination (a log group for logs, X-Ray for traces), and a
    // delivery joining each pair.
    const gatewayLogGroup = new logs.LogGroup(this, "GatewayLogs", {
      // Vended log delivery requires the /aws/vendedlogs/ prefix.
      logGroupName: `/aws/vendedlogs/bedrock-agentcore/${cdk.Names.uniqueId(this).toLowerCase()}-gateway`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const gatewayLogSource = new logs.CfnDeliverySource(this, "GatewayLogSource", {
      name: `${this.stackName}-gw-logs`,
      logType: "APPLICATION_LOGS",
      resourceArn: gateway.gatewayArn,
    });
    const gatewayLogDestination = new logs.CfnDeliveryDestination(this, "GatewayLogDestination", {
      name: `${this.stackName}-gw-logs-dest`,
      deliveryDestinationType: "CWL",
      destinationResourceArn: gatewayLogGroup.logGroupArn,
    });
    const gatewayLogDelivery = new logs.CfnDelivery(this, "GatewayLogDelivery", {
      deliverySourceName: gatewayLogSource.name,
      deliveryDestinationArn: gatewayLogDestination.attrArn,
    });
    // A delivery can only be created once both ends exist. The source is referenced by
    // name (a plain string), so CloudFormation cannot infer that edge from the template.
    gatewayLogDelivery.node.addDependency(gatewayLogSource, gatewayLogDestination);

    // exceptionLevel is not set: delivery carries full MCP request/response tracing
    // without it.

    if (enableTransactionSearch) {
      // A traces delivery to X-Ray requires the account's trace segment destination to be
      // CloudWatch Logs already. Accounts default to X-Ray, so without the two resources
      // below the delivery fails and rolls back the stack.
      // https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Enable-TransactionSearch.html
      //
      // Step 1: allow X-Ray to write spans into the reserved log groups. This is an
      // account-level resource policy with a fixed name, not attached to a role.
      const spanIngestionPolicy = new logs.CfnResourcePolicy(this, "XraySpanIngestionPolicy", {
        policyName: `${this.stackName}-xray-span-ingestion`,
        policyDocument: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "TransactionSearchXRayAccess",
              Effect: "Allow",
              Principal: { Service: "xray.amazonaws.com" },
              Action: "logs:PutLogEvents",
              Resource: [
                `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans:*`,
                `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/application-signals/data:*`,
              ],
              Condition: {
                ArnLike: { "aws:SourceArn": `arn:aws:xray:${this.region}:${this.account}:*` },
                StringEquals: { "aws:SourceAccount": this.account },
              },
            },
          ],
        }),
      });

      // Step 2: switch the account's trace segment destination to CloudWatch Logs and wait
      // for it to report ACTIVE. Two constraints shape this:
      //
      // 1. AWS::XRay::TransactionSearchConfig is an account+region singleton, so in an
      //    account where Transaction Search is already on it fails Create with
      //    AlreadyExists and rolls back the stack. UpdateTraceSegmentDestination is a PUT
      //    and therefore idempotent.
      // 2. That call is asynchronous: it returns PENDING, X-Ray finishes in the background,
      //    and it can still be rejected after responding. An AwsCustomResource would return
      //    immediately and the trace delivery would then be created against a PENDING
      //    account and fail, so this polls GetTraceSegmentDestination until it reports
      //    CloudWatchLogs and ACTIVE.
      //
      // Delete is a no-op: the setting is account-wide and pre-exists this stack in some
      // accounts, so reverting it could switch off tracing something else uses.
      const transactionSearchFn = new lambda.Function(this, "TransactionSearchFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        // Spans can take ~10 min to become searchable; ACTIVE arrives well before that.
        timeout: cdk.Duration.minutes(10),
        code: lambda.Code.fromInline(
          [
            "import json, time, urllib.request",
            "import boto3",
            "",
            "def _respond(event, context, status, reason=None):",
            "    body = json.dumps({",
            "        'Status': status,",
            "        'Reason': reason or ('See CloudWatch log stream: ' + context.log_stream_name),",
            "        'PhysicalResourceId': 'xray-transaction-search',",
            "        'StackId': event['StackId'],",
            "        'RequestId': event['RequestId'],",
            "        'LogicalResourceId': event['LogicalResourceId'],",
            "        'Data': {},",
            "    }).encode('utf-8')",
            "    req = urllib.request.Request(event['ResponseURL'], data=body, method='PUT')",
            "    req.add_header('content-type', '')",
            "    req.add_header('content-length', str(len(body)))",
            "    urllib.request.urlopen(req, timeout=30)",
            "",
            "def handler(event, context):",
            "    try:",
            "        # Delete is a no-op on purpose: the setting is account-wide.",
            "        if event['RequestType'] == 'Delete':",
            "            _respond(event, context, 'SUCCESS', 'Delete is a no-op')",
            "            return",
            "        x = boto3.client('xray')",
            "        cur = x.get_trace_segment_destination()",
            "        if cur.get('Destination') != 'CloudWatchLogs':",
            "            r = x.update_trace_segment_destination(Destination='CloudWatchLogs')",
            "            print('update returned: %s' % json.dumps(r, default=str))",
            "        # Poll until ACTIVE. The update is async and can even be rejected",
            "        # after responding, so the GET is the only signal worth trusting.",
            "        deadline = time.time() + max(30, (context.get_remaining_time_in_millis() / 1000.0) - 45)",
            "        last = None",
            "        while time.time() < deadline:",
            "            d = x.get_trace_segment_destination()",
            "            last = (d.get('Destination'), d.get('Status'))",
            "            if last == ('CloudWatchLogs', 'ACTIVE'):",
            "                print('transaction search ACTIVE')",
            "                _respond(event, context, 'SUCCESS')",
            "                return",
            "            print('waiting, currently %s' % (last,))",
            "            time.sleep(10)",
            "        _respond(event, context, 'FAILED',",
            "                 'Transaction Search did not reach CloudWatchLogs/ACTIVE in time; last=%s' % (last,))",
            "    except Exception as e:",
            "        _respond(event, context, 'FAILED', reason=str(e))",
          ].join("\n")
        ),
      });
      // The caller needs far more than xray:*, because the call provisions the two
      // reserved span log groups and wires up Application Signals on your behalf. This
      // mirrors the "Prerequisites" policy in the docs; granting less fails part-way
      // through, leaving Transaction Search half-enabled.
      for (const statement of [
        new iam.PolicyStatement({
          // Account-scoped X-Ray configuration calls; no resource-level support.
          actions: [
            "xray:GetTraceSegmentDestination",
            "xray:UpdateTraceSegmentDestination",
            "xray:GetIndexingRules",
            "xray:UpdateIndexingRule",
          ],
          resources: ["*"],
        }),
        new iam.PolicyStatement({
          // Scoped to the two reserved span log groups the call manages.
          actions: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutRetentionPolicy"],
          resources: [
            `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans:*`,
            `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/application-signals/data:*`,
          ],
        }),
        new iam.PolicyStatement({
          // PutResourcePolicy is account-scoped (no resource-level support), and
          // DescribeResourcePolicies is needed to read the existing set first.
          actions: ["logs:PutResourcePolicy", "logs:DescribeResourcePolicies"],
          resources: ["*"],
        }),
        new iam.PolicyStatement({
          actions: ["application-signals:StartDiscovery"],
          resources: ["*"],
        }),
        new iam.PolicyStatement({
          // Application Signals needs its service-linked role to exist; GetRole is how
          // the call checks before creating it.
          actions: ["iam:CreateServiceLinkedRole"],
          resources: [
            "arn:aws:iam::*:role/aws-service-role/application-signals.cloudwatch.amazonaws.com/AWSServiceRoleForCloudWatchApplicationSignals",
          ],
          conditions: {
            StringLike: { "iam:AWSServiceName": "application-signals.cloudwatch.amazonaws.com" },
          },
        }),
        new iam.PolicyStatement({
          actions: ["iam:GetRole"],
          resources: [
            "arn:aws:iam::*:role/aws-service-role/application-signals.cloudwatch.amazonaws.com/AWSServiceRoleForCloudWatchApplicationSignals",
          ],
        }),
        new iam.PolicyStatement({
          actions: ["cloudtrail:CreateServiceLinkedChannel"],
          resources: ["arn:aws:cloudtrail:*:*:channel/aws-service-channel/application-signals/*"],
        }),
      ]) {
        transactionSearchFn.addToRolePolicy(statement);
      }

      const transactionSearch = new cdk.CustomResource(this, "TransactionSearchEnable", {
        serviceToken: transactionSearchFn.functionArn,
      });
      // The resource policy must exist first, or X-Ray cannot write the spans it is now
      // being told to send to CloudWatch Logs.
      transactionSearch.node.addDependency(spanIngestionPolicy);

      const gatewayTraceSource = new logs.CfnDeliverySource(this, "GatewayTraceSource", {
        name: `${this.stackName}-gw-traces`,
        logType: "TRACES",
        resourceArn: gateway.gatewayArn,
      });
      // Traces go to X-Ray, which has no destination resource of its own.
      const gatewayTraceDestination = new logs.CfnDeliveryDestination(
        this,
        "GatewayTraceDestination",
        { name: `${this.stackName}-gw-traces-dest`, deliveryDestinationType: "XRAY" }
      );
      const gatewayTraceDelivery = new logs.CfnDelivery(this, "GatewayTraceDelivery", {
        deliverySourceName: gatewayTraceSource.name,
        deliveryDestinationArn: gatewayTraceDestination.attrArn,
      });
      gatewayTraceDelivery.node.addDependency(gatewayTraceSource, gatewayTraceDestination);
      // The XRAY destination is only valid once Transaction Search is ACTIVE, and CFN
      // cannot infer that edge (nothing references the config), so state it explicitly
      // rather than relying on creation order.
      gatewayTraceDestination.node.addDependency(transactionSearch);
      gatewayTraceDelivery.node.addDependency(transactionSearch);
    }

    const harnessRole = new iam.Role(this, "ManagementHarnessRole", {
      assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com", {
        // Confused-deputy protection: only AgentCore acting on this account's own
        // resources may assume the execution role.
        conditions: {
          StringEquals: { "aws:SourceAccount": this.account },
          ArnLike: { "aws:SourceArn": `arn:aws:bedrock-agentcore:${this.region}:${this.account}:*` },
        },
      }),
      description: "Execution role assumed by the FlowAMP management harness.",
    });

    // Declared once and reused by the harness itself and by the memory ARN patterns in its
    // execution role, which have to match the name AgentCore derives resources from.
    // Pattern: ^[a-zA-Z][a-zA-Z0-9_]{0,39}$ - underscores, no hyphens.
    const MANAGEMENT_HARNESS_NAME = "flowamp_management_agent";

    // Model inference, scoped to the one inference profile plus the underlying
    // foundation model in every region the profile can route to.
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        resources: [inferenceProfileArn, `arn:aws:bedrock:*::foundation-model/${baseModelId}`],
      })
    );
    // The harness pulls its application container from ECR Public at session start.
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["ecr-public:GetAuthorizationToken", "sts:GetServiceBearerToken"],
        resources: ["*"],
      })
    );
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["bedrock-agentcore:InvokeGateway"],
        resources: [gateway.gatewayArn],
      })
    );
    // AgentCore Memory. A harness enables managed memory by default and provisions the
    // memory resource itself. Without these actions the first InvokeHarness fails with
    // AccessDeniedException on ListEvents, because the harness reads conversation history
    // before it answers. The sample execution-role policy in the AgentCore docs omits
    // memory, so it must be granted explicitly.
    //
    // The memory resource is named `<harnessName>-<suffix>` — NOT `harness_<harnessName>`.
    // The `harness_` prefix applies to the backing runtime and its log group, not to
    // memory, so a pattern built on that prefix never matches and chat fails on the very
    // first message. Both patterns are granted so either naming resolves.
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock-agentcore:CreateEvent",
          "bedrock-agentcore:GetEvent",
          "bedrock-agentcore:ListEvents",
          "bedrock-agentcore:DeleteEvent",
          "bedrock-agentcore:RetrieveMemoryRecords",
        ],
        resources: [
          `arn:aws:bedrock-agentcore:${this.region}:${this.account}:memory/${MANAGEMENT_HARNESS_NAME}-*`,
          `arn:aws:bedrock-agentcore:${this.region}:${this.account}:memory/harness_${MANAGEMENT_HARNESS_NAME}-*`,
        ],
      })
    );
    // Observability. A harness runs inside AgentCore Runtime, so its logs land under
    // /aws/bedrock-agentcore/runtimes/*. The metrics and X-Ray actions do not
    // support resource-level permissions, so those need Resource "*" (PutMetricData
    // is fenced to the bedrock-agentcore namespace instead).
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["logs:CreateLogGroup", "logs:DescribeLogStreams"],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*`,
        ],
      })
    );
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["logs:DescribeLogGroups"],
        resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:*`],
      })
    );
    // Unified span destination: AgentCore delivers the harness's OTEL spans into the
    // agent's own log group (rather than the shared aws/spans group) only if the execution
    // role can grant X-Ray write access to that group. Without this the traces still
    // exist, but split away from the logs they belong to.
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["logs:PutResourcePolicy"],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*`,
        ],
      })
    );
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*`,
        ],
      })
    );
    harnessRole.addToPrincipalPolicy(
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
    harnessRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["cloudwatch:PutMetricData"],
        resources: ["*"],
        conditions: { StringEquals: { "cloudwatch:namespace": "bedrock-agentcore" } },
      })
    );

    const harness = new agentcore.CfnHarness(this, "ManagementHarness", {
      // AWS::BedrockAgentCore::Harness documents a Description property, but the L1 in the
      // pinned aws-cdk-lib does not expose it.
      harnessName: MANAGEMENT_HARNESS_NAME,
      executionRoleArn: harnessRole.roleArn,
      model: {
        bedrockModelConfig: {
          modelId: inferenceProfileId,
          // Always set maxTokens. Left unset, Bedrock reserves the model's maximum output
          // budget per call against the account's token quota, which throttles far earlier
          // than real usage warrants.
          maxTokens: 4096,
        },
      },
      systemPrompt: [
        {
          text: `You are an AI agent management assistant for an enterprise.
You help operators monitor and manage AI agents deployed across operations,
asset and infrastructure, finance and trading, security and compliance, and customer operations.
Use the available tools to fetch real data before responding.`,
        },
      ],
      tools: [
        {
          // The tool-type enum is lower_snake_case: remote_mcp | agentcore_browser |
          // agentcore_gateway | inline_function | agentcore_code_interpreter. A
          // SHOUTING_CASE value is rejected by the AWS::EarlyValidation
          // ::PropertyValidation hook at change-set time, not at synth.
          type: "agentcore_gateway",
          name: "agentManagement",
          config: {
            agentCoreGateway: {
              gatewayArn: gateway.gatewayArn,
              // The gateway uses SigV4 inbound auth, so the harness calls it with
              // its own execution-role credentials rather than a stored token.
              outboundAuth: { awsIam: {} },
            },
          },
        },
      ],
      // Restrict the agent to the registry tools served by the gateway. Left unset,
      // allowedTools defaults to "*", which also exposes the harness's built-in `shell`
      // and `file_operations` tools (arbitrary command execution in the session microVM).
      allowedTools: ["@agentManagement/*"],
      // Bound the loop so a runaway reasoning chain cannot burn the account's token
      // budget. Eight iterations is ample for these read-only lookups.
      maxIterations: 8,
      timeoutSeconds: 120,
      // Per-agent cost-allocation tag, so a Cost Explorer group-by lines up with the
      // FinOps dashboard's rows.
      tags: [
        { key: "AgentId", value: "flowamp-management-agent" },
        { key: "BusinessUnit", value: "Platform" },
        { key: "CostCenter", value: "AI-Governance" },
      ],
    });
    // The harness resolves gateway tools at create time; make the ordering explicit
    // rather than relying on the gatewayArn reference alone.
    harness.node.addDependency(gateway);

    // ─── AgentCore Runtimes (Strands agents) ───
    // The two governance agents (discovery-scanner, compliance-scanner) are AgentCore
    // runtimes: they are real Python programs, and a harness cannot host custom code. The
    // 3 sample workload agents (claims-triage, supply-chain, request-intake) are optional
    // demo content behind deploySampleAgents and are tool-less harnesses.
    {
      // Imported lazily so the alpha module is only loaded when used. Only Runtime comes
      // from alpha; Harness and Gateway are stable in aws-cdk-lib (imported at the top as
      // `agentcore`), so the two are kept visibly distinct here.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const agentcoreAlpha = require("@aws-cdk/aws-bedrock-agentcore-alpha");

      // Least-privilege model-invocation policy shared by every runtime.
      const modelInvokeStatement = new iam.PolicyStatement({
        actions: [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:GetInferenceProfile",
        ],
        resources: [
          inferenceProfileArn,
          `arn:aws:bedrock:*::foundation-model/${baseModelId}`,
          // The governance/sample agents may resolve model ids via inference
          // profiles in any region; scope to this account's profiles + base models.
          `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
        ],
      });

      // Observability env shared by every runtime: activates the AgentCore ADOT pipeline so
      // the runtime injects the OTLP endpoint and the agent's Strands tracer exports spans
      // to aws/spans (Transaction Search). AGENT_OBSERVABILITY_ENABLED is required - without
      // it the runtime never sets OTEL_EXPORTER_OTLP_ENDPOINT, the tracer stays inert, no
      // spans are produced, and AgentCore Evaluations has nothing to score.
      const observabilityEnv: Record<string, string> = {
        AGENT_OBSERVABILITY_ENABLED: "true",
        OTEL_PYTHON_DISTRO: "aws_distro",
        OTEL_PYTHON_CONFIGURATOR: "aws_configurator",
        OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
      };

      // ── Core governance agents: discovery + compliance scanners ──
      // Runtimes rather than harnesses: they are Python programs with custom tools,
      // DynamoDB writes and cross-account assume-role, whereas a harness runs only a model,
      // prompt and declared tools. The management agent is the ManagementHarness above.
      if (deployGovernanceAgents) {
      // discovery-scanner: enumerates and LLM-classifies real AgentCore runtimes and writes
      // normalized catalog rows. It owns native discovery whenever it is deployed.
      const discoveryScannerBundle = assembleAgentBundle({
        agentDir: path.join(assetsSrc, "agents", "discovery-scanner"),
        sharedDir,
        sharedPackages: ["flowamp_tools"],
        stagingRoot: bundleStagingRoot,
        bundleName: "discovery-scanner",
      });
      const discoveryScanner = new agentcoreAlpha.Runtime(this, "DiscoveryScannerRuntime", {
        runtimeName: "flowampDiscoveryScanner",
        // Direct-code deploy: bundle carries main.py, the vendored flowamp_tools
        // package, and all arm64 pip deps (installed by assembleAgentBundle).
        agentRuntimeArtifact: agentcoreAlpha.AgentRuntimeArtifact.fromCodeAsset({
          path: discoveryScannerBundle,
          runtime: agentcoreAlpha.AgentCoreRuntime.PYTHON_3_12,
          entrypoint: ["main.py"],
        }),
        environmentVariables: {
          AGENT_TABLE_NAME: agentTable.tableName,
          FLOWAMP_AGENT_ID: "flowamp_discovery_scanner",
          ENVIRONMENT: "local",
          PORT: "8080",
          ...observabilityEnv,
        },
        description: "FlowAMP discovery scanner — discovers and classifies AgentCore runtimes",
      });
      agentTable.grantReadWriteData(discoveryScanner);
      discoveryScanner.addToRolePolicy(modelInvokeStatement);
      cdk.Tags.of(discoveryScanner).add(COST_TAG_KEY, "flowampDiscoveryScanner");
      // Discovery/enrichment: get runtimes, invoke them for self-description, tag them.
      // These actions support resource-level permissions on the AgentCore `runtime`
      // resource type, so scope them to this account+region's runtimes (and their
      // endpoints) rather than "*". The scanner discovers runtimes it does not know
      // ahead of time, so a runtime-id wildcard within the account is the tightest
      // feasible scope.
      discoveryScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "bedrock-agentcore:GetAgentRuntime",
            "bedrock-agentcore:InvokeAgentRuntime",
            "bedrock-agentcore:TagResource",
          ],
          resources: [
            `arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*`,
            `arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*/*`,
          ],
        })
      );
      // Fleet-enumeration and cross-inventory reads. The List actions do not support
      // resource-level permissions, and bedrock:GetAgent inspects the separate Bedrock
      // Agents Classic inventory. All read-only, so "*" is required.
      discoveryScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "bedrock-agentcore:ListAgentRuntimes",
            // Harnesses must be enumerated as a first-class surface, or a harness is
            // registered under its backing-runtime name (harness_<name>) instead.
            "bedrock-agentcore:ListHarnesses",
            "bedrock-agentcore:GetHarness",
            "bedrock:ListAgents",
            "bedrock:GetAgent",
            // Display only: the account alias is the nearest thing to an account name
            // available from inside the account, so the registry's Account column can read
            // "<id> - <alias>". Discovery works without it (the label stays empty), and the
            // action does not support resource-level permissions.
            "iam:ListAccountAliases",
          ],
          resources: ["*"],
        })
      );
      new cdk.CfnOutput(this, "DiscoveryScannerRuntimeArn", {
        value: discoveryScanner.agentRuntimeArn,
      });

      // Invoker Lambda bridging the UI "Discover agents" button to the scanner runtime
      // (which has no API of its own). Wired to POST /discovery/scan below. Fixed name so
      // the function can grant itself invoke via a constructed ARN string: referencing its
      // own .functionArn in its own role policy creates a CloudFormation circular
      // dependency (role -> function -> role).
      const scanInvokerName = `${cdk.Stack.of(this).stackName}-DiscoveryScanInvoker`;
      discoveryScanInvokerFn = new lambda.Function(this, "DiscoveryScanInvokerFn", {
        functionName: scanInvokerName,
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "discovery-scan-invoker")),
        environment: { DISCOVERY_SCANNER_ARN: discoveryScanner.agentRuntimeArn },
        timeout: cdk.Duration.seconds(120),
      });
      discoveryScanInvokerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["bedrock-agentcore:InvokeAgentRuntime"],
          resources: [
            discoveryScanner.agentRuntimeArn,
            `${discoveryScanner.agentRuntimeArn}/*`,
          ],
        })
      );
      // Self-invoke permission: the API path fires an async copy so the long scan runs out
      // of band. Constructed ARN, to avoid the circular dependency that .grantInvoke(self)
      // would introduce.
      discoveryScanInvokerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["lambda:InvokeFunction"],
          resources: [
            `arn:aws:lambda:${this.region}:${this.account}:function:${scanInvokerName}`,
          ],
        })
      );

      // compliance-scanner: runs the deterministic checks framework + LLM judgment,
      // writes AUDIT#/RAI#/EVENT# rows for the compliance and RAI surfaces.
      const complianceScannerBundle = assembleAgentBundle({
        agentDir: path.join(assetsSrc, "agents", "compliance-scanner"),
        sharedDir,
        sharedPackages: ["flowamp_tools", "flowamp_compliance_checks"],
        stagingRoot: bundleStagingRoot,
        bundleName: "compliance-scanner",
      });
      const complianceScanner = new agentcoreAlpha.Runtime(this, "ComplianceScannerRuntime", {
        runtimeName: "flowampComplianceScanner",
        // Direct-code deploy: bundle carries main.py + tools.py, the vendored
        // flowamp_tools + flowamp_compliance_checks packages, and all arm64 deps.
        agentRuntimeArtifact: agentcoreAlpha.AgentRuntimeArtifact.fromCodeAsset({
          path: complianceScannerBundle,
          runtime: agentcoreAlpha.AgentCoreRuntime.PYTHON_3_12,
          entrypoint: ["main.py"],
        }),
        environmentVariables: {
          AGENT_TABLE_NAME: agentTable.tableName,
          FLOWAMP_AGENT_ID: "flowamp_compliance_scanner",
          ENVIRONMENT: "local",
          PORT: "8080",
          ...observabilityEnv,
        },
        description: "FlowAMP compliance scanner — deterministic checks + RAI grading",
      });
      agentTable.grantReadWriteData(complianceScanner);
      complianceScanner.addToRolePolicy(modelInvokeStatement);
      cdk.Tags.of(complianceScanner).add(COST_TAG_KEY, "flowampComplianceScanner");
      // InvokeAgentRuntime supports resource-level permissions on the AgentCore
      // `runtime` resource type, so scope it to this account+region's runtimes (and
      // their endpoints). The scanner audits runtimes it discovers at runtime, so a
      // runtime-id wildcard within the account is the tightest feasible scope.
      complianceScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["bedrock-agentcore:InvokeAgentRuntime"],
          resources: [
            `arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*`,
            `arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*/*`,
          ],
        })
      );
      // Read-only inspection APIs the deterministic checks call. All List/Get/Describe -
      // the scanner never mutates the agents it audits. These are cross-service
      // enumeration/read actions (Bedrock, CloudWatch, Logs, CloudTrail, Lambda,
      // Config); they are list/describe-style calls that do not support resource-level
      // permissions, so "*" is required here.
      complianceScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "bedrock:GetAgent",
            "bedrock:ListAgents",
            // Read a Classic agent's aliases: the transparency check reports on
            // agents a customer still runs on Bedrock Agents Classic.
            "bedrock:ListAgentAliases",
            "bedrock:GetAgentAlias",
            "bedrock:GetGuardrail",
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock-agentcore:GetAgentRuntime",
            "bedrock-agentcore:ListAgentRuntimes",
            // Harnesses are an execution surface the scanner audits too.
            "bedrock-agentcore:GetHarness",
            "bedrock-agentcore:ListHarnesses",
            "bedrock-agentcore:ListTagsForResource",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:DescribeAlarmsForMetric",
            "logs:DescribeLogGroups",
            "cloudtrail:LookupEvents",
            "lambda:GetFunctionConfiguration",
            "lambda:ListTags",
            "config:GetComplianceDetailsByResource",
          ],
          resources: ["*"],
        })
      );
      new cdk.CfnOutput(this, "ComplianceScannerRuntimeArn", {
        value: complianceScanner.agentRuntimeArn,
      });

      // ── AgentCore Online Evaluations (provisioned at runtime) ──
      // An online-eval config samples an agent runtime's traces and scores them with
      // built-in LLM-as-a-Judge evaluators. It cannot be created at deploy time: the eval
      // control plane validates that the agent's trace log group already exists, and that
      // group's name carries a runtime-id suffix that only exists once the agent has run.
      // The eval-provisioner Lambda below therefore discovers the live log groups and
      // service.name and calls CreateOnlineEvaluationConfig on demand via
      // POST /evaluations/enable. Judge invocations cost tokens, so this is opt-in.
      //
      // The role below is what the eval service assumes for each config: read agent traces,
      // write the results log group, emit EMF metrics, invoke the judge model. Always
      // created so the provisioner can pass its ARN.
      const evalExecutionRole = new iam.Role(this, "EvaluationsExecutionRole", {
        assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
        description: "Execution role for AgentCore online evaluations (reads traces, writes results, invokes judge model)",
      });
      // DescribeLogGroups is a list op - no resource-level scoping, must be "*".
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["logs:DescribeLogGroups"],
          resources: ["*"],
        })
      );
      // Read agent traces. Log-group query APIs require both the bare log-group ARN and its
      // ":*" (log-stream) form; the eval control plane rejects a role that lacks either.
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["logs:StartQuery", "logs:GetQueryResults", "logs:GetLogEvents", "logs:FilterLogEvents"],
          resources: [
            `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/*`,
            `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/*:*`,
            `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans`,
            `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans:*`,
          ],
        })
      );
      // Read the Transaction Search field-index policy and fields on aws/spans, which the
      // eval service needs to query spans. List-style actions, so "*".
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["logs:DescribeIndexPolicies", "logs:GetLogGroupFields", "logs:DescribeFieldIndexes"],
          resources: ["*"],
        })
      );
      // Write evaluation results.
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
          resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/evaluations/*`],
        })
      );
      // Emit EMF metrics (namespace Bedrock-AgentCore/Evaluations).
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({ actions: ["cloudwatch:PutMetricData"], resources: ["*"] })
      );
      // Invoke the judge foundation model / inference profile.
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["bedrock:InvokeModel"],
          resources: [
            "arn:aws:bedrock:*::foundation-model/*",
            `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
          ],
        })
      );

      // Provisioner Lambda: on POST /evaluations/enable it discovers each core agent's
      // live `-DEFAULT` runtime log group + service.name from CloudWatch and calls
      // bedrock-agentcore-control create_online_evaluation_config (idempotent - lists
      // first, skips/reactivates existing). POST /evaluations/disable flips them DISABLED.
      evalProvisionerFn = new lambda.Function(this, "EvalProvisionerFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "eval-provisioner")),
        environment: {
          EVAL_EXECUTION_ROLE_ARN: evalExecutionRole.roleArn,
          EVAL_SERVICE_NAMES: "harness_flowamp_management_agent,flowampDiscoveryScanner,flowampComplianceScanner",
        },
        timeout: cdk.Duration.seconds(120),
      });
      evalProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          // The API is on the `bedrock-agentcore-control` client, but the IAM action
          // namespace is `bedrock-agentcore:`, not `bedrock-agentcore-control:`.
          actions: [
            "bedrock-agentcore:CreateOnlineEvaluationConfig",
            "bedrock-agentcore:ListOnlineEvaluationConfigs",
            "bedrock-agentcore:UpdateOnlineEvaluationConfig",
            "bedrock-agentcore:GetOnlineEvaluationConfig",
            "bedrock-agentcore:DeleteOnlineEvaluationConfig",
          ],
          // "*" is required: CreateOnlineEvaluationConfig and ListOnlineEvaluationConfigs
          // have no resource type in the AgentCore IAM reference, and the config ids used by
          // Update/Get/Delete are AWS-assigned at create time, so they are unknown at synth.
          resources: ["*"],
        })
      );
      // Discover the real runtime log-group names.
      evalProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({ actions: ["logs:DescribeLogGroups"], resources: ["*"] })
      );
      // CreateOnlineEvaluationConfig validates at create time that it can query the agent's
      // spans, which live in the Transaction Search index on `aws/spans`. The caller (this
      // Lambda role, not just the eval execution role) must therefore be able to read that
      // log group's field-index policy and fields and query the source groups, or the create
      // fails with "Access denied when accessing index policy for aws/spans". List-style
      // index/describe actions do not support resource scoping, hence "*".
      evalProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "logs:DescribeIndexPolicies",
            "logs:GetLogGroupFields",
            "logs:DescribeFieldIndexes",
            "logs:StartQuery",
            "logs:GetQueryResults",
            "logs:GetLogEvents",
            "logs:FilterLogEvents",
          ],
          resources: ["*"],
        })
      );
      // Pass the eval execution role to the control plane when creating a config.
      evalProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({ actions: ["iam:PassRole"], resources: [evalExecutionRole.roleArn] })
      );

      // Invoker Lambda bridging the UI "Run compliance audit" button and a daily schedule to
      // the compliance-scanner (which has no API of its own). Fire-and-forget (202 + async
      // self-invoke), because an audit takes minutes and API Gateway caps at 29s.
      const complianceInvokerName = `${cdk.Stack.of(this).stackName}-ComplianceScanInvoker`;
      complianceScanInvokerFn = new lambda.Function(this, "ComplianceScanInvokerFn", {
        functionName: complianceInvokerName,
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "compliance-scan-invoker")),
        environment: { COMPLIANCE_SCANNER_ARN: complianceScanner.agentRuntimeArn },
        timeout: cdk.Duration.seconds(120),
      });
      complianceScanInvokerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["bedrock-agentcore:InvokeAgentRuntime"],
          resources: [complianceScanner.agentRuntimeArn, `${complianceScanner.agentRuntimeArn}/*`],
        })
      );
      // Self-invoke via constructed ARN (avoids the circular dependency that
      // .functionArn in the function's own role policy would introduce).
      complianceScanInvokerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["lambda:InvokeFunction"],
          resources: [`arn:aws:lambda:${this.region}:${this.account}:function:${complianceInvokerName}`],
        })
      );
      // Daily schedule → rotation audit (scanner picks the oldest-audited agent).
      new events.Rule(this, "ComplianceAuditSchedule", {
        schedule: events.Schedule.cron({ minute: "0", hour: "4" }),
        description: "Daily compliance audit — one agent per run (oldest lastAuditedAt first)",
      }).addTarget(new targets.LambdaFunction(complianceScanInvokerFn));

      } // end governance agents (deployGovernanceAgents)

      // ── Standalone sample agents (real discoverable workloads) ──
      // Tool-less harnesses, defined once in ./sample-agents so TeamStack and the standalone
      // SampleAgentsStack cannot drift apart.
      if (deploySampleAgents) {
        const sampleArns = SAMPLE_AGENTS.map((def) =>
          addSampleHarness(this, def, {
            region: this.region,
            account: this.account,
            inferenceProfileId,
            modelInvokeStatement,
            costTagKey: COST_TAG_KEY,
          })
        );
        new cdk.CfnOutput(this, "SampleAgentHarnessArns", {
          value: cdk.Fn.join(",", sampleArns),
          description: "ARNs of the 3 sample workload harnesses.",
        });
      } // end sample agents (deploySampleAgents)
    } // end AgentCore toolchain block

    // ─── API Gateway: Frontend → management harness ───
    const apiFn = new lambda.Function(this, "ApiHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "api-handler")),
      environment: {
        HARNESS_ARN: harness.attrArn,
        // Live FinOps ledger: after each successful /chat the handler increments today's
        // COST# row and the agent's INFO 'requests' counter.
        AGENT_TABLE_NAME: agentTable.tableName,
        REP_AGENT_ID: "service-health-monitor",
      },
      timeout: cdk.Duration.seconds(120),
    });

    // InvokeHarness requires both bedrock-agentcore:InvokeHarness and
    // bedrock-agentcore:InvokeAgentRuntime on the harness ARN: a harness is a managed
    // abstraction over a runtime, and the call authorizes against both. Granting only
    // InvokeHarness yields AccessDenied.
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock-agentcore:InvokeHarness",
          "bedrock-agentcore:InvokeAgentRuntime",
        ],
        resources: [harness.attrArn],
      })
    );
    // Lets the chat handler update_item the COST#/INFO rows for the live ledger.
    agentTable.grantReadWriteData(apiFn);

    // ─── Lambda: Data Handler (REST backend for the UI) ───
    // Serves the UI's read routes, the registry write routes, and the append-only audit
    // event rows those writes produce, so it is granted read+write on the table.
    const dataHandlerFn = new lambda.Function(this, "DataHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "data-handler")),
      environment: {
        AGENT_TABLE_NAME: agentTable.tableName,
        // Online-evaluations wiring. Results land in
        // `/aws/bedrock-agentcore/evaluations/results/<config-id>`, and the config id is
        // assigned on create, so the handler discovers the group under this prefix via
        // logs:DescribeLogGroups rather than a hard-coded name.
        EVAL_RESULTS_LOG_GROUP_PREFIX: "/aws/bedrock-agentcore/evaluations/results/",
        // EMF metrics namespace AgentCore publishes evaluator scores under, keyed by
        // evaluator name + config id.
        EVAL_METRIC_NAMESPACE: "Bedrock-AgentCore/Evaluations",
        // OTEL service.name values of the evaluated core agents. For the management agent
        // this is the harness's backing runtime name (harness_<harnessName>), which is what
        // AgentCore uses for its log group and OTEL service.name, not the harness name.
        EVAL_SERVICE_NAMES: "harness_flowamp_management_agent,flowampDiscoveryScanner,flowampComplianceScanner",
      },
      timeout: cdk.Duration.seconds(30),
    });
    agentTable.grantReadWriteData(dataHandlerFn);
    // Read evaluation results. Granted unconditionally so the UI readiness check works even
    // when evaluations are off: query the results log groups, read the EMF score metrics,
    // and probe X-Ray Transaction Search (a trace-segment destination of CloudWatch Logs is
    // the AgentCore evaluations readiness signal).
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:FilterLogEvents",
        ],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/*`,
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/*:*`,
          // aws/spans (Transaction Search) - the readiness spansPresent probe filters it.
          `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans`,
          `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans:*`,
        ],
      })
    );
    // DescribeLogGroups is a list operation and does not support resource-level scoping, so
    // it must be granted on "*". The readiness check's trafficPresent and resultsLogGroup
    // probes depend on it.
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["logs:DescribeLogGroups"],
        resources: ["*"],
      })
    );
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
        resources: ["*"],
      })
    );
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["xray:GetTraceSegmentDestination"],
        resources: ["*"],
      })
    );
    // List existing online-eval configs so the readiness check knows whether any
    // config has been provisioned (configPresent) and the fleet view can label them.
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock-agentcore:ListOnlineEvaluationConfigs",
          "bedrock-agentcore:GetOnlineEvaluationConfig",
        ],
        resources: ["*"],
      })
    );
    // Re-read one agent's platform run state on activation, so an approval is not granted
    // against a reading from the last scheduled discovery. Read-only, one agent per human
    // action. Scoped to "*" because the target is whichever agent the reviewer is approving,
    // which is unknown at synth time. Same-account only: cross-account and Foundry agents
    // fall back to the stored sample, which the UI labels with its age.
    dataHandlerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock-agentcore:GetAgentRuntime",
          "bedrock-agentcore:GetHarness",
          "bedrock:GetAgent",
        ],
        resources: ["*"],
      })
    );

    // Access log group for the API stage (Checkov CKV_AWS_76).
    const apiAccessLogs = new logs.LogGroup(this, "AgentApiAccessLogs", {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ─── S3 + CloudFront (created before the API so CORS can scope to the CloudFront origin) ───
    const siteBucket = new s3.Bucket(this, "DemoSiteBucket", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      // Not autoDeleteObjects: that helper empties the bucket once, which cannot work for a
      // bucket that is its own server-access-log target, since its own DELETE calls generate
      // log records S3 delivers back afterwards. SiteBucketDrain below handles this instead.
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      // Deny non-TLS requests via the bucket policy (cdk-nag AwsSolutions-S10 /
      // Checkov CKV_AWS_18). CloudFront already redirects viewers to HTTPS; this
      // enforces it at the bucket layer too.
      enforceSSL: true,
      // Server access logging (Checkov CKV_AWS_18). Logs to a prefix in the same
      // bucket to avoid spawning a second log bucket that trips the same finding.
      serverAccessLogsPrefix: "access-logs/",
      lifecycleRules: [
        {
          // Expire access logs after 7 days, which also keeps an abandoned bucket bounded if
          // a teardown is interrupted.
          id: "expire-access-logs",
          prefix: "access-logs/",
          expiration: cdk.Duration.days(7),
        },
      ],
    });

    // ─── Site bucket drain (replaces autoDeleteObjects) ───
    // On stack Delete, switch off the bucket's own access logging and then empty it, sweeping
    // until two consecutive passes come back clean so any log records already in flight are
    // collected. Bounded by the Lambda's remaining time, holding back a reserve so there is
    // always room to answer CloudFormation. Does nothing on Create or Update.
    const siteDrainFn = new lambda.Function(this, "SiteBucketDrainFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      // Access-log delivery can lag well behind the last request, so allow time for the
      // in-flight queue to drain rather than the 3s default.
      timeout: cdk.Duration.minutes(14),
      code: lambda.Code.fromInline(
        [
          "import json, time, urllib.request",
          "import boto3",
          "",
          "def _respond(event, context, status, reason=None):",
          "    body = json.dumps({",
          "        'Status': status,",
          "        'Reason': reason or ('See CloudWatch log stream: ' + context.log_stream_name),",
          "        'PhysicalResourceId': event.get('PhysicalResourceId') or 'site-bucket-drain',",
          "        'StackId': event['StackId'],",
          "        'RequestId': event['RequestId'],",
          "        'LogicalResourceId': event['LogicalResourceId'],",
          "        'Data': {},",
          "    }).encode('utf-8')",
          "    req = urllib.request.Request(event['ResponseURL'], data=body, method='PUT')",
          "    req.add_header('content-type', '')",
          "    req.add_header('content-length', str(len(body)))",
          "    urllib.request.urlopen(req, timeout=30)",
          "",
          "def _empty_once(s3, bucket):",
          "    removed = 0",
          "    # Delete versions AND delete-markers too: a versioned bucket is not empty",
          "    # until both are gone, and S3 rejects the bucket delete otherwise.",
          "    for api, key in (('list_object_versions', 'Versions'),",
          "                     ('list_object_versions', 'DeleteMarkers'),",
          "                     ('list_objects_v2', 'Contents')):",
          "        try:",
          "            paginator = s3.get_paginator(api)",
          "            for page in paginator.paginate(Bucket=bucket):",
          "                objs = [{'Key': o['Key'], **({'VersionId': o['VersionId']} if 'VersionId' in o else {})}",
          "                        for o in page.get(key, [])]",
          "                for i in range(0, len(objs), 1000):",
          "                    s3.delete_objects(Bucket=bucket, Delete={'Objects': objs[i:i+1000]})",
          "                removed += len(objs)",
          "        except Exception as exc:",
          "            print('sweep pass on %s via %s/%s: %s' % (bucket, api, key, exc))",
          "    return removed",
          "",
          "def handler(event, context):",
          "    try:",
          "        if event['RequestType'] != 'Delete':",
          "            _respond(event, context, 'SUCCESS', 'Nothing to do on ' + event['RequestType'])",
          "            return",
          "        bucket = event['ResourceProperties']['BucketName']",
          "        s3 = boto3.client('s3')",
          "        # Switch off server access logging before sweeping. This bucket is its",
          "        # own log target, so while logging is on the sweep's own DELETE calls",
          "        # generate records S3 delivers back into it. Removing the log",
          "        # configuration turns an endless stream into a finite queue.",
          "        try:",
          "            s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={})",
          "            print('disabled server access logging on %s' % bucket)",
          "        except Exception as exc:",
          "            # Non-fatal: the sweep still runs, it just has to out-wait deliveries.",
          "            print('could not disable logging on %s (continuing): %s' % (bucket, exc))",
          "        pause, reserve_ms, clean, attempt = 15, 45000, 0, 0",
          "        while context.get_remaining_time_in_millis() > reserve_ms + pause * 1000:",
          "            attempt += 1",
          "            removed = _empty_once(s3, bucket)",
          "            clean = clean + 1 if removed == 0 else 0",
          "            print('sweep %d removed %d (clean streak %d)' % (attempt, removed, clean))",
          "            if clean >= 2:",
          "                _respond(event, context, 'SUCCESS', 'Drained after %d pass(es)' % attempt)",
          "                return",
          "            time.sleep(pause)",
          "        # Out of time. Report SUCCESS anyway: failing here would leave the stack",
          "        # in DELETE_FAILED, which is worse than a bucket the 7-day lifecycle rule",
          "        # will empty. CloudFormation will surface the bucket delete failure itself.",
          "        _respond(event, context, 'SUCCESS', 'Stopped on time budget after %d pass(es)' % attempt)",
          "    except Exception as exc:",
          "        print('drain failed: %s' % exc)",
          "        _respond(event, context, 'SUCCESS', 'Drain error (non-fatal): %s' % exc)",
        ].join("\n")
      ),
    });
    siteBucket.grantRead(siteDrainFn);
    siteDrainFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "s3:ListBucket",
          "s3:ListBucketVersions",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          // Needed to switch off this bucket's own access logging before sweeping (see the
          // handler). Without it the drain races an asynchronous log delivery it cannot
          // outrun.
          "s3:PutBucketLogging",
        ],
        resources: [siteBucket.bucketArn, `${siteBucket.bucketArn}/*`],
      })
    );
    const siteDrain = new cdk.CustomResource(this, "SiteBucketDrain", {
      serviceToken: siteDrainFn.functionArn,
      properties: { BucketName: siteBucket.bucketName },
    });
    // The drain must run before the bucket is deleted. CloudFormation deletes in reverse
    // dependency order, so having the drain depend on the bucket is what puts the drain
    // first on the way down.
    siteDrain.node.addDependency(siteBucket);

    const distribution = new cloudfront.Distribution(this, "DemoDistribution", {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(siteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: "agent-management.html",
    });
    // Do NOT add `distribution.node.addDependency(siteDrain)` to force the distribution to
    // delete before the drain. The origin access control makes the bucket policy depend on
    // the distribution, and the drain depends on the bucket, so that edge closes a cycle and
    // synth fails with a circular dependency. Teardown ordering is handled inside the drain
    // instead: it switches access logging off before sweeping, so the bucket cannot refill
    // while the distribution is still being deleted.

    // The UI (served from CloudFront) calls this API cross-origin, so the
    // CloudFront distribution domain is the only legitimate origin. Scoping to it
    // (instead of Cors.ALL_ORIGINS) follows least-privilege for CORS.
    const allowedOrigin = `https://${distribution.distributionDomainName}`;

    const api = new apigateway.RestApi(this, "AgentApi", {
      restApiName: "Agent Management API",
      defaultCorsPreflightOptions: {
        allowOrigins: [allowedOrigin],
        // Must list every method any route accepts. The connector configuration API uses
        // PUT to save and DELETE to remove; omitting them here makes the browser's
        // preflight reject the request before it is sent, so the call never reaches API
        // Gateway and the UI reports a failure with no HTTP status to explain it.
        allowMethods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization"],
      },
      deployOptions: {
        accessLogDestination: new apigateway.LogGroupLogDestination(apiAccessLogs),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
      },
    });

    // The RestApi construct auto-creates a CloudWatch logging role and an
    // ApiGateway::Account resource, both of which CDK defaults to
    // DeletionPolicy/UpdateReplacePolicy: Retain. Retained resources can block redeployment
    // retries, so force them to Delete. CloudWatchRole is an L2 construct (use its
    // defaultChild); Account is itself the L1 CfnResource (use it directly).
    for (const child of [
      api.node.tryFindChild("CloudWatchRole"),
      api.node.tryFindChild("Account"),
    ]) {
      if (!child) continue;
      const cfn = (child instanceof cdk.CfnResource
        ? child
        : child.node.defaultChild) as cdk.CfnResource | undefined;
      cfn?.applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    }

    // Gate every data route behind the Cognito user pool. The UI obtains an IdToken
    // via USER_PASSWORD_AUTH and sends it as `Authorization: Bearer <token>`.
    const apiAuthorizer = new apigateway.CognitoUserPoolsAuthorizer(this, "ApiAuthorizer", {
      cognitoUserPools: [userPool],
    });
    const authedMethodOptions: apigateway.MethodOptions = {
      authorizer: apiAuthorizer,
      authorizationType: apigateway.AuthorizationType.COGNITO,
    };

    api.root
      .addResource("chat")
      .addMethod("POST", new apigateway.LambdaIntegration(apiFn), authedMethodOptions);

    // ─── Data API (REST backend for the UI) ───
    // Read routes the single-page UI calls directly (entity rows from the table). Kept
    // separate from agent-handler, which serves the harness's MCP tools. The write routes
    // also append audit EVENT# rows, which GET /events reads back on this same handler.
    const dataIntegration = new apigateway.LambdaIntegration(dataHandlerFn);
    let agentsResource: apigateway.Resource | undefined;
    let complianceResource: apigateway.Resource | undefined;
    let evaluationsResource: apigateway.Resource | undefined;
    // "audits" (plural) is the fleet-wide latest-audit-per-agent view, distinct from
    // GET /agents/{agentId}/audit (singular, one agent's history) below. "evaluations" is
    // fleet-wide online-evaluation scores plus readiness.
    for (const name of ["agents", "compliance", "aops", "access", "events", "costs", "audits", "evaluations"]) {
      const r = api.root.addResource(name);
      r.addMethod("GET", dataIntegration, authedMethodOptions);
      if (name === "agents") agentsResource = r;
      if (name === "compliance") complianceResource = r;
      if (name === "evaluations") evaluationsResource = r;
    }
    // GET /evaluations/readiness reports whether AgentCore online evaluations can run (X-Ray
    // Transaction Search enabled, config present), so the UI can show a preflight state
    // instead of an empty grid.
    evaluationsResource!.addResource("readiness").addMethod("GET", dataIntegration, authedMethodOptions);
    // POST /evaluations/enable and /disable create (or flip ENABLED/DISABLED) one online-eval
    // config per core agent, discovering each agent's runtime-id-suffixed trace log group at
    // call time. Synchronous, since list+create is well under API Gateway's 29s cap. Only
    // wired when the provisioner is deployed.
    if (evalProvisionerFn) {
      const evalProvisionerIntegration = new apigateway.LambdaIntegration(evalProvisionerFn);
      evaluationsResource!.addResource("enable").addMethod("POST", evalProvisionerIntegration, authedMethodOptions);
      evaluationsResource!.addResource("disable").addMethod("POST", evalProvisionerIntegration, authedMethodOptions);
    }

    // Write routes on the agents resource: register, field update, lifecycle.
    agentsResource!.addMethod("POST", dataIntegration, authedMethodOptions);
    const agentIdResource = agentsResource!.addResource("{agentId}");
    agentIdResource.addMethod("PATCH", dataIntegration, authedMethodOptions);
    agentIdResource.addResource("lifecycle").addMethod("POST", dataIntegration, authedMethodOptions);
    // GET /agents/{agentId}/audit → the compliance-scanner's AUDIT# rows for one agent.
    agentIdResource.addResource("audit").addMethod("GET", dataIntegration, authedMethodOptions);
    // GET /agents/{agentId}/evaluations → online-evaluation scores for one agent.
    agentIdResource.addResource("evaluations").addMethod("GET", dataIntegration, authedMethodOptions);

    // RAI scoring route: on-demand re-score triggered from the UI. The same
    // rai-scorer Lambda also runs on the daily EventBridge schedule above; its
    // handler detects API Gateway invocation and returns a proxy response.
    api.root
      .addResource("rai")
      .addResource("score")
      .addMethod("POST", new apigateway.LambdaIntegration(raiScorerFn), authedMethodOptions);

    // Discovery API routes
    const discoveryResource = api.root.addResource("discovery");
    const discoveryIntegration = new apigateway.LambdaIntegration(discoveryFn);
    discoveryResource.addResource("sync").addMethod("POST", discoveryIntegration, authedMethodOptions);
    discoveryResource.addResource("status").addMethod("GET", discoveryIntegration, authedMethodOptions);
    discoveryResource
      .addResource("platforms")
      .addMethod("GET", discoveryIntegration, authedMethodOptions);

    // Connector configuration API, served by discoveryFn so that the handler writing a
    // credential is the one reading it back on the scheduled sync; splitting them would
    // duplicate the Secrets Manager grant above.
    //
    // {platform} is a path parameter, so the child resource is added once and the methods
    // hang off it. API Gateway rejects a second resource with the same path part on the same
    // parent, so calling addResource("{platform}") per method fails at synth.
    const connectorsResource = discoveryResource.addResource("connectors");
    // GET /discovery/connectors returns every configured connector, redacted: the response
    // reports only whether a credential is set, never the credential.
    connectorsResource.addMethod("GET", discoveryIntegration, authedMethodOptions);
    const connectorPlatformResource = connectorsResource.addResource("{platform}");
    // PUT is an upsert rather than POST-then-PATCH: there is at most one config per
    // platform, and the client secret is optional on update so an operator can change
    // the endpoint without re-entering credentials.
    connectorPlatformResource.addMethod("PUT", discoveryIntegration, authedMethodOptions);
    // DELETE removes the config row and the secret together, so a removed connector
    // leaves no orphaned credential behind.
    connectorPlatformResource.addMethod("DELETE", discoveryIntegration, authedMethodOptions);
    // POST /discovery/connectors/{platform}/test proves the stored credentials can reach the
    // platform, so a misconfiguration surfaces here rather than as a silently empty scheduled
    // sync hours later. Synchronous: one token mint plus one list call is well inside API
    // Gateway's 29s cap.
    connectorPlatformResource
      .addResource("test")
      .addMethod("POST", discoveryIntegration, authedMethodOptions);

    // POST /discovery/scan invokes the AgentCore discovery-scanner, and is only wired when
    // that runtime is deployed. The UI's Discover button prefers this over /discovery/sync so
    // it triggers native discovery plus LLM classification.
    if (discoveryScanInvokerFn) {
      discoveryResource
        .addResource("scan")
        .addMethod(
          "POST",
          new apigateway.LambdaIntegration(discoveryScanInvokerFn),
          authedMethodOptions
        );
    }

    // POST /compliance/scan triggers the AgentCore compliance-scanner for one agent
    // ({"agentId": "..."}) or a rotation run (empty body). Fire-and-forget.
    if (complianceScanInvokerFn) {
      complianceResource!
        .addResource("scan")
        .addMethod(
          "POST",
          new apigateway.LambdaIntegration(complianceScanInvokerFn),
          authedMethodOptions
        );
    }

    // ─── Deploy the static UI to the site bucket (bucket + distribution defined above) ───
    new s3deploy.BucketDeployment(this, "DeploySite", {
      sources: [
        s3deploy.Source.asset(path.join(assetsSrc, "site")),
        s3deploy.Source.data(
          "config.js",
          `window.CHAT_API_URL="${api.url}chat";\n` +
            `window.COGNITO={ userPoolId:"${userPool.userPoolId}", clientId:"${userPoolClient.userPoolClientId}", region:"${this.region}" };\n` +
            // Tells the UI the AgentCore discovery-scanner route exists, so the Discover
            // button targets POST /discovery/scan instead of /discovery/sync.
            `window.DISCOVERY_SCAN_ENABLED=${discoveryScanInvokerFn ? "true" : "false"};\n` +
            // Whether POST /compliance/scan exists. False when deployGovernanceAgents=false,
            // so the audit buttons can report the feature as not deployed rather than firing
            // at a missing route (API Gateway answers those with a bare 403, which reads as
            // an auth failure).
            `window.COMPLIANCE_SCAN_ENABLED=${complianceScanInvokerFn ? "true" : "false"};`
        ),
      ],
      destinationBucket: siteBucket,
      // The bucket writes its own server-access records into `access-logs/`. Prune defaults to
      // true, which would try to delete every object not in the source asset (all the
      // accumulated logs), and because logging keeps adding objects during the sync the delete
      // set never drains and the deploy Lambda times out. Excluding the prefix keeps prune
      // working for the UI files.
      exclude: ["access-logs/*"],
      // `distribution`/`distributionPaths` are not passed. They only trigger a post-upload
      // CloudFront invalidation, which forces CDK to attach cloudfront:CreateInvalidation on
      // Resource:"*" to the deploy role (Checkov CKV_AWS_111). The bucket is populated into a
      // fresh, empty-cache distribution at provision time, so there is nothing to invalidate.
      // After any later UI change, invalidate manually.
    });

    // ─── Outputs ───
    new cdk.CfnOutput(this, "DemoUrl", {
      value: `https://${distribution.distributionDomainName}`,
      description: "Agent Management Platform URL",
    });
    new cdk.CfnOutput(this, "ApiUrl", {
      value: api.url,
      description: "API Gateway URL (POST /chat)",
    });
    new cdk.CfnOutput(this, "AgentTableName", { value: agentTable.tableName });
    new cdk.CfnOutput(this, "ManagementHarnessArn", {
      value: harness.attrArn,
      description: "ARN of the AgentCore harness backing POST /chat.",
    });
    new cdk.CfnOutput(this, "AgentManagementGatewayArn", {
      value: gateway.gatewayArn,
      description: "ARN of the AgentCore Gateway exposing the registry tools to the harness.",
    });
    new cdk.CfnOutput(this, "LoginUsername", { value: "flowadmin" });
    new cdk.CfnOutput(this, "LoginPassword", { value: seedUser.getAttString("Password") });
    new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
  }
}
