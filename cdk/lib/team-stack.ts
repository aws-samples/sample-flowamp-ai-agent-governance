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
import * as bedrock from "@aws-cdk/aws-bedrock-alpha";
// AgentCore online-evaluation configs are created at RUNTIME by the eval-provisioner
// Lambda (via bedrock-agentcore-control), not as a CFN resource. The control plane
// validates, at create time, that the runtime-id-suffixed trace log groups already
// exist; those names are only available after an agent has run. See the
// eval-provisioner block below.
import { Construct } from "constructs";
import * as path from "path";
import * as fs from "fs";
import { assembleAgentBundle } from "./agent-bundle";

/**
 * FlowAMP ("Agent Management Platform").
 *
 * Deployment model:
 *   - Extends the standard `cdk.Stack`, so it deploys into any account via the normal
 *     `cdk bootstrap` + `cdk deploy` flow (assets published by the CDK toolkit).
 *   - Lambda / container / site assets are sourced from ../assetsSrc.
 *
 * Core AgentCore agents deploy ALWAYS: the management agent + the governance agents
 * (discovery-scanner, compliance-scanner). The discovery-scanner owns single-account
 * native discovery; the Lambda connector handles external + cross-account org discovery.
 *
 * Context flags (all default OFF):
 *   - `deploySampleAgents=true` deploys the 3 optional sample workload agents
 *     (claims-triage, supply-chain, request-intake) as real discoverable AgentCore runtimes.
 *   - `seedSampleData=true`   loads the demo agent catalog + simulated external connectors.
 *   - `enableCostExplorer` (default ON) deploys the real Cost Explorer FinOps collector;
 *     turn off with `-c enableCostExplorer=false`.
 *   - `enableOrgDiscovery` (default ON) real cross-account org discovery; requires the
 *     management/delegated-admin account. Turn off with `-c enableOrgDiscovery=false`.
 */
export class TeamStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const assetsSrc = path.join(__dirname, "..", "..", "assetsSrc");
    const sharedDir = path.join(assetsSrc, "agents", "_shared");
    const bundleStagingRoot = path.join(__dirname, "..", "cdk.out", "agent-bundles");

    // ─── Deploy-time context flags ───
    const seedSampleData = this.node.tryGetContext("seedSampleData") === "true";
    // Core AgentCore agents (management + discovery-scanner + compliance-scanner)
    // deploy ALWAYS — no flag. Only the 3 optional SAMPLE workload agents are gated,
    // default OFF; turn them on with `-c deploySampleAgents=true`.
    const deploySampleAgents = this.node.tryGetContext("deploySampleAgents") === "true";
    // Real FinOps: deploy the Cost Explorer collector (daily) + activate the
    // flowamp:agentId cost-allocation tag. ON by default. CE-grouped-by-tag
    // data appears after the tag is activated in Billing (up to ~48h) and real
    // spend accrues; until then the collector runs cleanly and writes nothing.
    // Turn off with `-c enableCostExplorer=false`.
    const enableCostExplorer = this.node.tryGetContext("enableCostExplorer") !== "false";
    const COST_TAG_KEY = "flowamp:agentId";
    // Real cross-account org discovery via the aws-org connector — ON by default,
    // alongside single-account (native) discovery. Requires FlowAMP to run in the org
    // MANAGEMENT (or delegated-admin) account: organizations:ListAccounts + assuming a
    // role in each member account. If it's not that account, the connector returns []
    // with a UI warning (no simulated fallback). Turn off with `-c enableOrgDiscovery=false`.
    // Override the assumed role / regions with `-c orgDiscoveryRoleName=...` /
    // `-c orgDiscoveryRegions=us-east-1,us-west-2`.
    const enableOrgDiscovery = this.node.tryGetContext("enableOrgDiscovery") !== "false";
    // Default to Control Tower's execution role (present in enrolled accounts, trusts
    // the management account). For a plain org use OrganizationAccountAccessRole.
    const orgDiscoveryRoleName = this.node.tryGetContext("orgDiscoveryRoleName") || "AWSControlTowerExecution";
    const orgDiscoveryRegions = this.node.tryGetContext("orgDiscoveryRegions") || "";

    // Set inside the core-agents block; wired to API routes below so the UI can
    // trigger the discovery-scanner and compliance-scanner directly.
    let discoveryScanInvokerFn: lambda.Function | undefined;
    let complianceScanInvokerFn: lambda.Function | undefined;
    let evalProvisionerFn: lambda.Function | undefined;

    // ─── DynamoDB ───
    // Single table for the whole platform. Composite key: agentId (PK) + sk (SK).
    //   - Agent / compliance: / aop: / access: records use sk = "INFO" (one row per entity).
    //   - Live cost ledger rows (Pick 1) use sk = "COST#<YYYY-MM-DD>" under their agentId.
    //   - Append-only audit events (Pick 3) use sk = "EVENT#<ISO-ts>#<eventId>"
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

    // ─── Lambda: Bedrock Agent action group handler ───
    const agentHandlerFn = new lambda.Function(this, "AgentHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "agent-handler")),
      environment: { AGENT_TABLE_NAME: agentTable.tableName },
      timeout: cdk.Duration.seconds(30),
    });
    agentTable.grantReadData(agentHandlerFn);

    // ─── Seed DynamoDB (demo catalog) — GATED, OFF BY DEFAULT ───
    // The seed loads ~30 demo agent rows so the UI has content in a sandbox. A
    // production deploy leaves this OFF (seedSampleData=false) so the catalog
    // starts empty and is populated only by real discovery of the customer's
    // own agents. Opt in with `-c seedSampleData=true`.
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
    // Single-account NATIVE discovery is owned by the AgentCore discovery-scanner
    // (a core, always-deployed runtime), so the two never double-write the same
    // runtime. The NATIVE_DISCOVERY_ENABLED=false env flag tells the Lambda to skip
    // its native pass (the scanner owns it). Org discovery stays with the Lambda.
    const nativeDiscoveryOwnedByLambda = false;
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
    // Native discovery reads real AWS agents (Bedrock Agents + AgentCore runtimes).
    // List/Get only — discovery never invokes or mutates the agents it governs.
    // Granted regardless of the flag so the handler can enumerate when it owns native.
    discoveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock:ListAgents",
          "bedrock:GetAgent",
          "bedrock-agentcore:ListAgentRuntimes",
        ],
        resources: ["*"],
      })
    );
    // Real cross-account org discovery: enumerate the org + assume a read role in
    // each member account. Granted only when enabled so a normal single-account
    // deploy carries no cross-account privileges.
    if (enableOrgDiscovery) {
      discoveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["organizations:ListAccounts", "sts:GetCallerIdentity"],
          resources: ["*"],
        })
      );
      // Assume only the named discovery role, in any account (org-wide) — scoped to
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
        ? "Sync agents from native AWS + simulated Microsoft/Okta/MuleSoft/org connectors every 6 hours"
        : "Sync simulated Microsoft/Okta/MuleSoft/org connectors every 6 hours (native discovery owned by the AgentCore scanner)",
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

    // ─── Real FinOps: Cost Explorer collector (daily) — GATED, OFF BY DEFAULT ───
    // Pulls REAL per-agent spend from AWS Cost Explorer (grouped by the
    // flowamp:agentId cost-allocation tag) and writes COST#<date> rows the UI reads.
    // Gated because CE-grouped-by-tag data requires the tag to be activated in
    // Billing (up to ~48h) and real spend to accrue.
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
      // Run daily at 03:00 UTC — a few hours after CE finalizes the prior UTC day.
      new events.Rule(this, "FinopsCollectorSchedule", {
        schedule: events.Schedule.cron({ minute: "0", hour: "3" }),
        description: "Collect real per-agent spend from Cost Explorer (flowamp:agentId tag)",
      }).addTarget(new targets.LambdaFunction(finopsCollectorFn));

      // Best-effort activation of the cost-allocation tag (management account only;
      // fails gracefully elsewhere — see README for the manual Billing-console step).
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

    // Cost-allocation tag on the whole stack: every taggable resource gets
    // flowamp:agentId so Cost Explorer can attribute spend. Stack-level value is
    // "platform"; the discovery-scanner overrides it per AgentCore runtime with the
    // specific agentId. Applied regardless of the flag so tags accrue history early
    // (activation/collection is what the flag gates).
    cdk.Tags.of(this).add(COST_TAG_KEY, "platform");

    // ─── Bedrock Agent ───
    // Model the Bedrock Agent runs on. Two constraints govern this choice:
    //  1. Bedrock marks older models "Legacy" and blocks accounts that have not
    //     used them recently; this surfaces as a runtime "ARN not found / model
    //     access" error on /chat even when access was granted. Choose a current,
    //     non-Legacy model.
    //  2. The Bedrock *Agents* runtime injects a `thinking.type.enabled` param
    //     that Opus 4.8 rejects (it expects thinking.type.adaptive + output_config
    //     .effort), so Opus 4.8 cannot currently be driven via a Bedrock Agent.
    // Sonnet 4.6 is current AND compatible with the Agents runtime.
    const inferenceProfileId = "us.anthropic.claude-sonnet-4-6";
    const baseModelId = "anthropic.claude-sonnet-4-6";
    const inferenceProfileArn = `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${inferenceProfileId}`;

    const agent = new bedrock.Agent(this, "ManagementAgent", {
      foundationModel: new bedrock.BedrockFoundationModel(inferenceProfileId, {
        supportsAgents: true,
      }),
      instruction: `You are an AI agent management assistant for an enterprise.
You help operators monitor and manage AI agents deployed across operations,
asset and infrastructure, finance and trading, security and compliance, and customer operations.
Use the available tools to fetch real data before responding.`,
      // Auto-prepare the DRAFT version on deploy. Without this the construct
      // leaves the agent NOT_PREPARED, so the TSTALIASID test alias the api-handler
      // invokes returns "agent not found" and chat fails until someone manually
      // runs prepare-agent. Required for unattended provisioning.
      shouldPrepareAgent: true,
    });

    // Override the foundation model ARN to use inference-profile instead of foundation-model
    const cfnAgent = agent.node.defaultChild as cdk.CfnResource;
    cfnAgent.addPropertyOverride("FoundationModel", inferenceProfileArn);

    // Grant the agent role permission to use the inference profile. Actions are
    // explicit (not a bedrock:InvokeModel* wildcard) and resources are scoped to
    // the exact inference-profile and base-model ARNs — least privilege.
    agent.role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:GetInferenceProfile",
        ],
        resources: [
          inferenceProfileArn,
          `arn:aws:bedrock:*::foundation-model/${baseModelId}`,
        ],
      })
    );

    agent.addActionGroup(
      new bedrock.AgentActionGroup({
        name: "AgentManagement",
        apiSchema: bedrock.ApiSchema.fromInline(
          fs.readFileSync(path.join(assetsSrc, "lambda", "agent-handler", "openapi.json"), "utf-8")
        ),
        executor: bedrock.ActionGroupExecutor.fromLambda(agentHandlerFn),
      })
    );

    // ─── AgentCore Runtimes (Strands agents) ───
    // The management agent + the two governance agents (discovery-scanner,
    // compliance-scanner) are CORE platform functionality and deploy ALWAYS.
    // The 3 standalone SAMPLE workload agents (claims-triage, supply-chain,
    // request-intake) are optional demo content, gated behind deploySampleAgents
    // (default off). All agents are real AgentCore runtimes (no mock constructs).
    {
      // Imported lazily so the alpha agentcore module is only loaded when used.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const agentcore = require("@aws-cdk/aws-bedrock-agentcore-alpha");

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

      // Observability env shared by every runtime: activates the AgentCore ADOT pipeline
      // so the runtime injects the OTLP endpoint and the agent's Strands tracer exports
      // spans to aws/spans (Transaction Search). AGENT_OBSERVABILITY_ENABLED is required:
      // without it the runtime does not set OTEL_EXPORTER_OTLP_ENDPOINT, the tracer stays
      // inert, no spans are produced, and AgentCore Evaluations has nothing to score.
      const observabilityEnv: Record<string, string> = {
        AGENT_OBSERVABILITY_ENABLED: "true",
        OTEL_PYTHON_DISTRO: "aws_distro",
        OTEL_PYTHON_CONFIGURATOR: "aws_configurator",
        OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
      };

      // ── Core agents: management + discovery/compliance scanners (always on) ──
      // ── Management agent (self-contained; own dir) ──
      const managementRuntime = new agentcore.Runtime(this, "ManagementAgentRuntime", {
        runtimeName: "managementAgentRuntime",
        // Direct-code deploy (no Docker). assembleAgentBundle vendors arm64/cp312
        // dependencies into the bundle (via `uv pip install --python-platform
        // aarch64-manylinux2014 --target`), per the AWS-documented direct-code
        // packaging procedure, so the uploaded zip is self-contained.
        agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromCodeAsset({
          path: assembleAgentBundle({
            agentDir: path.join(assetsSrc, "agents", "agent-runtime"),
            sharedDir,
            sharedPackages: [],
            stagingRoot: bundleStagingRoot,
            bundleName: "agent-runtime",
          }),
          runtime: agentcore.AgentCoreRuntime.PYTHON_3_12,
          entrypoint: ["main.py"],
        }),
        environmentVariables: { AGENT_TABLE_NAME: agentTable.tableName, PORT: "8080", ...observabilityEnv },
        description: "AI Agent Management Runtime powered by Strands",
      });
      agentTable.grantReadData(managementRuntime);
      managementRuntime.addToRolePolicy(modelInvokeStatement);
      // Per-agent cost-allocation tag. Applied on the runtime construct (bottom of
      // the tree) so it beats the stack-level flowamp:agentId=platform tag — Cost
      // Explorer then attributes this runtime's spend to its own agentId, not the
      // shared "platform" bucket.
      cdk.Tags.of(managementRuntime).add(COST_TAG_KEY, "managementAgentRuntime");
      const managementEndpoint = managementRuntime.addEndpoint("managementAgentEndpoint", {
        description: "Agent Management API endpoint",
      });
      new cdk.CfnOutput(this, "AgentCoreRuntimeArn", { value: managementRuntime.agentRuntimeArn });
      new cdk.CfnOutput(this, "AgentCoreEndpointArn", {
        value: managementEndpoint.agentRuntimeEndpointArn,
      });

      // ── Governance agents (need the shared packages vendored into the bundle) ──
      // discovery-scanner: enumerates + LLM-classifies real AgentCore runtimes and
      // writes normalized catalog rows. It OWNS native discovery in this mode.
      const discoveryScannerBundle = assembleAgentBundle({
        agentDir: path.join(assetsSrc, "agents", "discovery-scanner"),
        sharedDir,
        sharedPackages: ["flowamp_tools"],
        stagingRoot: bundleStagingRoot,
        bundleName: "discovery-scanner",
      });
      const discoveryScanner = new agentcore.Runtime(this, "DiscoveryScannerRuntime", {
        runtimeName: "flowampDiscoveryScanner",
        // Direct-code deploy: bundle carries main.py, the vendored flowamp_tools
        // package, and all arm64 pip deps (installed by assembleAgentBundle).
        agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromCodeAsset({
          path: discoveryScannerBundle,
          runtime: agentcore.AgentCoreRuntime.PYTHON_3_12,
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
      // Fleet-enumeration + cross-inventory reads. ListAgentRuntimes and
      // bedrock:ListAgents are list actions that do not support resource-level
      // permissions, and bedrock:GetAgent inspects the separate Bedrock Agents
      // inventory. These are read-only, so "*" is required here.
      discoveryScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "bedrock-agentcore:ListAgentRuntimes",
            "bedrock:ListAgents",
            "bedrock:GetAgent",
          ],
          resources: ["*"],
        })
      );
      new cdk.CfnOutput(this, "DiscoveryScannerRuntimeArn", {
        value: discoveryScanner.agentRuntimeArn,
      });

      // Invoker Lambda bridging the UI "Discover agents" button to the scanner
      // runtime (which has no API of its own). Wired to POST /discovery/scan below.
      // Fixed name so the function can grant itself invoke via a CONSTRUCTED ARN
      // string (below) rather than the function's own .functionArn attribute —
      // referencing the attribute in the function's own role policy creates a
      // CloudFormation circular dependency (role → function → role).
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
      // Self-invoke permission (the API path fires an async copy to run the long
      // ~60-90s scan out of band). Uses a constructed ARN to avoid the circular
      // dependency that .grantInvoke(self) / .functionArn would introduce.
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
      const complianceScanner = new agentcore.Runtime(this, "ComplianceScannerRuntime", {
        runtimeName: "flowampComplianceScanner",
        // Direct-code deploy: bundle carries main.py + tools.py, the vendored
        // flowamp_tools + flowamp_compliance_checks packages, and all arm64 deps.
        agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromCodeAsset({
          path: complianceScannerBundle,
          runtime: agentcore.AgentCoreRuntime.PYTHON_3_12,
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
      // Read-only inspection APIs the deterministic checks call. All List/Get/Describe —
      // the scanner never mutates the agents it audits. These are cross-service
      // enumeration/read actions (Bedrock, CloudWatch, Logs, CloudTrail, Lambda,
      // Config); they are list/describe-style calls that do not support resource-level
      // permissions, so "*" is required here.
      complianceScanner.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            "bedrock:GetAgent",
            "bedrock:ListAgents",
            "bedrock:GetGuardrail",
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock-agentcore:GetAgentRuntime",
            "bedrock-agentcore:ListAgentRuntimes",
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

      // ── AgentCore Online Evaluations (runtime-provisioned) ──
      // An online-eval config continuously samples an agent runtime's traces and scores
      // them with built-in LLM-as-a-Judge evaluators. It is NOT created at deploy time:
      // the eval control plane validates at create-time that the agent's trace log group
      // already exists, and that group's real name carries a runtime-id suffix
      // (`/aws/bedrock-agentcore/runtimes/<runtimeName>-<runtimeId>-DEFAULT`) that only
      // exists after the agent has run. So provisioning is a RUNTIME operation: the
      // eval-provisioner Lambda (below) discovers the live log groups + service.name and
      // calls CreateOnlineEvaluationConfig on demand (POST /evaluations/enable). Judge
      // invocations accrue token cost, hence it is opt-in via that button, not a flag.
      //
      // Execution role the eval service assumes for each config it creates. Mirrors the
      // AWS "Evaluations prerequisites": read agent traces, write the results log group,
      // emit EMF metrics, invoke the judge model. Created here (always) so the provisioner
      // can pass its ARN; unused until a config is actually created.
      const evalExecutionRole = new iam.Role(this, "EvaluationsExecutionRole", {
        assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
        description: "Execution role for AgentCore online evaluations (reads traces, writes results, invokes judge model)",
      });
      // DescribeLogGroups is a list op — no resource-level scoping, must be "*".
      evalExecutionRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["logs:DescribeLogGroups"],
          resources: ["*"],
        })
      );
      // Read agent traces. Log-group query APIs require BOTH the bare log-group ARN and
      // its ":*" (log-stream) form; the eval control plane rejects a role that lacks both.
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
      // Read the Transaction Search field-index policy/fields on aws/spans — the eval
      // service reads these to query spans (same "index policy for aws/spans" access the
      // create-time validation needs). List-style actions → "*".
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
      // bedrock-agentcore-control create_online_evaluation_config (idempotent — lists
      // first, skips/reactivates existing). POST /evaluations/disable flips them DISABLED.
      evalProvisionerFn = new lambda.Function(this, "EvalProvisionerFn", {
        runtime: lambda.Runtime.PYTHON_3_12,
        handler: "index.handler",
        code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "eval-provisioner")),
        environment: {
          EVAL_EXECUTION_ROLE_ARN: evalExecutionRole.roleArn,
          EVAL_SERVICE_NAMES: "managementAgentRuntime,flowampDiscoveryScanner,flowampComplianceScanner",
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
          // "*" is required here. CreateOnlineEvaluationConfig and
          // ListOnlineEvaluationConfigs do not support resource-level permissions
          // (per the AgentCore IAM reference, they have no resource type), and the
          // config ids for the Update/Get/Delete calls are not known ahead of time —
          // this Lambda lists, then creates or reconciles configs on demand whose
          // AWS-assigned ids only exist after creation.
          resources: ["*"],
        })
      );
      // Discover the real runtime log-group names.
      evalProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({ actions: ["logs:DescribeLogGroups"], resources: ["*"] })
      );
      // CreateOnlineEvaluationConfig validates at create-time that it can query the
      // agent's spans, which live in the Transaction Search index on `aws/spans`. The
      // CALLER (this Lambda role) must therefore be able to read that log group's
      // field-index policy + fields, plus query the source groups; otherwise the create
      // fails with "Access denied when accessing index policy for aws/spans". (List-style
      // index/describe actions do not support resource scoping, hence "*".)
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

      // Invoker Lambda bridging the UI "Run compliance audit" button + a daily
      // schedule to the compliance-scanner (which has no API of its own). Fire-and-
      // forget (202 + async self-invoke) — an audit takes minutes, past API GW's 29s.
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

      // ── Standalone sample agents (self-contained; real discoverable workloads) ──
      if (deploySampleAgents) {
      const sampleAgents: Array<{ id: string; runtimeName: string; dir: string; description: string }> = [
        {
          id: "SampleClaimsTriageRuntime",
          runtimeName: "sampleClaimsTriage",
          dir: "sample-claims-triage",
          description: "Sample agent: insurance claims triage assistant",
        },
        {
          id: "SampleSupplyChainRuntime",
          runtimeName: "sampleSupplyChain",
          dir: "sample-supply-chain",
          description: "Sample agent: supply-chain disruption analyst",
        },
        {
          id: "SampleRequestIntakeRuntime",
          runtimeName: "sampleRequestIntake",
          dir: "sample-request-intake",
          description: "Sample agent: service request intake assistant",
        },
      ];
      const sampleArns: string[] = [];
      for (const s of sampleAgents) {
        const runtime = new agentcore.Runtime(this, s.id, {
          runtimeName: s.runtimeName,
          // Direct-code deploy: self-contained (no _shared), but still needs its
          // arm64 pip deps (strands, boto3) vendored into the bundle.
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
        // Per-agent cost-allocation tag (beats the stack-level 'platform' tag).
        cdk.Tags.of(runtime).add(COST_TAG_KEY, s.runtimeName);
        sampleArns.push(runtime.agentRuntimeArn);
      }
      new cdk.CfnOutput(this, "SampleAgentRuntimeArns", { value: cdk.Fn.join(",", sampleArns) });
      } // end sample agents (deploySampleAgents)
    } // end AgentCore toolchain block

    // ─── API Gateway: Frontend → Bedrock Agent ───
    const apiFn = new lambda.Function(this, "ApiHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "api-handler")),
      environment: {
        BEDROCK_AGENT_ID: agent.agentId,
        BEDROCK_AGENT_ALIAS_ID: "TSTALIASID",
        // Live FinOps ledger (Pick 1): after each successful /chat the handler
        // increments today's COST# row + the agent's INFO 'requests' counter.
        AGENT_TABLE_NAME: agentTable.tableName,
        REP_AGENT_ID: "service-health-monitor",
      },
      timeout: cdk.Duration.seconds(120),
    });

    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeAgent"],
        resources: [`arn:aws:bedrock:${this.region}:${this.account}:agent-alias/${agent.agentId}/*`],
      })
    );
    // Lets the chat handler update_item the COST#/INFO rows for the live ledger.
    agentTable.grantReadWriteData(apiFn);

    // ─── Lambda: Data Handler (REST backend for the UI) ───
    // Serves the UI's direct read routes today; gains write routes (Pick 2) and
    // audit-event writes (Pick 3) later, so it is granted read+write now.
    const dataHandlerFn = new lambda.Function(this, "DataHandlerFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(assetsSrc, "lambda", "data-handler")),
      environment: {
        AGENT_TABLE_NAME: agentTable.tableName,
        // Online-evaluations wiring. The provisioner + read routes are ALWAYS deployed,
        // so the UI can render an honest state. Whether any eval config actually exists
        // is determined at read time (list_online_evaluation_configs), not from an env
        // flag — a config is created on demand via the "Enable evaluations" button.
        // AgentCore writes results to `/aws/bedrock-agentcore/evaluations/results/<config-id>`.
        // The concrete config id isn't known at synth (it's assigned on create), so the
        // handler discovers the concrete group under this PREFIX via logs:DescribeLogGroups
        // rather than relying on a hard-coded group name.
        EVAL_RESULTS_LOG_GROUP_PREFIX: "/aws/bedrock-agentcore/evaluations/results/",
        // EMF metrics namespace AgentCore publishes evaluator scores under, keyed by
        // evaluator name + config id.
        EVAL_METRIC_NAMESPACE: "Bedrock-AgentCore/Evaluations",
        // OTEL service.name values (== runtimeName) of the evaluated core runtimes.
        EVAL_SERVICE_NAMES: "managementAgentRuntime,flowampDiscoveryScanner,flowampComplianceScanner",
      },
      timeout: cdk.Duration.seconds(30),
    });
    agentTable.grantReadWriteData(dataHandlerFn);
    // Read evaluation results — granted ALWAYS (not gated). It's cheap and lets the
    // UI readiness check work even when evaluations are off: query the results log
    // groups, read the EMF score metrics, and probe X-Ray Transaction Search (whose
    // trace-segment destination being CloudWatch Logs is the AgentCore evaluations
    // readiness signal).
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
          // aws/spans (Transaction Search) — the readiness spansPresent probe filters it.
          `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans`,
          `arn:aws:logs:${this.region}:${this.account}:log-group:aws/spans:*`,
        ],
      })
    );
    // DescribeLogGroups is a list operation — it does NOT support resource-level scoping,
    // so it must be granted on "*". The readiness check's trafficPresent/resultsLogGroup
    // probes depend on this action.
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

    // Access log group for the API stage (Checkov CKV_AWS_76).
    const apiAccessLogs = new logs.LogGroup(this, "AgentApiAccessLogs", {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ─── S3 + CloudFront (created before the API so CORS can scope to the CloudFront origin) ───
    const siteBucket = new s3.Bucket(this, "DemoSiteBucket", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      // Deny non-TLS requests via the bucket policy (cdk-nag AwsSolutions-S10 /
      // Checkov CKV_AWS_18). CloudFront already redirects viewers to HTTPS; this
      // enforces it at the bucket layer too.
      enforceSSL: true,
      // Server access logging (Checkov CKV_AWS_18). Logs to a prefix in the same
      // bucket to avoid spawning a second log bucket that trips the same finding.
      serverAccessLogsPrefix: "access-logs/",
    });

    const distribution = new cloudfront.Distribution(this, "DemoDistribution", {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(siteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: "agent-management.html",
    });

    // The UI (served from CloudFront) calls this API cross-origin, so the
    // CloudFront distribution domain is the only legitimate origin. Scoping to it
    // (instead of Cors.ALL_ORIGINS) follows least-privilege for CORS.
    const allowedOrigin = `https://${distribution.distributionDomainName}`;

    const api = new apigateway.RestApi(this, "AgentApi", {
      restApiName: "Agent Management API",
      defaultCorsPreflightOptions: {
        allowOrigins: [allowedOrigin],
        allowMethods: ["GET", "POST", "PATCH", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization"],
      },
      deployOptions: {
        accessLogDestination: new apigateway.LogGroupLogDestination(apiAccessLogs),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
      },
    });

    // The RestApi construct auto-creates a CloudWatch logging role and an
    // ApiGateway::Account resource, both of which CDK defaults to
    // DeletionPolicy/UpdateReplacePolicy: Retain. Retained resources can block
    // redeployment retries, so force them to Delete.
    // CloudWatchRole is an L2 construct (use its defaultChild); Account is
    // itself the L1 CfnResource (use it directly).
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
    // Read routes the single-page UI calls directly (entity rows from the table).
    // Kept separate from agent-handler, which serves the Bedrock Agent action group.
    // Read+write granted now; write routes also append audit EVENT# rows, and
    // GET /events reads them back (append-only audit log) on this same handler.
    const dataIntegration = new apigateway.LambdaIntegration(dataHandlerFn);
    let agentsResource: apigateway.Resource | undefined;
    let complianceResource: apigateway.Resource | undefined;
    let evaluationsResource: apigateway.Resource | undefined;
    // "audits" (plural) → fleet-wide latest-audit-per-agent for the Compliance view;
    // distinct from GET /agents/{agentId}/audit (singular, one agent's history) below.
    // "evaluations" → fleet-wide online-evaluation scores + readiness for the Evaluations view.
    for (const name of ["agents", "compliance", "aops", "access", "events", "costs", "audits", "evaluations"]) {
      const r = api.root.addResource(name);
      r.addMethod("GET", dataIntegration, authedMethodOptions);
      if (name === "agents") agentsResource = r;
      if (name === "compliance") complianceResource = r;
      if (name === "evaluations") evaluationsResource = r;
    }
    // GET /evaluations/readiness → whether AgentCore online evaluations can run
    // (X-Ray Transaction Search enabled + config present). Lets the UI show a
    // preflight state instead of an empty grid.
    evaluationsResource!.addResource("readiness").addMethod("GET", dataIntegration, authedMethodOptions);
    // POST /evaluations/enable | /disable → the eval-provisioner Lambda creates (or
    // flips ENABLED/DISABLED) one online-eval config per core agent, discovering each
    // agent's real runtime-id-suffixed trace log group at call time. Synchronous
    // (list+create is well under API GW's 29s), unlike the fire-and-forget scan invokers.
    // Only wired when the AgentCore toolchain (hence the provisioner) is deployed.
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

    // POST /discovery/scan → invokes the AgentCore discovery-scanner (only wired
    // when it is deployed). The UI Discover button prefers this over /discovery/sync
    // so it triggers real native discovery + LLM classification rather than the
    // Lambda's simulated connectors.
    if (discoveryScanInvokerFn) {
      discoveryResource
        .addResource("scan")
        .addMethod(
          "POST",
          new apigateway.LambdaIntegration(discoveryScanInvokerFn),
          authedMethodOptions
        );
    }

    // POST /compliance/scan → triggers the AgentCore compliance-scanner for one
    // agent ({"agentId": "..."}) or a rotation run (empty body). Fire-and-forget.
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
            // Tells the UI the AgentCore discovery-scanner route exists, so the
            // Discover button targets POST /discovery/scan instead of the Lambda's
            // simulated /discovery/sync.
            `window.DISCOVERY_SCAN_ENABLED=${discoveryScanInvokerFn ? "true" : "false"};`
        ),
      ],
      destinationBucket: siteBucket,
      // The bucket logs its own S3 server-access records into `access-logs/`
      // (serverAccessLogsPrefix above). Prune defaults to true (`s3 sync --delete`),
      // which would try to delete every object not in the source asset — i.e. all
      // accumulated access logs. Because logging writes NEW objects into that prefix
      // continuously (including during the sync itself), the delete set never drains
      // and the 128MB deploy Lambda hits its 15-min timeout. Excluding the prefix
      // keeps prune for real UI files while leaving the logs untouched.
      exclude: ["access-logs/*"],
      // Intentionally NOT passing `distribution`/`distributionPaths`. Those only
      // trigger a post-upload CloudFront invalidation, which forces CDK to attach
      // cloudfront:CreateInvalidation on Resource:"*" to the deploy role (Checkov
      // CKV_AWS_111). Each team's bucket is populated once into a fresh, empty-cache
      // distribution at provision time, so there is nothing to invalidate.
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
    new cdk.CfnOutput(this, "BedrockAgentId", { value: agent.agentId });
    new cdk.CfnOutput(this, "LoginUsername", { value: "flowadmin" });
    new cdk.CfnOutput(this, "LoginPassword", { value: seedUser.getAttString("Password") });
    new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
  }
}
