# Developer guides

Standalone, self-contained HTML deep-dives into how each FlowAMP subsystem actually
works today, and what you would harden or extend for production. They are **reference
docs for people who clone this repo** - they are intentionally **not** bundled into the
deployed UI or served from CloudFront. Open them locally in a browser
(`open finops-developer-guide.html`) or read the source.

Each guide is grounded in the current code (it cites the real source files) and keeps an
honest "real now vs. still-to-harden" framing rather than the earlier "demo vs.
production" split.

| Guide | Covers | Key source it documents |
|---|---|---|
| [agentcore-developer-guide.html](agentcore-developer-guide.html) | The three always-on AgentCore runtimes (management, discovery-scanner, compliance-scanner) + optional sample agents; direct-code deployment (Lambda-style shared responsibility, `uv` synth-time vendoring, no Docker); which AgentCore services are used vs. adoptable next. | `cdk/lib/agent-bundle.ts`, `cdk/lib/team-stack.ts`, `assetsSrc/agents/` |
| [otel-observability-developer-guide.html](otel-observability-developer-guide.html) | How agent OpenTelemetry spans reach `aws/spans` and feed AgentCore Observability + Evaluations: the in-process `opentelemetry-instrument` re-exec that direct-code deploy needs, the OpenInference span processor, the observability env, the Transaction Search prerequisite, and how to verify/troubleshoot. | `assetsSrc/agents/*/main.py`, `cdk/lib/team-stack.ts`, `assetsSrc/lambda/data-handler/` |
| [risk-compliance-developer-guide.html](risk-compliance-developer-guide.html) | The wired compliance-scanner: deterministic checks + LLM judgment, A-F `AUDIT#`/`RAI#` rows, the five code-defined frameworks, the daily rotation + on-demand triggers, and the fleet Compliance view. | `assetsSrc/agents/compliance-scanner/`, `assetsSrc/agents/_shared/`, `assetsSrc/lambda/compliance-scan-invoker/` |
| [finops-developer-guide.html](finops-developer-guide.html) | Real Cost Explorer FinOps: the `flowamp:agentId` cost-allocation tag, the daily `finops-collector`, `COST#` ledger rows, and what is still a hardening TODO (token cost, forecast, anomaly detection). | `assetsSrc/lambda/finops-collector/`, `assetsSrc/lambda/cost-tag-activator/` |
| [rai-scoring-developer-guide.html](rai-scoring-developer-guide.html) | The daily Responsible-AI scorer, the CloudWatch/CloudTrail signals it derives from, base-value behavior in a fresh account, and the on-demand rescore path. | `assetsSrc/lambda/rai-scorer/` |
| [aop-developer-guide.html](aop-developer-guide.html) | Agent Operating Policies. **Honest note:** this is a demo/illustrative surface - the AOP tab is seed data and the work-item/enforcement runtime is intentionally stubbed. The guide marks what is not built and sketches a Cedar-based enforcement design. | `assetsSrc/site/agent-management.html` (`aopsData`), `assetsSrc/agents/_shared/flowamp_tools/work_items.py` |

> These guides describe the implementation as of the current branch. If you change a
> subsystem, update its guide (and the source-file citations in its footer) alongside the code.
