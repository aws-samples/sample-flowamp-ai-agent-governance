import json
import os
import random
import boto3
from datetime import datetime, timedelta
from decimal import Decimal

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['AGENT_TABLE_NAME'])

# Live FinOps cost ledger. Each active native agent gets `days` daily COST# rows
# (sk='COST#<YYYY-MM-DD>'), split 60/25/10/5 across components with +/-15% jitter.
FINOPS_JITTER_PCT = 0.15
COST_SPLIT = (("modelInference", "0.60"), ("agentCompute", "0.25"), ("toolExecution", "0.10"))

SEED_DATA = [
    # Operations (7) — RAI scores computed by rai-scorer Lambda
    {"agentId": "service-health-monitor", "name": "Service Health Monitor", "system": "Datadog", "category": "Operations", "platform": "native", "status": "active", "requests": 8712, "errors": 12, "avgResponseMs": 85, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("892"), "costPerInvocation": Decimal("0.0003"), "utilization": 94},
    {"agentId": "demand-forecast", "name": "Demand Forecast Agent", "system": "Snowflake", "category": "Operations", "platform": "native", "status": "active", "requests": 6234, "errors": 18, "avgResponseMs": 142, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("645"), "costPerInvocation": Decimal("0.0008"), "utilization": 88},
    {"agentId": "inventory-optimizer", "name": "Inventory Optimization Agent", "system": "SAP IBP", "category": "Operations", "platform": "native", "status": "active", "requests": 4890, "errors": 9, "avgResponseMs": 198, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("467"), "costPerInvocation": Decimal("0.0006"), "utilization": 86},
    {"agentId": "logistics-routing", "name": "Logistics Routing Agent", "system": "Oracle OTM", "category": "Operations", "platform": "native", "status": "active", "requests": 7456, "errors": 21, "avgResponseMs": 67, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("534"), "costPerInvocation": Decimal("0.0004"), "utilization": 91},
    {"agentId": "production-line-monitor", "name": "Production Line Monitor", "system": "Siemens MindSphere", "category": "Operations", "platform": "native", "status": "active", "requests": 12450, "errors": 8, "avgResponseMs": 34, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("723"), "costPerInvocation": Decimal("0.0002"), "utilization": 96},
    {"agentId": "throughput-optimizer", "name": "Throughput Optimization Agent", "system": "AWS IoT SiteWise", "category": "Operations", "platform": "native", "status": "active", "requests": 5678, "errors": 14, "avgResponseMs": 112, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("398"), "costPerInvocation": Decimal("0.0005"), "utilization": 79},
    {"agentId": "incident-prediction", "name": "Incident Prediction Agent", "system": "PagerDuty", "category": "Operations", "platform": "native", "status": "active", "requests": 3201, "errors": 7, "avgResponseMs": 245, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("412"), "costPerInvocation": Decimal("0.0009"), "utilization": 78},
    # Asset & Infrastructure (6)
    {"agentId": "equipment-integrity", "name": "Equipment Integrity Agent", "system": "IBM Maximo", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 2156, "errors": 5, "avgResponseMs": 380, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("356"), "costPerInvocation": Decimal("0.0004"), "utilization": 71},
    {"agentId": "asset-health-monitor", "name": "Asset Health Monitor", "system": "GE Predix", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 1890, "errors": 3, "avgResponseMs": 420, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("312"), "costPerInvocation": Decimal("0.0007"), "utilization": 68},
    {"agentId": "machine-performance", "name": "Machine Performance Agent", "system": "IBM Maximo", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 2345, "errors": 11, "avgResponseMs": 310, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("287"), "costPerInvocation": Decimal("0.0005"), "utilization": 64},
    {"agentId": "facilities-inspection", "name": "Facilities Inspection Agent", "system": "Esri ArcGIS", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 876, "errors": 4, "avgResponseMs": 520, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("178"), "costPerInvocation": Decimal("0.0005"), "utilization": 52},
    {"agentId": "datacenter-monitor", "name": "Data Center Monitor", "system": "Nlyte DCIM", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 9870, "errors": 16, "avgResponseMs": 56, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("621"), "costPerInvocation": Decimal("0.0002"), "utilization": 89},
    {"agentId": "predictive-maintenance", "name": "Predictive Maintenance Agent", "system": "SAP PM", "category": "Asset & Infrastructure", "platform": "native", "status": "active", "requests": 1563, "errors": 8, "avgResponseMs": 380, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("245"), "costPerInvocation": Decimal("0.0006"), "utilization": 61},
    # Finance & Trading (5)
    {"agentId": "fraud-detection", "name": "Fraud Detection Agent", "system": "Databricks", "category": "Finance & Trading", "platform": "native", "status": "active", "requests": 1095, "errors": 5, "avgResponseMs": 190, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("578"), "costPerInvocation": Decimal("0.0012"), "utilization": 82},
    {"agentId": "revenue-forecast", "name": "Revenue Forecast Agent", "system": "Snowflake", "category": "Finance & Trading", "platform": "native", "status": "active", "requests": 2890, "errors": 6, "avgResponseMs": 340, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("445"), "costPerInvocation": Decimal("0.0007"), "utilization": 76},
    {"agentId": "ap-automation", "name": "AP Automation Agent", "system": "Oracle EBS", "category": "Finance & Trading", "platform": "native", "status": "active", "requests": 1456, "errors": 3, "avgResponseMs": 275, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("334"), "costPerInvocation": Decimal("0.0006"), "utilization": 69},
    {"agentId": "capacity-planning", "name": "Capacity Planning Agent", "system": "Anaplan", "category": "Finance & Trading", "platform": "native", "status": "active", "requests": 987, "errors": 2, "avgResponseMs": 450, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("267"), "costPerInvocation": Decimal("0.0008"), "utilization": 58},
    {"agentId": "portfolio-risk", "name": "Portfolio Risk Agent", "system": "Bloomberg", "category": "Finance & Trading", "platform": "native", "status": "active", "requests": 654, "errors": 1, "avgResponseMs": 380, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("198"), "costPerInvocation": Decimal("0.0009"), "utilization": 54},
    # Security & Compliance (6)
    {"agentId": "network-anomaly", "name": "Network Anomaly Detector", "system": "Netskope", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 8920, "errors": 23, "avgResponseMs": 45, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("523"), "costPerInvocation": Decimal("0.0002"), "utilization": 91},
    {"agentId": "data-privacy-monitor", "name": "Data Privacy Monitor", "system": "Security Lake", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 4567, "errors": 6, "avgResponseMs": 290, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("289"), "costPerInvocation": Decimal("0.0003"), "utilization": 65},
    {"agentId": "incident-response", "name": "Incident Response Agent", "system": "Security Lake", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 3456, "errors": 2, "avgResponseMs": 180, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("256"), "costPerInvocation": Decimal("0.0004"), "utilization": 72},
    {"agentId": "regulatory-filing", "name": "Regulatory Filing Agent", "system": "Security Lake", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 987, "errors": 1, "avgResponseMs": 520, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("189"), "costPerInvocation": Decimal("0.0007"), "utilization": 55},
    {"agentId": "access-validator", "name": "Access Validation Agent", "system": "Okta", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 15670, "errors": 15, "avgResponseMs": 32, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("234"), "costPerInvocation": Decimal("0.0001"), "utilization": 73},
    {"agentId": "compliance-auditor", "name": "Compliance Auditor", "system": "AWS Audit Manager", "category": "Security & Compliance", "platform": "native", "status": "active", "requests": 2340, "errors": 4, "avgResponseMs": 410, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("213"), "costPerInvocation": Decimal("0.0005"), "utilization": 67},
    # Customer Operations (6)
    {"agentId": "billing-reconciliation", "name": "Billing Reconciliation Agent", "system": "Zuora", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 4102, "errors": 15, "avgResponseMs": 310, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("378"), "costPerInvocation": Decimal("0.0005"), "utilization": 74},
    {"agentId": "churn-prediction", "name": "Churn Prediction Agent", "system": "Salesforce", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 2340, "errors": 8, "avgResponseMs": 220, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("298"), "costPerInvocation": Decimal("0.0006"), "utilization": 70},
    {"agentId": "usage-analytics", "name": "Usage Analytics Agent", "system": "Amplitude", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 6789, "errors": 12, "avgResponseMs": 165, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("345"), "costPerInvocation": Decimal("0.0003"), "utilization": 77},
    {"agentId": "customer-notification", "name": "Customer Notification Agent", "system": "Amazon Connect", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 3456, "errors": 5, "avgResponseMs": 140, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("267"), "costPerInvocation": Decimal("0.0004"), "utilization": 75},
    {"agentId": "self-service-assistant", "name": "Self-Service Assistant", "system": "Amazon Lex", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 5670, "errors": 9, "avgResponseMs": 195, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("389"), "costPerInvocation": Decimal("0.0004"), "utilization": 81},
    {"agentId": "order-validator", "name": "Order Validation Agent", "system": "Shopify", "category": "Customer Operations", "platform": "native", "status": "active", "requests": 8901, "errors": 10, "avgResponseMs": 28, "score": 0, "fairness": 0, "transparency": 0, "accountability": 0, "ethics": 0, "monthlyCost": Decimal("156"), "costPerInvocation": Decimal("0.0001"), "utilization": 70},
]

COMPLIANCE_DATA = [
    {"agentId": "compliance:iso27001", "name": "ISO 27001", "complianceScore": Decimal("96"), "status": "compliant", "lastAudit": "2/10/2026", "controls": '[{"n":"Access Control","s":97},{"n":"Cryptography","s":95},{"n":"Incident Management","s":96},{"n":"Business Continuity","s":94}]'},
    {"agentId": "compliance:gdpr", "name": "GDPR", "complianceScore": Decimal("93"), "status": "compliant", "lastAudit": "1/15/2026", "controls": '[{"n":"Lawful Basis","s":95},{"n":"Data Subject Rights","s":92},{"n":"Breach Notification","s":93}]'},
    {"agentId": "compliance:pci-dss", "name": "PCI DSS", "complianceScore": Decimal("89"), "status": "warning", "lastAudit": "12/20/2025", "controls": '[{"n":"Network Security","s":91},{"n":"Cardholder Data Protection","s":86},{"n":"Access Control","s":88}]'},
    {"agentId": "compliance:iso42001", "name": "ISO 42001 (AI MS)", "complianceScore": Decimal("94"), "status": "compliant", "lastAudit": "1/28/2026", "controls": '[{"n":"AI Policy","s":95},{"n":"AI Lifecycle Management","s":93},{"n":"Performance Evaluation","s":94}]'},
    {"agentId": "compliance:soc2", "name": "SOC 2 Type II", "complianceScore": Decimal("92"), "status": "compliant", "lastAudit": "11/30/2025", "controls": '[{"n":"Security","s":94},{"n":"Availability","s":91},{"n":"Confidentiality","s":92}]'},
    {"agentId": "compliance:eu-ai-act", "name": "EU AI Act", "complianceScore": Decimal("88"), "status": "warning", "lastAudit": "1/5/2026", "controls": '[{"n":"Risk Classification","s":90},{"n":"Transparency Obligations","s":85},{"n":"Human Oversight","s":87}]'},
    {"agentId": "compliance:nist-govern", "name": "NIST AI RMF - Govern", "complianceScore": Decimal("91"), "status": "compliant", "lastAudit": "2/18/2026", "controls": '[{"n":"Governance Structure","s":93},{"n":"Risk Tolerance","s":90},{"n":"Accountability Mechanisms","s":91},{"n":"Organizational Policies","s":89}]'},
    {"agentId": "compliance:nist-map", "name": "NIST AI RMF - Map", "complianceScore": Decimal("88"), "status": "warning", "lastAudit": "2/18/2026", "controls": '[{"n":"Context & Use Case Mapping","s":90},{"n":"Stakeholder Identification","s":87},{"n":"Benefit/Risk Framing","s":86},{"n":"Interdependency Analysis","s":88}]'},
    {"agentId": "compliance:nist-measure", "name": "NIST AI RMF - Measure", "complianceScore": Decimal("90"), "status": "compliant", "lastAudit": "2/18/2026", "controls": '[{"n":"Bias & Fairness Metrics","s":92},{"n":"Reliability Testing","s":91},{"n":"Explainability Assessment","s":88},{"n":"Privacy Risk Quantification","s":89}]'},
    {"agentId": "compliance:nist-manage", "name": "NIST AI RMF - Manage", "complianceScore": Decimal("87"), "status": "warning", "lastAudit": "2/18/2026", "controls": '[{"n":"Risk Prioritization","s":89},{"n":"Mitigation Strategies","s":86},{"n":"Continuous Monitoring","s":88},{"n":"Incident Response for AI","s":84}]'},
    {"agentId": "compliance:nist-sp800-37", "name": "NIST SP 800-37 (RMF)", "complianceScore": Decimal("89"), "status": "warning", "lastAudit": "3/15/2026", "controls": '[{"n":"Prepare - Risk Context & Priorities","s":92},{"n":"Categorize - System Impact Level","s":91},{"n":"Select - Security Controls (SP 800-53)","s":88},{"n":"Implement - Control Deployment","s":90},{"n":"Assess - Control Effectiveness","s":87},{"n":"Authorize - Risk Acceptance Decision","s":85},{"n":"Monitor - Continuous Posture Tracking","s":91}]'},
]

AOP_DATA = [
    {"agentId": "aop:AOP-01", "aopId": "AOP-01", "name": "Service Degradation Response", "status": "active", "agents": "Service Health Monitor, Incident Prediction Agent", "executions": 12450, "successRate": Decimal("97.8"), "owner": "Operations", "entry": "Service latency exceeds SLA threshold for 5 consecutive minutes"},
    {"agentId": "aop:AOP-02", "aopId": "AOP-02", "name": "Inventory Replenishment Optimization", "status": "active", "agents": "Inventory Optimization Agent, Demand Forecast Agent", "executions": 3890, "successRate": Decimal("95.2"), "owner": "Supply Chain", "entry": "Forecasted demand exceeds available stock within lead time"},
    {"agentId": "aop:AOP-03", "aopId": "AOP-03", "name": "Network Intrusion Detection", "status": "active", "agents": "Network Anomaly Detector, Incident Response Agent", "executions": 8920, "successRate": Decimal("99.1"), "owner": "Security Operations", "entry": "Anomalous network traffic pattern detected"},
    {"agentId": "aop:AOP-04", "aopId": "AOP-04", "name": "Asset Health Assessment", "status": "active", "agents": "Asset Health Monitor, Predictive Maintenance Agent", "executions": 2156, "successRate": Decimal("94.5"), "owner": "Asset Management", "entry": "Scheduled sensor reading received or thermal alert triggered"},
    {"agentId": "aop:AOP-05", "aopId": "AOP-05", "name": "Daily Risk Position Review", "status": "active", "agents": "Fraud Detection Agent, Portfolio Risk Agent", "executions": 1095, "successRate": Decimal("93.8"), "owner": "Finance", "entry": "Daily trigger at market close"},
    {"agentId": "aop:AOP-06", "aopId": "AOP-06", "name": "Data Privacy Breach Response", "status": "active", "agents": "Data Privacy Monitor, Incident Response Agent", "executions": 4567, "successRate": Decimal("96.3"), "owner": "Privacy Office", "entry": "PII access pattern exceeds policy threshold"},
    {"agentId": "aop:AOP-07", "aopId": "AOP-07", "name": "Demand Surge Capacity Staging", "status": "active", "agents": "Incident Prediction Agent, Throughput Optimization Agent", "executions": 876, "successRate": Decimal("91.4"), "owner": "Operations", "entry": "Forecasted load exceeds 80% of provisioned capacity"},
    {"agentId": "aop:AOP-08", "aopId": "AOP-08", "name": "Customer Churn Intervention", "status": "active", "agents": "Churn Prediction Agent, Usage Analytics Agent", "executions": 2340, "successRate": Decimal("94.9"), "owner": "Customer Operations", "entry": "Customer churn-risk score exceeds intervention threshold"},
    {"agentId": "aop:AOP-09", "aopId": "AOP-09", "name": "Equipment Inspection Workflow", "status": "active", "agents": "Equipment Integrity Agent, Incident Response Agent", "executions": 312, "successRate": Decimal("97.1"), "owner": "Facilities", "entry": "Scheduled inspection run or integrity alert triggered"},
    {"agentId": "aop:AOP-10", "aopId": "AOP-10", "name": "Order Fulfillment Load Management", "status": "active", "agents": "Order Validation Agent, Logistics Routing Agent", "executions": 5670, "successRate": Decimal("95.7"), "owner": "Customer Operations", "entry": "Order volume exceeds 70% of fulfillment capacity"},
    {"agentId": "aop:AOP-11", "aopId": "AOP-11", "name": "Financial Close Reconciliation", "status": "draft", "agents": "AP Automation Agent, Revenue Forecast Agent", "executions": 0, "successRate": Decimal("0"), "owner": "Finance", "entry": "Month-end close period begins"},
    {"agentId": "aop:AOP-12", "aopId": "AOP-12", "name": "Production Line Failover", "status": "draft", "agents": "Production Line Monitor, Machine Performance Agent", "executions": 0, "successRate": Decimal("0"), "owner": "Manufacturing", "entry": "Production line throughput drops below threshold"},
    {"agentId": "aop:AOP-13", "aopId": "AOP-13", "name": "High-Risk Transaction Hold", "status": "review", "agents": "Fraud Detection Agent, Access Validation Agent", "executions": 45, "successRate": Decimal("88.9"), "owner": "Risk & Compliance", "entry": "Transaction risk score exceeds high-risk threshold"},
    {"agentId": "aop:AOP-14", "aopId": "AOP-14", "name": "Critical System Access Revocation", "status": "review", "agents": "Access Validation Agent, Incident Response Agent", "executions": 128, "successRate": Decimal("100"), "owner": "Security Operations", "entry": "Compromised credential detected for privileged account"},
]

ACCESS_DATA = [
    {"agentId": "access:rachel-torres", "userName": "Rachel Torres", "role": "Operations Director", "accessLevel": "admin", "operations": "full", "assetMgmt": "full", "finance": "read", "security": "full", "customer": "read"},
    {"agentId": "access:mark-sullivan", "userName": "Mark Sullivan", "role": "Chief Information Security Officer", "accessLevel": "admin", "operations": "audit", "assetMgmt": "audit", "finance": "audit", "security": "full", "customer": "audit"},
    {"agentId": "access:anika-patel", "userName": "Anika Patel", "role": "ML Engineer - Platform AI", "accessLevel": "engineer", "operations": "exec", "assetMgmt": "exec", "finance": "read", "security": "exec", "customer": "read"},
    {"agentId": "access:tom-nguyen", "userName": "Tom Nguyen", "role": "Site Reliability Engineer", "accessLevel": "engineer", "operations": "full", "assetMgmt": "exec", "finance": "none", "security": "full", "customer": "none"},
    {"agentId": "access:karen-mitchell", "userName": "Karen Mitchell", "role": "Compliance Officer", "accessLevel": "viewer", "operations": "read", "assetMgmt": "read", "finance": "read", "security": "audit", "customer": "read"},
    {"agentId": "access:david-chen", "userName": "David Chen", "role": "Finance Analyst", "accessLevel": "viewer", "operations": "read", "assetMgmt": "none", "finance": "full", "security": "none", "customer": "read"},
]

def _finops_rows(days=7):
    """Backfill `days` daily cost rows per active native agent.

    Iterates SEED_DATA (the native agents), skips any whose status != 'active' or
    whose monthlyCost <= 0, and emits one COST#<date> row per day for the most
    recent `days` calendar days ending today. base_daily = monthlyCost/30 with
    +/-15% jitter; components split 60/25/10/5 (storage is the remainder so the
    parts always sum back to totalCost). These are NOT sk='INFO' rows; each
    carries its own sk='COST#<date>'.
    """
    for item in SEED_DATA:
        if item.get('status') != 'active':
            continue
        monthly_cost = float(item.get('monthlyCost', 0))
        if monthly_cost <= 0:
            continue
        base_daily = monthly_cost / 30.0
        cpi = float(item.get('costPerInvocation', Decimal('0.05')))
        for day_offset in range(days - 1, -1, -1):
            date_str = (datetime.utcnow() - timedelta(days=day_offset)).strftime('%Y-%m-%d')
            jitter = 1.0 + random.uniform(-FINOPS_JITTER_PCT, FINOPS_JITTER_PCT)
            d = Decimal(str(round(base_daily * jitter, 6)))
            model_inf = (d * Decimal('0.60')).quantize(Decimal('0.000001'))
            agent_comp = (d * Decimal('0.25')).quantize(Decimal('0.000001'))
            tool_exec = (d * Decimal('0.10')).quantize(Decimal('0.000001'))
            storage = (d - model_inf - agent_comp - tool_exec).quantize(Decimal('0.000001'))
            invocations = max(1, int(base_daily / cpi * jitter))
            yield {
                'agentId': item['agentId'],
                'sk': 'COST#' + date_str,
                'date': date_str,
                'status': 'final',
                'totalCost': d,
                'costByComponent': {
                    'modelInference': model_inf,
                    'agentCompute': agent_comp,
                    'toolExecution': tool_exec,
                    'storage': storage,
                },
                'invocationCount': invocations,
                'costPerInvocation': (d / Decimal(str(invocations))).quantize(Decimal('0.000001')),
                'source': 'demo-seed',
            }


def handler(event, context):
    request_type = event.get('RequestType', '')
    physical_id = event.get('PhysicalResourceId', context.log_stream_name)
    if request_type in ('Create', 'Update'):
        # The table is keyed agentId (PK) + sk (SK). Every seeded entity is the
        # canonical "INFO" row for its agentId; audit (EVENT#…) rows are written
        # later by the runtime. Cost (COST#…) rows are backfilled here so the
        # FinOps spend trend has 7 days of history on first load.
        with table.batch_writer() as batch:
            for item in SEED_DATA + COMPLIANCE_DATA + AOP_DATA + ACCESS_DATA:
                # Stamp source='demo-seed' on every seeded INFO row so the UI can
                # distinguish demo agents from real discovered/registered ones.
                # A row that already sets 'source' keeps its own value.
                batch.put_item(Item={'sk': 'INFO', 'source': 'demo-seed', **item})
            for row in _finops_rows(7):
                batch.put_item(Item=row)
    return {'PhysicalResourceId': physical_id}
