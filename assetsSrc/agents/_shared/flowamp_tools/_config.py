# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared config helpers for the single-table flowamp_tools.

This deployment uses a single ``AgentTable`` keyed ``agentId`` (PK) + ``sk`` (SK),
so every ``get_*_table`` accessor here resolves to that ONE table. The distinct
row domains are kept apart by the ``sk`` prefix convention used by the
data-handler Lambda:

  sk = 'INFO'                         canonical entity (agent) row
  sk = 'EVENT#<ISO-ts>#<eventId>'     append-only audit event (UI Event Explorer)
  sk = 'AUDIT#<ISO-ts>'               compliance audit report row
  sk = 'NOTE#<ref>'                   audit note row
  sk = 'RAI#<ISO-ts>'                 responsible-AI score row
  sk = 'COMPLIANCE#<frameworkId>'     per-agent framework assignment
  sk = 'REVIEW#<ISO-ts>'              discovery review/lifecycle marker
  sk = 'MODEL#<provider>/<name>'      inferred model registry row
  sk = 'FRAMEWORK#<frameworkId>'      framework definition (partition 'FLOWAMP_FRAMEWORKS')

Table name resolution: the AGENT_TABLE_NAME env var (injected by the CDK stack)
always wins. There is no SSM fallback and no per-domain table name — there is
only one table.
"""
import os

import boto3

# Sentinel partition keys for non-agent singleton collections on the shared table.
FRAMEWORKS_PARTITION = "FLOWAMP_FRAMEWORKS"
MODELS_PARTITION = "FLOWAMP_MODELS"
CATEGORIES_PARTITION = "FLOWAMP_CATEGORIES"


def get_agent_id() -> str:
    """Return this agent's canonical id (FLOWAMP_AGENT_ID), injected by the stack."""
    agent_id = os.environ.get("FLOWAMP_AGENT_ID")
    if not agent_id:
        raise EnvironmentError(
            "FLOWAMP_AGENT_ID is not set. "
            "This variable must be injected by the AgentCore runtime infrastructure."
        )
    return agent_id


def get_agent_table_name() -> str:
    """Physical name of the single AgentTable (AGENT_TABLE_NAME env var)."""
    name = os.environ.get("AGENT_TABLE_NAME")
    if not name:
        raise EnvironmentError(
            "AGENT_TABLE_NAME is not set. "
            "This variable must be injected by the AgentCore runtime infrastructure."
        )
    return name


def get_agent_table():
    """Return the single shared DynamoDB Table resource."""
    region = os.environ.get("AWS_REGION", "us-east-1")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(get_agent_table_name())


# ── Single-table aliases ─────────────────────────────────────────────────────
# The distinct table accessors all resolve to the same physical table, so every
# accessor returns it. Keeping the distinct names lets the modules read unchanged.
get_event_table_name = get_agent_table_name
get_agent_compliance_table_name = get_agent_table_name
get_compliance_framework_table_name = get_agent_table_name
get_dynamodb_table = get_agent_table
get_agent_compliance_table = get_agent_table
get_compliance_framework_table = get_agent_table
