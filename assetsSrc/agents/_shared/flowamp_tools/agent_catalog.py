# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared agent catalog query helper.

The AgentTable has no GSI, so we Scan with a ``FilterExpression`` of
``sk = 'INFO'`` — the same pattern the data-handler Lambda uses (scan_info).
Status/category/field filtering is applied post-read.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from ._config import get_agent_table_name

_logger = logging.getLogger(__name__)


def list_active_agents(
    *,
    status: str | list[str] | None = None,
    category: str | None = None,
    fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return agent INFO rows from the shared AgentTable.

    Scans with FilterExpression sk='INFO' (no GSI in this repo). Sub-collection
    rows (COMPLIANCE#, REVIEW#, MODEL#, EVENT#, COST#, …) share the partition key
    but a different sk, so the filter returns only INFO rows.

    Args:
        status: When set, post-filters rows by the `status` attribute (str or list).
            None returns all rows regardless of lifecycle state.
        category: When set, post-filters rows by the `category` attribute.
        fields: Optional attribute allowlist via ProjectionExpression. agentId and
            sk are always included. None returns the full INFO row.

    Returns:
        list[dict] of INFO rows, each representing one agent.

    Raises:
        ClientError: propagated unchanged when DynamoDB returns an error.
    """
    region = os.environ.get("AWS_REGION", "us-east-1")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(get_agent_table_name())

    kwargs: dict[str, Any] = {"FilterExpression": Attr("sk").eq("INFO")}

    if fields is not None:
        projection_set = set(fields) | {"agentId", "sk"}
        _RESERVED = {"name", "status", "size", "type", "owner", "source"}
        expr_names: dict[str, str] = {}
        proj_parts: list[str] = []
        for f in sorted(projection_set):
            if f in _RESERVED:
                alias = f"#_proj_{f}"
                expr_names[alias] = f
                proj_parts.append(alias)
            else:
                proj_parts.append(f)
        kwargs["ProjectionExpression"] = ", ".join(proj_parts)
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names

    items: list[dict] = []
    try:
        while True:
            response = table.scan(**kwargs)
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
    except ClientError as exc:
        _logger.warning(
            "agent_catalog.list_active_agents: DynamoDB scan failed: %s", exc, exc_info=True,
        )
        raise

    # Post-read filters — ProjectionExpression does not filter values.
    if status is not None:
        allowed = {status} if isinstance(status, str) else set(status)
        items = [i for i in items if i.get("status") in allowed]

    if category is not None:
        items = [i for i in items if i.get("category") == category]

    return items
