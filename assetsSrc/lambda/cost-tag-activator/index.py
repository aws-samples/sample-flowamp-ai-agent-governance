# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudFormation custom resource — activate the flowamp:agentId cost-allocation tag.

Cost Explorer only groups by a user-defined tag once that tag key is ACTIVATED as a
cost-allocation tag in Billing. Activation is a billing/payer-account operation:
`ce:UpdateCostAllocationTagsStatus`. This custom resource attempts it on deploy so a
management/payer account is set up automatically.

IMPORTANT: this only works from the ORGANIZATION MANAGEMENT (payer) account. In a
member/linked or sandbox account the call is AccessDenied — expected. The resource
NEVER fails the stack: it reports SUCCESS either way, and on failure logs that the
tag must be activated manually in the Billing console (see README). Two caveats even
on success: the tag key must have appeared in Billing first (up to ~24h after the
first tagged resource), and CE needs up to another ~24h before returning data.
"""
import json
import os
import urllib.request

import boto3

TAG_KEY = os.environ.get("COST_TAG_KEY", "flowamp:agentId")


def _send(event, context, status, reason):
    """Minimal CFN custom-resource response (no cfnresponse dependency)."""
    body = json.dumps({
        "Status": status,
        "Reason": reason[:1000],
        "PhysicalResourceId": event.get("PhysicalResourceId") or f"cost-tag-{TAG_KEY}",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {"tagKey": TAG_KEY, "activationStatus": reason[:200]},
    }).encode("utf-8")
    # ResponseURL is the CloudFormation-provided pre-signed S3 URL for the custom-resource
    # response. Enforce https so only the expected scheme is opened (never file:/ or a
    # custom scheme), which addresses the scheme-restriction concern for urlopen.
    response_url = event["ResponseURL"]
    if not response_url.lower().startswith("https://"):
        raise ValueError("CloudFormation ResponseURL must be an https URL")
    req = urllib.request.Request(
        response_url, data=body, method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    urllib.request.urlopen(req)  # nosec B310 - https-only CFN pre-signed S3 response URL (validated above)


def handler(event, context):
    request_type = event.get("RequestType")
    # Only act on Create/Update; Delete is a no-op (we don't deactivate the tag).
    if request_type == "Delete":
        return _send(event, context, "SUCCESS", "delete: no-op")

    try:
        ce = boto3.client("ce", region_name="us-east-1")  # CE is always us-east-1
        ce.update_cost_allocation_tags_status(
            CostAllocationTagsStatus=[{"TagKey": TAG_KEY, "Status": "Active"}]
        )
        msg = f"activated cost-allocation tag '{TAG_KEY}'"
        print("cost-tag-activator:", msg)
        return _send(event, context, "SUCCESS", msg)
    except Exception as exc:  # noqa: BLE001 — never fail the stack over billing perms
        msg = (f"could not auto-activate cost-allocation tag '{TAG_KEY}' "
               f"({type(exc).__name__}); activate it manually in the Billing console "
               f"(management account only). Detail: {exc}")
        print("cost-tag-activator:", msg)
        return _send(event, context, "SUCCESS", msg)
