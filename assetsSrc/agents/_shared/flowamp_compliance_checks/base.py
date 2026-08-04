# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Base classes for the flowamp_compliance_checks library.

Defines the Check ABC, convenience subclasses (AthenaCheck, AwsConfigCheck,
IamPolicyCheck), and all shared dataclasses (CheckResult, CheckContext,
AgentTarget, DatasetTarget, ToolTarget).
"""
from __future__ import annotations

import abc
import operator as _operator
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Union
import urllib.parse

Category = Literal["fairness", "transparency", "accountability", "ethics", "operational"]
Cost = Literal["cheap", "moderate", "expensive"]
AppliesTo = Literal["agent", "dataset", "tool"]
Severity = Literal["critical", "high", "medium", "low", "info"]
ResultType = Literal["pass", "fail", "skip"]


@dataclass
class CheckResult:
    result: ResultType
    evidence: str
    duration_ms: int = 0
    # When True the caller (agent system prompt) must create a work item
    # to track resolution. Used by non-AWS guardrail evidence checks.
    requiresWorkItem: bool = False


@dataclass
class AgentTarget:
    agent_id: str
    record: dict
    primary_resource_type: Optional[str] = None
    primary_resource_id: Optional[str] = None
    role_arn: Optional[str] = None
    runtime_arn: Optional[str] = None
    function_name: Optional[str] = None
    region: Optional[str] = None


@dataclass
class DatasetTarget:
    dataset_id: str
    record: dict


@dataclass
class ToolTarget:
    tool_id: str
    record: dict


Target = Union[AgentTarget, DatasetTarget, ToolTarget]


@dataclass
class CheckContext:
    """Per-run scratch space passed to every check.

    Internal helper-cache entries use a leading underscore prefix
    (e.g. "_guardrail::{agent_id}") to avoid colliding with the
    check-id keyed dedup cache the runner maintains. The runner only
    reads keys equal to the checkId slug (no underscore prefix).
    """

    clients: dict[str, Any]
    cache: dict[str, Any] = field(default_factory=dict)
    framework_set: list[dict] = field(default_factory=list)
    region: str = "us-east-1"
    athena_database: Optional[str] = None
    athena_workgroup: Optional[str] = None
    athena_output_location: Optional[str] = None

    def client(self, service: str) -> Any:
        """Return a boto3 client for `service`, creating it lazily if needed."""
        if service not in self.clients:
            import boto3

            self.clients[service] = boto3.client(service, region_name=self.region)
        return self.clients[service]


class Check(abc.ABC):
    """Abstract base for all compliance checks.

    Class-level constants are intentional — the GET /compliance/check-registry
    endpoint serialises them without instantiating the class.
    """

    check_id: str = ""
    category: Category = "operational"
    description: str = ""
    cost: Cost = "cheap"
    applies_to: list[AppliesTo] = ["agent"]
    default_severity: Severity = "medium"
    parameter_schema: dict = {}

    @abc.abstractmethod
    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult: ...


class AthenaCheck(Check):
    """Convenience subclass for Athena-backed trend checks.

    Subclass declares `sql_template` and `threshold_predicate`; evaluate
    binds params, runs the query, waits (30s), applies the predicate, and
    returns an appropriate CheckResult.
    """

    sql_template: str = ""
    threshold_predicate: str = ""

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        start = time.monotonic()
        athena = ctx.client("athena")
        try:
            sql = self.sql_template.format(**self._bind_params(target, params, ctx))
            resp = athena.start_query_execution(
                QueryString=sql,
                QueryExecutionContext={"Database": ctx.athena_database or "default"},
                WorkGroup=ctx.athena_workgroup or "primary",
                ResultConfiguration={"OutputLocation": ctx.athena_output_location or ""},
            )
            qid = resp["QueryExecutionId"]
            self._wait(athena, qid, timeout_s=30)
            value = self._extract_value(athena, qid)
            ok = self._predicate(value)
            duration = int((time.monotonic() - start) * 1000)
            return CheckResult(
                result="pass" if ok else "fail",
                evidence=f"value={value} predicate={self.threshold_predicate}",
                duration_ms=duration,
            )
        except Exception as e:
            code = getattr(getattr(e, "response", {}).get("Error", {}), "get", lambda _: None)("Code")
            if code == "AccessDeniedException" or "AccessDenied" in type(e).__name__:
                return CheckResult(
                    result="skip",
                    evidence=f"AccessDenied: {e}",
                    duration_ms=int((time.monotonic() - start) * 1000),
                )
            return CheckResult(
                result="skip",
                evidence=f"{type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    def _bind_params(self, target: Target, params: dict, ctx: CheckContext) -> dict:
        return {"target_id": getattr(target, "agent_id", ""), **params}

    def _wait(self, athena: Any, qid: str, timeout_s: int) -> None:
        import time as _time

        deadline = _time.monotonic() + timeout_s
        while _time.monotonic() < deadline:
            resp = athena.get_query_execution(QueryExecutionId=qid)
            state = resp["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED",):
                return
            if state in ("FAILED", "CANCELLED"):
                raise RuntimeError(f"Athena query {qid} ended with state {state}")
            _time.sleep(0.5)  # nosemgrep: arbitrary-sleep - poll interval for async Athena GetQueryExecution; loop is deadline-bounded and exits on terminal state
        raise TimeoutError(f"Athena query {qid} did not finish within {timeout_s}s")

    def _extract_value(self, athena: Any, qid: str) -> Any:
        rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
        if len(rows) < 2:
            return None
        return rows[1]["Data"][0].get("VarCharValue")

    # Comparison operators supported in `threshold_predicate` (e.g. ">= 90").
    _PREDICATE_OPS = {
        ">=": _operator.ge, "<=": _operator.le, "==": _operator.eq,
        "!=": _operator.ne, ">": _operator.gt, "<": _operator.lt,
    }

    def _predicate(self, value: Any) -> bool:
        """Evaluate `<value> <threshold_predicate>` (e.g. "0.9 >= 0.8").

        Parses the operator + numeric threshold explicitly instead of eval() so no
        code execution is possible from the predicate string. Two-character operators
        (>=, <=, ==, !=) are checked before single-character ones.
        """
        if value is None:
            return False
        predicate = (self.threshold_predicate or "").strip()
        try:
            left = float(value)
            for token, op in self._PREDICATE_OPS.items():
                if predicate.startswith(token):
                    return op(left, float(predicate[len(token):].strip()))
            return False
        except (TypeError, ValueError):
            return False


class AwsConfigCheck(Check):
    """Convenience subclass for AWS Config compliance checks.

    Subclass declares `resource_type`; evaluate calls
    config.get_compliance_details_by_resource and normalises findings.
    Requires the target to be an AgentTarget with a primary_resource_id.
    """

    resource_type: str = ""

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        start = time.monotonic()
        if not isinstance(target, AgentTarget) or not target.primary_resource_id:
            return CheckResult(result="skip", evidence="No primary AWS resource on target", duration_ms=0)
        cfg = ctx.client("config")
        resource_type = self.resource_type or target.primary_resource_type or ""
        try:
            resp = cfg.get_compliance_details_by_resource(
                ResourceType=resource_type,
                ResourceId=target.primary_resource_id,
                ComplianceTypes=["NON_COMPLIANT"],
            )
            findings = resp.get("EvaluationResults", [])
            duration = int((time.monotonic() - start) * 1000)
            if not findings:
                return CheckResult(
                    result="pass",
                    evidence=f"0 non-compliant findings on {target.primary_resource_id}",
                    duration_ms=duration,
                )
            rules = ", ".join(
                sorted(
                    {
                        f["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"]
                        for f in findings
                    }
                )
            )
            return CheckResult(
                result="fail",
                evidence=f"{len(findings)} non-compliant findings (rules: {rules})",
                duration_ms=duration,
            )
        except Exception as e:
            code = None
            if hasattr(e, "response"):
                code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "AccessDenied") or "AccessDenied" in str(e):
                return CheckResult(
                    result="skip",
                    evidence="AccessDeniedException on config:GetComplianceDetailsByResource",
                    duration_ms=int((time.monotonic() - start) * 1000),
                )
            return CheckResult(
                result="skip",
                evidence=f"{type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )


class IamPolicyCheck(Check):
    """Convenience subclass for IAM policy checks.

    Resolves attached managed policies + inline statements for the target's
    role_arn; passes them to the subclass-defined _check_policies method.
    """

    def evaluate(self, target: Target, params: dict, ctx: CheckContext) -> CheckResult:
        start = time.monotonic()
        if not isinstance(target, AgentTarget) or not target.role_arn:
            return CheckResult(result="skip", evidence="No role ARN on target", duration_ms=0)
        iam = ctx.client("iam")
        role_name = target.role_arn.rsplit("/", 1)[-1]
        try:
            stmts = self._collect_statements(iam, role_name)
            outcome = self._check_policies(stmts)
            return CheckResult(
                result=outcome.result,
                evidence=outcome.evidence,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return CheckResult(
                result="skip",
                evidence=f"{type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    def _collect_statements(self, iam: Any, role_name: str) -> list[dict]:
        """Return all Statement blocks from attached managed + inline policies."""
        stmts: list[dict] = []

        # Attached managed policies
        paginator = iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                arn = pol["PolicyArn"]
                ver_resp = iam.get_policy(PolicyArn=arn)
                default_ver = ver_resp["Policy"]["DefaultVersionId"]
                doc_resp = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
                doc = doc_resp["PolicyVersion"]["Document"]
                raw = doc.get("Statement", [])
                stmts.extend(raw if isinstance(raw, list) else [raw])

        # Inline policies
        paginator2 = iam.get_paginator("list_role_policies")
        for page in paginator2.paginate(RoleName=role_name):
            for pol_name in page.get("PolicyNames", []):
                doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                doc = doc_resp.get("PolicyDocument", {})
                if isinstance(doc, str):
                    import json

                    doc = json.loads(urllib.parse.unquote(doc))
                raw = doc.get("Statement", [])
                stmts.extend(raw if isinstance(raw, list) else [raw])

        return stmts

    @abc.abstractmethod
    def _check_policies(self, stmts: list[dict]) -> CheckResult: ...


def _register(cls: type[Check]) -> type[Check]:
    """Class decorator — appends cls to the package-level _BUILTIN_CHECKS list.

    Import-time side effect is intentional: each check module decorates its
    classes with @_register so the registry is assembled automatically when
    __init__.py imports the modules.
    """
    from flowamp_compliance_checks import _BUILTIN_CHECKS

    _BUILTIN_CHECKS.append(cls)
    return cls
