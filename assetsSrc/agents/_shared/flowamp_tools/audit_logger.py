# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AuditLogger — emit structured JSON audit entries via the standard logger.

Low-level transaction breadcrumbs (e.g. AOP condition-evaluation detail) are
written to whatever CloudWatch log group the host — a Lambda or an AgentCore
runtime — is already configured to log to. No dedicated log group is created,
so no ``logs:*`` IAM beyond the host's own logging is required.

Durable, queryable audit data belongs in the EventTable (see
``flowamp_tools.audit``); this class is only for breadcrumbs in the host's
normal log stream.

Design constraints:
- ``log`` must never raise — audit failures are swallowed and re-logged via the
  standard logger.
"""
import json
import logging
from datetime import datetime, timezone

_DEFAULT_LOGGER = "flowamp.audit"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLogger:
    """Emit structured JSON audit records to the host's standard logger.

    Args:
        name: Optional logger name. Retained for backwards compatibility with
            call sites that previously passed a CloudWatch log-group name; it now
            only selects the Python logger, never a CloudWatch group.
    """

    def __init__(self, name: str | None = None) -> None:
        self._logger = logging.getLogger(name or _DEFAULT_LOGGER)

    def log(self, entry: dict) -> None:
        """Emit a structured audit record.

        Enriches the entry with a timestamp if absent. Never raises — all
        exceptions are swallowed and re-logged via the standard logger.
        """
        try:
            if "timestamp" not in entry:
                entry = {**entry, "timestamp": _now_iso()}
            self._logger.info("audit %s", json.dumps(entry, default=str))
        except Exception as exc:  # noqa: BLE001 — audit must never fail the caller
            logging.getLogger(_DEFAULT_LOGGER).error("AuditLogger.log failed: %s", exc)
