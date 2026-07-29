"""Exact Pi-facing request contracts for the durable write lifecycle."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Mapping

from .gateway import RequestContext
from .operations import Approval, canonical_json
from .odoo.bootstrap import request_context_from_mapping
from .write_protocol import approval_from_mapping


class WriteApiError(ValueError):
    pass


WRITE_ACTIONS = frozenset(
    {
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
        "operation.status",
        "operation.result",
        "operation.diagnostics",
        "operation.recover",
    }
)
_FIELDS = {
    "operation.prepare": frozenset(
        {"context", "operation_id", "request_id", "capability_id", "parameters"}
    ),
    "operation.preview": frozenset({"context", "operation_id"}),
    "operation.approve_execute": frozenset(
        {"context", "operation_id", "approval", "reconciliation_only"}
    ),
    "operation.status": frozenset({"context", "operation_id"}),
    "operation.result": frozenset({"context", "operation_id"}),
    "operation.diagnostics": frozenset(
        {"context", "company_id", "operation_id"}
    ),
    "operation.recover": frozenset(
        {
            "context",
            "origin_operation_id",
            "expected_origin_revision",
            "recovery_operation_id",
            "request_id",
            "recovery_date",
            "reason",
            "idempotency_key",
        }
    ),
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True)
class WriteApiRequest:
    action: str
    context: RequestContext
    payload: dict[str, Any]
    approval: Approval | None = None

    @property
    def signed_request(self) -> dict[str, Any]:
        """Return the exact canonical content covered by write-action auth."""

        return json.loads(canonical_json(self.payload))


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise WriteApiError(f"{field} is invalid")
    return value


def _canonical_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WriteApiError(f"{field} must be an object")
    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WriteApiError(f"{field} is not canonical JSON") from exc
    if not isinstance(detached, dict):
        raise WriteApiError(f"{field} must be an object")
    return detached


def parse_write_api_request(action: str, value: Any) -> WriteApiRequest:
    """Parse one exact request without dropping any signed business field."""

    if action not in WRITE_ACTIONS:
        raise WriteApiError("write action is invalid")
    if not isinstance(value, Mapping) or set(value) != _FIELDS[action]:
        raise WriteApiError(f"{action} request fields are invalid")
    try:
        detached = json.loads(canonical_json(dict(value)))
        context = request_context_from_mapping(detached.pop("context"))
    except WriteApiError:
        raise
    except Exception as exc:
        raise WriteApiError("write request context is invalid") from exc
    if not isinstance(detached, dict):
        raise WriteApiError("write request payload is invalid")

    approval = None
    if action == "operation.prepare":
        _identifier(detached["operation_id"], "operation_id")
        _identifier(detached["request_id"], "request_id")
        _identifier(detached["capability_id"], "capability_id")
        detached["parameters"] = _canonical_object(
            detached["parameters"], "parameters"
        )
    elif action == "operation.approve_execute":
        operation_id = _identifier(detached["operation_id"], "operation_id")
        if type(detached["reconciliation_only"]) is not bool:
            raise WriteApiError("reconciliation_only must be a boolean")
        try:
            approval = approval_from_mapping(detached["approval"])
        except Exception as exc:
            raise WriteApiError("approval is invalid") from exc
        if approval.operation_id != operation_id:
            raise WriteApiError("approval operation_id binding mismatch")
    elif action == "operation.recover":
        _identifier(detached["origin_operation_id"], "origin_operation_id")
        _identifier(detached["recovery_operation_id"], "recovery_operation_id")
        _identifier(detached["request_id"], "request_id")
        _identifier(detached["idempotency_key"], "idempotency_key")
        revision = detached["expected_origin_revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise WriteApiError("expected_origin_revision is invalid")
        recovery_date = detached["recovery_date"]
        try:
            parsed_date = date.fromisoformat(recovery_date)
        except (TypeError, ValueError) as exc:
            raise WriteApiError("recovery_date is invalid") from exc
        if parsed_date.isoformat() != recovery_date:
            raise WriteApiError("recovery_date is invalid")
        reason = detached["reason"]
        if (
            not isinstance(reason, str)
            or reason != reason.strip()
            or not reason
            or len(reason) > 512
        ):
            raise WriteApiError("recovery reason is invalid")
    else:
        _identifier(detached["operation_id"], "operation_id")
        if action == "operation.diagnostics":
            company_id = detached["company_id"]
            if (
                isinstance(company_id, bool)
                or not isinstance(company_id, int)
                or company_id <= 0
                or company_id != context.company_id
            ):
                raise WriteApiError(
                    "company_id does not match the authenticated context"
                )

    return WriteApiRequest(
        action=action,
        context=context,
        payload=json.loads(canonical_json(detached)),
        approval=approval,
    )
