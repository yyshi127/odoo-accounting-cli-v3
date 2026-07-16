"""Exact JSON mappings for durable write operations and signed evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from .operations import (
    Approval,
    Operation,
    ResultKind,
    State,
    TrustedResult,
    canonical_json,
)


_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_OPERATION_FIELDS = {
    "operation_id",
    "request_id",
    "capability_id",
    "parameters",
    "principal",
    "user_id",
    "company_id",
    "idempotency_key",
    "odoo_instance_id",
    "database_name",
    "database_uuid",
    "environment",
    "registry_digest",
    "release_digest",
    "digest",
    "protocol_version",
    "precheck_digest",
    "state",
    "revision",
    "approval",
    "execution_result_digest",
    "verification_result_digest",
}
_OPERATION_APPROVAL_FIELDS = {
    "signature",
    "nonce_digest",
    "issued_at",
    "expires_at",
    "revision",
    "approver_user_id",
}
_APPROVAL_FIELDS = {
    "operation_id",
    "request_id",
    "operation_digest",
    "precheck_digest",
    "user_id",
    "company_id",
    "operation_revision",
    "approver_user_id",
    "nonce",
    "issued_at",
    "expires_at",
    "signature_version",
    "signature_purpose",
    "key_id",
    "signature",
}
_TRUSTED_RESULT_FIELDS = {
    "kind",
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_state_digest",
    "operation_revision",
    "company_id",
    "issuer",
    "key_id",
    "succeeded",
    "evidence_digest",
    "prior_evidence_digest",
    "issued_at",
    "signature_version",
    "signature_purpose",
    "signature",
}


def approved_write_authentication_parameters(
    parameters: Mapping[str, Any], reconciliation_only: bool
) -> dict[str, Any]:
    """Bind the Odoo child authority to both content and execution permission."""

    if not isinstance(parameters, Mapping) or type(reconciliation_only) is not bool:
        raise ValueError("approved write authentication content is invalid")
    try:
        detached = json.loads(canonical_json(dict(parameters)))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("approved write authentication content is invalid") from exc
    return {
        "parameters": detached,
        "reconciliation_only": reconciliation_only,
    }


def _mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("protocol timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def operation_to_mapping(operation: Operation) -> dict[str, Any]:
    if not isinstance(operation, Operation):
        raise ValueError("operation is invalid")
    operation.assert_integrity()
    approval = None
    if operation.approval_signature is not None:
        approval = {
            "signature": operation.approval_signature,
            "nonce_digest": operation.approval_nonce_digest,
            "issued_at": _utc(operation.approval_issued_at),
            "expires_at": _utc(operation.approval_expires_at),
            "revision": operation.approval_revision,
            "approver_user_id": operation.approver_user_id,
        }
    return {
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "capability_id": operation.capability_id,
        "parameters": operation.parameters,
        "principal": operation.principal,
        "user_id": operation.user_id,
        "company_id": operation.company_id,
        "idempotency_key": operation.idempotency_key,
        "odoo_instance_id": operation.odoo_instance_id,
        "database_name": operation.database_name,
        "database_uuid": operation.database_uuid,
        "environment": operation.environment,
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
        "digest": operation.digest,
        "protocol_version": operation.protocol_version,
        "precheck_digest": operation.precheck_digest,
        "state": operation.state.value,
        "revision": operation.revision,
        "approval": approval,
        "execution_result_digest": operation.execution_result_digest,
        "verification_result_digest": operation.verification_result_digest,
    }


def operation_from_mapping(value: Any) -> Operation:
    item = _mapping(value, _OPERATION_FIELDS, "operation")
    approval_value = item["approval"]
    if approval_value is None:
        approval = {
            "approval_signature": None,
            "approval_nonce_digest": None,
            "approval_issued_at": None,
            "approval_expires_at": None,
            "approval_revision": None,
            "approver_user_id": None,
        }
    else:
        raw = _mapping(
            approval_value, _OPERATION_APPROVAL_FIELDS, "operation approval"
        )
        approval = {
            "approval_signature": raw["signature"],
            "approval_nonce_digest": raw["nonce_digest"],
            "approval_issued_at": _timestamp(raw["issued_at"], "approval issued_at"),
            "approval_expires_at": _timestamp(raw["expires_at"], "approval expires_at"),
            "approval_revision": raw["revision"],
            "approver_user_id": raw["approver_user_id"],
        }
    parameters = item["parameters"]
    if not isinstance(parameters, dict):
        raise ValueError("operation parameters must be an object")
    try:
        state = State(item["state"])
    except (TypeError, ValueError) as exc:
        raise ValueError("operation state is invalid") from exc
    operation = Operation(
        operation_id=item["operation_id"],
        request_id=item["request_id"],
        capability_id=item["capability_id"],
        parameters_json=canonical_json(parameters).decode("utf-8"),
        principal=item["principal"],
        user_id=item["user_id"],
        company_id=item["company_id"],
        idempotency_key=item["idempotency_key"],
        odoo_instance_id=item["odoo_instance_id"],
        database_name=item["database_name"],
        database_uuid=item["database_uuid"],
        environment=item["environment"],
        registry_digest=item["registry_digest"],
        release_digest=item["release_digest"],
        digest=item["digest"],
        protocol_version=item["protocol_version"],
        precheck_digest=item["precheck_digest"],
        state=state,
        revision=item["revision"],
        execution_result_digest=item["execution_result_digest"],
        verification_result_digest=item["verification_result_digest"],
        **approval,
    )
    operation.assert_integrity()
    return operation


def approval_to_mapping(approval: Approval) -> dict[str, Any]:
    if not isinstance(approval, Approval):
        raise ValueError("approval is invalid")
    return {
        "operation_id": approval.operation_id,
        "request_id": approval.request_id,
        "operation_digest": approval.operation_digest,
        "precheck_digest": approval.precheck_digest,
        "user_id": approval.user_id,
        "company_id": approval.company_id,
        "operation_revision": approval.operation_revision,
        "approver_user_id": approval.approver_user_id,
        "nonce": approval.nonce,
        "issued_at": _utc(approval.issued_at),
        "expires_at": _utc(approval.expires_at),
        "signature_version": approval.signature_version,
        "signature_purpose": approval.signature_purpose,
        "key_id": approval.key_id,
        "signature": approval.signature,
    }


def approval_from_mapping(value: Any) -> Approval:
    item = _mapping(value, _APPROVAL_FIELDS, "approval")
    return Approval(
        operation_id=item["operation_id"],
        request_id=item["request_id"],
        operation_digest=item["operation_digest"],
        precheck_digest=item["precheck_digest"],
        user_id=item["user_id"],
        company_id=item["company_id"],
        operation_revision=item["operation_revision"],
        approver_user_id=item["approver_user_id"],
        nonce=item["nonce"],
        issued_at=_timestamp(item["issued_at"], "approval issued_at"),
        expires_at=_timestamp(item["expires_at"], "approval expires_at"),
        signature_version=item["signature_version"],
        signature_purpose=item["signature_purpose"],
        key_id=item["key_id"],
        signature=item["signature"],
    )


def trusted_result_to_mapping(result: TrustedResult) -> dict[str, Any]:
    if not isinstance(result, TrustedResult):
        raise ValueError("trusted result is invalid")
    return {
        "kind": result.kind.value,
        "operation_id": result.operation_id,
        "request_id": result.request_id,
        "operation_digest": result.operation_digest,
        "operation_state_digest": result.operation_state_digest,
        "operation_revision": result.operation_revision,
        "company_id": result.company_id,
        "issuer": result.issuer,
        "key_id": result.key_id,
        "succeeded": result.succeeded,
        "evidence_digest": result.evidence_digest,
        "prior_evidence_digest": result.prior_evidence_digest,
        "issued_at": _utc(result.issued_at),
        "signature_version": result.signature_version,
        "signature_purpose": result.signature_purpose,
        "signature": result.signature,
    }


def trusted_result_from_mapping(value: Any) -> TrustedResult:
    item = _mapping(value, _TRUSTED_RESULT_FIELDS, "trusted result")
    try:
        kind = ResultKind(item["kind"])
    except (TypeError, ValueError) as exc:
        raise ValueError("trusted result kind is invalid") from exc
    return TrustedResult(
        kind=kind,
        operation_id=item["operation_id"],
        request_id=item["request_id"],
        operation_digest=item["operation_digest"],
        operation_state_digest=item["operation_state_digest"],
        operation_revision=item["operation_revision"],
        company_id=item["company_id"],
        issuer=item["issuer"],
        key_id=item["key_id"],
        succeeded=item["succeeded"],
        evidence_digest=item["evidence_digest"],
        prior_evidence_digest=item["prior_evidence_digest"],
        issued_at=_timestamp(item["issued_at"], "trusted result issued_at"),
        signature_version=item["signature_version"],
        signature_purpose=item["signature_purpose"],
        signature=item["signature"],
    )
