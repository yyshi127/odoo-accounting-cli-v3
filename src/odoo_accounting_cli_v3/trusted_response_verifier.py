"""Release-pinned cryptographic verification for trusted broker responses.

The broker has already authenticated the request before dispatch.  This module
independently proves that a successful CLI response belongs to that exact
request, durable operation, database, company, and immutable release route.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

from .auth import authentication_request_digest, write_action_request_digest
from .gateway import (
    AUTH_SIGNATURE_PURPOSE,
    AUTH_SIGNATURE_VERSION,
    WRITE_AUTH_SIGNATURE_PURPOSE,
    WRITE_AUTH_SIGNATURE_VERSION,
    RequestContext,
)
from .odoo.bootstrap import request_context_from_mapping
from .operations import (
    ALLOWED_TRANSITIONS,
    APPROVAL_PURPOSE,
    APPROVAL_SIGNATURE_VERSION,
    Approval,
    Operation,
    State,
    canonical_json,
)
from .receipts import verify_read_receipt
from .trusted_broker import ReleaseResponseVerifier
from .write_protocol import (
    approval_from_mapping,
    operation_from_mapping,
    operation_to_mapping,
)
from .write_receipts import RESULT_BODY_FIELDS, verify_write_audit_receipt


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CHANNELS = frozenset({"staged", "enabled"})
_TERMINAL_ACTIONS = frozenset(
    {"operation.approve_execute", "operation.result"}
)
_NONTERMINAL_ACTIONS = frozenset(
    {
        "operation.prepare",
        "operation.preview",
        "operation.status",
        "operation.recover",
    }
)
_DIAGNOSTIC_ACTIONS = frozenset({"operation.diagnostics"})
_DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1"

_READ_REQUEST_FIELDS = {"capability_id", "context", "parameters"}
_WRITE_REQUEST_FIELDS = {
    "operation.prepare": {
        "capability_id",
        "context",
        "operation_id",
        "parameters",
        "request_id",
    },
    "operation.preview": {"context", "operation_id"},
    "operation.approve_execute": {
        "approval",
        "context",
        "operation_id",
        "reconciliation_only",
    },
    "operation.status": {"context", "operation_id"},
    "operation.result": {"context", "operation_id"},
    "operation.diagnostics": {"company_id", "context", "operation_id"},
    "operation.recover": {
        "context",
        "expected_origin_revision",
        "idempotency_key",
        "origin_operation_id",
        "reason",
        "recovery_date",
        "recovery_operation_id",
        "request_id",
    },
}
_RELEASE_IDENTITY_FIELDS = {
    "commit",
    "manifest_sha256",
    "package_sha256",
    "registry_digest",
    "release",
    "verified",
    "version",
}
_RUNTIME_FIELDS = {
    "capability_channel",
    "database_name",
    "database_uuid",
    "environment",
    "instance_id",
}
_OPERATION_RESPONSE_FIELDS = {
    "capability_id",
    "next_action",
    "operation",
    "operation_digest",
    "operation_id",
    "operation_revision",
    "operation_state",
    "result_available",
}
_PREVIEW_FIELDS = {
    "approval",
    "business_description",
    "capability_id",
    "operation_digest",
    "operation_id",
    "operation_state",
    "parameters",
    "precheck",
    "precheck_digest",
    "precheck_identity",
    "recovery",
    "risk_level",
}
_PRECHECK_IDENTITY_FIELDS = {
    "operation_id",
    "precheck_digest",
    "registry_digest",
    "release_digest",
}
_RECOVERY_EXTRA_FIELDS = {
    "origin_operation_id",
    "origin_operation_revision",
    "recovery_plan_digest",
}
_DIAGNOSTIC_BODY_FIELDS = {
    "audit",
    "failure",
    "odoo_refs",
    "operation",
    "page",
    "receipts",
    "recovery",
    "verification",
}
_DIAGNOSTIC_OPERATION_FIELDS = {
    "allowed_next_states",
    "business_succeeded",
    "capability_id",
    "company_id",
    "operation_id",
    "revision",
    "state",
    "terminal",
}
_DIAGNOSTIC_AUDIT_FIELDS = {
    "chain_verified",
    "event_count",
    "event_types",
    "event_types_offset",
    "event_types_truncated",
    "global_head_hash",
    "last_event_hash",
    "last_event_id",
}
_DIAGNOSTIC_VERIFICATION_FIELDS = {
    "evidence_digest",
    "method",
    "passed",
    "trusted_terminal_result_verified",
}
_DIAGNOSTIC_FAILURE_FIELDS = {
    "evidence_digest",
    "present",
    "result_id",
    "stage",
}
_DIAGNOSTIC_RECOVERY_FIELDS = {
    "attempt_count",
    "available",
    "bound_operation_ids",
    "completion_evidence_digest",
    "completion_receipt_body_digest",
    "completion_receipt_id",
    "latest_attempt_plan_digest",
    "lifecycle_status",
    "plan_digest",
    "plan_status",
    "recovery_capability_id",
    "requires_approval",
}
_DIAGNOSTIC_RECEIPT_FIELDS = {
    "current_candidate_count",
    "database_finalization_digest",
    "difference_digest",
    "durable_final_receipt_body_digest",
    "durable_final_receipt_id",
    "unique_final_receipt_verified",
    "write_audit_head",
    "write_audit_receipt_id",
    "write_audit_result_digest",
}
_DIAGNOSTIC_ODOO_REF_FIELDS = {
    "company_id",
    "model",
    "record_fingerprint",
    "record_id",
    "record_state",
}


class ResponseVerifierConfigurationError(ValueError):
    """A response-verifier dependency is unsafe or incomplete."""


class _ResponseRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseReceiptVerificationConfig:
    """Receipt credentials and route identity for one immutable release."""

    release_digest: str
    registry_digest: str
    capability_channel: str
    read_receipt_key_id: str
    read_receipt_secret: bytes = field(repr=False)
    write_receipt_key_id: str
    write_receipt_secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _digest(self.release_digest)
            or not _digest(self.registry_digest)
            or type(self.capability_channel) is not str
            or self.capability_channel not in _CHANNELS
            or not _key_id(self.read_receipt_key_id)
            or not _key_id(self.write_receipt_key_id)
            or type(self.read_receipt_secret) is not bytes
            or len(self.read_receipt_secret) < 32
            or type(self.write_receipt_secret) is not bytes
            or len(self.write_receipt_secret) < 32
        ):
            raise ResponseVerifierConfigurationError(
                "release receipt verification configuration is invalid"
            )


def _digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _key_id(value: object) -> bool:
    return type(value) is str and _KEY_ID.fullmatch(value) is not None


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise _ResponseRejected("identifier")
    return value


def _text(value: object) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _ResponseRejected("text")
    return value


def _exact_mapping(value: object, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _ResponseRejected("fields")
    return value


def _route_matches(
    release_digest: object,
    registry_digest: object,
    config: ReleaseReceiptVerificationConfig,
) -> bool:
    return (
        _digest(release_digest)
        and _digest(registry_digest)
        and hmac.compare_digest(release_digest, config.release_digest)
        and hmac.compare_digest(registry_digest, config.registry_digest)
    )


def _aware_clock(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise _ResponseRejected("clock")
    return now


def _context(
    action: str, request: Mapping[str, Any]
) -> tuple[RequestContext, dict[str, Any]]:
    context = request_context_from_mapping(request["context"])
    unsigned = {key: value for key, value in request.items() if key != "context"}
    if action == "read":
        if (
            context.auth_signature_version != AUTH_SIGNATURE_VERSION
            or context.auth_signature_purpose != AUTH_SIGNATURE_PURPOSE
            or context.auth_request_digest
            != authentication_request_digest(
                request["capability_id"], request["parameters"]
            )
        ):
            raise _ResponseRejected("read context")
    elif (
        context.auth_signature_version != WRITE_AUTH_SIGNATURE_VERSION
        or context.auth_signature_purpose != WRITE_AUTH_SIGNATURE_PURPOSE
        or context.auth_request_digest
        != write_action_request_digest(action, unsigned)
    ):
        raise _ResponseRejected("write context")
    return context, unsigned


def _operation_context_matches(
    operation: Operation,
    context: RequestContext,
    config: ReleaseReceiptVerificationConfig,
) -> bool:
    return (
        operation.principal == context.principal
        and operation.user_id == context.user_id
        and operation.company_id == context.company_id
        and operation.odoo_instance_id == context.odoo_instance_id
        and operation.database_name == context.database_name
        and operation.database_uuid == context.database_uuid
        and operation.environment == context.environment
        and _route_matches(
            operation.release_digest, operation.registry_digest, config
        )
    )


def _next_action(operation: Operation) -> str:
    if operation.state in {State.PREPARED, State.PRECHECKED}:
        return "operation.preview"
    if operation.state in {
        State.AWAITING_APPROVAL,
        State.APPROVED,
        State.EXECUTING,
        State.VERIFYING,
    }:
        return "operation.approve_execute"
    if operation.state == State.RECOVERED:
        return "operation.diagnostics"
    return "operation.result"


def _terminal(operation: Operation) -> bool:
    return operation.state in {State.COMPLETED, State.FAILED, State.RECOVERED}


def _result_available(operation: Operation) -> bool:
    return operation.state in {State.COMPLETED, State.FAILED}


def _already_consumed_read_receipt(
    _receipt_id: str,
    _request_digest: str,
    _observed_at: datetime,
    _now: datetime,
) -> bool:
    # The Odoo read executor performed the durable one-time consume before the
    # CLI returned this response.  Broker verification is a second independent
    # HMAC/content check and must not consume the business receipt a second time.
    return True


class _BoundResponseVerifier:
    __slots__ = ("_clock", "_config", "_operation_resolver")

    def __init__(
        self,
        config: ReleaseReceiptVerificationConfig,
        operation_resolver: Callable[[str], Operation | None],
        clock: Callable[[], datetime],
    ) -> None:
        self._config = config
        self._operation_resolver = operation_resolver
        self._clock = clock

    def __repr__(self) -> str:
        return "<release-pinned response verifier>"

    def __call__(
        self,
        action: str,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> bool:
        try:
            now = _aware_clock(self._clock)
            if action == "read":
                self._verify_read(response, request, now)
            elif action in _DIAGNOSTIC_ACTIONS:
                self._verify_diagnostics(action, response, request, now)
            elif action in _TERMINAL_ACTIONS:
                self._verify_terminal_write(action, response, request, now)
            elif action in _NONTERMINAL_ACTIONS:
                self._verify_nonterminal_write(action, response, request)
            else:
                return False
        except Exception:
            return False
        return True

    def _operation(self, operation_id: object) -> Operation:
        identifier = _identifier(operation_id)
        operation = self._operation_resolver(identifier)
        if type(operation) is not Operation or operation.operation_id != identifier:
            raise _ResponseRejected("operation")
        operation.assert_integrity()
        _identifier(operation.request_id)
        _identifier(operation.capability_id)
        return operation

    def _optional_operation(self, operation_id: object) -> Operation | None:
        identifier = _identifier(operation_id)
        operation = self._operation_resolver(identifier)
        if operation is None:
            return None
        if type(operation) is not Operation or operation.operation_id != identifier:
            raise _ResponseRejected("operation")
        operation.assert_integrity()
        _identifier(operation.request_id)
        _identifier(operation.capability_id)
        return operation

    def _verify_read(
        self,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
        now: datetime,
    ) -> None:
        _exact_mapping(request, _READ_REQUEST_FIELDS)
        capability_id = _identifier(request["capability_id"])
        if not isinstance(request["parameters"], dict):
            raise _ResponseRejected("parameters")
        context, _unsigned = _context("read", request)

        envelope = _exact_mapping(response, {"command", "data", "ok"})
        if envelope["command"] != "read" or envelope["ok"] is not True:
            raise _ResponseRejected("read envelope")
        data = _exact_mapping(
            envelope["data"],
            {"capability_id", "release_identity", "result", "runtime"},
        )
        if data["capability_id"] != capability_id:
            raise _ResponseRejected("capability")

        identity = _exact_mapping(
            data["release_identity"], _RELEASE_IDENTITY_FIELDS
        )
        if (
            identity["verified"] is not True
            or not _route_matches(
                identity["manifest_sha256"],
                identity["registry_digest"],
                self._config,
            )
            or not _digest(identity["package_sha256"])
        ):
            raise _ResponseRejected("release")
        for field_name in ("commit", "release", "version"):
            _text(identity[field_name])

        runtime = _exact_mapping(data["runtime"], _RUNTIME_FIELDS)
        if runtime != {
            "capability_channel": self._config.capability_channel,
            "database_name": context.database_name,
            "database_uuid": context.database_uuid,
            "environment": context.environment,
            "instance_id": context.odoo_instance_id,
        }:
            raise _ResponseRejected("runtime")

        result = data["result"]
        if not isinstance(result, Mapping) or "receipt" not in result:
            raise _ResponseRejected("result")
        receipt = result["receipt"]
        body = {key: value for key, value in result.items() if key != "receipt"}
        page = body.get("page")
        if not isinstance(page, Mapping):
            raise _ResponseRejected("page")
        record_count = page.get("total_count")
        if type(record_count) is not int or record_count < 0:
            raise _ResponseRejected("record count")
        verify_read_receipt(
            receipt,
            capability_id=capability_id,
            parameters=request["parameters"],
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=self._config.registry_digest,
            release_digest=self._config.release_digest,
            environment=context.environment,
            capability_channel=self._config.capability_channel,
            expected_record_count=record_count,
            now=now,
            consume_receipt=_already_consumed_read_receipt,
            expected_key_id=self._config.read_receipt_key_id,
            secret=self._config.read_receipt_secret,
        )

    def _verify_diagnostics(
        self,
        action: str,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
        now: datetime,
    ) -> None:
        _exact_mapping(request, _WRITE_REQUEST_FIELDS[action])
        context, _unsigned = _context(action, request)
        operation = self._operation(request["operation_id"])
        if (
            type(request["company_id"]) is not int
            or request["company_id"] <= 0
            or request["company_id"] != context.company_id
            or not _operation_context_matches(operation, context, self._config)
        ):
            raise _ResponseRejected("diagnostic request")

        envelope = _exact_mapping(response, {"command", "data", "ok"})
        if envelope["command"] != action or envelope["ok"] is not True:
            raise _ResponseRejected("diagnostic envelope")
        data = _exact_mapping(
            envelope["data"], _DIAGNOSTIC_BODY_FIELDS | {"receipt"}
        )
        body = {field_name: data[field_name] for field_name in _DIAGNOSTIC_BODY_FIELDS}

        operation_view = _exact_mapping(
            body["operation"], _DIAGNOSTIC_OPERATION_FIELDS
        )
        terminal = _terminal(operation)
        expected_next_states = sorted(
            state.value for state in ALLOWED_TRANSITIONS[operation.state]
        )
        if (
            operation_view["operation_id"] != operation.operation_id
            or operation_view["capability_id"] != operation.capability_id
            or operation_view["company_id"] != operation.company_id
            or operation_view["state"] != operation.state.value
            or operation_view["revision"] != operation.revision
            or operation_view["terminal"] is not terminal
            or operation_view["allowed_next_states"] != expected_next_states
            or type(operation_view["business_succeeded"]) is not bool
        ):
            raise _ResponseRejected("diagnostic operation")

        audit = _exact_mapping(body["audit"], _DIAGNOSTIC_AUDIT_FIELDS)
        event_types = audit["event_types"]
        if (
            audit["chain_verified"] is not True
            or type(audit["event_count"]) is not int
            or audit["event_count"] < 0
            or not isinstance(event_types, list)
            or len(event_types) > 1000
            or any(type(item) is not str or not item for item in event_types)
            or type(audit["event_types_offset"]) is not int
            or audit["event_types_offset"] < 0
            or audit["event_types_offset"] + len(event_types)
            != audit["event_count"]
            or audit["event_types_truncated"]
            is not (audit["event_count"] > 1000)
        ):
            raise _ResponseRejected("diagnostic audit")
        if audit["event_count"] == 0:
            if any(
                audit[field_name] is not None
                for field_name in (
                    "last_event_id",
                    "last_event_hash",
                )
            ) or (
                audit["global_head_hash"] is not None
                and not _digest(audit["global_head_hash"])
            ):
                raise _ResponseRejected("diagnostic audit digest")
        else:
            _text(audit["last_event_id"])
            if (
                not _digest(audit["last_event_hash"])
                or not _digest(audit["global_head_hash"])
            ):
                raise _ResponseRejected("diagnostic audit digest")

        verification = _exact_mapping(
            body["verification"], _DIAGNOSTIC_VERIFICATION_FIELDS
        )
        terminal_verified = verification["trusted_terminal_result_verified"]
        if type(terminal_verified) is not bool:
            raise _ResponseRejected("diagnostic verification")
        if terminal_verified:
            if (
                operation.state not in {State.COMPLETED, State.FAILED}
                or type(verification["passed"]) is not bool
                or not _digest(verification["evidence_digest"])
            ):
                raise _ResponseRejected("diagnostic verification")
            _text(verification["method"])
        elif any(
            verification[field_name] is not None
            for field_name in ("passed", "method", "evidence_digest")
        ):
            raise _ResponseRejected("diagnostic verification")
        expected_succeeded = bool(
            operation.state == State.COMPLETED
            and terminal_verified
            and verification["passed"] is True
        )
        if operation_view["business_succeeded"] is not expected_succeeded:
            raise _ResponseRejected("diagnostic business result")

        failure = _exact_mapping(body["failure"], _DIAGNOSTIC_FAILURE_FIELDS)
        if failure["present"] is not (operation.state == State.FAILED):
            raise _ResponseRejected("diagnostic failure")
        if failure["present"]:
            if failure["stage"] not in {
                "execute",
                "verify",
                "recover",
                "unknown",
            } or not _digest(failure["evidence_digest"]):
                raise _ResponseRejected("diagnostic failure")
            _text(failure["result_id"])
        elif any(
            failure[field_name] is not None
            for field_name in ("stage", "result_id", "evidence_digest")
        ):
            raise _ResponseRejected("diagnostic failure")

        recovery = _exact_mapping(
            body["recovery"], _DIAGNOSTIC_RECOVERY_FIELDS
        )
        if (
            recovery["lifecycle_status"]
            not in {
                "in_progress",
                "recovered_verified",
                "prepared_separately",
                "not_started",
            }
            or type(recovery["available"]) is not bool
            or type(recovery["attempt_count"]) is not int
            or recovery["attempt_count"] < 0
            or not isinstance(recovery["bound_operation_ids"], list)
            or recovery["bound_operation_ids"]
            != sorted(set(recovery["bound_operation_ids"]))
        ):
            raise _ResponseRejected("diagnostic recovery")
        if (
            recovery["lifecycle_status"] == "recovered_verified"
        ) is not (operation.state == State.RECOVERED):
            raise _ResponseRejected("diagnostic recovered state")
        completion_fields = (
            "completion_evidence_digest",
            "completion_receipt_body_digest",
            "completion_receipt_id",
        )
        if operation.state == State.RECOVERED:
            if (
                not _digest(recovery["completion_evidence_digest"])
                or not _digest(
                    recovery["completion_receipt_body_digest"]
                )
            ):
                raise _ResponseRejected(
                    "diagnostic recovery completion digest"
                )
            _identifier(recovery["completion_receipt_id"])
        elif any(
            recovery[field_name] is not None
            for field_name in completion_fields
        ):
            raise _ResponseRejected("diagnostic recovery completion")
        for bound_operation_id in recovery["bound_operation_ids"]:
            _identifier(bound_operation_id)
        for field_name in ("plan_digest", "latest_attempt_plan_digest"):
            value = recovery[field_name]
            if value is not None and not _digest(value):
                raise _ResponseRejected("diagnostic recovery digest")
        for field_name in ("plan_status", "recovery_capability_id"):
            value = recovery[field_name]
            if value is not None:
                _text(value)
        if (
            recovery["requires_approval"] is not None
            and type(recovery["requires_approval"]) is not bool
        ):
            raise _ResponseRejected("diagnostic recovery approval")

        refs = body["odoo_refs"]
        if not isinstance(refs, list) or len(refs) > 1000:
            raise _ResponseRejected("diagnostic Odoo references")
        for raw_ref in refs:
            ref = _exact_mapping(raw_ref, _DIAGNOSTIC_ODOO_REF_FIELDS)
            if (
                type(ref["record_id"]) is not int
                or ref["record_id"] <= 0
                or ref["company_id"] != operation.company_id
                or not _digest(ref["record_fingerprint"])
            ):
                raise _ResponseRejected("diagnostic Odoo reference")
            _text(ref["model"])
            _text(ref["record_state"])

        receipts = _exact_mapping(
            body["receipts"], _DIAGNOSTIC_RECEIPT_FIELDS
        )
        if (
            type(receipts["unique_final_receipt_verified"]) is not bool
            or receipts["unique_final_receipt_verified"] is not terminal_verified
            or type(receipts["current_candidate_count"]) is not int
            or receipts["current_candidate_count"] < 0
        ):
            raise _ResponseRejected("diagnostic receipts")
        receipt_optional_fields = _DIAGNOSTIC_RECEIPT_FIELDS - {
            "unique_final_receipt_verified",
            "current_candidate_count",
        }
        if terminal_verified:
            if receipts["current_candidate_count"] != 1:
                raise _ResponseRejected("diagnostic receipts")
            for field_name in receipt_optional_fields:
                value = receipts[field_name]
                if field_name in {
                    "durable_final_receipt_id",
                    "write_audit_receipt_id",
                }:
                    _text(value)
                elif (
                    field_name == "database_finalization_digest"
                    and value is None
                ):
                    continue
                elif not _digest(value):
                    raise _ResponseRejected("diagnostic receipt digest")
        elif any(receipts[field_name] is not None for field_name in receipt_optional_fields):
            raise _ResponseRejected("diagnostic receipts")

        page = _exact_mapping(body["page"], {"count", "total_count"})
        if page["count"] != 1 or page["total_count"] != 1:
            raise _ResponseRejected("diagnostic page")

        verify_read_receipt(
            data["receipt"],
            capability_id=_DIAGNOSTICS_CAPABILITY_ID,
            parameters={
                "company_id": request["company_id"],
                "operation_id": request["operation_id"],
            },
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=self._config.registry_digest,
            release_digest=self._config.release_digest,
            environment=context.environment,
            capability_channel=self._config.capability_channel,
            expected_record_count=1,
            now=now,
            consume_receipt=_already_consumed_read_receipt,
            expected_key_id=self._config.read_receipt_key_id,
            secret=self._config.read_receipt_secret,
        )

    def _request_operation(
        self,
        action: str,
        request: Mapping[str, Any],
    ) -> tuple[RequestContext, dict[str, Any], Operation]:
        _exact_mapping(request, _WRITE_REQUEST_FIELDS[action])
        context, unsigned = _context(action, request)
        operation = self._operation(request["operation_id"])
        if not _operation_context_matches(operation, context, self._config):
            raise _ResponseRejected("operation context")
        return context, unsigned, operation

    @staticmethod
    def _approval_matches_operation(
        approval: Approval, operation: Operation
    ) -> bool:
        return (
            approval.signature_version == APPROVAL_SIGNATURE_VERSION
            and approval.signature_purpose == APPROVAL_PURPOSE
            and _key_id(approval.key_id)
            and _digest(approval.signature)
            and isinstance(approval.nonce, str)
            and bool(approval.nonce)
            and hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest()
            == operation.approval_nonce_digest
            and approval.operation_id == operation.operation_id
            and approval.request_id == operation.request_id
            and approval.operation_digest == operation.digest
            and approval.precheck_digest == operation.precheck_digest
            and approval.user_id == operation.user_id
            and approval.company_id == operation.company_id
            and approval.operation_revision == operation.approval_revision
            and approval.approver_user_id == operation.approver_user_id
            and approval.issued_at == operation.approval_issued_at
            and approval.expires_at == operation.approval_expires_at
            and approval.signature == operation.approval_signature
        )

    def _verify_terminal_write(
        self,
        action: str,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
        now: datetime,
    ) -> None:
        _context_value, _unsigned, operation = self._request_operation(
            action, request
        )
        if not _result_available(operation) or any(
            value is None
            for value in (
                operation.approval_signature,
                operation.approval_nonce_digest,
                operation.approval_issued_at,
                operation.approval_expires_at,
                operation.approval_revision,
                operation.approver_user_id,
            )
        ):
            raise _ResponseRejected("terminal operation")
        if action == "operation.approve_execute":
            if type(request["reconciliation_only"]) is not bool:
                raise _ResponseRejected("reconciliation mode")
            approval = approval_from_mapping(request["approval"])
            if not self._approval_matches_operation(approval, operation):
                raise _ResponseRejected("approval")

        envelope = _exact_mapping(
            response, {"business_succeeded", "command", "data", "ok"}
        )
        if (
            envelope["command"] != action
            or envelope["ok"] is not True
            or type(envelope["business_succeeded"]) is not bool
        ):
            raise _ResponseRejected("write envelope")
        data = _exact_mapping(
            envelope["data"], set(RESULT_BODY_FIELDS) | {"audit_receipt"}
        )
        result_body = {field_name: data[field_name] for field_name in RESULT_BODY_FIELDS}
        if (
            data["operation_id"] != operation.operation_id
            or data["operation_state"] != operation.state.value
        ):
            raise _ResponseRejected("terminal result")
        succeeded = (
            operation.state == State.COMPLETED
            and isinstance(data["verification"], Mapping)
            and data["verification"].get("passed") is True
        )
        if envelope["business_succeeded"] is not succeeded:
            raise _ResponseRejected("business result")

        receipt = data["audit_receipt"]
        if not isinstance(receipt, dict):
            raise _ResponseRejected("audit receipt")
        verify_write_audit_receipt(
            receipt,
            request_id=operation.request_id,
            operation_id=operation.operation_id,
            capability_id=operation.capability_id,
            principal=operation.principal,
            odoo_instance_id=operation.odoo_instance_id,
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            user_id=operation.user_id,
            approver_user_id=operation.approver_user_id,
            company_id=operation.company_id,
            environment=operation.environment,
            capability_channel=self._config.capability_channel,
            request_digest=authentication_request_digest(
                operation.capability_id, operation.parameters
            ),
            operation_digest=operation.digest,
            approval_digest=operation.approval_signature,
            registry_digest=self._config.registry_digest,
            release_digest=self._config.release_digest,
            audit_head=receipt.get("audit_head"),
            result_body=result_body,
            now=now,
            expected_signing_key_id=self._config.write_receipt_key_id,
            secret=self._config.write_receipt_secret,
        )

    def _verify_operation_mapping(
        self,
        data: Mapping[str, Any],
        operation: Operation,
        *,
        expected_next_action: str,
    ) -> None:
        returned = operation_from_mapping(data["operation"])
        if (
            returned != operation
            or dict(data["operation"]) != operation_to_mapping(operation)
            or data["operation_id"] != operation.operation_id
            or data["operation_state"] != operation.state.value
            or data["capability_id"] != operation.capability_id
            or data["operation_revision"] != operation.revision
            or data["operation_digest"] != operation.digest
            or data["result_available"] is not _result_available(operation)
            or data["next_action"] != expected_next_action
        ):
            raise _ResponseRejected("operation response")

    def _verify_nonterminal_write(
        self,
        action: str,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> None:
        _exact_mapping(request, _WRITE_REQUEST_FIELDS[action])
        context, _unsigned = _context(action, request)
        envelope = _exact_mapping(response, {"command", "data", "ok"})
        if envelope["command"] != action or envelope["ok"] is not True:
            raise _ResponseRejected("write envelope")
        if action == "operation.preview":
            self._verify_preview(envelope["data"], request, context)
        elif action == "operation.prepare":
            self._verify_prepare(envelope["data"], request, context)
        elif action == "operation.status":
            self._verify_status(envelope["data"], request, context)
        elif action == "operation.recover":
            self._verify_recover(envelope["data"], request, context)
        else:  # pragma: no cover - guarded by the public action set
            raise _ResponseRejected("action")

    def _verify_prepare(
        self,
        raw_data: object,
        request: Mapping[str, Any],
        context: RequestContext,
    ) -> None:
        data = _exact_mapping(raw_data, _OPERATION_RESPONSE_FIELDS)
        _identifier(request["capability_id"])
        _identifier(request["request_id"])
        operation = self._operation(data["operation_id"])
        if (
            not _operation_context_matches(operation, context, self._config)
            or operation.capability_id != request["capability_id"]
            or operation.parameters != request["parameters"]
            or not isinstance(request["parameters"], dict)
            or operation.idempotency_key
            != request["parameters"].get("idempotency_key")
        ):
            raise _ResponseRejected("prepared operation")
        requested_id = _identifier(request["operation_id"])
        if operation.operation_id == requested_id:
            if operation.request_id != request["request_id"]:
                raise _ResponseRejected("request")
        elif self._optional_operation(requested_id) is not None:
            raise _ResponseRejected("idempotency")
        self._verify_operation_mapping(
            data, operation, expected_next_action="operation.preview"
        )

    def _verify_status(
        self,
        raw_data: object,
        request: Mapping[str, Any],
        context: RequestContext,
    ) -> None:
        data = _exact_mapping(raw_data, _OPERATION_RESPONSE_FIELDS)
        operation = self._operation(request["operation_id"])
        if (
            data["operation_id"] != operation.operation_id
            or not _operation_context_matches(operation, context, self._config)
        ):
            raise _ResponseRejected("status")
        self._verify_operation_mapping(
            data, operation, expected_next_action=_next_action(operation)
        )

    def _verify_preview(
        self,
        raw_data: object,
        request: Mapping[str, Any],
        context: RequestContext,
    ) -> None:
        data = _exact_mapping(raw_data, _PREVIEW_FIELDS)
        operation = self._operation(request["operation_id"])
        identity = _exact_mapping(
            data["precheck_identity"], _PRECHECK_IDENTITY_FIELDS
        )
        try:
            observed_precheck = hashlib.sha256(
                canonical_json(data["precheck"])
            ).hexdigest()
        except (TypeError, ValueError, UnicodeError) as exc:
            raise _ResponseRejected("precheck") from exc
        if (
            operation.state != State.AWAITING_APPROVAL
            or not _operation_context_matches(operation, context, self._config)
            or data["operation_id"] != operation.operation_id
            or data["operation_state"] != operation.state.value
            or data["capability_id"] != operation.capability_id
            or data["parameters"] != operation.parameters
            or data["operation_digest"] != operation.digest
            or data["precheck_digest"] != operation.precheck_digest
            or observed_precheck != operation.precheck_digest
            or identity
            != {
                "operation_id": operation.operation_id,
                "precheck_digest": operation.precheck_digest,
                "registry_digest": operation.registry_digest,
                "release_digest": operation.release_digest,
            }
            or not isinstance(data["business_description"], str)
            or not data["business_description"].strip()
            or not isinstance(data["approval"], Mapping)
            or not isinstance(data["recovery"], Mapping)
            or not isinstance(data["risk_level"], str)
            or not data["risk_level"].strip()
        ):
            raise _ResponseRejected("preview")

    def _verify_recover(
        self,
        raw_data: object,
        request: Mapping[str, Any],
        context: RequestContext,
    ) -> None:
        data = _exact_mapping(
            raw_data, _OPERATION_RESPONSE_FIELDS | _RECOVERY_EXTRA_FIELDS
        )
        _identifier(request["request_id"])
        _identifier(request["idempotency_key"])
        if (
            type(request["expected_origin_revision"]) is not int
            or request["expected_origin_revision"] < 0
        ):
            raise _ResponseRejected("origin revision")
        _text(request["recovery_date"])
        _text(request["reason"])
        origin = self._operation(request["origin_operation_id"])
        recovery = self._operation(data["operation_id"])
        expected_parameters = {
            "company_id",
            "expected_recovery_plan_digest",
            "idempotency_key",
            "origin_operation_id",
            "reason",
            "recovery_date",
        }
        parameters = recovery.parameters
        if (
            origin.state not in {State.COMPLETED, State.FAILED}
            or request["expected_origin_revision"] != origin.revision
            or not _operation_context_matches(origin, context, self._config)
            or not _operation_context_matches(recovery, context, self._config)
            or recovery.capability_id != "acct.recovery.execute.v1"
            or set(parameters) != expected_parameters
            or parameters["company_id"] != context.company_id
            or parameters["origin_operation_id"] != origin.operation_id
            or parameters["recovery_date"] != request["recovery_date"]
            or parameters["reason"] != request["reason"]
            or parameters["idempotency_key"] != request["idempotency_key"]
            or recovery.idempotency_key != request["idempotency_key"]
            or not _digest(parameters["expected_recovery_plan_digest"])
            or data["origin_operation_id"] != origin.operation_id
            or data["origin_operation_revision"] != origin.revision
            or data["recovery_plan_digest"]
            != parameters["expected_recovery_plan_digest"]
        ):
            raise _ResponseRejected("recovery")
        requested_id = _identifier(request["recovery_operation_id"])
        if recovery.operation_id == requested_id:
            if recovery.request_id != request["request_id"]:
                raise _ResponseRejected("request")
        elif self._optional_operation(requested_id) is not None:
            raise _ResponseRejected("idempotency")
        self._verify_operation_mapping(
            data, recovery, expected_next_action="operation.preview"
        )


def build_release_response_verifier(
    config: ReleaseReceiptVerificationConfig,
    *,
    operation_resolver: Callable[[str], Operation | None],
    utc_clock: Callable[[], datetime],
) -> ReleaseResponseVerifier:
    """Build the broker verifier for exactly one release/registry route."""

    if (
        type(config) is not ReleaseReceiptVerificationConfig
        or not callable(operation_resolver)
        or not callable(utc_clock)
    ):
        raise ResponseVerifierConfigurationError(
            "response verifier dependencies are invalid"
        )
    return ReleaseResponseVerifier(
        release_digest=config.release_digest,
        registry_digest=config.registry_digest,
        verify=_BoundResponseVerifier(config, operation_resolver, utc_clock),
    )


def build_release_response_verifier_resolver(
    configs: Iterable[ReleaseReceiptVerificationConfig],
    *,
    operation_resolver: Callable[[str], Operation | None],
    utc_clock: Callable[[], datetime],
) -> Callable[[str, str], ReleaseResponseVerifier | None]:
    """Build a no-fallback resolver for current and historical release routes."""

    if not callable(operation_resolver) or not callable(utc_clock):
        raise ResponseVerifierConfigurationError(
            "response verifier dependencies are invalid"
        )
    try:
        config_items = tuple(configs)
    except TypeError:
        raise ResponseVerifierConfigurationError(
            "response verifier release configurations are invalid"
        ) from None
    if not config_items:
        raise ResponseVerifierConfigurationError(
            "at least one release response verifier is required"
        )
    routes: dict[tuple[str, str], ReleaseResponseVerifier] = {}
    for config in config_items:
        verifier = build_release_response_verifier(
            config,
            operation_resolver=operation_resolver,
            utc_clock=utc_clock,
        )
        route = (config.release_digest, config.registry_digest)
        if route in routes:
            raise ResponseVerifierConfigurationError(
                "duplicate release response verifier route"
            )
        routes[route] = verifier

    def resolve(
        release_digest: str, registry_digest: str
    ) -> ReleaseResponseVerifier | None:
        if not _digest(release_digest) or not _digest(registry_digest):
            return None
        return routes.get((release_digest, registry_digest))

    return resolve


__all__ = [
    "ReleaseReceiptVerificationConfig",
    "ResponseVerifierConfigurationError",
    "build_release_response_verifier",
    "build_release_response_verifier_resolver",
]
