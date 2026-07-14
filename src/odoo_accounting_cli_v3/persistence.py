"""Durable SQLite primitives for replay, operations, idempotency, and audit.

This module deliberately does not execute Odoo or implement gateway policy.  It
provides the transactional storage invariants those layers need.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .operations import (
    ALLOWED_TRANSITIONS,
    Approval,
    ConcurrentUpdate as OperationConcurrentUpdate,
    Operation,
    State,
    approve_operation,
    begin_execution as validate_begin_execution,
    canonical_json,
)
from .receipts import (
    READ_RECEIPT_PURPOSE,
    SIGNATURE_VERSION as READ_RECEIPT_SIGNATURE_VERSION,
    ReceiptError,
    valid_read_runtime_binding,
    verify_read_receipt,
)


LEGACY_SCHEMA_VERSION = 1
SCHEMA_VERSION = 2
GENESIS_HASH = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_DIAGNOSTIC_AUDIT_PAYLOAD_BYTES = 64 * 1024
_RECEIPT_KEY_ID_META = "receipt_verifier_key_id"
_RECEIPT_KEY_DIGEST_META = "receipt_verifier_secret_sha256"

_READ_RECEIPT_FIELDS = {
    "capability_id",
    "capability_channel",
    "company_id",
    "database_name",
    "database_uuid",
    "id",
    "environment",
    "observed_at",
    "odoo_instance_id",
    "record_count",
    "registry_digest",
    "release_digest",
    "request_digest",
    "result_digest",
    "signature",
    "signature_key_id",
    "signature_purpose",
    "signature_version",
    "user_id",
}
_READ_AUDIT_FIELDS = {
    "auth_token_id",
    "capability_id",
    "company_id",
    "environment",
    "capability_channel",
    "database_name",
    "database_uuid",
    "odoo_instance_id",
    "principal",
    "receipt",
    "receipt_id",
    "registry_digest",
    "release_digest",
    "request_digest",
    "result_digest",
    "user_id",
}


class PersistenceError(ValueError):
    pass


class ReplayRejected(PersistenceError):
    pass


class PersistenceIntegrityError(PersistenceError):
    pass


class ConcurrentUpdate(PersistenceError):
    pass


class IdempotencyConflict(PersistenceError):
    pass


class OperationNotFound(PersistenceError):
    pass


@dataclass(frozen=True)
class StoredAuditEvent:
    sequence: int
    event_id: str
    event_type: str
    operation_id: str | None
    occurred_at: datetime
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class StoredApprovalRecord:
    operation_id: str
    request_id: str
    operation_digest: str
    operation_revision: int
    requester_user_id: int
    company_id: int
    approver_user_id: int
    nonce_digest: str
    signature_version: int
    signature_purpose: str
    key_id: str | None
    issued_at: datetime
    expires_at: datetime
    approval_signature: str
    accepted_at: datetime | None
    audit_event_id: str | None
    record_origin: str
    record_hash: str


@dataclass(frozen=True)
class ApprovalAcceptance:
    operation: Operation
    approval_record: StoredApprovalRecord
    audit_event: StoredAuditEvent


@dataclass(frozen=True)
class ExecutionAcceptance:
    operation: Operation
    approval_record: StoredApprovalRecord
    audit_event: StoredAuditEvent


_OPERATION_COLUMNS = (
    "operation_id",
    "request_id",
    "capability_id",
    "parameters_json",
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
    "state",
    "revision",
    "approval_signature",
    "approval_nonce_digest",
    "approval_issued_at",
    "approval_expires_at",
    "approval_revision",
    "approver_user_id",
    "execution_result_digest",
    "verification_result_digest",
)

_IMMUTABLE_OPERATION_FIELDS = _OPERATION_COLUMNS[:15]

_EXPECTED_COLUMNS_V1 = {
    "schema_meta": ("key", "value"),
    "consumed_auth_tokens": ("token_id", "request_digest", "expires_at", "consumed_at"),
    "consumed_receipts": ("receipt_id", "request_digest", "observed_at", "consumed_at"),
    "operations": (*_OPERATION_COLUMNS, "record_hash"),
    "idempotency_keys": (
        "odoo_instance_id",
        "database_uuid",
        "environment",
        "company_id",
        "capability_id",
        "scope",
        "idempotency_key",
        "operation_id",
        "operation_digest",
    ),
    "audit_events": (
        "sequence",
        "event_id",
        "event_type",
        "operation_id",
        "occurred_at",
        "payload_json",
        "previous_hash",
        "event_hash",
    ),
}

_SCHEMA_V1 = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS consumed_auth_tokens (
        token_id TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
        expires_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS consumed_receipts (
        receipt_id TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
        observed_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        principal TEXT NOT NULL,
        user_id INTEGER NOT NULL CHECK(user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        idempotency_key TEXT NOT NULL,
        odoo_instance_id TEXT NOT NULL,
        database_name TEXT NOT NULL,
        database_uuid TEXT NOT NULL,
        environment TEXT NOT NULL CHECK(environment IN ('test', 'sandbox', 'production')),
        registry_digest TEXT NOT NULL CHECK(length(registry_digest) = 64),
        release_digest TEXT NOT NULL CHECK(length(release_digest) = 64),
        digest TEXT NOT NULL CHECK(length(digest) = 64),
        state TEXT NOT NULL CHECK(state IN (
            'prepared', 'prechecked', 'awaiting_approval', 'approved', 'executing',
            'verifying', 'completed', 'failed', 'recovering', 'recovered'
        )),
        revision INTEGER NOT NULL CHECK(revision >= 0),
        approval_signature TEXT,
        approval_nonce_digest TEXT,
        approval_issued_at TEXT,
        approval_expires_at TEXT,
        approval_revision INTEGER CHECK(approval_revision IS NULL OR approval_revision >= 0),
        approver_user_id INTEGER CHECK(approver_user_id IS NULL OR approver_user_id > 0),
        execution_result_digest TEXT,
        verification_result_digest TEXT,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency_keys (
        odoo_instance_id TEXT NOT NULL,
        database_uuid TEXT NOT NULL,
        environment TEXT NOT NULL,
        company_id INTEGER NOT NULL,
        capability_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation_id TEXT NOT NULL UNIQUE,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        PRIMARY KEY (
            odoo_instance_id, database_uuid, environment, company_id, capability_id, scope
        ),
        UNIQUE (
            odoo_instance_id, database_uuid, environment, company_id,
            capability_id, idempotency_key
        ),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        operation_id TEXT,
        occurred_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
        event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash) = 64)
    ) STRICT
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events are append-only');
    END
    """,
)

_APPROVAL_RECORD_COLUMNS = (
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_revision",
    "requester_user_id",
    "company_id",
    "approver_user_id",
    "nonce_digest",
    "signature_version",
    "signature_purpose",
    "key_id",
    "issued_at",
    "expires_at",
    "approval_signature",
    "accepted_at",
    "audit_event_id",
    "record_origin",
    "record_hash",
)

_APPROVAL_RECORD_SCHEMA = """
    CREATE TABLE IF NOT EXISTS approval_records (
        operation_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        operation_revision INTEGER NOT NULL CHECK(operation_revision >= 0),
        requester_user_id INTEGER NOT NULL CHECK(requester_user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        approver_user_id INTEGER NOT NULL CHECK(approver_user_id > 0),
        nonce_digest TEXT NOT NULL UNIQUE CHECK(length(nonce_digest) = 64),
        signature_version INTEGER NOT NULL CHECK(signature_version > 0),
        signature_purpose TEXT NOT NULL,
        key_id TEXT,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL CHECK(issued_at < expires_at),
        approval_signature TEXT NOT NULL CHECK(length(approval_signature) = 64),
        accepted_at TEXT,
        audit_event_id TEXT UNIQUE,
        record_origin TEXT NOT NULL CHECK(record_origin IN (
            'native_v2', 'legacy_v1_unverifiable'
        )),
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        CHECK(approver_user_id <> requester_user_id),
        CHECK(
            (
                record_origin = 'native_v2'
                AND signature_version = 2
                AND signature_purpose = 'approval_v2'
                AND key_id IS NOT NULL AND length(key_id) > 0
                AND accepted_at IS NOT NULL
                AND audit_event_id IS NOT NULL
            )
            OR
            (
                record_origin = 'legacy_v1_unverifiable'
                AND signature_version = 1
                AND signature_purpose = 'approval_v1'
                AND key_id IS NULL
                AND accepted_at IS NULL
                AND audit_event_id IS NULL
            )
        ),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT,
        FOREIGN KEY(audit_event_id) REFERENCES audit_events(event_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
"""

_APPROVAL_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_no_update
    BEFORE UPDATE ON approval_records
    BEGIN
        SELECT RAISE(ABORT, 'approval_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_no_delete
    BEFORE DELETE ON approval_records
    BEGIN
        SELECT RAISE(ABORT, 'approval_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_native_only
    BEFORE INSERT ON approval_records
    WHEN NEW.record_origin <> 'native_v2'
    BEGIN
        SELECT RAISE(ABORT, 'only native v2 approval records may be inserted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_bind_awaiting_operation
    BEFORE INSERT ON approval_records
    WHEN NEW.record_origin = 'native_v2'
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.user_id = NEW.requester_user_id
              AND operation.company_id = NEW.company_id
              AND operation.state = 'awaiting_approval'
              AND operation.approval_signature IS NULL
              AND operation.approval_nonce_digest IS NULL
              AND operation.approval_issued_at IS NULL
              AND operation.approval_expires_at IS NULL
              AND operation.approval_revision IS NULL
              AND operation.approver_user_id IS NULL
        ) THEN RAISE(ABORT, 'native approval must bind an awaiting operation') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_approved_requires_native_approval
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'approved' AND OLD.state <> 'approved'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'awaiting_approval'
            OR NEW.revision <> OLD.revision + 1
            THEN RAISE(ABORT, 'approved transition requires native approval') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM approval_records AS approval
            WHERE approval.operation_id = NEW.operation_id
              AND approval.request_id = NEW.request_id
              AND approval.operation_digest = NEW.digest
              AND approval.operation_revision = OLD.revision
              AND approval.requester_user_id = NEW.user_id
              AND approval.company_id = NEW.company_id
              AND approval.approver_user_id = NEW.approver_user_id
              AND approval.nonce_digest = NEW.approval_nonce_digest
              AND approval.issued_at = NEW.approval_issued_at
              AND approval.expires_at = NEW.approval_expires_at
              AND approval.approval_signature = NEW.approval_signature
              AND approval.record_origin = 'native_v2'
              AND EXISTS (
                  SELECT 1 FROM audit_events AS audit
                  WHERE audit.event_id = approval.audit_event_id
                    AND audit.event_type = 'operation.approved'
                    AND audit.operation_id = NEW.operation_id
              )
        ) THEN RAISE(ABORT, 'approved transition requires native approval') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_insert_pristine
    BEFORE INSERT ON operations
    WHEN NEW.state <> 'prepared'
      OR NEW.revision <> 0
      OR NEW.approval_signature IS NOT NULL
      OR NEW.approval_nonce_digest IS NOT NULL
      OR NEW.approval_issued_at IS NOT NULL
      OR NEW.approval_expires_at IS NOT NULL
      OR NEW.approval_revision IS NOT NULL
      OR NEW.approver_user_id IS NOT NULL
      OR NEW.execution_result_digest IS NOT NULL
      OR NEW.verification_result_digest IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'new operation must be pristine prepared revision zero');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_executing_requires_native_approval
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'executing' AND OLD.state <> 'executing'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'approved'
            OR NEW.revision <> OLD.revision + 1
            THEN RAISE(ABORT, 'executing transition requires native approval') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM approval_records AS approval
            WHERE approval.operation_id = NEW.operation_id
              AND approval.request_id = NEW.request_id
              AND approval.operation_digest = NEW.digest
              AND approval.operation_revision = OLD.revision - 1
              AND approval.requester_user_id = NEW.user_id
              AND approval.company_id = NEW.company_id
              AND approval.approver_user_id = NEW.approver_user_id
              AND approval.nonce_digest = NEW.approval_nonce_digest
              AND approval.issued_at = NEW.approval_issued_at
              AND approval.expires_at = NEW.approval_expires_at
              AND approval.approval_signature = NEW.approval_signature
              AND approval.record_origin = 'native_v2'
              AND EXISTS (
                  SELECT 1 FROM audit_events AS audit
                  WHERE audit.event_type = 'operation.executing'
                    AND audit.operation_id = NEW.operation_id
              )
        ) THEN RAISE(ABORT, 'executing transition requires native approval') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_unimplemented_protected_states_closed
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state IN ('failed', 'verifying', 'completed', 'recovering', 'recovered')
      AND OLD.state <> NEW.state
    BEGIN
        SELECT RAISE(ABORT, 'protected transition requires an implemented transaction');
    END
    """,
)

_EXPECTED_COLUMNS_V2 = {
    **_EXPECTED_COLUMNS_V1,
    "approval_records": _APPROVAL_RECORD_COLUMNS,
}

_TABLE_SCHEMAS_V1 = dict(
    zip(_EXPECTED_COLUMNS_V1, _SCHEMA_V1[: len(_EXPECTED_COLUMNS_V1)], strict=True)
)
_TRIGGER_SCHEMAS_V1 = {
    "audit_events_no_update": _SCHEMA_V1[-2],
    "audit_events_no_delete": _SCHEMA_V1[-1],
}
_TABLE_SCHEMAS_V2 = {**_TABLE_SCHEMAS_V1, "approval_records": _APPROVAL_RECORD_SCHEMA}
_TRIGGER_SCHEMAS_V2 = {
    **_TRIGGER_SCHEMAS_V1,
    "approval_records_no_update": _APPROVAL_TRIGGER_SCHEMAS[0],
    "approval_records_no_delete": _APPROVAL_TRIGGER_SCHEMAS[1],
    "approval_records_native_only": _APPROVAL_TRIGGER_SCHEMAS[2],
    "approval_records_bind_awaiting_operation": _APPROVAL_TRIGGER_SCHEMAS[3],
    "operations_approved_requires_native_approval": _APPROVAL_TRIGGER_SCHEMAS[4],
    "operations_insert_pristine": _APPROVAL_TRIGGER_SCHEMAS[5],
    "operations_executing_requires_native_approval": _APPROVAL_TRIGGER_SCHEMAS[6],
    "operations_unimplemented_protected_states_closed": _APPROVAL_TRIGGER_SCHEMAS[7],
}
_SCHEMA_V2 = (
    *_TABLE_SCHEMAS_V2.values(),
    *_TRIGGER_SCHEMAS_V2.values(),
)


def _required_text(value: Any, field: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 512:
        raise PersistenceError(f"{field} must be a non-empty string of at most 512 characters")
    return value


def _required_digest(value: Any, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PersistenceError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _utc_text(value: Any, field: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PersistenceError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise PersistenceIntegrityError(f"stored {field} is not a timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PersistenceIntegrityError(f"stored {field} is not a timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise PersistenceIntegrityError(f"stored {field} has no timezone")
    return result


def _optional_datetime_text(value: datetime | None, field: str) -> str | None:
    return None if value is None else _utc_text(value, field)


def _operation_payload(operation: Operation) -> dict[str, Any]:
    try:
        operation.assert_integrity()
        if not isinstance(operation.state, State):
            raise PersistenceError("operation state is invalid")
        if isinstance(operation.revision, bool) or not isinstance(operation.revision, int) or operation.revision < 0:
            raise PersistenceError("operation revision is invalid")
        payload = {
            "operation_id": operation.operation_id,
            "request_id": operation.request_id,
            "capability_id": operation.capability_id,
            "parameters_json": operation.parameters_json,
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
            "state": operation.state.value,
            "revision": operation.revision,
            "approval_signature": operation.approval_signature,
            "approval_nonce_digest": operation.approval_nonce_digest,
            "approval_issued_at": _optional_datetime_text(
                operation.approval_issued_at, "approval_issued_at"
            ),
            "approval_expires_at": _optional_datetime_text(
                operation.approval_expires_at, "approval_expires_at"
            ),
            "approval_revision": operation.approval_revision,
            "approver_user_id": operation.approver_user_id,
            "execution_result_digest": operation.execution_result_digest,
            "verification_result_digest": operation.verification_result_digest,
        }
    except PersistenceError:
        raise
    except Exception as exc:
        raise PersistenceIntegrityError("operation cannot be serialized safely") from exc

    for field in (
        "approval_signature",
        "approval_nonce_digest",
        "execution_result_digest",
        "verification_result_digest",
    ):
        value = payload[field]
        if value is not None and (
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
        ):
            raise PersistenceIntegrityError(f"operation {field} is invalid")
    for field in ("approval_revision", "approver_user_id"):
        value = payload[field]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < (1 if field == "approver_user_id" else 0)
        ):
            raise PersistenceIntegrityError(f"operation {field} is invalid")
    return payload


def _operation_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _approval_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _approval_event_id(
    operation_id: str, operation_revision: int, nonce_digest: str
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "nonce_digest": nonce_digest,
                "operation_id": operation_id,
                "operation_revision": operation_revision,
            }
        )
    ).hexdigest()
    return f"operation.approved:{digest}"


def _approval_audit_payload(
    operation: Operation,
    *,
    approval_revision: int,
    approver_user_id: int,
    nonce_digest: str,
    key_id: str,
    signature_purpose: str,
    signature_version: int,
    approval_signature: str,
    record_hash: str,
) -> dict[str, Any]:
    return {
        "approval_key_id": key_id,
        "approval_nonce_digest": nonce_digest,
        "approval_purpose": signature_purpose,
        "approval_record_hash": record_hash,
        "approval_signature_digest": hashlib.sha256(
            approval_signature.encode("utf-8")
        ).hexdigest(),
        "approval_version": signature_version,
        "approver_user_id": approver_user_id,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "from_revision": approval_revision,
        "from_state": State.AWAITING_APPROVAL.value,
        "operation_digest": operation.digest,
        "request_id": operation.request_id,
        "requester_user_id": operation.user_id,
        "to_revision": approval_revision + 1,
        "to_state": State.APPROVED.value,
    }


def _execution_event_id(
    operation_id: str, operation_revision: int, approval_record_hash: str
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "approval_record_hash": approval_record_hash,
                "operation_id": operation_id,
                "operation_revision": operation_revision,
            }
        )
    ).hexdigest()
    return f"operation.executing:{digest}"


def _execution_audit_payload(
    operation: Operation, approval_record: StoredApprovalRecord
) -> dict[str, Any]:
    approved_revision = approval_record.operation_revision + 1
    return {
        "approval_record_hash": approval_record.record_hash,
        "approver_user_id": approval_record.approver_user_id,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "from_revision": approved_revision,
        "from_state": State.APPROVED.value,
        "operation_digest": operation.digest,
        "request_id": operation.request_id,
        "requester_user_id": operation.user_id,
        "to_revision": approved_revision + 1,
        "to_state": State.EXECUTING.value,
    }


def _native_approval_payload(
    *,
    operation: Operation,
    approval: Approval,
    nonce_digest: str,
    accepted_at: datetime,
    audit_event_id: str,
) -> dict[str, Any]:
    return {
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_revision": approval.operation_revision,
        "requester_user_id": operation.user_id,
        "company_id": operation.company_id,
        "approver_user_id": approval.approver_user_id,
        "nonce_digest": nonce_digest,
        "signature_version": approval.signature_version,
        "signature_purpose": approval.signature_purpose,
        "key_id": approval.key_id,
        "issued_at": _utc_text(approval.issued_at, "approval.issued_at"),
        "expires_at": _utc_text(approval.expires_at, "approval.expires_at"),
        "approval_signature": approval.signature,
        "accepted_at": _utc_text(accepted_at, "accepted_at"),
        "audit_event_id": audit_event_id,
        "record_origin": "native_v2",
    }


def _legacy_approval_payload(operation: Operation) -> dict[str, Any]:
    if (
        operation.approval_revision is None
        or operation.approver_user_id is None
        or operation.approval_nonce_digest is None
        or operation.approval_signature is None
        or operation.approval_issued_at is None
        or operation.approval_expires_at is None
    ):
        raise PersistenceIntegrityError("legacy approval metadata is incomplete")
    return {
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_revision": operation.approval_revision,
        "requester_user_id": operation.user_id,
        "company_id": operation.company_id,
        "approver_user_id": operation.approver_user_id,
        "nonce_digest": operation.approval_nonce_digest,
        "signature_version": 1,
        "signature_purpose": "approval_v1",
        "key_id": None,
        "issued_at": _utc_text(operation.approval_issued_at, "approval_issued_at"),
        "expires_at": _utc_text(operation.approval_expires_at, "approval_expires_at"),
        "approval_signature": operation.approval_signature,
        "accepted_at": None,
        "audit_event_id": None,
        "record_origin": "legacy_v1_unverifiable",
    }


def _audit_hash(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    operation_id: str | None,
    occurred_at: str,
    payload_json: str,
    previous_hash: str,
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "event_id": event_id,
                "event_type": event_type,
                "occurred_at": occurred_at,
                "operation_id": operation_id,
                "payload_json": payload_json,
                "previous_hash": previous_hash,
                "sequence": sequence,
            }
        )
    ).hexdigest()


def _normalize_schema_sql(value: str) -> str:
    normalized = " ".join(value.split())
    normalized = normalized.replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")
    return normalized.replace("CREATE TRIGGER IF NOT EXISTS", "CREATE TRIGGER")


class SQLitePersistence:
    """One-file SQLite store; every public database call opens a new connection."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        receipt_key_id: str | None = None,
        receipt_secret: bytes | None = None,
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise PersistenceError(":memory: cannot be used with connection-per-call persistence")
        if not self.path.is_absolute():
            raise PersistenceError("persistence path must be absolute")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise PersistenceError("busy_timeout_ms must be a positive integer")
        if (receipt_key_id is None) != (receipt_secret is None):
            raise PersistenceError(
                "receipt verifier key ID and secret must be configured together"
            )
        if receipt_key_id is not None:
            _required_text(receipt_key_id, "receipt_key_id")
            if type(receipt_secret) is not bytes or len(receipt_secret) < 32:
                raise PersistenceError(
                    "receipt verifier secret must be bytes of at least 32 bytes"
                )
        self.busy_timeout_ms = busy_timeout_ms
        self._receipt_key_id = receipt_key_id
        self._receipt_secret = receipt_secret
        self._receipt_secret_digest = (
            None
            if receipt_secret is None
            else hashlib.sha256(receipt_secret).hexdigest()
        )
        self.initialize()

    def _prepare_private_database_file(self) -> tuple[int, int]:
        try:
            parent = self.path.parent
            parent_metadata = parent.lstat()
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent.is_symlink()
                or parent.resolve(strict=True) != parent
            ):
                raise PersistenceError("persistence parent directory is invalid")
            if os.name == "posix" and (
                parent_metadata.st_uid not in {0, os.geteuid()}
                or parent_metadata.st_mode & 0o022
            ):
                raise PersistenceError("persistence parent directory is not private")
            if not os.path.lexists(self.path):
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(self.path, flags, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
                raise PersistenceError("persistence database must be a regular non-symlink file")
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise PersistenceError("persistence database file is not private")
            return metadata.st_dev, metadata.st_ino
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceError("persistence database path cannot be secured") from exc

    def _verify_database_and_sidecars(self, expected: tuple[int, int]) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise PersistenceIntegrityError("persistence database path changed while open")
            if os.name == "posix":
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(f"{self.path}{suffix}")
                    if os.path.lexists(sidecar):
                        sidecar_metadata = sidecar.lstat()
                        if (
                            not stat.S_ISREG(sidecar_metadata.st_mode)
                            or sidecar.is_symlink()
                            or sidecar_metadata.st_uid != os.geteuid()
                            or sidecar_metadata.st_mode & 0o077
                        ):
                            raise PersistenceIntegrityError(
                                "persistence SQLite sidecar is not private"
                            )
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceIntegrityError("persistence database path cannot be verified") from exc

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        expected_database = self._prepare_private_database_file()
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise PersistenceError("SQLite WAL mode is required")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise PersistenceError("SQLite foreign keys are required")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_and_sidecars(expected_database)

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection, version: int) -> None:
        if version == LEGACY_SCHEMA_VERSION:
            expected_columns = _EXPECTED_COLUMNS_V1
            expected_tables = _TABLE_SCHEMAS_V1
            expected_triggers = _TRIGGER_SCHEMAS_V1
        elif version == SCHEMA_VERSION:
            expected_columns = _EXPECTED_COLUMNS_V2
            expected_tables = _TABLE_SCHEMAS_V2
            expected_triggers = _TRIGGER_SCHEMAS_V2
        else:  # pragma: no cover - callers validate before dispatch
            raise PersistenceIntegrityError("unsupported persistence schema version")

        stored = connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        if stored is None or stored["value"] != str(version):
            raise PersistenceIntegrityError("persistence schema metadata mismatch")

        for table, expected in expected_columns.items():
            actual = tuple(
                row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if actual != expected:
                raise PersistenceIntegrityError(
                    f"persistence table schema mismatch: {table}"
                )

        actual_tables = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if set(actual_tables) != set(expected_tables) or any(
            not isinstance(actual_tables[name], str)
            or _normalize_schema_sql(actual_tables[name])
            != _normalize_schema_sql(statement)
            for name, statement in expected_tables.items()
        ):
            raise PersistenceIntegrityError("persistence table schema mismatch")

        actual_triggers = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        if set(actual_triggers) != set(expected_triggers) or any(
            not isinstance(actual_triggers[name], str)
            or _normalize_schema_sql(actual_triggers[name])
            != _normalize_schema_sql(statement)
            for name, statement in expected_triggers.items()
        ):
            raise PersistenceIntegrityError("persistence trigger schema mismatch")

        unexpected_objects = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE (type = 'view' OR (type = 'index' AND sql IS NOT NULL)) "
            "AND name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        if unexpected_objects is not None:
            raise PersistenceIntegrityError("persistence schema has unexpected objects")

    @staticmethod
    def _verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
        quick_check = tuple(
            row[0] for row in connection.execute("PRAGMA quick_check")
        )
        if quick_check != ("ok",):
            raise PersistenceIntegrityError("SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise PersistenceIntegrityError("SQLite foreign key check failed")

    @classmethod
    def _verify_audit_chain_connection(cls, connection: sqlite3.Connection) -> int:
        events = cls._load_audit_events(connection)
        previous_hash = GENESIS_HASH
        for expected_sequence, event in enumerate(events, start=1):
            occurred_text = _utc_text(event.occurred_at, "occurred_at")
            payload_json = canonical_json(event.payload).decode("utf-8")
            expected_hash = _audit_hash(
                sequence=event.sequence,
                event_id=event.event_id,
                event_type=event.event_type,
                operation_id=event.operation_id,
                occurred_at=occurred_text,
                payload_json=payload_json,
                previous_hash=event.previous_hash,
            )
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous_hash
                or not isinstance(event.event_hash, str)
                or not hmac.compare_digest(event.event_hash, expected_hash)
            ):
                raise PersistenceIntegrityError(
                    "audit hash chain verification failed"
                )
            previous_hash = event.event_hash
        return len(events)

    @classmethod
    def _verify_stored_data(
        cls, connection: sqlite3.Connection, *, include_approvals: bool
    ) -> None:
        operation_ids = tuple(
            row["operation_id"]
            for row in connection.execute("SELECT operation_id FROM operations")
        )
        for operation_id in operation_ids:
            if include_approvals:
                cls._load_operation_with_evidence(connection, operation_id)
            else:
                cls._load_operation(connection, operation_id)
        cls._verify_idempotency_bindings(connection, operation_ids)
        cls._verify_audit_chain_connection(connection)
        if include_approvals:
            approval_ids = tuple(
                row["operation_id"]
                for row in connection.execute(
                    "SELECT operation_id FROM approval_records"
                )
            )
            for operation_id in approval_ids:
                cls._load_approval_record(connection, operation_id)
            missing = connection.execute(
                """
                SELECT operation.operation_id
                FROM operations AS operation
                LEFT JOIN approval_records AS approval
                  ON approval.operation_id = operation.operation_id
                WHERE operation.approval_signature IS NOT NULL
                  AND approval.operation_id IS NULL
                LIMIT 1
                """
            ).fetchone()
            if missing is not None:
                raise PersistenceIntegrityError(
                    "approved operation has no durable approval record"
                )
            cls._verify_reserved_audit_namespaces(connection)

    @classmethod
    def _verify_idempotency_bindings(
        cls,
        connection: sqlite3.Connection,
        operation_ids: tuple[str, ...],
    ) -> None:
        rows = tuple(connection.execute("SELECT * FROM idempotency_keys"))
        if (
            len(rows) != len(operation_ids)
            or {row["operation_id"] for row in rows} != set(operation_ids)
        ):
            raise PersistenceIntegrityError(
                "stored operation/idempotency relation is incomplete"
            )
        for row in rows:
            operation = cls._load_operation(connection, row["operation_id"])
            try:
                _required_text(row["scope"], "stored idempotency scope")
            except PersistenceError as exc:
                raise PersistenceIntegrityError(
                    "stored idempotency binding is invalid"
                ) from exc
            expected = {
                "odoo_instance_id": operation.odoo_instance_id,
                "database_uuid": operation.database_uuid,
                "environment": operation.environment,
                "company_id": operation.company_id,
                "capability_id": operation.capability_id,
                "idempotency_key": operation.idempotency_key,
                "operation_id": operation.operation_id,
                "operation_digest": operation.digest,
            }
            if any(row[field] != value for field, value in expected.items()):
                raise PersistenceIntegrityError(
                    "stored idempotency binding does not match its operation"
                )

    @classmethod
    def _verify_read_audit_event(
        cls, connection: sqlite3.Connection, event: StoredAuditEvent
    ) -> None:
        payload = event.payload
        receipt = payload.get("receipt") if isinstance(payload, dict) else None
        if (
            set(payload) != _READ_AUDIT_FIELDS
            or not isinstance(receipt, dict)
            or set(receipt) != _READ_RECEIPT_FIELDS
        ):
            raise PersistenceIntegrityError(
                "stored verified read audit evidence is invalid"
            )
        try:
            observed_at = _parse_datetime(
                receipt["observed_at"], "read receipt observed_at"
            )
            normalized_database_uuid = str(uuid.UUID(receipt["database_uuid"]))
        except (PersistenceError, AttributeError, TypeError, ValueError) as exc:
            raise PersistenceIntegrityError(
                "stored verified read audit evidence is invalid"
            ) from exc
        required_text = (
            "capability_id",
            "capability_channel",
            "database_name",
            "database_uuid",
            "id",
            "environment",
            "odoo_instance_id",
            "signature_key_id",
        )
        required_digests = (
            "registry_digest",
            "release_digest",
            "request_digest",
            "result_digest",
            "signature",
        )
        if (
            any(
                not isinstance(receipt[field], str) or not receipt[field].strip()
                for field in required_text
            )
            or any(
                not isinstance(receipt[field], str)
                or _SHA256.fullmatch(receipt[field]) is None
                for field in required_digests
            )
            or normalized_database_uuid != receipt["database_uuid"]
            or type(receipt["company_id"]) is not int
            or receipt["company_id"] <= 0
            or type(receipt["user_id"]) is not int
            or receipt["user_id"] <= 0
            or type(receipt["record_count"]) is not int
            or receipt["record_count"] < 0
            or not valid_read_runtime_binding(
                receipt["environment"], receipt["capability_channel"]
            )
            or type(receipt["signature_version"]) is not int
            or receipt["signature_version"] != READ_RECEIPT_SIGNATURE_VERSION
            or receipt["signature_purpose"] != READ_RECEIPT_PURPOSE
            or event.event_id != f"read:{receipt['id']}"
            or event.event_type != "read.verified"
            or event.operation_id is not None
            or event.occurred_at != observed_at
        ):
            raise PersistenceIntegrityError(
                "stored verified read audit evidence is invalid"
            )
        expected_summary = {
            "auth_token_id": payload["auth_token_id"],
            "capability_id": receipt["capability_id"],
            "capability_channel": receipt["capability_channel"],
            "company_id": receipt["company_id"],
            "environment": receipt["environment"],
            "database_name": receipt["database_name"],
            "database_uuid": receipt["database_uuid"],
            "odoo_instance_id": receipt["odoo_instance_id"],
            "principal": payload["principal"],
            "receipt_id": receipt["id"],
            "registry_digest": receipt["registry_digest"],
            "release_digest": receipt["release_digest"],
            "request_digest": receipt["request_digest"],
            "result_digest": receipt["result_digest"],
            "user_id": receipt["user_id"],
        }
        if (
            any(
                not isinstance(payload[field], str) or not payload[field].strip()
                for field in ("auth_token_id", "principal")
            )
            or any(payload[field] != value for field, value in expected_summary.items())
        ):
            raise PersistenceIntegrityError(
                "stored verified read audit evidence is invalid"
            )
        consumed = connection.execute(
            "SELECT request_digest, observed_at FROM consumed_receipts "
            "WHERE receipt_id = ?",
            (receipt["id"],),
        ).fetchone()
        if (
            consumed is None
            or consumed["request_digest"] != receipt["request_digest"]
            or consumed["observed_at"] != _utc_text(observed_at, "observed_at")
        ):
            raise PersistenceIntegrityError(
                "stored verified read audit has no matching consumed receipt"
            )

    @classmethod
    def _verify_reserved_audit_namespaces(
        cls, connection: sqlite3.Connection
    ) -> None:
        native_approval_ids = {
            row["audit_event_id"]
            for row in connection.execute(
                "SELECT audit_event_id FROM approval_records "
                "WHERE record_origin = 'native_v2'"
            )
        }
        legacy_operation_ids = {
            row["operation_id"]
            for row in connection.execute(
                "SELECT operation_id FROM approval_records "
                "WHERE record_origin = 'legacy_v1_unverifiable'"
            )
        }
        native_execution_ids = {
            _execution_event_id(
                row["operation_id"], row["operation_revision"], row["record_hash"]
            )
            for row in connection.execute(
                """
                SELECT operation.operation_id, approval.operation_revision,
                       approval.record_hash
                FROM operations AS operation
                JOIN approval_records AS approval
                  ON approval.operation_id = operation.operation_id
                WHERE approval.record_origin = 'native_v2'
                  AND operation.state IN ('executing', 'verifying', 'completed')
                """
            )
        }
        seen_legacy: set[str] = set()
        for event in cls._load_audit_events(connection):
            diagnostic_id = event.event_id.startswith("diagnostic:")
            diagnostic_type = event.event_type.startswith("diagnostic.")
            if diagnostic_id or diagnostic_type:
                if diagnostic_id and diagnostic_type:
                    continue
                raise PersistenceIntegrityError(
                    "stored audit diagnostic namespace is ambiguous"
                )
            if event.event_type == "operation.approved.legacy":
                if (
                    event.event_id.startswith(("operation.", "read:"))
                    or event.operation_id not in legacy_operation_ids
                    or event.operation_id in seen_legacy
                ):
                    raise PersistenceIntegrityError(
                        "stored legacy approval audit evidence is invalid"
                    )
                seen_legacy.add(event.operation_id)
                continue
            if event.event_type == "operation.approved":
                valid = event.event_id in native_approval_ids
            elif event.event_type == "operation.executing":
                valid = event.event_id in native_execution_ids
            elif event.event_type == "read.verified":
                cls._verify_read_audit_event(connection, event)
                valid = True
            else:
                valid = not (
                    event.event_id.startswith(("operation.", "read:"))
                    or event.event_type.startswith(("operation.", "read."))
                )
            if not valid:
                raise PersistenceIntegrityError(
                    "stored reserved audit event has no native evidence"
                )

    @classmethod
    def _backfill_legacy_approvals(cls, connection: sqlite3.Connection) -> None:
        operation_ids = tuple(
            row["operation_id"]
            for row in connection.execute(
                """
                SELECT operation_id FROM operations
                WHERE approval_signature IS NOT NULL
                   OR approval_nonce_digest IS NOT NULL
                   OR approval_issued_at IS NOT NULL
                   OR approval_expires_at IS NOT NULL
                   OR approval_revision IS NOT NULL
                   OR approver_user_id IS NOT NULL
                """
            )
        )
        nonce_digests: set[str] = set()
        for operation_id in operation_ids:
            operation = cls._load_operation(connection, operation_id)
            payload = _legacy_approval_payload(operation)
            nonce_digest = payload["nonce_digest"]
            if nonce_digest in nonce_digests:
                raise PersistenceIntegrityError(
                    "legacy state contains a duplicate approval nonce"
                )
            nonce_digests.add(nonce_digest)
            values = tuple(payload[column] for column in _APPROVAL_RECORD_COLUMNS[:-1])
            connection.execute(
                f"INSERT INTO approval_records({', '.join(_APPROVAL_RECORD_COLUMNS)}) "
                f"VALUES({', '.join('?' for _ in _APPROVAL_RECORD_COLUMNS)})",
                (*values, _approval_record_hash(payload)),
            )

    @staticmethod
    def _verify_legacy_migration_states(connection: sqlite3.Connection) -> None:
        unsupported = connection.execute(
            "SELECT operation_id, state FROM operations "
            "WHERE state NOT IN ("
            "'prepared', 'prechecked', 'awaiting_approval', 'approved'"
            ") LIMIT 1"
        ).fetchone()
        if unsupported is not None:
            raise PersistenceIntegrityError(
                "legacy operation state cannot be migrated without durable evidence"
            )

    @classmethod
    def _verify_legacy_audit_namespaces(
        cls, connection: sqlite3.Connection
    ) -> None:
        """Never promote a v1 event that impersonates native v2 evidence."""
        for event in cls._load_audit_events(connection):
            diagnostic_id = event.event_id.startswith("diagnostic:")
            diagnostic_type = event.event_type.startswith("diagnostic.")
            if diagnostic_id or diagnostic_type:
                if diagnostic_id and diagnostic_type:
                    continue
                raise PersistenceIntegrityError(
                    "legacy audit diagnostic namespace is ambiguous"
                )
            reserved_id = event.event_id.startswith(("operation.", "read:"))
            reserved_type = event.event_type.startswith(("operation.", "read."))
            if event.event_type == "operation.approved.legacy":
                operation = connection.execute(
                    "SELECT state FROM operations WHERE operation_id = ?",
                    (event.operation_id,),
                ).fetchone()
                if (
                    reserved_id
                    or event.operation_id is None
                    or operation is None
                    or operation["state"] != State.APPROVED.value
                ):
                    raise PersistenceIntegrityError(
                        "legacy reserved audit event is invalid"
                    )
                continue
            if reserved_id or reserved_type:
                raise PersistenceIntegrityError(
                    "legacy reserved audit event cannot be migrated"
                )

    def _verify_or_bind_receipt_verifier(
        self, connection: sqlite3.Connection
    ) -> None:
        rows = {
            row["key"]: row["value"]
            for row in connection.execute(
                "SELECT key, value FROM schema_meta WHERE key IN (?, ?)",
                (_RECEIPT_KEY_ID_META, _RECEIPT_KEY_DIGEST_META),
            )
        }
        if rows and set(rows) != {
            _RECEIPT_KEY_ID_META,
            _RECEIPT_KEY_DIGEST_META,
        }:
            raise PersistenceIntegrityError(
                "stored receipt verifier binding is incomplete"
            )
        if rows:
            try:
                _required_text(
                    rows[_RECEIPT_KEY_ID_META], "stored receipt verifier key ID"
                )
                _required_digest(
                    rows[_RECEIPT_KEY_DIGEST_META],
                    "stored receipt verifier secret digest",
                )
            except PersistenceError as exc:
                raise PersistenceIntegrityError(
                    "stored receipt verifier binding is invalid"
                ) from exc
        if self._receipt_key_id is None:
            return
        if not rows:
            if connection.execute(
                "SELECT 1 FROM audit_events WHERE event_type = 'read.verified' LIMIT 1"
            ).fetchone() is not None:
                raise PersistenceIntegrityError(
                    "existing verified reads have no receipt verifier binding"
                )
            connection.executemany(
                "INSERT INTO schema_meta(key, value) VALUES(?, ?)",
                (
                    (_RECEIPT_KEY_ID_META, self._receipt_key_id),
                    (_RECEIPT_KEY_DIGEST_META, self._receipt_secret_digest),
                ),
            )
            return
        if (
            rows[_RECEIPT_KEY_ID_META] != self._receipt_key_id
            or self._receipt_secret_digest is None
            or not hmac.compare_digest(
                rows[_RECEIPT_KEY_DIGEST_META], self._receipt_secret_digest
            )
        ):
            raise PersistenceIntegrityError(
                "stored receipt verifier binding does not match configuration"
            )

    def initialize(self) -> None:
        with self._transaction() as connection:
            current_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if current_version == 0:
                existing = connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
                ).fetchone()
                if existing is not None:
                    raise PersistenceIntegrityError(
                        "unversioned persistence database is not empty"
                    )
                for statement in _SCHEMA_V2:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif current_version == LEGACY_SCHEMA_VERSION:
                self._verify_schema(connection, LEGACY_SCHEMA_VERSION)
                self._verify_sqlite_integrity(connection)
                self._verify_stored_data(connection, include_approvals=False)
                self._verify_legacy_migration_states(connection)
                self._verify_legacy_audit_namespaces(connection)
                connection.execute(_APPROVAL_RECORD_SCHEMA)
                self._backfill_legacy_approvals(connection)
                for statement in _APPROVAL_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                cursor = connection.execute(
                    "UPDATE schema_meta SET value = ? "
                    "WHERE key = 'schema_version' AND value = ?",
                    (str(SCHEMA_VERSION), str(LEGACY_SCHEMA_VERSION)),
                )
                if cursor.rowcount != 1:
                    raise PersistenceIntegrityError(
                        "persistence schema metadata changed during migration"
                    )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif current_version != SCHEMA_VERSION:
                raise PersistenceIntegrityError(
                    "unsupported persistence schema version"
                )

            self._verify_schema(connection, SCHEMA_VERSION)
            self._verify_sqlite_integrity(connection)
            self._verify_or_bind_receipt_verifier(connection)
            self._verify_stored_data(connection, include_approvals=True)

    def consume_auth_token(
        self,
        *,
        token_id: str,
        request_digest: str,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        token_id = _required_text(token_id, "token_id")
        request_digest = _required_digest(request_digest, "request_digest")
        expires_text = _utc_text(expires_at, "expires_at")
        now_text = _utc_text(now, "now")
        if expires_at <= now:
            raise ReplayRejected("authentication token is expired")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT request_digest FROM consumed_auth_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], request_digest):
                    raise ReplayRejected(
                        "authentication token was already consumed for a different request"
                    )
                raise ReplayRejected("authentication token was already consumed")
            connection.execute(
                """
                INSERT INTO consumed_auth_tokens(token_id, request_digest, expires_at, consumed_at)
                VALUES(?, ?, ?, ?)
                """,
                (token_id, request_digest, expires_text, now_text),
            )

    def consume_receipt(
        self,
        *,
        receipt_id: str,
        request_digest: str,
        observed_at: datetime,
        now: datetime,
    ) -> None:
        with self._transaction() as connection:
            self._consume_receipt_in_transaction(
                connection,
                receipt_id=receipt_id,
                request_digest=request_digest,
                observed_at=observed_at,
                now=now,
            )

    @staticmethod
    def _consume_receipt_in_transaction(
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        request_digest: str,
        observed_at: datetime,
        now: datetime,
    ) -> None:
        receipt_id = _required_text(receipt_id, "receipt_id")
        request_digest = _required_digest(request_digest, "request_digest")
        observed_text = _utc_text(observed_at, "observed_at")
        now_text = _utc_text(now, "now")
        if observed_at > now:
            raise ReplayRejected("receipt observation time is in the future")
        existing = connection.execute(
            "SELECT request_digest FROM consumed_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if existing is not None:
            if not hmac.compare_digest(existing["request_digest"], request_digest):
                raise ReplayRejected(
                    "receipt was already consumed for a different request"
                )
            raise ReplayRejected("receipt was already consumed")
        connection.execute(
            """
            INSERT INTO consumed_receipts(receipt_id, request_digest, observed_at, consumed_at)
            VALUES(?, ?, ?, ?)
            """,
            (receipt_id, request_digest, observed_text, now_text),
        )

    @staticmethod
    def _insert_operation(connection: sqlite3.Connection, operation: Operation) -> None:
        payload = _operation_payload(operation)
        columns = (*_OPERATION_COLUMNS, "record_hash")
        values = tuple(payload[column] for column in _OPERATION_COLUMNS) + (
            _operation_record_hash(payload),
        )
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO operations({', '.join(columns)}) VALUES({placeholders})", values
        )

    @staticmethod
    def _load_operation(connection: sqlite3.Connection, operation_id: str) -> Operation:
        row = connection.execute(
            f"SELECT {', '.join((*_OPERATION_COLUMNS, 'record_hash'))} "
            "FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("operation does not exist")
        stored_payload = {column: row[column] for column in _OPERATION_COLUMNS}
        expected_hash = _operation_record_hash(stored_payload)
        if not isinstance(row["record_hash"], str) or not hmac.compare_digest(
            expected_hash, row["record_hash"]
        ):
            raise PersistenceIntegrityError("stored operation record hash mismatch")
        try:
            operation = Operation(
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                capability_id=row["capability_id"],
                parameters_json=row["parameters_json"],
                principal=row["principal"],
                user_id=row["user_id"],
                company_id=row["company_id"],
                idempotency_key=row["idempotency_key"],
                odoo_instance_id=row["odoo_instance_id"],
                database_name=row["database_name"],
                database_uuid=row["database_uuid"],
                environment=row["environment"],
                registry_digest=row["registry_digest"],
                release_digest=row["release_digest"],
                digest=row["digest"],
                state=State(row["state"]),
                revision=row["revision"],
                approval_signature=row["approval_signature"],
                approval_nonce_digest=row["approval_nonce_digest"],
                approval_issued_at=(
                    None
                    if row["approval_issued_at"] is None
                    else _parse_datetime(row["approval_issued_at"], "approval_issued_at")
                ),
                approval_expires_at=(
                    None
                    if row["approval_expires_at"] is None
                    else _parse_datetime(row["approval_expires_at"], "approval_expires_at")
                ),
                approval_revision=row["approval_revision"],
                approver_user_id=row["approver_user_id"],
                execution_result_digest=row["execution_result_digest"],
                verification_result_digest=row["verification_result_digest"],
            )
            payload = _operation_payload(operation)
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceIntegrityError("stored operation is invalid") from exc
        if any(row[column] != payload[column] for column in _OPERATION_COLUMNS):
            raise PersistenceIntegrityError("stored operation representation is not canonical")
        return operation

    @classmethod
    def _load_approval_record(
        cls, connection: sqlite3.Connection, operation_id: str
    ) -> StoredApprovalRecord:
        row = connection.execute(
            f"SELECT {', '.join(_APPROVAL_RECORD_COLUMNS)} "
            "FROM approval_records WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("approval record does not exist")
        payload = {
            column: row[column] for column in _APPROVAL_RECORD_COLUMNS[:-1]
        }
        expected_hash = _approval_record_hash(payload)
        if not isinstance(row["record_hash"], str) or not hmac.compare_digest(
            expected_hash, row["record_hash"]
        ):
            raise PersistenceIntegrityError("stored approval record hash mismatch")
        try:
            issued_at = _parse_datetime(row["issued_at"], "approval issued_at")
            expires_at = _parse_datetime(row["expires_at"], "approval expires_at")
            accepted_at = (
                None
                if row["accepted_at"] is None
                else _parse_datetime(row["accepted_at"], "approval accepted_at")
            )
            record = StoredApprovalRecord(
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                operation_digest=row["operation_digest"],
                operation_revision=row["operation_revision"],
                requester_user_id=row["requester_user_id"],
                company_id=row["company_id"],
                approver_user_id=row["approver_user_id"],
                nonce_digest=row["nonce_digest"],
                signature_version=row["signature_version"],
                signature_purpose=row["signature_purpose"],
                key_id=row["key_id"],
                issued_at=issued_at,
                expires_at=expires_at,
                approval_signature=row["approval_signature"],
                accepted_at=accepted_at,
                audit_event_id=row["audit_event_id"],
                record_origin=row["record_origin"],
                record_hash=row["record_hash"],
            )
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored approval record is invalid"
            ) from exc

        canonical_payload = {
            "operation_id": record.operation_id,
            "request_id": record.request_id,
            "operation_digest": record.operation_digest,
            "operation_revision": record.operation_revision,
            "requester_user_id": record.requester_user_id,
            "company_id": record.company_id,
            "approver_user_id": record.approver_user_id,
            "nonce_digest": record.nonce_digest,
            "signature_version": record.signature_version,
            "signature_purpose": record.signature_purpose,
            "key_id": record.key_id,
            "issued_at": _utc_text(record.issued_at, "approval issued_at"),
            "expires_at": _utc_text(record.expires_at, "approval expires_at"),
            "approval_signature": record.approval_signature,
            "accepted_at": (
                None
                if record.accepted_at is None
                else _utc_text(record.accepted_at, "approval accepted_at")
            ),
            "audit_event_id": record.audit_event_id,
            "record_origin": record.record_origin,
        }
        if payload != canonical_payload:
            raise PersistenceIntegrityError(
                "stored approval record representation is not canonical"
            )
        if (
            _SHA256.fullmatch(record.operation_digest) is None
            or _SHA256.fullmatch(record.nonce_digest) is None
            or _SHA256.fullmatch(record.approval_signature) is None
            or type(record.operation_revision) is not int
            or record.operation_revision < 0
            or type(record.requester_user_id) is not int
            or record.requester_user_id <= 0
            or type(record.company_id) is not int
            or record.company_id <= 0
            or type(record.approver_user_id) is not int
            or record.approver_user_id <= 0
            or record.approver_user_id == record.requester_user_id
            or record.expires_at <= record.issued_at
        ):
            raise PersistenceIntegrityError("stored approval record is invalid")

        operation = cls._load_operation(connection, record.operation_id)
        if (
            operation.request_id != record.request_id
            or operation.digest != record.operation_digest
            or operation.user_id != record.requester_user_id
            or operation.company_id != record.company_id
            or operation.approval_revision != record.operation_revision
            or operation.approver_user_id != record.approver_user_id
            or operation.approval_nonce_digest != record.nonce_digest
            or operation.approval_issued_at != record.issued_at
            or operation.approval_expires_at != record.expires_at
            or operation.approval_signature != record.approval_signature
        ):
            raise PersistenceIntegrityError(
                "stored approval record does not match its operation"
            )
        if record.record_origin == "native_v2":
            expected_event_id = _approval_event_id(
                record.operation_id,
                record.operation_revision,
                record.nonce_digest,
            )
            event = connection.execute(
                "SELECT event_type, operation_id, occurred_at, payload_json "
                "FROM audit_events WHERE event_id = ?",
                (record.audit_event_id,),
            ).fetchone()
            try:
                event_payload = (
                    None if event is None else json.loads(event["payload_json"])
                )
                event_occurred_at = (
                    None
                    if event is None
                    else _parse_datetime(
                        event["occurred_at"], "approval audit occurred_at"
                    )
                )
            except (PersistenceError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PersistenceIntegrityError(
                    "stored approval audit evidence is invalid"
                ) from exc
            expected_payload = _approval_audit_payload(
                operation,
                approval_revision=record.operation_revision,
                approver_user_id=record.approver_user_id,
                nonce_digest=record.nonce_digest,
                key_id=record.key_id or "",
                signature_purpose=record.signature_purpose,
                signature_version=record.signature_version,
                approval_signature=record.approval_signature,
                record_hash=record.record_hash,
            )
            if (
                record.signature_version != 2
                or record.signature_purpose != "approval_v2"
                or not isinstance(record.key_id, str)
                or not record.key_id
                or record.accepted_at is None
                or not record.issued_at <= record.accepted_at < record.expires_at
                or record.audit_event_id != expected_event_id
                or event is None
                or event["event_type"] != "operation.approved"
                or event["operation_id"] != record.operation_id
                or event_occurred_at != record.accepted_at
                or event["payload_json"]
                != canonical_json(expected_payload).decode("utf-8")
                or canonical_json(event_payload).decode("utf-8")
                != event["payload_json"]
            ):
                raise PersistenceIntegrityError(
                    "stored native approval audit evidence is invalid"
                )
            if operation.state not in {
                State.APPROVED,
                State.EXECUTING,
                State.VERIFYING,
                State.COMPLETED,
            }:
                raise PersistenceIntegrityError(
                    "native approval evidence is invalid for stored operation state"
                )
        elif record.record_origin == "legacy_v1_unverifiable":
            if (
                record.signature_version != 1
                or record.signature_purpose != "approval_v1"
                or record.key_id is not None
                or record.accepted_at is not None
                or record.audit_event_id is not None
            ):
                raise PersistenceIntegrityError(
                    "stored legacy approval record is invalid"
                )
            if operation.state != State.APPROVED:
                raise PersistenceIntegrityError(
                    "legacy approval evidence is invalid for stored execution state"
                )
        else:
            raise PersistenceIntegrityError("stored approval record origin is invalid")
        return record

    @classmethod
    def _verify_execution_audit(
        cls,
        connection: sqlite3.Connection,
        operation: Operation,
        approval_record: StoredApprovalRecord,
    ) -> StoredAuditEvent:
        event_id = _execution_event_id(
            operation.operation_id,
            approval_record.operation_revision,
            approval_record.record_hash,
        )
        event = next(
            (
                item
                for item in cls._load_audit_events(connection)
                if item.event_id == event_id
            ),
            None,
        )
        expected_payload = _execution_audit_payload(operation, approval_record)
        if (
            event is None
            or event.event_type != "operation.executing"
            or event.operation_id != operation.operation_id
            or canonical_json(event.payload) != canonical_json(expected_payload)
            or approval_record.accepted_at is None
            or not approval_record.accepted_at
            <= event.occurred_at
            < approval_record.expires_at
        ):
            raise PersistenceIntegrityError(
                "executing operation has no valid durable execution audit"
            )
        return event

    @classmethod
    def _load_operation_with_evidence(
        cls, connection: sqlite3.Connection, operation_id: str
    ) -> Operation:
        operation = cls._load_operation(connection, operation_id)
        if operation.approval_signature is None:
            return operation
        approval_record = cls._load_approval_record(connection, operation_id)
        if (
            approval_record.record_origin == "native_v2"
            and operation.state
            in {State.EXECUTING, State.VERIFYING, State.COMPLETED}
        ):
            cls._verify_execution_audit(
                connection, operation, approval_record
            )
        return operation

    def get_operation(self, operation_id: str) -> Operation:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_operation_with_evidence(connection, operation_id)

    def get_approval_record(self, operation_id: str) -> StoredApprovalRecord:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_approval_record(connection, operation_id)

    def get_or_create_operation(
        self, operation: Operation, *, scope: str
    ) -> tuple[Operation, bool]:
        _operation_payload(operation)
        if (
            operation.state != State.PREPARED
            or operation.revision != 0
            or any(
                getattr(operation, field) is not None
                for field in _OPERATION_COLUMNS[17:]
            )
        ):
            raise PersistenceIntegrityError(
                "new operation must be pristine prepared revision zero"
            )
        scope = _required_text(scope, "scope")
        identity = (
            operation.odoo_instance_id,
            operation.database_uuid,
            operation.environment,
            operation.company_id,
            operation.capability_id,
            scope,
        )
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            existing_key = connection.execute(
                """
                SELECT operation_id, operation_digest, idempotency_key
                FROM idempotency_keys
                WHERE odoo_instance_id = ? AND database_uuid = ? AND environment = ?
                  AND company_id = ? AND capability_id = ? AND scope = ?
                """,
                identity,
            ).fetchone()
            if existing_key is not None:
                existing = self._load_operation_with_evidence(
                    connection, existing_key["operation_id"]
                )
                if (
                    not hmac.compare_digest(existing.digest, existing_key["operation_digest"])
                    or not hmac.compare_digest(existing.digest, operation.digest)
                    or existing_key["idempotency_key"] != operation.idempotency_key
                ):
                    raise IdempotencyConflict("idempotency identity has different request content")
                return existing, False
            try:
                self._insert_operation(connection, operation)
                connection.execute(
                    """
                    INSERT INTO idempotency_keys(
                        odoo_instance_id, database_uuid, environment, company_id,
                        capability_id, scope, idempotency_key, operation_id, operation_digest
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *identity,
                        operation.idempotency_key,
                        operation.operation_id,
                        operation.digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IdempotencyConflict("operation or idempotency identity already exists") from exc
            return operation, True

    def cas_update_operation(
        self, operation: Operation, *, expected_revision: int
    ) -> Operation:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise PersistenceError("expected_revision must be a non-negative integer")
        if operation.revision != expected_revision + 1:
            raise ConcurrentUpdate("operation revision must advance by exactly one")
        if operation.state in {
            State.APPROVED,
            State.EXECUTING,
            State.VERIFYING,
            State.COMPLETED,
            State.FAILED,
            State.RECOVERING,
            State.RECOVERED,
        }:
            raise PersistenceIntegrityError(
                "protected operation transition requires a specialized transactional method"
            )
        payload = _operation_payload(operation)
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            current = self._load_operation_with_evidence(
                connection, operation.operation_id
            )
            if current.revision != expected_revision:
                raise ConcurrentUpdate("stored operation revision has changed")
            if any(
                getattr(current, field) != getattr(operation, field)
                for field in _IMMUTABLE_OPERATION_FIELDS
            ):
                raise PersistenceIntegrityError("operation immutable fields changed during CAS")
            if any(
                getattr(current, field) != getattr(operation, field)
                for field in _OPERATION_COLUMNS[17:]
            ):
                raise PersistenceIntegrityError(
                    "operation evidence fields changed during generic CAS"
                )
            if operation.state not in ALLOWED_TRANSITIONS[current.state]:
                raise PersistenceIntegrityError("operation CAS contains an invalid state transition")
            mutable_columns = _OPERATION_COLUMNS[1:]
            assignments = ", ".join(f"{column} = ?" for column in mutable_columns)
            values = tuple(payload[column] for column in mutable_columns) + (
                _operation_record_hash(payload),
                operation.operation_id,
                expected_revision,
            )
            cursor = connection.execute(
                f"UPDATE operations SET {assignments}, record_hash = ? "
                "WHERE operation_id = ? AND revision = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdate("stored operation revision has changed")
            return self._load_operation_with_evidence(
                connection, operation.operation_id
            )

    def accept_approval(
        self,
        approval: Approval,
        *,
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        is_approver_authorized: Callable[[int, int, str], bool],
        approval_ttl_seconds: int,
        expected_revision: int,
    ) -> ApprovalAcceptance:
        if not isinstance(approval, Approval):
            raise PersistenceError("approval must be an Approval")
        operation_id = _required_text(approval.operation_id, "approval.operation_id")
        nonce_digest = (
            hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest()
            if isinstance(approval.nonce, str) and approval.nonce
            else None
        )
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)
                if nonce_digest is not None:
                    replay = connection.execute(
                        "SELECT operation_id FROM approval_records "
                        "WHERE nonce_digest = ?",
                        (nonce_digest,),
                    ).fetchone()
                    if replay is not None:
                        raise ReplayRejected(
                            "approval nonce was already consumed"
                        )
                current = self._load_operation(connection, operation_id)
                try:
                    approved = approve_operation(
                        current,
                        approval,
                        now=now,
                        secret=secret,
                        expected_key_id=expected_key_id,
                        is_approver_authorized=is_approver_authorized,
                        consume_nonce=lambda *_: True,
                        approval_ttl_seconds=approval_ttl_seconds,
                        expected_revision=expected_revision,
                    )
                except OperationConcurrentUpdate as exc:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    ) from exc
                if nonce_digest is None:  # approve_operation supplies the stable error
                    raise PersistenceIntegrityError(
                        "validated approval nonce has no digest"
                    )

                event_id = _approval_event_id(
                    current.operation_id, current.revision, nonce_digest
                )
                record_payload = _native_approval_payload(
                    operation=current,
                    approval=approval,
                    nonce_digest=nonce_digest,
                    accepted_at=now,
                    audit_event_id=event_id,
                )
                record_hash = _approval_record_hash(record_payload)
                record_values = tuple(
                    record_payload[column]
                    for column in _APPROVAL_RECORD_COLUMNS[:-1]
                )
                connection.execute(
                    f"INSERT INTO approval_records({', '.join(_APPROVAL_RECORD_COLUMNS)}) "
                    f"VALUES({', '.join('?' for _ in _APPROVAL_RECORD_COLUMNS)})",
                    (*record_values, record_hash),
                )

                audit_event = self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type="operation.approved",
                    operation_id=current.operation_id,
                    occurred_at=now,
                    payload=_approval_audit_payload(
                        current,
                        approval_revision=approval.operation_revision,
                        approver_user_id=approval.approver_user_id,
                        nonce_digest=nonce_digest,
                        key_id=approval.key_id,
                        signature_purpose=approval.signature_purpose,
                        signature_version=approval.signature_version,
                        approval_signature=approval.signature,
                        record_hash=record_hash,
                    ),
                )

                approved_payload = _operation_payload(approved)
                mutable_columns = _OPERATION_COLUMNS[1:]
                assignments = ", ".join(
                    f"{column} = ?" for column in mutable_columns
                )
                update_values = tuple(
                    approved_payload[column] for column in mutable_columns
                ) + (
                    _operation_record_hash(approved_payload),
                    current.operation_id,
                    current.revision,
                )
                cursor = connection.execute(
                    f"UPDATE operations SET {assignments}, record_hash = ? "
                    "WHERE operation_id = ? AND revision = ?",
                    update_values,
                )
                if cursor.rowcount != 1:
                    raise ConcurrentUpdate("stored operation revision has changed")
                stored_operation = self._load_operation(
                    connection, current.operation_id
                )
                stored_record = self._load_approval_record(
                    connection, current.operation_id
                )
                acceptance = ApprovalAcceptance(
                    operation=stored_operation,
                    approval_record=stored_record,
                    audit_event=audit_event,
                )
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("approval transaction failed") from exc
        return acceptance

    def begin_execution(
        self,
        approval: Approval,
        *,
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        is_approver_authorized: Callable[[int, int, str], bool],
        approval_ttl_seconds: int,
        expected_revision: int,
    ) -> ExecutionAcceptance:
        if not isinstance(approval, Approval):
            raise PersistenceError("approval must be an Approval")
        operation_id = _required_text(approval.operation_id, "approval.operation_id")
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)
                current = self._load_operation_with_evidence(
                    connection, operation_id
                )
                approval_record = self._load_approval_record(
                    connection, operation_id
                )
                if approval_record.record_origin != "native_v2":
                    raise PersistenceIntegrityError(
                        "legacy approval evidence cannot authorize execution"
                    )
                try:
                    executing = validate_begin_execution(
                        current,
                        approval,
                        now=now,
                        secret=secret,
                        expected_key_id=expected_key_id,
                        is_approver_authorized=is_approver_authorized,
                        approval_ttl_seconds=approval_ttl_seconds,
                        expected_revision=expected_revision,
                    )
                except OperationConcurrentUpdate as exc:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    ) from exc
                nonce_digest = hashlib.sha256(
                    approval.nonce.encode("utf-8")
                ).hexdigest()
                if (
                    approval_record.signature_version
                    != approval.signature_version
                    or approval_record.signature_purpose
                    != approval.signature_purpose
                    or approval_record.key_id != approval.key_id
                    or approval_record.approval_signature
                    != approval.signature
                    or approval_record.nonce_digest != nonce_digest
                    or approval_record.operation_revision
                    != approval.operation_revision
                ):
                    raise PersistenceIntegrityError(
                        "durable approval record does not match signed approval"
                    )

                event_id = _execution_event_id(
                    current.operation_id,
                    approval_record.operation_revision,
                    approval_record.record_hash,
                )
                audit_event = self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type="operation.executing",
                    operation_id=current.operation_id,
                    occurred_at=now,
                    payload=_execution_audit_payload(
                        current, approval_record
                    ),
                )

                executing_payload = _operation_payload(executing)
                mutable_columns = _OPERATION_COLUMNS[1:]
                assignments = ", ".join(
                    f"{column} = ?" for column in mutable_columns
                )
                update_values = tuple(
                    executing_payload[column] for column in mutable_columns
                ) + (
                    _operation_record_hash(executing_payload),
                    current.operation_id,
                    current.revision,
                )
                cursor = connection.execute(
                    f"UPDATE operations SET {assignments}, record_hash = ? "
                    "WHERE operation_id = ? AND revision = ?",
                    update_values,
                )
                if cursor.rowcount != 1:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    )
                stored_operation = self._load_operation_with_evidence(
                    connection, current.operation_id
                )
                acceptance = ExecutionAcceptance(
                    operation=stored_operation,
                    approval_record=approval_record,
                    audit_event=audit_event,
                )
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("execution transaction failed") from exc
        return acceptance

    @classmethod
    def _append_audit_event(
        cls,
        connection: sqlite3.Connection,
        *,
        event_id: str,
        event_type: str,
        operation_id: str | None,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> StoredAuditEvent:
        cls._verify_audit_chain_connection(connection)
        last = connection.execute(
            "SELECT sequence, event_hash FROM audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if last is None else last["sequence"] + 1
        previous_hash = GENESIS_HASH if last is None else last["event_hash"]
        payload_json = canonical_json(payload).decode("utf-8")
        occurred_text = _utc_text(occurred_at, "occurred_at")
        event_hash = _audit_hash(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            operation_id=operation_id,
            occurred_at=occurred_text,
            payload_json=payload_json,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO audit_events(
                sequence, event_id, event_type, operation_id, occurred_at,
                payload_json, previous_hash, event_hash
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                event_id,
                event_type,
                operation_id,
                occurred_text,
                payload_json,
                previous_hash,
                event_hash,
            ),
        )
        return StoredAuditEvent(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            operation_id=operation_id,
            occurred_at=_parse_datetime(occurred_text, "occurred_at"),
            payload=json.loads(payload_json),
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def append_audit_event(
        self,
        *,
        event_id: str,
        event_type: str,
        operation_id: str | None,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> StoredAuditEvent:
        event_id = _required_text(event_id, "event_id")
        event_type = _required_text(event_type, "event_type")
        if not (
            event_id.startswith("diagnostic:")
            and event_type.startswith("diagnostic.")
        ):
            raise PersistenceIntegrityError(
                "reserved audit event identity or type requires a specialized method"
            )
        if operation_id is not None:
            operation_id = _required_text(operation_id, "operation_id")
        if not isinstance(payload, dict):
            raise PersistenceError("audit payload must be an object")
        try:
            payload_size = len(canonical_json(payload))
        except (TypeError, ValueError) as exc:
            raise PersistenceError("audit payload is not canonical JSON") from exc
        if payload_size > MAX_DIAGNOSTIC_AUDIT_PAYLOAD_BYTES:
            raise PersistenceError("diagnostic audit payload exceeds the size limit")
        with self._transaction() as connection:
            try:
                return self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type=event_type,
                    operation_id=operation_id,
                    occurred_at=occurred_at,
                    payload=payload,
                )
            except sqlite3.IntegrityError as exc:
                raise PersistenceError(
                    "audit event identity already exists"
                ) from exc

    def record_verified_read(
        self,
        *,
        receipt: dict[str, Any],
        capability_id: str,
        parameters: dict[str, Any],
        result_body: dict[str, Any],
        auth_token_id: str,
        principal: str,
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        company_id: int,
        user_id: int,
        registry_digest: str,
        release_digest: str,
        environment: str,
        capability_channel: str,
        expected_record_count: int,
        now: datetime,
    ) -> StoredAuditEvent:
        """Verify, consume, and audit one signed read receipt atomically."""
        if self._receipt_key_id is None or self._receipt_secret is None:
            raise PersistenceError("receipt verifier is not configured for this store")
        if not all(
            isinstance(value, dict) for value in (receipt, parameters, result_body)
        ):
            raise PersistenceError(
                "verified read receipt, parameters, and result must be objects"
            )
        for field, value in (
            ("capability_id", capability_id),
            ("auth_token_id", auth_token_id),
            ("principal", principal),
            ("odoo_instance_id", odoo_instance_id),
            ("database_name", database_name),
            ("environment", environment),
            ("capability_channel", capability_channel),
        ):
            _required_text(value, field)
        _required_digest(registry_digest, "registry_digest")
        _required_digest(release_digest, "release_digest")
        try:
            normalized_database_uuid = str(uuid.UUID(database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise PersistenceError("database_uuid must be a UUID") from exc
        if normalized_database_uuid != database_uuid:
            raise PersistenceError("database_uuid must be canonical")
        if not valid_read_runtime_binding(environment, capability_channel):
            raise PersistenceError(
                "verified read environment/capability channel is invalid"
            )
        if (
            type(company_id) is not int
            or company_id <= 0
            or type(user_id) is not int
            or user_id <= 0
            or type(expected_record_count) is not int
            or expected_record_count < 0
        ):
            raise PersistenceError("verified read numeric bindings are invalid")
        _utc_text(now, "now")
        try:
            receipt_document = json.loads(canonical_json(receipt))
            parameters_document = json.loads(canonical_json(parameters))
            result_document = json.loads(canonical_json(result_body))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PersistenceError("verified read evidence is not canonical JSON") from exc

        recorded: list[StoredAuditEvent] = []
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)

                def consume_and_audit(
                    receipt_id: str,
                    request_digest: str,
                    observed_at: datetime,
                    verified_at: datetime,
                ) -> bool:
                    self._consume_receipt_in_transaction(
                        connection,
                        receipt_id=receipt_id,
                        request_digest=request_digest,
                        observed_at=observed_at,
                        now=verified_at,
                    )
                    audit_payload = {
                        "auth_token_id": auth_token_id,
                        "capability_id": capability_id,
                        "capability_channel": capability_channel,
                        "company_id": company_id,
                        "environment": environment,
                        "database_name": database_name,
                        "database_uuid": normalized_database_uuid,
                        "odoo_instance_id": odoo_instance_id,
                        "principal": principal,
                        "receipt": receipt_document,
                        "receipt_id": receipt_id,
                        "registry_digest": registry_digest,
                        "release_digest": release_digest,
                        "request_digest": request_digest,
                        "result_digest": receipt_document["result_digest"],
                        "user_id": user_id,
                    }
                    event = self._append_audit_event(
                        connection,
                        event_id=f"read:{receipt_id}",
                        event_type="read.verified",
                        operation_id=None,
                        occurred_at=observed_at,
                        payload=audit_payload,
                    )
                    self._verify_read_audit_event(connection, event)
                    recorded.append(event)
                    return True

                verify_read_receipt(
                    receipt_document,
                    capability_id=capability_id,
                    parameters=parameters_document,
                    result_body=result_document,
                    auth_token_id=auth_token_id,
                    principal=principal,
                    odoo_instance_id=odoo_instance_id,
                    database_name=database_name,
                    database_uuid=database_uuid,
                    company_id=company_id,
                    user_id=user_id,
                    registry_digest=registry_digest,
                    release_digest=release_digest,
                    environment=environment,
                    capability_channel=capability_channel,
                    expected_record_count=expected_record_count,
                    now=now,
                    consume_receipt=consume_and_audit,
                    expected_key_id=self._receipt_key_id,
                    secret=self._receipt_secret,
                )
        except PersistenceError:
            raise
        except ReceiptError as exc:
            raise PersistenceIntegrityError(
                "verified read receipt rejected"
            ) from exc
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("verified read audit transaction failed") from exc
        if len(recorded) != 1:  # pragma: no cover - verifier calls once or raises
            raise PersistenceIntegrityError("verified read audit was not recorded")
        return recorded[0]

    @staticmethod
    def _load_audit_events(connection: sqlite3.Connection) -> tuple[StoredAuditEvent, ...]:
        result = []
        for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            try:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict) or canonical_json(payload).decode("utf-8") != row["payload_json"]:
                    raise PersistenceIntegrityError("audit payload is not canonical")
                occurred_at = _parse_datetime(row["occurred_at"], "occurred_at")
                if row["occurred_at"] != _utc_text(occurred_at, "occurred_at"):
                    raise PersistenceIntegrityError(
                        "audit occurred_at representation is not canonical"
                    )
                result.append(
                    StoredAuditEvent(
                        sequence=row["sequence"],
                        event_id=row["event_id"],
                        event_type=row["event_type"],
                        operation_id=row["operation_id"],
                        occurred_at=occurred_at,
                        payload=payload,
                        previous_hash=row["previous_hash"],
                        event_hash=row["event_hash"],
                    )
                )
            except PersistenceError:
                raise
            except Exception as exc:
                raise PersistenceIntegrityError("stored audit event is invalid") from exc
        return tuple(result)

    def audit_events(self) -> tuple[StoredAuditEvent, ...]:
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_audit_events(connection)

    def verify_chain(self) -> int:
        with self._transaction() as connection:
            return self._verify_audit_chain_connection(connection)


__all__ = [
    "ApprovalAcceptance",
    "ConcurrentUpdate",
    "ExecutionAcceptance",
    "GENESIS_HASH",
    "IdempotencyConflict",
    "OperationNotFound",
    "PersistenceError",
    "PersistenceIntegrityError",
    "ReplayRejected",
    "SCHEMA_VERSION",
    "SQLitePersistence",
    "StoredApprovalRecord",
    "StoredAuditEvent",
]
