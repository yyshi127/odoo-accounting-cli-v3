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
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .monotonic_deadline import (
    bounded_sqlite_busy_timeout_ms,
    bounded_sqlite_connect_timeout_seconds,
)
from .operations import (
    ALLOWED_TRANSITIONS,
    Approval,
    ConcurrentUpdate as OperationConcurrentUpdate,
    Operation,
    ResultKind,
    State,
    TrustedResult,
    _operation_state_digest,
    approve_operation,
    begin_recovery as validate_begin_recovery,
    begin_execution as validate_begin_execution,
    canonical_json,
    complete_operation as validate_complete_operation,
    complete_recovery as validate_complete_recovery,
    record_precheck as validate_record_precheck,
    record_execution_result as validate_execution_result,
)
from .receipts import (
    READ_RECEIPT_PURPOSE,
    SIGNATURE_VERSION as READ_RECEIPT_SIGNATURE_VERSION,
    ReceiptError,
    valid_read_runtime_binding,
    verify_read_receipt,
)
from .write_receipts import WriteReceiptError, validate_recovery_plan


LEGACY_SCHEMA_VERSION = 1
PREVIOUS_SCHEMA_VERSION = 2
RESULT_SCHEMA_VERSION = 3
SCHEMA_VERSION = 4
GENESIS_HASH = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_DIAGNOSTIC_AUDIT_PAYLOAD_BYTES = 64 * 1024
_RECEIPT_KEY_ID_META = "receipt_verifier_key_id"
_RECEIPT_KEY_DIGEST_META = "receipt_verifier_secret_sha256"
_RECOVERY_BINDING_EVENT_PREFIX = "recovery-binding:"
_RECOVERY_BINDING_EVENT_TYPE = "recovery.binding.created"
_RECOVERY_BINDING_FIELDS = frozenset(
    {
        "binding_version",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "origin_final_receipt_body_digest",
        "origin_final_receipt_id",
        "origin_execution_evidence_digest",
        "origin_execution_result_id",
        "origin_operation_digest",
        "origin_operation_id",
        "origin_operation_revision",
        "origin_request_id",
        "origin_result_evidence_digest",
        "origin_result_id",
        "origin_terminal_state",
        "plan_digest",
        "principal",
        "recovery_operation_digest",
        "recovery_operation_id",
        "recovery_operation_revision",
        "recovery_request_id",
        "registry_digest",
        "release_digest",
        "user_id",
    }
)

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


@dataclass(frozen=True)
class StoredTrustedResultRecord:
    result_id: str
    operation_id: str
    request_id: str
    operation_digest: str
    operation_state_digest: str
    operation_revision: int
    requester_user_id: int
    requester_principal: str
    company_id: int
    approval_record_hash: str
    kind: str
    succeeded: bool
    evidence_digest: str
    evidence_json: str
    prior_evidence_digest: str | None
    issuer: str
    key_id: str
    signature_version: int
    signature_purpose: str
    signature: str
    issued_at: datetime
    accepted_at: datetime
    audit_event_id: str
    record_hash: str

    @property
    def evidence(self) -> dict[str, Any]:
        return json.loads(self.evidence_json)


@dataclass(frozen=True)
class StoredRecoveryRecord:
    recovery_id: str
    operation_id: str
    request_id: str
    operation_digest: str
    operation_revision: int
    from_state: str
    actor_principal: str
    actor_user_id: int
    company_id: int
    approval_record_hash: str
    plan_digest: str
    plan_json: str
    initiated_at: datetime
    audit_event_id: str
    record_hash: str

    @property
    def plan(self) -> dict[str, Any]:
        return json.loads(self.plan_json)


@dataclass(frozen=True)
class StoredPrecheckRecord:
    operation_id: str
    request_id: str
    operation_digest: str
    operation_revision: int
    principal: str
    user_id: int
    company_id: int
    evidence_digest: str
    evidence_json: str
    occurred_at: datetime
    audit_event_id: str
    record_hash: str

    @property
    def evidence(self) -> dict[str, Any]:
        return json.loads(self.evidence_json)


@dataclass(frozen=True)
class StoredFinalWriteReceipt:
    receipt_id: str
    operation_id: str
    request_id: str
    operation_digest: str
    operation_revision: int
    terminal_state: str
    protocol_version: int
    principal: str
    user_id: int
    company_id: int
    result_id: str
    result_kind: str
    result_succeeded: bool
    evidence_digest: str
    body_digest: str
    body_json: str
    recorded_at: datetime
    audit_event_id: str
    record_hash: str

    @property
    def body(self) -> dict[str, Any]:
        return json.loads(self.body_json)


@dataclass(frozen=True)
class StoredRecoveryOperationBinding:
    binding_id: str
    origin_operation_id: str
    origin_request_id: str
    origin_operation_digest: str
    origin_operation_revision: int
    origin_terminal_state: str
    origin_final_receipt_id: str
    origin_final_receipt_body_digest: str
    origin_execution_result_id: str
    origin_execution_evidence_digest: str
    origin_result_id: str
    origin_result_evidence_digest: str
    recovery_operation_id: str
    recovery_request_id: str
    recovery_operation_digest: str
    recovery_operation_revision: int
    plan_digest: str
    principal: str
    user_id: int
    company_id: int
    odoo_instance_id: str
    database_name: str
    database_uuid: str
    environment: str
    registry_digest: str
    release_digest: str
    audit_event: StoredAuditEvent


@dataclass(frozen=True)
class PrecheckAcceptance:
    operation: Operation
    precheck_record: StoredPrecheckRecord
    audit_event: StoredAuditEvent


@dataclass(frozen=True)
class ResultAcceptance:
    operation: Operation
    approval_record: StoredApprovalRecord
    result_record: StoredTrustedResultRecord
    audit_event: StoredAuditEvent
    final_receipt: StoredFinalWriteReceipt | None = None


@dataclass(frozen=True)
class RecoveryAcceptance:
    operation: Operation
    approval_record: StoredApprovalRecord
    recovery_record: StoredRecoveryRecord
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

_TRUSTED_RESULT_RECORD_COLUMNS = (
    "result_id",
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_state_digest",
    "operation_revision",
    "requester_user_id",
    "requester_principal",
    "company_id",
    "approval_record_hash",
    "kind",
    "succeeded",
    "evidence_digest",
    "evidence_json",
    "prior_evidence_digest",
    "issuer",
    "key_id",
    "signature_version",
    "signature_purpose",
    "signature",
    "issued_at",
    "accepted_at",
    "audit_event_id",
    "record_hash",
)

_TRUSTED_RESULT_RECORD_SCHEMA = """
    CREATE TABLE IF NOT EXISTS trusted_result_records (
        result_id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        operation_state_digest TEXT NOT NULL CHECK(length(operation_state_digest) = 64),
        operation_revision INTEGER NOT NULL CHECK(operation_revision >= 0),
        requester_user_id INTEGER NOT NULL CHECK(requester_user_id > 0),
        requester_principal TEXT NOT NULL,
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        approval_record_hash TEXT NOT NULL CHECK(length(approval_record_hash) = 64),
        kind TEXT NOT NULL CHECK(kind IN ('execution', 'verification', 'recovery')),
        succeeded INTEGER NOT NULL CHECK(succeeded IN (0, 1)),
        evidence_digest TEXT NOT NULL CHECK(length(evidence_digest) = 64),
        evidence_json TEXT NOT NULL,
        prior_evidence_digest TEXT CHECK(
            prior_evidence_digest IS NULL OR length(prior_evidence_digest) = 64
        ),
        issuer TEXT NOT NULL,
        key_id TEXT NOT NULL,
        signature_version INTEGER NOT NULL CHECK(signature_version = 2),
        signature_purpose TEXT NOT NULL,
        signature TEXT NOT NULL CHECK(length(signature) = 64),
        issued_at TEXT NOT NULL,
        accepted_at TEXT NOT NULL CHECK(issued_at <= accepted_at),
        audit_event_id TEXT NOT NULL UNIQUE,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        UNIQUE(operation_id, operation_revision, kind),
        CHECK(
            (kind = 'execution' AND prior_evidence_digest IS NULL
                AND signature_purpose = 'execution_result_v2')
            OR (kind = 'verification' AND prior_evidence_digest IS NOT NULL
                AND signature_purpose = 'verification_result_v2')
            OR (kind = 'recovery' AND prior_evidence_digest IS NOT NULL
                AND signature_purpose = 'recovery_result_v2')
        ),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT,
        FOREIGN KEY(audit_event_id) REFERENCES audit_events(event_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
"""

_RECOVERY_RECORD_COLUMNS = (
    "recovery_id",
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_revision",
    "from_state",
    "actor_principal",
    "actor_user_id",
    "company_id",
    "approval_record_hash",
    "plan_digest",
    "plan_json",
    "initiated_at",
    "audit_event_id",
    "record_hash",
)

_RECOVERY_RECORD_SCHEMA = """
    CREATE TABLE IF NOT EXISTS recovery_records (
        recovery_id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        operation_revision INTEGER NOT NULL CHECK(operation_revision >= 0),
        from_state TEXT NOT NULL CHECK(from_state IN ('completed', 'failed')),
        actor_principal TEXT NOT NULL,
        actor_user_id INTEGER NOT NULL CHECK(actor_user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        approval_record_hash TEXT NOT NULL CHECK(length(approval_record_hash) = 64),
        plan_digest TEXT NOT NULL CHECK(length(plan_digest) = 64),
        plan_json TEXT NOT NULL,
        initiated_at TEXT NOT NULL,
        audit_event_id TEXT NOT NULL UNIQUE,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        UNIQUE(operation_id, operation_revision),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT,
        FOREIGN KEY(audit_event_id) REFERENCES audit_events(event_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
"""

_RESULT_RECOVERY_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS trusted_result_records_no_update
    BEFORE UPDATE ON trusted_result_records
    BEGIN
        SELECT RAISE(ABORT, 'trusted_result_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trusted_result_records_no_delete
    BEFORE DELETE ON trusted_result_records
    BEGIN
        SELECT RAISE(ABORT, 'trusted_result_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trusted_result_records_bind_operation
    BEFORE INSERT ON trusted_result_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN approval_records AS approval
              ON approval.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.user_id = NEW.requester_user_id
              AND operation.principal = NEW.requester_principal
              AND operation.company_id = NEW.company_id
              AND operation.state = CASE NEW.kind
                    WHEN 'execution' THEN 'executing'
                    WHEN 'verification' THEN 'verifying'
                    ELSE 'recovering'
                  END
              AND approval.record_origin = 'native_v2'
              AND approval.record_hash = NEW.approval_record_hash
        ) THEN RAISE(ABORT, 'trusted result must bind an approved operation') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS recovery_records_no_update
    BEFORE UPDATE ON recovery_records
    BEGIN
        SELECT RAISE(ABORT, 'recovery_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS recovery_records_no_delete
    BEFORE DELETE ON recovery_records
    BEGIN
        SELECT RAISE(ABORT, 'recovery_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS recovery_records_bind_operation
    BEFORE INSERT ON recovery_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN approval_records AS approval
              ON approval.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.state = NEW.from_state
              AND operation.principal = NEW.actor_principal
              AND operation.user_id = NEW.actor_user_id
              AND operation.company_id = NEW.company_id
              AND approval.record_origin = 'native_v2'
              AND approval.record_hash = NEW.approval_record_hash
        ) THEN RAISE(ABORT, 'recovery must bind an approved operation identity') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_verifying_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'verifying' AND OLD.state <> 'verifying'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'executing'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM trusted_result_records AS result
                JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
                WHERE result.operation_id = NEW.operation_id
                  AND result.operation_revision = OLD.revision
                  AND result.kind = 'execution' AND result.succeeded = 1
                  AND result.evidence_digest = NEW.execution_result_digest
                  AND audit.event_type = 'operation.verifying'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'verifying transition requires a successful execution result') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_completed_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'completed' AND OLD.state <> 'completed'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'verifying'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.execution_result_digest IS NOT OLD.execution_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM trusted_result_records AS result
                JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
                WHERE result.operation_id = NEW.operation_id
                  AND result.operation_revision = OLD.revision
                  AND result.kind = 'verification' AND result.succeeded = 1
                  AND result.evidence_digest = NEW.verification_result_digest
                  AND audit.event_type = 'operation.completed'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'completed transition requires a successful verification result') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_failed_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'failed' AND OLD.state <> 'failed'
    BEGIN
        SELECT CASE WHEN NEW.revision <> OLD.revision + 1
          OR (
            OLD.state = 'executing'
            AND (
              NEW.execution_result_digest IS NOT (
                SELECT evidence_digest FROM trusted_result_records
                WHERE operation_id = NEW.operation_id
                  AND operation_revision = OLD.revision
                  AND kind = 'execution' AND succeeded = 0
              )
              OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            )
          )
          OR (
            OLD.state = 'verifying'
            AND (
              NEW.execution_result_digest IS NOT OLD.execution_result_digest
              OR NEW.verification_result_digest IS NOT (
                SELECT evidence_digest FROM trusted_result_records
                WHERE operation_id = NEW.operation_id
                  AND operation_revision = OLD.revision
                  AND kind = 'verification' AND succeeded = 0
              )
            )
          )
          OR (
            OLD.state = 'recovering'
            AND (
              NEW.execution_result_digest IS NOT OLD.execution_result_digest
              OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            )
          )
          OR NOT EXISTS (
            SELECT 1 FROM trusted_result_records AS result
            JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
            WHERE result.operation_id = NEW.operation_id
              AND result.operation_revision = OLD.revision
              AND result.succeeded = 0
              AND result.kind = CASE OLD.state
                    WHEN 'executing' THEN 'execution'
                    WHEN 'verifying' THEN 'verification'
                    WHEN 'recovering' THEN 'recovery'
                    ELSE ''
                  END
              AND audit.event_type = 'operation.failed'
              AND audit.operation_id = NEW.operation_id
        ) THEN RAISE(ABORT, 'failed transition requires a trusted negative result') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_recovering_requires_record
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'recovering' AND OLD.state <> 'recovering'
    BEGIN
        SELECT CASE WHEN OLD.state NOT IN ('completed', 'failed')
            OR NEW.revision <> OLD.revision + 1
            OR NEW.execution_result_digest IS NOT OLD.execution_result_digest
            OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM recovery_records AS recovery
                JOIN audit_events AS audit ON audit.event_id = recovery.audit_event_id
                WHERE recovery.operation_id = NEW.operation_id
                  AND recovery.operation_revision = OLD.revision
                  AND recovery.from_state = OLD.state
                  AND audit.event_type = 'operation.recovering'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'recovering transition requires a bound recovery record') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_recovered_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'recovered' AND OLD.state <> 'recovered'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'recovering'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.execution_result_digest IS NOT OLD.execution_result_digest
            OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM trusted_result_records AS result
                JOIN recovery_records AS recovery
                  ON recovery.operation_id = result.operation_id
                 AND recovery.operation_revision = result.operation_revision - 1
                JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
                WHERE result.operation_id = NEW.operation_id
                  AND result.operation_revision = OLD.revision
                  AND result.kind = 'recovery' AND result.succeeded = 1
                  AND result.prior_evidence_digest = recovery.plan_digest
                  AND audit.event_type = 'operation.recovered'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'recovered transition requires a successful recovery result') END;
    END
    """,
)

_EXPECTED_COLUMNS_V3 = {
    **_EXPECTED_COLUMNS_V2,
    "trusted_result_records": _TRUSTED_RESULT_RECORD_COLUMNS,
    "recovery_records": _RECOVERY_RECORD_COLUMNS,
}
_TABLE_SCHEMAS_V3 = {
    **_TABLE_SCHEMAS_V2,
    "trusted_result_records": _TRUSTED_RESULT_RECORD_SCHEMA,
    "recovery_records": _RECOVERY_RECORD_SCHEMA,
}
_TRIGGER_SCHEMAS_V3 = {
    key: value
    for key, value in _TRIGGER_SCHEMAS_V2.items()
    if key != "operations_unimplemented_protected_states_closed"
}
_TRIGGER_SCHEMAS_V3.update(
    {
        "trusted_result_records_no_update": _RESULT_RECOVERY_TRIGGER_SCHEMAS[0],
        "trusted_result_records_no_delete": _RESULT_RECOVERY_TRIGGER_SCHEMAS[1],
        "trusted_result_records_bind_operation": _RESULT_RECOVERY_TRIGGER_SCHEMAS[2],
        "recovery_records_no_update": _RESULT_RECOVERY_TRIGGER_SCHEMAS[3],
        "recovery_records_no_delete": _RESULT_RECOVERY_TRIGGER_SCHEMAS[4],
        "recovery_records_bind_operation": _RESULT_RECOVERY_TRIGGER_SCHEMAS[5],
        "operations_verifying_requires_result": _RESULT_RECOVERY_TRIGGER_SCHEMAS[6],
        "operations_completed_requires_result": _RESULT_RECOVERY_TRIGGER_SCHEMAS[7],
        "operations_failed_requires_result": _RESULT_RECOVERY_TRIGGER_SCHEMAS[8],
        "operations_recovering_requires_record": _RESULT_RECOVERY_TRIGGER_SCHEMAS[9],
        "operations_recovered_requires_result": _RESULT_RECOVERY_TRIGGER_SCHEMAS[10],
    }
)
_SCHEMA_V3 = (*_TABLE_SCHEMAS_V3.values(), *_TRIGGER_SCHEMAS_V3.values())


_APPROVAL_RECORD_SCHEMA_V4 = """
    CREATE TABLE IF NOT EXISTS "approval_records" (
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
            'native_v3', 'native_v2', 'legacy_v1_unverifiable'
        )),
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        CHECK(approver_user_id <> requester_user_id),
        CHECK(
            (
                record_origin = 'native_v3'
                AND signature_version = 3
                AND signature_purpose = 'approval_v3'
                AND key_id IS NOT NULL AND length(key_id) > 0
                AND accepted_at IS NOT NULL
                AND audit_event_id IS NOT NULL
            )
            OR
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
_APPROVAL_RECORD_SCHEMA_V4_TEMP = _APPROVAL_RECORD_SCHEMA_V4.replace(
    '"approval_records"', '"approval_records_v4"', 1
)


_OPERATION_PROTOCOL_COLUMNS = (
    "operation_id",
    "protocol_version",
    "record_hash",
)
_OPERATION_PROTOCOL_SCHEMA = """
    CREATE TABLE IF NOT EXISTS operation_protocols (
        operation_id TEXT PRIMARY KEY,
        protocol_version INTEGER NOT NULL CHECK(protocol_version IN (3, 4)),
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT
    ) STRICT
"""

_PRECHECK_RECORD_COLUMNS = (
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_revision",
    "principal",
    "user_id",
    "company_id",
    "evidence_digest",
    "evidence_json",
    "occurred_at",
    "audit_event_id",
    "record_hash",
)
_PRECHECK_RECORD_SCHEMA = """
    CREATE TABLE IF NOT EXISTS precheck_records (
        operation_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        operation_revision INTEGER NOT NULL CHECK(operation_revision = 0),
        principal TEXT NOT NULL,
        user_id INTEGER NOT NULL CHECK(user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        evidence_digest TEXT NOT NULL CHECK(length(evidence_digest) = 64),
        evidence_json TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        audit_event_id TEXT NOT NULL UNIQUE,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT,
        FOREIGN KEY(audit_event_id) REFERENCES audit_events(event_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
"""

_FINAL_WRITE_RECEIPT_COLUMNS = (
    "receipt_id",
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_revision",
    "terminal_state",
    "protocol_version",
    "principal",
    "user_id",
    "company_id",
    "result_id",
    "result_kind",
    "result_succeeded",
    "evidence_digest",
    "body_digest",
    "body_json",
    "recorded_at",
    "audit_event_id",
    "record_hash",
)
_FINAL_WRITE_RECEIPT_SCHEMA = """
    CREATE TABLE IF NOT EXISTS final_write_receipts (
        receipt_id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        operation_revision INTEGER NOT NULL CHECK(operation_revision > 0),
        terminal_state TEXT NOT NULL CHECK(terminal_state IN (
            'completed', 'failed', 'recovered'
        )),
        protocol_version INTEGER NOT NULL CHECK(protocol_version IN (3, 4)),
        principal TEXT NOT NULL,
        user_id INTEGER NOT NULL CHECK(user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        result_id TEXT NOT NULL UNIQUE,
        result_kind TEXT NOT NULL CHECK(result_kind IN (
            'execution', 'verification', 'recovery'
        )),
        result_succeeded INTEGER NOT NULL CHECK(result_succeeded IN (0, 1)),
        evidence_digest TEXT NOT NULL CHECK(length(evidence_digest) = 64),
        body_digest TEXT NOT NULL CHECK(length(body_digest) = 64),
        body_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        audit_event_id TEXT NOT NULL UNIQUE,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64),
        UNIQUE(operation_id, operation_revision),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT,
        FOREIGN KEY(result_id) REFERENCES trusted_result_records(result_id) ON DELETE RESTRICT,
        FOREIGN KEY(audit_event_id) REFERENCES audit_events(event_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT
"""

_APPROVAL_V4_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_native_only
    BEFORE INSERT ON approval_records
    WHEN NEW.record_origin <> 'native_v3'
    BEGIN
        SELECT RAISE(ABORT, 'only native v3 approval records may be inserted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS approval_records_bind_awaiting_operation
    BEFORE INSERT ON approval_records
    WHEN NEW.record_origin = 'native_v3'
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND protocol.protocol_version = 4
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
        ) THEN RAISE(ABORT, 'native v3 approval must bind a native awaiting operation') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_approved_requires_native_approval
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'approved' AND OLD.state <> 'approved'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'awaiting_approval'
            OR NEW.revision <> OLD.revision + 1
            THEN RAISE(ABORT, 'approved transition requires native v3 approval') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM approval_records AS approval
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = approval.operation_id
            WHERE approval.operation_id = NEW.operation_id
              AND protocol.protocol_version = 4
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
              AND approval.record_origin = 'native_v3'
              AND EXISTS (
                  SELECT 1 FROM audit_events AS audit
                  WHERE audit.event_id = approval.audit_event_id
                    AND audit.event_type = 'operation.approved'
                    AND audit.operation_id = NEW.operation_id
              )
        ) THEN RAISE(ABORT, 'approved transition requires native v3 approval') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_executing_requires_native_approval
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'executing' AND OLD.state <> 'executing'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'approved'
            OR NEW.revision <> OLD.revision + 1
            THEN RAISE(ABORT, 'executing transition requires native v3 approval') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM approval_records AS approval
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = approval.operation_id
            WHERE approval.operation_id = NEW.operation_id
              AND protocol.protocol_version = 4
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
              AND approval.record_origin = 'native_v3'
              AND EXISTS (
                  SELECT 1 FROM audit_events AS audit
                  WHERE audit.event_type = 'operation.executing'
                    AND audit.operation_id = NEW.operation_id
              )
        ) THEN RAISE(ABORT, 'executing transition requires native v3 approval') END;
    END
    """,
)

_RESULT_BIND_V4_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS trusted_result_records_bind_operation
    BEFORE INSERT ON trusted_result_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = operation.operation_id
            JOIN approval_records AS approval
              ON approval.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.user_id = NEW.requester_user_id
              AND operation.principal = NEW.requester_principal
              AND operation.company_id = NEW.company_id
              AND operation.state = CASE NEW.kind
                    WHEN 'execution' THEN 'executing'
                    WHEN 'verification' THEN 'verifying'
                    ELSE 'recovering'
                  END
              AND approval.record_hash = NEW.approval_record_hash
              AND approval.record_origin = CASE protocol.protocol_version
                    WHEN 4 THEN 'native_v3'
                    ELSE 'native_v2'
                  END
        ) THEN RAISE(ABORT, 'trusted result must bind a protocol-matched approval') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS recovery_records_bind_operation
    BEFORE INSERT ON recovery_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = operation.operation_id
            JOIN approval_records AS approval
              ON approval.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.state = NEW.from_state
              AND operation.principal = NEW.actor_principal
              AND operation.user_id = NEW.actor_user_id
              AND operation.company_id = NEW.company_id
              AND approval.record_hash = NEW.approval_record_hash
              AND approval.record_origin = CASE protocol.protocol_version
                    WHEN 4 THEN 'native_v3'
                    ELSE 'native_v2'
                  END
        ) THEN RAISE(ABORT, 'recovery must bind a protocol-matched approval') END;
    END
    """,
)

_CONTROL_V4_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS operation_protocols_no_update
    BEFORE UPDATE ON operation_protocols
    BEGIN
        SELECT RAISE(ABORT, 'operation_protocols are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operation_protocols_no_delete
    BEFORE DELETE ON operation_protocols
    BEGIN
        SELECT RAISE(ABORT, 'operation_protocols are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS precheck_records_no_update
    BEFORE UPDATE ON precheck_records
    BEGIN
        SELECT RAISE(ABORT, 'precheck_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS precheck_records_no_delete
    BEFORE DELETE ON precheck_records
    BEGIN
        SELECT RAISE(ABORT, 'precheck_records are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS precheck_records_bind_operation
    BEFORE INSERT ON precheck_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = operation.operation_id
            WHERE operation.operation_id = NEW.operation_id
              AND protocol.protocol_version = 4
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision = NEW.operation_revision
              AND operation.state = 'prepared'
              AND operation.principal = NEW.principal
              AND operation.user_id = NEW.user_id
              AND operation.company_id = NEW.company_id
        ) THEN RAISE(ABORT, 'precheck must bind a prepared native operation') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_prechecked_requires_record
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'prechecked' AND OLD.state <> 'prechecked'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'prepared'
            OR NEW.revision <> OLD.revision + 1
            OR NOT EXISTS (
                SELECT 1 FROM operation_protocols AS protocol
                JOIN precheck_records AS precheck
                  ON precheck.operation_id = protocol.operation_id
                JOIN audit_events AS audit
                  ON audit.event_id = precheck.audit_event_id
                WHERE protocol.operation_id = NEW.operation_id
                  AND protocol.protocol_version = 4
                  AND precheck.operation_revision = OLD.revision
                  AND precheck.request_id = NEW.request_id
                  AND precheck.operation_digest = NEW.digest
                  AND precheck.principal = NEW.principal
                  AND precheck.user_id = NEW.user_id
                  AND precheck.company_id = NEW.company_id
                  AND audit.event_type = 'operation.prechecked'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'prechecked transition requires canonical precheck evidence') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_awaiting_requires_precheck
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'awaiting_approval' AND OLD.state <> 'awaiting_approval'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'prechecked'
            OR NEW.revision <> OLD.revision + 1
            OR NOT EXISTS (
                SELECT 1 FROM operation_protocols AS protocol
                JOIN precheck_records AS precheck
                  ON precheck.operation_id = protocol.operation_id
                WHERE protocol.operation_id = NEW.operation_id
                  AND protocol.protocol_version = 4
                  AND precheck.operation_digest = NEW.digest
            )
            OR NOT EXISTS (
                SELECT 1 FROM audit_events AS audit
                WHERE audit.operation_id = NEW.operation_id
                  AND audit.event_type = 'operation.awaiting_approval'
            )
            THEN RAISE(ABORT, 'awaiting approval requires a durable precheck') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS final_write_receipts_no_update
    BEFORE UPDATE ON final_write_receipts
    BEGIN
        SELECT RAISE(ABORT, 'final_write_receipts are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS final_write_receipts_no_delete
    BEFORE DELETE ON final_write_receipts
    BEGIN
        SELECT RAISE(ABORT, 'final_write_receipts are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS final_write_receipts_bind_result
    BEFORE INSERT ON final_write_receipts
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM operations AS operation
            JOIN operation_protocols AS protocol
              ON protocol.operation_id = operation.operation_id
            JOIN trusted_result_records AS result
              ON result.operation_id = operation.operation_id
             AND result.result_id = NEW.result_id
            WHERE operation.operation_id = NEW.operation_id
              AND operation.request_id = NEW.request_id
              AND operation.digest = NEW.operation_digest
              AND operation.revision + 1 = NEW.operation_revision
              AND operation.principal = NEW.principal
              AND operation.user_id = NEW.user_id
              AND operation.company_id = NEW.company_id
              AND protocol.protocol_version = NEW.protocol_version
              AND result.operation_revision = operation.revision
              AND result.kind = NEW.result_kind
              AND result.succeeded = NEW.result_succeeded
              AND result.evidence_digest = NEW.evidence_digest
              AND (
                (NEW.terminal_state = 'completed'
                    AND result.kind = 'verification' AND result.succeeded = 1)
                OR (NEW.terminal_state = 'recovered'
                    AND result.kind = 'recovery' AND result.succeeded = 1)
                OR (NEW.terminal_state = 'failed' AND result.succeeded = 0)
              )
        ) THEN RAISE(ABORT, 'final receipt must bind a trusted terminal result') END;
    END
    """,
)

_TERMINAL_V4_TRIGGER_SCHEMAS = (
    """
    CREATE TRIGGER IF NOT EXISTS operations_completed_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'completed' AND OLD.state <> 'completed'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'verifying'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.execution_result_digest IS NOT OLD.execution_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM trusted_result_records AS result
                JOIN final_write_receipts AS receipt
                  ON receipt.result_id = result.result_id
                JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
                WHERE result.operation_id = NEW.operation_id
                  AND result.operation_revision = OLD.revision
                  AND result.kind = 'verification' AND result.succeeded = 1
                  AND result.evidence_digest = NEW.verification_result_digest
                  AND receipt.operation_revision = NEW.revision
                  AND receipt.terminal_state = 'completed'
                  AND receipt.audit_event_id = result.audit_event_id
                  AND audit.event_type = 'operation.completed'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'completed transition requires a final write receipt') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_failed_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'failed' AND OLD.state <> 'failed'
    BEGIN
        SELECT CASE WHEN NEW.revision <> OLD.revision + 1
          OR (
            OLD.state = 'executing'
            AND (
              NEW.execution_result_digest IS NOT (
                SELECT evidence_digest FROM trusted_result_records
                WHERE operation_id = NEW.operation_id
                  AND operation_revision = OLD.revision
                  AND kind = 'execution' AND succeeded = 0
              )
              OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            )
          )
          OR (
            OLD.state = 'verifying'
            AND (
              NEW.execution_result_digest IS NOT OLD.execution_result_digest
              OR NEW.verification_result_digest IS NOT (
                SELECT evidence_digest FROM trusted_result_records
                WHERE operation_id = NEW.operation_id
                  AND operation_revision = OLD.revision
                  AND kind = 'verification' AND succeeded = 0
              )
            )
          )
          OR (
            OLD.state = 'recovering'
            AND (
              NEW.execution_result_digest IS NOT OLD.execution_result_digest
              OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            )
          )
          OR NOT EXISTS (
            SELECT 1 FROM trusted_result_records AS result
            JOIN final_write_receipts AS receipt
              ON receipt.result_id = result.result_id
            JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
            WHERE result.operation_id = NEW.operation_id
              AND result.operation_revision = OLD.revision
              AND result.succeeded = 0
              AND result.kind = CASE OLD.state
                    WHEN 'executing' THEN 'execution'
                    WHEN 'verifying' THEN 'verification'
                    WHEN 'recovering' THEN 'recovery'
                    ELSE ''
                  END
              AND receipt.operation_revision = NEW.revision
              AND receipt.terminal_state = 'failed'
              AND receipt.audit_event_id = result.audit_event_id
              AND audit.event_type = 'operation.failed'
              AND audit.operation_id = NEW.operation_id
        ) THEN RAISE(ABORT, 'failed transition requires a final write receipt') END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS operations_recovered_requires_result
    BEFORE UPDATE OF state ON operations
    WHEN NEW.state = 'recovered' AND OLD.state <> 'recovered'
    BEGIN
        SELECT CASE WHEN OLD.state <> 'recovering'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.execution_result_digest IS NOT OLD.execution_result_digest
            OR NEW.verification_result_digest IS NOT OLD.verification_result_digest
            OR NOT EXISTS (
                SELECT 1 FROM trusted_result_records AS result
                JOIN recovery_records AS recovery
                  ON recovery.operation_id = result.operation_id
                 AND recovery.operation_revision = result.operation_revision - 1
                JOIN final_write_receipts AS receipt
                  ON receipt.result_id = result.result_id
                JOIN audit_events AS audit ON audit.event_id = result.audit_event_id
                WHERE result.operation_id = NEW.operation_id
                  AND result.operation_revision = OLD.revision
                  AND result.kind = 'recovery' AND result.succeeded = 1
                  AND result.prior_evidence_digest = recovery.plan_digest
                  AND receipt.operation_revision = NEW.revision
                  AND receipt.terminal_state = 'recovered'
                  AND receipt.audit_event_id = result.audit_event_id
                  AND audit.event_type = 'operation.recovered'
                  AND audit.operation_id = NEW.operation_id
            )
            THEN RAISE(ABORT, 'recovered transition requires a final write receipt') END;
    END
    """,
)

_EXPECTED_COLUMNS_V4 = {
    **_EXPECTED_COLUMNS_V3,
    "operation_protocols": _OPERATION_PROTOCOL_COLUMNS,
    "precheck_records": _PRECHECK_RECORD_COLUMNS,
    "final_write_receipts": _FINAL_WRITE_RECEIPT_COLUMNS,
}
_TABLE_SCHEMAS_V4 = {
    **_TABLE_SCHEMAS_V3,
    "approval_records": _APPROVAL_RECORD_SCHEMA_V4,
    "operation_protocols": _OPERATION_PROTOCOL_SCHEMA,
    "precheck_records": _PRECHECK_RECORD_SCHEMA,
    "final_write_receipts": _FINAL_WRITE_RECEIPT_SCHEMA,
}
_TRIGGER_SCHEMAS_V4 = {
    key: value
    for key, value in _TRIGGER_SCHEMAS_V3.items()
    if key not in {
        "approval_records_native_only",
        "approval_records_bind_awaiting_operation",
        "operations_approved_requires_native_approval",
        "operations_executing_requires_native_approval",
        "trusted_result_records_bind_operation",
        "recovery_records_bind_operation",
        "operations_completed_requires_result",
        "operations_failed_requires_result",
        "operations_recovered_requires_result",
    }
}
_TRIGGER_SCHEMAS_V4.update(
    {
        "operation_protocols_no_update": _CONTROL_V4_TRIGGER_SCHEMAS[0],
        "operation_protocols_no_delete": _CONTROL_V4_TRIGGER_SCHEMAS[1],
        "precheck_records_no_update": _CONTROL_V4_TRIGGER_SCHEMAS[2],
        "precheck_records_no_delete": _CONTROL_V4_TRIGGER_SCHEMAS[3],
        "precheck_records_bind_operation": _CONTROL_V4_TRIGGER_SCHEMAS[4],
        "operations_prechecked_requires_record": _CONTROL_V4_TRIGGER_SCHEMAS[5],
        "operations_awaiting_requires_precheck": _CONTROL_V4_TRIGGER_SCHEMAS[6],
        "final_write_receipts_no_update": _CONTROL_V4_TRIGGER_SCHEMAS[7],
        "final_write_receipts_no_delete": _CONTROL_V4_TRIGGER_SCHEMAS[8],
        "final_write_receipts_bind_result": _CONTROL_V4_TRIGGER_SCHEMAS[9],
        "approval_records_native_only": _APPROVAL_V4_TRIGGER_SCHEMAS[0],
        "approval_records_bind_awaiting_operation": _APPROVAL_V4_TRIGGER_SCHEMAS[1],
        "operations_approved_requires_native_approval": _APPROVAL_V4_TRIGGER_SCHEMAS[2],
        "operations_executing_requires_native_approval": _APPROVAL_V4_TRIGGER_SCHEMAS[3],
        "trusted_result_records_bind_operation": _RESULT_BIND_V4_TRIGGER_SCHEMAS[0],
        "recovery_records_bind_operation": _RESULT_BIND_V4_TRIGGER_SCHEMAS[1],
        "operations_completed_requires_result": _TERMINAL_V4_TRIGGER_SCHEMAS[0],
        "operations_failed_requires_result": _TERMINAL_V4_TRIGGER_SCHEMAS[1],
        "operations_recovered_requires_result": _TERMINAL_V4_TRIGGER_SCHEMAS[2],
    }
)
_SCHEMA_V4 = (*_TABLE_SCHEMAS_V4.values(), *_TRIGGER_SCHEMAS_V4.values())


def _required_text(value: Any, field: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 512:
        raise PersistenceError(f"{field} must be a non-empty string of at most 512 characters")
    return value


def _required_digest(value: Any, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PersistenceError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _approval_origin_matches_operation(
    operation: Operation, record_origin: str
) -> bool:
    return (
        operation.protocol_version == SCHEMA_VERSION
        and record_origin == "native_v3"
    ) or (
        operation.protocol_version == RESULT_SCHEMA_VERSION
        and record_origin == "native_v2"
    )


def _canonical_object_json(value: Any, field: str) -> str:
    if type(value) is not dict:
        raise PersistenceError(f"{field} must be an object")
    try:
        return canonical_json(value).decode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PersistenceError(f"{field} must be canonical JSON") from exc


def _canonical_object_digest(value: Any, field: str) -> tuple[str, str]:
    encoded = _canonical_object_json(value, field)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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


def _operation_protocol_payload(
    operation_id: str, protocol_version: int
) -> dict[str, Any]:
    return {
        "operation_id": operation_id,
        "protocol_version": protocol_version,
    }


def _operation_protocol_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _precheck_event_id(
    operation: Operation, evidence_digest: str
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "evidence_digest": evidence_digest,
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
            }
        )
    ).hexdigest()
    return f"operation.prechecked:{digest}"


def _precheck_record_payload(
    *,
    operation: Operation,
    evidence_digest: str,
    evidence_json: str,
    occurred_at: datetime,
    audit_event_id: str,
) -> dict[str, Any]:
    return {
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_revision": operation.revision,
        "principal": operation.principal,
        "user_id": operation.user_id,
        "company_id": operation.company_id,
        "evidence_digest": evidence_digest,
        "evidence_json": evidence_json,
        "occurred_at": _utc_text(occurred_at, "precheck.occurred_at"),
        "audit_event_id": audit_event_id,
    }


def _precheck_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _precheck_audit_payload(
    operation: Operation,
    *,
    evidence_digest: str,
    record_hash: str,
) -> dict[str, Any]:
    return {
        "approval_record_hash": None,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "content_digest": evidence_digest,
        "from_revision": operation.revision,
        "from_state": operation.state.value,
        "operation_digest": operation.digest,
        "precheck_digest": evidence_digest,
        "precheck_record_hash": record_hash,
        "principal": operation.principal,
        "protocol_version": operation.protocol_version,
        "request_id": operation.request_id,
        "requester_user_id": operation.user_id,
        "to_revision": operation.revision + 1,
        "to_state": State.PRECHECKED.value,
    }


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
    payload = {
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
    if operation.protocol_version >= 4:
        payload["precheck_digest"] = operation.precheck_digest
        payload["protocol_version"] = operation.protocol_version
    return payload


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
    payload = {
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
    if operation.protocol_version >= 4:
        payload["precheck_digest"] = operation.precheck_digest
        payload["protocol_version"] = operation.protocol_version
    return payload


def _generic_transition_event_id(
    operation: Operation, target: State
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "target_state": target.value,
            }
        )
    ).hexdigest()
    return f"operation.{target.value}:{digest}"


def _generic_transition_audit_payload(
    current: Operation, updated: Operation
) -> dict[str, Any]:
    updated_payload = _operation_payload(updated)
    payload = {
        "approval_record_hash": None,
        "capability_id": current.capability_id,
        "company_id": current.company_id,
        "content_digest": _operation_record_hash(updated_payload),
        "from_revision": current.revision,
        "from_state": current.state.value,
        "operation_digest": current.digest,
        "principal": current.principal,
        "request_id": current.request_id,
        "requester_user_id": current.user_id,
        "to_revision": updated.revision,
        "to_state": updated.state.value,
    }
    if current.protocol_version >= 4:
        payload["precheck_digest"] = current.precheck_digest
        payload["protocol_version"] = current.protocol_version
    return payload


def _trusted_result_id(result: TrustedResult) -> str:
    return "trusted-result:" + hashlib.sha256(
        canonical_json(result.payload())
    ).hexdigest()


def _result_event_id(
    operation: Operation, result: TrustedResult, target: State
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "result_id": _trusted_result_id(result),
                "target_state": target.value,
            }
        )
    ).hexdigest()
    return f"operation.{target.value}:{digest}"


def _trusted_result_payload(
    *,
    operation: Operation,
    approval_record: StoredApprovalRecord,
    result: TrustedResult,
    evidence_json: str,
    accepted_at: datetime,
    audit_event_id: str,
) -> dict[str, Any]:
    return {
        "result_id": _trusted_result_id(result),
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_state_digest": result.operation_state_digest,
        "operation_revision": operation.revision,
        "requester_user_id": operation.user_id,
        "requester_principal": operation.principal,
        "company_id": operation.company_id,
        "approval_record_hash": approval_record.record_hash,
        "kind": result.kind.value,
        "succeeded": int(result.succeeded),
        "evidence_digest": result.evidence_digest,
        "evidence_json": evidence_json,
        "prior_evidence_digest": result.prior_evidence_digest,
        "issuer": result.issuer,
        "key_id": result.key_id,
        "signature_version": result.signature_version,
        "signature_purpose": result.signature_purpose,
        "signature": result.signature,
        "issued_at": _utc_text(result.issued_at, "result.issued_at"),
        "accepted_at": _utc_text(accepted_at, "result.accepted_at"),
        "audit_event_id": audit_event_id,
    }


def _trusted_result_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _final_receipt_body(
    *,
    operation: Operation,
    result: TrustedResult,
    evidence: dict[str, Any],
    result_id: str,
    result_record_hash: str,
    receipt_details: dict[str, Any],
    audit_event: StoredAuditEvent,
) -> dict[str, Any]:
    return {
        "audit_event_hash": audit_event.event_hash,
        "audit_event_id": audit_event.event_id,
        "audit_sequence": audit_event.sequence,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "database_name": operation.database_name,
        "database_uuid": operation.database_uuid,
        "environment": operation.environment,
        "evidence": evidence,
        "evidence_digest": result.evidence_digest,
        "odoo_instance_id": operation.odoo_instance_id,
        "operation_digest": operation.digest,
        "operation_id": operation.operation_id,
        "operation_revision": operation.revision,
        "precheck_digest": operation.precheck_digest,
        "principal": operation.principal,
        "protocol_version": operation.protocol_version,
        "receipt_details": receipt_details,
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
        "request_id": operation.request_id,
        "result_id": result_id,
        "result_kind": result.kind.value,
        "result_record_hash": result_record_hash,
        "result_succeeded": result.succeeded,
        "schema_version": SCHEMA_VERSION,
        "terminal_state": operation.state.value,
        "user_id": operation.user_id,
    }


def _final_receipt_id(
    operation: Operation,
    *,
    result_id: str,
    body_digest: str,
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "body_digest": body_digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "result_id": result_id,
            }
        )
    ).hexdigest()
    return f"final-write-receipt:{digest}"


def _final_receipt_payload(
    *,
    operation: Operation,
    result: TrustedResult,
    body_json: str,
    body_digest: str,
    recorded_at: datetime,
    audit_event_id: str,
) -> dict[str, Any]:
    result_id = _trusted_result_id(result)
    return {
        "receipt_id": _final_receipt_id(
            operation, result_id=result_id, body_digest=body_digest
        ),
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_revision": operation.revision,
        "terminal_state": operation.state.value,
        "protocol_version": operation.protocol_version,
        "principal": operation.principal,
        "user_id": operation.user_id,
        "company_id": operation.company_id,
        "result_id": result_id,
        "result_kind": result.kind.value,
        "result_succeeded": int(result.succeeded),
        "evidence_digest": result.evidence_digest,
        "body_digest": body_digest,
        "body_json": body_json,
        "recorded_at": _utc_text(recorded_at, "receipt.recorded_at"),
        "audit_event_id": audit_event_id,
    }


def _final_receipt_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _recovery_operation_binding_event_id(recovery_operation_id: str) -> str:
    recovery_operation_id = _required_text(
        recovery_operation_id, "recovery_operation_id"
    )
    digest = hashlib.sha256(
        canonical_json(
            {
                "namespace": "recovery_operation_binding_v1",
                "recovery_operation_id": recovery_operation_id,
            }
        )
    ).hexdigest()
    return f"{_RECOVERY_BINDING_EVENT_PREFIX}{digest}"


def _recovery_operation_binding_payload(
    *,
    origin: Operation,
    recovery: Operation,
    origin_receipt: StoredFinalWriteReceipt,
    origin_execution: StoredTrustedResultRecord,
    plan_digest: str,
) -> dict[str, Any]:
    return {
        "binding_version": 1,
        "company_id": origin.company_id,
        "database_name": origin.database_name,
        "database_uuid": origin.database_uuid,
        "environment": origin.environment,
        "odoo_instance_id": origin.odoo_instance_id,
        "origin_execution_evidence_digest": origin_execution.evidence_digest,
        "origin_execution_result_id": origin_execution.result_id,
        "origin_final_receipt_body_digest": origin_receipt.body_digest,
        "origin_final_receipt_id": origin_receipt.receipt_id,
        "origin_operation_digest": origin.digest,
        "origin_operation_id": origin.operation_id,
        "origin_operation_revision": origin_receipt.operation_revision,
        "origin_request_id": origin.request_id,
        "origin_result_evidence_digest": origin_receipt.evidence_digest,
        "origin_result_id": origin_receipt.result_id,
        "origin_terminal_state": origin_receipt.terminal_state,
        "plan_digest": plan_digest,
        "principal": origin.principal,
        "recovery_operation_digest": recovery.digest,
        "recovery_operation_id": recovery.operation_id,
        "recovery_operation_revision": 0,
        "recovery_request_id": recovery.request_id,
        "registry_digest": origin.registry_digest,
        "release_digest": origin.release_digest,
        "user_id": origin.user_id,
    }


def _result_audit_payload(
    operation: Operation,
    approval_record: StoredApprovalRecord,
    result: TrustedResult,
    *,
    target: State,
    result_record_hash: str,
    final_receipt_required: bool = False,
    final_receipt_details_digest: str | None = None,
) -> dict[str, Any]:
    payload = {
        "approval_record_hash": approval_record.record_hash,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "content_digest": result.evidence_digest,
        "from_revision": operation.revision,
        "from_state": operation.state.value,
        "operation_digest": operation.digest,
        "principal": operation.principal,
        "request_id": operation.request_id,
        "requester_user_id": operation.user_id,
        "result_evidence_digest": result.evidence_digest,
        "result_id": _trusted_result_id(result),
        "result_issuer": result.issuer,
        "result_key_id": result.key_id,
        "result_kind": result.kind.value,
        "result_prior_evidence_digest": result.prior_evidence_digest,
        "result_record_hash": result_record_hash,
        "result_succeeded": result.succeeded,
        "to_revision": operation.revision + 1,
        "to_state": target.value,
    }
    if operation.protocol_version >= 4:
        payload["precheck_digest"] = operation.precheck_digest
        payload["protocol_version"] = operation.protocol_version
    if final_receipt_required:
        _required_digest(
            final_receipt_details_digest,
            "final_receipt_details_digest",
        )
        payload["final_receipt_required"] = True
        payload["final_receipt_details_digest"] = (
            final_receipt_details_digest
        )
    elif final_receipt_details_digest is not None:
        raise PersistenceError(
            "nonterminal audit cannot bind final receipt details"
        )
    return payload


def _recovery_id(
    operation: Operation,
    *,
    plan_digest: str,
    actor_principal: str,
    actor_user_id: int,
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "actor_principal": actor_principal,
                "actor_user_id": actor_user_id,
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "plan_digest": plan_digest,
            }
        )
    ).hexdigest()
    return f"recovery:{digest}"


def _recovery_event_id(recovery_id: str) -> str:
    return "operation.recovering:" + hashlib.sha256(
        recovery_id.encode("utf-8")
    ).hexdigest()


def _recovery_payload(
    *,
    operation: Operation,
    approval_record: StoredApprovalRecord,
    plan_digest: str,
    plan_json: str,
    actor_principal: str,
    actor_user_id: int,
    initiated_at: datetime,
    audit_event_id: str,
) -> dict[str, Any]:
    return {
        "recovery_id": _recovery_id(
            operation,
            plan_digest=plan_digest,
            actor_principal=actor_principal,
            actor_user_id=actor_user_id,
        ),
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "operation_digest": operation.digest,
        "operation_revision": operation.revision,
        "from_state": operation.state.value,
        "actor_principal": actor_principal,
        "actor_user_id": actor_user_id,
        "company_id": operation.company_id,
        "approval_record_hash": approval_record.record_hash,
        "plan_digest": plan_digest,
        "plan_json": plan_json,
        "initiated_at": _utc_text(initiated_at, "recovery.initiated_at"),
        "audit_event_id": audit_event_id,
    }


def _recovery_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _recovery_audit_payload(
    operation: Operation,
    approval_record: StoredApprovalRecord,
    *,
    recovery_id: str,
    recovery_record_hash: str,
    plan_digest: str,
    actor_principal: str,
    actor_user_id: int,
) -> dict[str, Any]:
    payload = {
        "actor_principal": actor_principal,
        "actor_user_id": actor_user_id,
        "approval_record_hash": approval_record.record_hash,
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "content_digest": plan_digest,
        "from_revision": operation.revision,
        "from_state": operation.state.value,
        "operation_digest": operation.digest,
        "principal": operation.principal,
        "recovery_id": recovery_id,
        "recovery_plan_digest": plan_digest,
        "recovery_record_hash": recovery_record_hash,
        "request_id": operation.request_id,
        "requester_user_id": operation.user_id,
        "to_revision": operation.revision + 1,
        "to_state": State.RECOVERING.value,
    }
    if operation.protocol_version >= 4:
        payload["precheck_digest"] = operation.precheck_digest
        payload["protocol_version"] = operation.protocol_version
    return payload


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
        "record_origin": "native_v3",
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
            timeout=bounded_sqlite_connect_timeout_seconds(self.busy_timeout_ms),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            busy_timeout_ms = bounded_sqlite_busy_timeout_ms(self.busy_timeout_ms)
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
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
        elif version == PREVIOUS_SCHEMA_VERSION:
            expected_columns = _EXPECTED_COLUMNS_V2
            expected_tables = _TABLE_SCHEMAS_V2
            expected_triggers = _TRIGGER_SCHEMAS_V2
        elif version == RESULT_SCHEMA_VERSION:
            expected_columns = _EXPECTED_COLUMNS_V3
            expected_tables = _TABLE_SCHEMAS_V3
            expected_triggers = _TRIGGER_SCHEMAS_V3
        elif version == SCHEMA_VERSION:
            expected_columns = _EXPECTED_COLUMNS_V4
            expected_tables = _TABLE_SCHEMAS_V4
            expected_triggers = _TRIGGER_SCHEMAS_V4
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

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone() is not None

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
        cls,
        connection: sqlite3.Connection,
        *,
        include_approvals: bool,
        include_results: bool = False,
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
        if include_results:
            cls._verify_result_and_recovery_evidence(connection, operation_ids)

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
    def _verify_result_and_recovery_state(
        cls, connection: sqlite3.Connection, operation: Operation
    ) -> None:
        operation_id = operation.operation_id
        if operation.state in {State.VERIFYING, State.COMPLETED}:
            execution = connection.execute(
                "SELECT succeeded, evidence_digest FROM trusted_result_records "
                "WHERE operation_id = ? AND kind = 'execution'",
                (operation_id,),
            ).fetchone()
            if (
                execution is None
                or execution["succeeded"] != 1
                or execution["evidence_digest"]
                != operation.execution_result_digest
            ):
                raise PersistenceIntegrityError(
                    "stored operation lacks execution result evidence"
                )
        if operation.state == State.COMPLETED:
            verification = connection.execute(
                "SELECT succeeded, evidence_digest FROM trusted_result_records "
                "WHERE operation_id = ? AND kind = 'verification'",
                (operation_id,),
            ).fetchone()
            if (
                verification is None
                or verification["succeeded"] != 1
                or verification["evidence_digest"]
                != operation.verification_result_digest
            ):
                raise PersistenceIntegrityError(
                    "stored completed operation lacks verification evidence"
                )
        if operation.state == State.FAILED:
            negative = connection.execute(
                "SELECT kind, succeeded, evidence_digest "
                "FROM trusted_result_records "
                "WHERE operation_id = ? AND operation_revision = ?",
                (operation_id, operation.revision - 1),
            ).fetchone()
            if (
                negative is None
                or negative["succeeded"] != 0
                or (
                    negative["kind"] == ResultKind.EXECUTION.value
                    and negative["evidence_digest"]
                    != operation.execution_result_digest
                )
                or (
                    negative["kind"] == ResultKind.VERIFICATION.value
                    and negative["evidence_digest"]
                    != operation.verification_result_digest
                )
            ):
                raise PersistenceIntegrityError(
                    "stored failed operation lacks negative result evidence"
                )
        if operation.state == State.RECOVERING:
            recovery = connection.execute(
                "SELECT 1 FROM recovery_records "
                "WHERE operation_id = ? AND operation_revision = ?",
                (operation_id, operation.revision - 1),
            ).fetchone()
            if recovery is None:
                raise PersistenceIntegrityError(
                    "stored recovering operation lacks recovery evidence"
                )
        if operation.state == State.RECOVERED:
            positive = connection.execute(
                "SELECT succeeded FROM trusted_result_records "
                "WHERE operation_id = ? AND operation_revision = ? "
                "AND kind = 'recovery'",
                (operation_id, operation.revision - 1),
            ).fetchone()
            if positive is None or positive["succeeded"] != 1:
                raise PersistenceIntegrityError(
                    "stored recovered operation lacks recovery result evidence"
                )
        if (
            operation.protocol_version == SCHEMA_VERSION
            and operation.state
            in {State.COMPLETED, State.FAILED, State.RECOVERED}
        ):
            receipt = connection.execute(
                "SELECT 1 FROM final_write_receipts "
                "WHERE operation_id = ? AND operation_revision = ? "
                "AND terminal_state = ?",
                (
                    operation_id,
                    operation.revision,
                    operation.state.value,
                ),
            ).fetchone()
            if receipt is None:
                raise PersistenceIntegrityError(
                    "stored native terminal operation lacks a final write receipt"
                )

    @classmethod
    def _verify_result_and_recovery_evidence(
        cls,
        connection: sqlite3.Connection,
        operation_ids: tuple[str, ...],
    ) -> None:
        result_ids = tuple(
            row["result_id"]
            for row in connection.execute(
                "SELECT result_id FROM trusted_result_records "
                "ORDER BY operation_id, operation_revision"
            )
        )
        for result_id in result_ids:
            cls._load_trusted_result_record(connection, result_id)
        recovery_ids = tuple(
            row["recovery_id"]
            for row in connection.execute(
                "SELECT recovery_id FROM recovery_records "
                "ORDER BY operation_id, operation_revision"
            )
        )
        for recovery_id in recovery_ids:
            cls._load_recovery_record(connection, recovery_id)

        for operation_id in operation_ids:
            operation = cls._load_operation(connection, operation_id)
            cls._verify_result_and_recovery_state(connection, operation)

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
                "WHERE record_origin IN ('native_v2', 'native_v3')"
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
                WHERE approval.record_origin IN ('native_v2', 'native_v3')
                  AND operation.state IN (
                    'executing', 'verifying', 'completed', 'failed',
                    'recovering', 'recovered'
                  )
                """
            )
        }
        native_result_events = {
            row["audit_event_id"]: (
                "operation.failed"
                if row["succeeded"] == 0
                else {
                    "execution": "operation.verifying",
                    "verification": "operation.completed",
                    "recovery": "operation.recovered",
                }[row["kind"]]
            )
            for row in connection.execute(
                "SELECT audit_event_id, kind, succeeded FROM trusted_result_records"
            )
        } if cls._table_exists(connection, "trusted_result_records") else {}
        native_recovery_ids = {
            row["audit_event_id"]
            for row in connection.execute(
                "SELECT audit_event_id FROM recovery_records"
            )
        } if cls._table_exists(connection, "recovery_records") else set()
        native_precheck_ids = {
            row["audit_event_id"]
            for row in connection.execute(
                "SELECT audit_event_id FROM precheck_records"
            )
        } if cls._table_exists(connection, "precheck_records") else set()
        native_generic_events: dict[str, str] = {}
        for row in connection.execute("SELECT operation_id FROM operations"):
            operation = cls._load_operation(connection, row["operation_id"])
            native_generic_events.update(
                {
                    event_id: evidence[0]
                    for event_id, evidence in cls._expected_generic_transition_events(
                        operation
                    ).items()
                }
            )
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
            recovery_binding_id = event.event_id.startswith(
                _RECOVERY_BINDING_EVENT_PREFIX
            )
            recovery_binding_type = event.event_type.startswith(
                "recovery.binding."
            )
            if recovery_binding_id or recovery_binding_type:
                if (
                    not recovery_binding_id
                    or event.event_type != _RECOVERY_BINDING_EVENT_TYPE
                ):
                    raise PersistenceIntegrityError(
                        "stored recovery operation binding namespace is ambiguous"
                    )
                if not cls._table_exists(connection, "final_write_receipts"):
                    raise PersistenceIntegrityError(
                        "legacy recovery operation binding cannot be migrated"
                    )
                cls._load_recovery_operation_binding_event(connection, event)
                continue
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
            elif event.event_type in {
                "operation.prechecked",
                "operation.awaiting_approval",
            }:
                valid = (
                    event.event_type == "operation.prechecked"
                    and event.event_id in native_precheck_ids
                ) or (
                    native_generic_events.get(event.event_id)
                    == event.event_type
                )
            elif event.event_type == "operation.executing":
                valid = event.event_id in native_execution_ids
            elif event.event_type in {
                "operation.verifying",
                "operation.completed",
                "operation.failed",
                "operation.recovered",
            }:
                valid = native_result_events.get(event.event_id) == event.event_type
            elif event.event_type == "operation.recovering":
                valid = event.event_id in native_recovery_ids
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
            reserved_id = event.event_id.startswith(
                ("operation.", "read:", _RECOVERY_BINDING_EVENT_PREFIX)
            )
            reserved_type = event.event_type.startswith(
                ("operation.", "read.", "recovery.binding.")
            )
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
                for statement in _SCHEMA_V4:
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
                    (str(PREVIOUS_SCHEMA_VERSION), str(LEGACY_SCHEMA_VERSION)),
                )
                if cursor.rowcount != 1:
                    raise PersistenceIntegrityError(
                        "persistence schema metadata changed during migration"
                    )
                connection.execute(
                    f"PRAGMA user_version = {PREVIOUS_SCHEMA_VERSION}"
                )
                current_version = PREVIOUS_SCHEMA_VERSION
            elif current_version not in {
                PREVIOUS_SCHEMA_VERSION,
                RESULT_SCHEMA_VERSION,
                SCHEMA_VERSION,
            }:
                raise PersistenceIntegrityError(
                    "unsupported persistence schema version"
                )

            if current_version == PREVIOUS_SCHEMA_VERSION:
                self._verify_schema(connection, PREVIOUS_SCHEMA_VERSION)
                self._verify_sqlite_integrity(connection)
                self._verify_stored_data(
                    connection,
                    include_approvals=True,
                    include_results=False,
                )
                connection.execute(
                    "DROP TRIGGER operations_unimplemented_protected_states_closed"
                )
                connection.execute(_TRUSTED_RESULT_RECORD_SCHEMA)
                connection.execute(_RECOVERY_RECORD_SCHEMA)
                for statement in _RESULT_RECOVERY_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                cursor = connection.execute(
                    "UPDATE schema_meta SET value = ? "
                    "WHERE key = 'schema_version' AND value = ?",
                    (str(RESULT_SCHEMA_VERSION), str(PREVIOUS_SCHEMA_VERSION)),
                )
                if cursor.rowcount != 1:
                    raise PersistenceIntegrityError(
                        "persistence schema metadata changed during migration"
                    )
                connection.execute(
                    f"PRAGMA user_version = {RESULT_SCHEMA_VERSION}"
                )
                current_version = RESULT_SCHEMA_VERSION

            if current_version == RESULT_SCHEMA_VERSION:
                self._verify_schema(connection, RESULT_SCHEMA_VERSION)
                self._verify_sqlite_integrity(connection)
                self._verify_stored_data(
                    connection,
                    include_approvals=True,
                    include_results=True,
                )
                connection.execute(_OPERATION_PROTOCOL_SCHEMA)
                connection.execute(_PRECHECK_RECORD_SCHEMA)
                connection.execute(_FINAL_WRITE_RECEIPT_SCHEMA)
                for row in connection.execute(
                    "SELECT operation_id FROM operations ORDER BY operation_id"
                ):
                    protocol_payload = _operation_protocol_payload(
                        row["operation_id"], RESULT_SCHEMA_VERSION
                    )
                    connection.execute(
                        "INSERT INTO operation_protocols("
                        "operation_id, protocol_version, record_hash) "
                        "VALUES(?, ?, ?)",
                        (
                            protocol_payload["operation_id"],
                            protocol_payload["protocol_version"],
                            _operation_protocol_record_hash(protocol_payload),
                        ),
                    )
                for trigger_name in (
                    "approval_records_no_update",
                    "approval_records_no_delete",
                    "approval_records_native_only",
                    "approval_records_bind_awaiting_operation",
                    "operations_approved_requires_native_approval",
                    "operations_executing_requires_native_approval",
                    "trusted_result_records_bind_operation",
                    "recovery_records_bind_operation",
                ):
                    connection.execute(f"DROP TRIGGER {trigger_name}")
                connection.execute(_APPROVAL_RECORD_SCHEMA_V4_TEMP)
                connection.execute(
                    f"INSERT INTO approval_records_v4("
                    f"{', '.join(_APPROVAL_RECORD_COLUMNS)}) "
                    f"SELECT {', '.join(_APPROVAL_RECORD_COLUMNS)} "
                    "FROM approval_records"
                )
                connection.execute("DROP TABLE approval_records")
                connection.execute(
                    "ALTER TABLE approval_records_v4 "
                    "RENAME TO approval_records"
                )
                for trigger_name in (
                    "operations_completed_requires_result",
                    "operations_failed_requires_result",
                    "operations_recovered_requires_result",
                ):
                    connection.execute(f"DROP TRIGGER {trigger_name}")
                for statement in _CONTROL_V4_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                for statement in _APPROVAL_TRIGGER_SCHEMAS[:2]:
                    connection.execute(statement)
                for statement in _APPROVAL_V4_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                for statement in _RESULT_BIND_V4_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                for statement in _TERMINAL_V4_TRIGGER_SCHEMAS:
                    connection.execute(statement)
                cursor = connection.execute(
                    "UPDATE schema_meta SET value = ? "
                    "WHERE key = 'schema_version' AND value = ?",
                    (str(SCHEMA_VERSION), str(RESULT_SCHEMA_VERSION)),
                )
                if cursor.rowcount != 1:
                    raise PersistenceIntegrityError(
                        "persistence schema metadata changed during migration"
                    )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

            self._verify_schema(connection, SCHEMA_VERSION)
            self._verify_sqlite_integrity(connection)
            self._verify_or_bind_receipt_verifier(connection)
            self._verify_stored_data(
                connection,
                include_approvals=True,
                include_results=True,
            )

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
        if operation.protocol_version != SCHEMA_VERSION:
            raise PersistenceIntegrityError(
                "new operation must use the current persistence protocol"
            )
        payload = _operation_payload(operation)
        columns = (*_OPERATION_COLUMNS, "record_hash")
        values = tuple(payload[column] for column in _OPERATION_COLUMNS) + (
            _operation_record_hash(payload),
        )
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO operations({', '.join(columns)}) VALUES({placeholders})", values
        )

        protocol_payload = _operation_protocol_payload(
            operation.operation_id, operation.protocol_version
        )
        connection.execute(
            "INSERT INTO operation_protocols("
            "operation_id, protocol_version, record_hash) VALUES(?, ?, ?)",
            (
                protocol_payload["operation_id"],
                protocol_payload["protocol_version"],
                _operation_protocol_record_hash(protocol_payload),
            ),
        )

    @classmethod
    def _load_operation_protocol(
        cls, connection: sqlite3.Connection, operation_id: str
    ) -> int:
        if not cls._table_exists(connection, "operation_protocols"):
            return RESULT_SCHEMA_VERSION
        row = connection.execute(
            "SELECT operation_id, protocol_version, record_hash "
            "FROM operation_protocols WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise PersistenceIntegrityError(
                "stored operation has no protocol binding"
            )
        payload = _operation_protocol_payload(
            row["operation_id"], row["protocol_version"]
        )
        if (
            row["operation_id"] != operation_id
            or type(row["protocol_version"]) is not int
            or row["protocol_version"] not in {
                RESULT_SCHEMA_VERSION,
                SCHEMA_VERSION,
            }
            or type(row["record_hash"]) is not str
            or not hmac.compare_digest(
                row["record_hash"], _operation_protocol_record_hash(payload)
            )
        ):
            raise PersistenceIntegrityError(
                "stored operation protocol binding is invalid"
            )
        return row["protocol_version"]

    @classmethod
    def _load_precheck_record(
        cls,
        connection: sqlite3.Connection,
        operation_id: str,
        *,
        operation: Operation,
    ) -> StoredPrecheckRecord:
        row = connection.execute(
            f"SELECT {', '.join(_PRECHECK_RECORD_COLUMNS)} "
            "FROM precheck_records WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("precheck record does not exist")
        payload = {
            column: row[column] for column in _PRECHECK_RECORD_COLUMNS[:-1]
        }
        if (
            type(row["record_hash"]) is not str
            or not hmac.compare_digest(
                row["record_hash"], _precheck_record_hash(payload)
            )
        ):
            raise PersistenceIntegrityError(
                "stored precheck record hash mismatch"
            )
        try:
            occurred_at = _parse_datetime(
                row["occurred_at"], "precheck occurred_at"
            )
            evidence = json.loads(row["evidence_json"])
            record = StoredPrecheckRecord(
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                operation_digest=row["operation_digest"],
                operation_revision=row["operation_revision"],
                principal=row["principal"],
                user_id=row["user_id"],
                company_id=row["company_id"],
                evidence_digest=row["evidence_digest"],
                evidence_json=row["evidence_json"],
                occurred_at=occurred_at,
                audit_event_id=row["audit_event_id"],
                record_hash=row["record_hash"],
            )
        except (PersistenceError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError(
                "stored precheck record is invalid"
            ) from exc
        canonical_payload = {
            **{
                column: getattr(record, column)
                for column in _PRECHECK_RECORD_COLUMNS[:-1]
                if column != "occurred_at"
            },
            "occurred_at": _utc_text(record.occurred_at, "precheck occurred_at"),
        }
        prepared = replace(
            operation,
            state=State.PREPARED,
            revision=0,
            precheck_digest=None,
            approval_signature=None,
            approval_nonce_digest=None,
            approval_issued_at=None,
            approval_expires_at=None,
            approval_revision=None,
            approver_user_id=None,
            execution_result_digest=None,
            verification_result_digest=None,
        )
        event = next(
            (
                item
                for item in cls._load_audit_events(connection)
                if item.event_id == record.audit_event_id
            ),
            None,
        )
        expected_event_id = _precheck_event_id(
            prepared, record.evidence_digest
        )
        expected_audit = _precheck_audit_payload(
            prepared,
            evidence_digest=record.evidence_digest,
            record_hash=record.record_hash,
        )
        if (
            payload != canonical_payload
            or operation.protocol_version != SCHEMA_VERSION
            or operation.precheck_digest != record.evidence_digest
            or record.operation_id != operation.operation_id
            or record.request_id != operation.request_id
            or record.operation_digest != operation.digest
            or record.operation_revision != 0
            or record.principal != operation.principal
            or record.user_id != operation.user_id
            or record.company_id != operation.company_id
            or type(evidence) is not dict
            or canonical_json(evidence).decode("utf-8") != record.evidence_json
            or hashlib.sha256(record.evidence_json.encode("utf-8")).hexdigest()
            != record.evidence_digest
            or record.audit_event_id != expected_event_id
            or event is None
            or event.event_type != "operation.prechecked"
            or event.operation_id != operation.operation_id
            or event.occurred_at != record.occurred_at
            or canonical_json(event.payload) != canonical_json(expected_audit)
        ):
            raise PersistenceIntegrityError(
                "stored precheck evidence is invalid"
            )
        return record

    @classmethod
    def _load_operation(cls, connection: sqlite3.Connection, operation_id: str) -> Operation:
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
        protocol_version = cls._load_operation_protocol(
            connection, operation_id
        )
        precheck_row = (
            connection.execute(
                "SELECT evidence_digest FROM precheck_records "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if cls._table_exists(connection, "precheck_records")
            else None
        )
        precheck_digest = (
            None if precheck_row is None else precheck_row["evidence_digest"]
        )
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
                protocol_version=protocol_version,
                precheck_digest=precheck_digest,
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
        if protocol_version == RESULT_SCHEMA_VERSION and precheck_row is not None:
            raise PersistenceIntegrityError(
                "legacy operation cannot have native precheck evidence"
            )
        if protocol_version == SCHEMA_VERSION:
            if operation.state == State.PREPARED and precheck_row is not None:
                raise PersistenceIntegrityError(
                    "prepared operation has premature precheck evidence"
                )
            if operation.state != State.PREPARED:
                if precheck_row is None:
                    raise PersistenceIntegrityError(
                        "native operation has no durable precheck evidence"
                    )
                cls._load_precheck_record(
                    connection, operation_id, operation=operation
                )
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
        if record.record_origin in {"native_v2", "native_v3"}:
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
                (
                    record.record_origin == "native_v3"
                    and (
                        operation.protocol_version != SCHEMA_VERSION
                        or record.signature_version != 3
                        or record.signature_purpose != "approval_v3"
                    )
                )
                or (
                    record.record_origin == "native_v2"
                    and (
                        operation.protocol_version != RESULT_SCHEMA_VERSION
                        or record.signature_version != 2
                        or record.signature_purpose != "approval_v2"
                    )
                )
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
                State.FAILED,
                State.RECOVERING,
                State.RECOVERED,
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
    def _load_final_write_receipt(
        cls,
        connection: sqlite3.Connection,
        receipt_id: str,
        *,
        terminal_operation: Operation,
        result_record: StoredTrustedResultRecord,
        trusted_result: TrustedResult,
        audit_event: StoredAuditEvent,
    ) -> StoredFinalWriteReceipt:
        row = connection.execute(
            f"SELECT {', '.join(_FINAL_WRITE_RECEIPT_COLUMNS)} "
            "FROM final_write_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("final write receipt does not exist")
        payload = {
            column: row[column]
            for column in _FINAL_WRITE_RECEIPT_COLUMNS[:-1]
        }
        if (
            type(row["record_hash"]) is not str
            or not hmac.compare_digest(
                row["record_hash"], _final_receipt_record_hash(payload)
            )
        ):
            raise PersistenceIntegrityError(
                "stored final write receipt hash mismatch"
            )
        try:
            recorded_at = _parse_datetime(
                row["recorded_at"], "final receipt recorded_at"
            )
            body = json.loads(row["body_json"])
            if (
                type(row["result_succeeded"]) is not int
                or row["result_succeeded"] not in {0, 1}
            ):
                raise ValueError("invalid result_succeeded representation")
            record = StoredFinalWriteReceipt(
                receipt_id=row["receipt_id"],
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                operation_digest=row["operation_digest"],
                operation_revision=row["operation_revision"],
                terminal_state=row["terminal_state"],
                protocol_version=row["protocol_version"],
                principal=row["principal"],
                user_id=row["user_id"],
                company_id=row["company_id"],
                result_id=row["result_id"],
                result_kind=row["result_kind"],
                result_succeeded=bool(row["result_succeeded"]),
                evidence_digest=row["evidence_digest"],
                body_digest=row["body_digest"],
                body_json=row["body_json"],
                recorded_at=recorded_at,
                audit_event_id=row["audit_event_id"],
                record_hash=row["record_hash"],
            )
        except (PersistenceError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError(
                "stored final write receipt is invalid"
            ) from exc
        canonical_payload = {
            **{
                column: getattr(record, column)
                for column in _FINAL_WRITE_RECEIPT_COLUMNS[:-1]
                if column not in {"result_succeeded", "recorded_at"}
            },
            "result_succeeded": int(record.result_succeeded),
            "recorded_at": _utc_text(
                record.recorded_at, "final receipt recorded_at"
            ),
        }
        receipt_details = (
            body.get("receipt_details") if isinstance(body, dict) else None
        )
        receipt_details_digest = (
            hashlib.sha256(canonical_json(receipt_details)).hexdigest()
            if isinstance(receipt_details, dict)
            else None
        )
        expected_body = (
            None
            if not isinstance(receipt_details, dict)
            else _final_receipt_body(
                operation=terminal_operation,
                result=trusted_result,
                evidence=result_record.evidence,
                result_id=result_record.result_id,
                result_record_hash=result_record.record_hash,
                receipt_details=receipt_details,
                audit_event=audit_event,
            )
        )
        if (
            payload != canonical_payload
            or terminal_operation.state
            not in {State.COMPLETED, State.FAILED, State.RECOVERED}
            or record.operation_id != terminal_operation.operation_id
            or record.request_id != terminal_operation.request_id
            or record.operation_digest != terminal_operation.digest
            or record.operation_revision != terminal_operation.revision
            or record.terminal_state != terminal_operation.state.value
            or record.protocol_version != terminal_operation.protocol_version
            or record.principal != terminal_operation.principal
            or record.user_id != terminal_operation.user_id
            or record.company_id != terminal_operation.company_id
            or record.result_id != result_record.result_id
            or record.result_kind != result_record.kind
            or record.result_succeeded != result_record.succeeded
            or record.evidence_digest != result_record.evidence_digest
            or record.recorded_at != result_record.accepted_at
            or record.recorded_at != audit_event.occurred_at
            or record.audit_event_id != audit_event.event_id
            or audit_event.payload.get("final_receipt_required") is not True
            or type(
                audit_event.payload.get("final_receipt_details_digest")
            )
            is not str
            or receipt_details_digest is None
            or not hmac.compare_digest(
                audit_event.payload["final_receipt_details_digest"],
                receipt_details_digest,
            )
            or record.receipt_id
            != _final_receipt_id(
                terminal_operation,
                result_id=result_record.result_id,
                body_digest=record.body_digest,
            )
            or type(body) is not dict
            or canonical_json(body).decode("utf-8") != record.body_json
            or hashlib.sha256(record.body_json.encode("utf-8")).hexdigest()
            != record.body_digest
            or expected_body is None
            or canonical_json(body) != canonical_json(expected_body)
        ):
            raise PersistenceIntegrityError(
                "stored final write receipt is invalid"
            )
        return record

    @classmethod
    def _load_trusted_result_record(
        cls, connection: sqlite3.Connection, result_id: str
    ) -> StoredTrustedResultRecord:
        row = connection.execute(
            f"SELECT {', '.join(_TRUSTED_RESULT_RECORD_COLUMNS)} "
            "FROM trusted_result_records WHERE result_id = ?",
            (result_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("trusted result record does not exist")
        payload = {
            column: row[column]
            for column in _TRUSTED_RESULT_RECORD_COLUMNS[:-1]
        }
        expected_hash = _trusted_result_record_hash(payload)
        if type(row["record_hash"]) is not str or not hmac.compare_digest(
            expected_hash, row["record_hash"]
        ):
            raise PersistenceIntegrityError(
                "stored trusted result record hash mismatch"
            )
        try:
            issued_at = _parse_datetime(row["issued_at"], "result issued_at")
            accepted_at = _parse_datetime(
                row["accepted_at"], "result accepted_at"
            )
            kind = ResultKind(row["kind"])
            if type(row["succeeded"]) is not int or row["succeeded"] not in {0, 1}:
                raise ValueError("invalid succeeded representation")
            record = StoredTrustedResultRecord(
                result_id=row["result_id"],
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                operation_digest=row["operation_digest"],
                operation_state_digest=row["operation_state_digest"],
                operation_revision=row["operation_revision"],
                requester_user_id=row["requester_user_id"],
                requester_principal=row["requester_principal"],
                company_id=row["company_id"],
                approval_record_hash=row["approval_record_hash"],
                kind=kind.value,
                succeeded=bool(row["succeeded"]),
                evidence_digest=row["evidence_digest"],
                evidence_json=row["evidence_json"],
                prior_evidence_digest=row["prior_evidence_digest"],
                issuer=row["issuer"],
                key_id=row["key_id"],
                signature_version=row["signature_version"],
                signature_purpose=row["signature_purpose"],
                signature=row["signature"],
                issued_at=issued_at,
                accepted_at=accepted_at,
                audit_event_id=row["audit_event_id"],
                record_hash=row["record_hash"],
            )
        except (PersistenceError, TypeError, ValueError) as exc:
            raise PersistenceIntegrityError(
                "stored trusted result record is invalid"
            ) from exc
        canonical_payload = {
            **{
                column: getattr(record, column)
                for column in _TRUSTED_RESULT_RECORD_COLUMNS[:-1]
                if column
                not in {"succeeded", "issued_at", "accepted_at"}
            },
            "succeeded": int(record.succeeded),
            "issued_at": _utc_text(record.issued_at, "result issued_at"),
            "accepted_at": _utc_text(record.accepted_at, "result accepted_at"),
        }
        if payload != canonical_payload:
            raise PersistenceIntegrityError(
                "stored trusted result representation is not canonical"
            )
        try:
            evidence = json.loads(record.evidence_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError(
                "stored trusted result evidence is invalid"
            ) from exc
        digest_fields = (
            record.operation_digest,
            record.operation_state_digest,
            record.approval_record_hash,
            record.evidence_digest,
            record.signature,
        )
        if (
            any(_SHA256.fullmatch(value) is None for value in digest_fields)
            or (
                record.prior_evidence_digest is not None
                and _SHA256.fullmatch(record.prior_evidence_digest) is None
            )
            or type(record.operation_revision) is not int
            or record.operation_revision < 0
            or type(record.requester_user_id) is not int
            or record.requester_user_id <= 0
            or type(record.company_id) is not int
            or record.company_id <= 0
            or record.accepted_at < record.issued_at
            or type(record.issuer) is not str
            or not record.issuer.strip()
            or type(record.key_id) is not str
            or not record.key_id.strip()
            or type(record.signature_version) is not int
            or record.signature_version != 2
            or record.signature_purpose
            != {
                ResultKind.EXECUTION.value: "execution_result_v2",
                ResultKind.VERIFICATION.value: "verification_result_v2",
                ResultKind.RECOVERY.value: "recovery_result_v2",
            }[record.kind]
            or (
                record.kind == ResultKind.EXECUTION.value
                and record.prior_evidence_digest is not None
            )
            or (
                record.kind
                in {ResultKind.VERIFICATION.value, ResultKind.RECOVERY.value}
                and record.prior_evidence_digest is None
            )
            or type(evidence) is not dict
            or canonical_json(evidence).decode("utf-8") != record.evidence_json
            or hashlib.sha256(record.evidence_json.encode("utf-8")).hexdigest()
            != record.evidence_digest
        ):
            raise PersistenceIntegrityError(
                "stored trusted result record is invalid"
            )

        operation = cls._load_operation(connection, record.operation_id)
        approval = cls._load_approval_record(connection, record.operation_id)
        expected_state = {
            ResultKind.EXECUTION: State.EXECUTING,
            ResultKind.VERIFICATION: State.VERIFYING,
            ResultKind.RECOVERY: State.RECOVERING,
        }[kind]
        pre_operation = replace(
            operation,
            state=expected_state,
            revision=record.operation_revision,
            execution_result_digest=(
                None
                if kind == ResultKind.EXECUTION
                else operation.execution_result_digest
            ),
            verification_result_digest=(
                None
                if kind in {ResultKind.EXECUTION, ResultKind.VERIFICATION}
                else operation.verification_result_digest
            ),
        )
        try:
            pre_operation.assert_integrity()
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored trusted result operation state is invalid"
            ) from exc
        if not hmac.compare_digest(
            record.operation_state_digest,
            _operation_state_digest(pre_operation),
        ):
            raise PersistenceIntegrityError(
                "stored trusted result state digest is invalid"
            )
        trusted_result = TrustedResult(
            kind=kind,
            operation_id=record.operation_id,
            request_id=record.request_id,
            operation_digest=record.operation_digest,
            operation_state_digest=record.operation_state_digest,
            operation_revision=record.operation_revision,
            company_id=record.company_id,
            issuer=record.issuer,
            key_id=record.key_id,
            succeeded=record.succeeded,
            evidence_digest=record.evidence_digest,
            prior_evidence_digest=record.prior_evidence_digest,
            issued_at=record.issued_at,
            signature_version=record.signature_version,
            signature_purpose=record.signature_purpose,
            signature=record.signature,
        )
        target = {
            ResultKind.EXECUTION: (
                State.VERIFYING if record.succeeded else State.FAILED
            ),
            ResultKind.VERIFICATION: (
                State.COMPLETED if record.succeeded else State.FAILED
            ),
            ResultKind.RECOVERY: (
                State.RECOVERED if record.succeeded else State.FAILED
            ),
        }[kind]
        event = next(
            (
                item
                for item in cls._load_audit_events(connection)
                if item.event_id == record.audit_event_id
            ),
            None,
        )
        result_changes: dict[str, Any] = {}
        if kind == ResultKind.EXECUTION:
            result_changes["execution_result_digest"] = record.evidence_digest
        elif kind == ResultKind.VERIFICATION:
            result_changes["verification_result_digest"] = record.evidence_digest
        terminal_operation = replace(
            pre_operation,
            state=target,
            revision=pre_operation.revision + 1,
            **result_changes,
        )
        try:
            terminal_operation.assert_integrity()
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored trusted result terminal state is invalid"
            ) from exc
        receipt_row = (
            connection.execute(
                "SELECT receipt_id FROM final_write_receipts "
                "WHERE result_id = ?",
                (record.result_id,),
            ).fetchone()
            if cls._table_exists(connection, "final_write_receipts")
            else None
        )
        final_receipt = None
        if receipt_row is not None and event is not None:
            final_receipt = cls._load_final_write_receipt(
                connection,
                receipt_row["receipt_id"],
                terminal_operation=terminal_operation,
                result_record=record,
                trusted_result=trusted_result,
                audit_event=event,
            )
        if target == State.VERIFYING and receipt_row is not None:
            raise PersistenceIntegrityError(
                "nonterminal result has a final write receipt"
            )
        if (
            target in {State.COMPLETED, State.FAILED, State.RECOVERED}
            and pre_operation.protocol_version == SCHEMA_VERSION
            and final_receipt is None
        ):
            raise PersistenceIntegrityError(
                "native terminal result has no final write receipt"
            )
        final_receipt_details_digest = None
        if final_receipt is not None:
            _, final_receipt_details_digest = _canonical_object_digest(
                final_receipt.body["receipt_details"],
                "final receipt details",
            )
        expected_audit_payload = _result_audit_payload(
            pre_operation,
            approval,
            trusted_result,
            target=target,
            result_record_hash=record.record_hash,
            final_receipt_required=final_receipt is not None,
            final_receipt_details_digest=final_receipt_details_digest,
        )
        if (
            record.result_id != _trusted_result_id(trusted_result)
            or record.request_id != operation.request_id
            or record.operation_digest != operation.digest
            or record.requester_user_id != operation.user_id
            or record.requester_principal != operation.principal
            or record.company_id != operation.company_id
            or record.approval_record_hash != approval.record_hash
            or record.audit_event_id
            != _result_event_id(pre_operation, trusted_result, target)
            or event is None
            or event.event_type != f"operation.{target.value}"
            or event.operation_id != operation.operation_id
            or event.occurred_at != record.accepted_at
            or canonical_json(event.payload)
            != canonical_json(expected_audit_payload)
        ):
            raise PersistenceIntegrityError(
                "stored trusted result audit evidence is invalid"
            )
        if kind == ResultKind.VERIFICATION and (
            record.prior_evidence_digest != operation.execution_result_digest
        ):
            raise PersistenceIntegrityError(
                "stored verification result prior evidence is invalid"
            )
        if kind == ResultKind.RECOVERY:
            recovery = connection.execute(
                "SELECT plan_digest FROM recovery_records "
                "WHERE operation_id = ? AND operation_revision = ?",
                (operation.operation_id, record.operation_revision - 1),
            ).fetchone()
            if (
                recovery is None
                or recovery["plan_digest"] != record.prior_evidence_digest
            ):
                raise PersistenceIntegrityError(
                    "stored recovery result prior evidence is invalid"
                )
        return record

    @classmethod
    def _load_final_write_receipt_by_id(
        cls, connection: sqlite3.Connection, receipt_id: str
    ) -> StoredFinalWriteReceipt:
        row = connection.execute(
            "SELECT operation_id, operation_revision, terminal_state, "
            "result_id, audit_event_id FROM final_write_receipts "
            "WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("final write receipt does not exist")
        operation = cls._load_operation(connection, row["operation_id"])
        result_record = cls._load_trusted_result_record(
            connection, row["result_id"]
        )
        try:
            kind = ResultKind(result_record.kind)
            terminal_operation = replace(
                operation,
                state=State(row["terminal_state"]),
                revision=row["operation_revision"],
            )
            terminal_operation.assert_integrity()
            trusted_result = TrustedResult(
                kind=kind,
                operation_id=result_record.operation_id,
                request_id=result_record.request_id,
                operation_digest=result_record.operation_digest,
                operation_state_digest=result_record.operation_state_digest,
                operation_revision=result_record.operation_revision,
                company_id=result_record.company_id,
                issuer=result_record.issuer,
                key_id=result_record.key_id,
                succeeded=result_record.succeeded,
                evidence_digest=result_record.evidence_digest,
                prior_evidence_digest=result_record.prior_evidence_digest,
                issued_at=result_record.issued_at,
                signature_version=result_record.signature_version,
                signature_purpose=result_record.signature_purpose,
                signature=result_record.signature,
            )
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored final receipt context is invalid"
            ) from exc
        audit_event = next(
            (
                event
                for event in cls._load_audit_events(connection)
                if event.event_id == row["audit_event_id"]
            ),
            None,
        )
        if audit_event is None:
            raise PersistenceIntegrityError(
                "stored final receipt has no terminal audit event"
            )
        return cls._load_final_write_receipt(
            connection,
            receipt_id,
            terminal_operation=terminal_operation,
            result_record=result_record,
            trusted_result=trusted_result,
            audit_event=audit_event,
        )

    @staticmethod
    def _validate_recovery_operation_runtime_binding(
        origin: Operation, recovery: Operation
    ) -> None:
        if origin.operation_id == recovery.operation_id:
            raise PersistenceIntegrityError(
                "recovery operation binding must use a distinct operation"
            )
        if recovery.capability_id != "acct.recovery.execute.v1":
            raise PersistenceIntegrityError(
                "recovery operation binding capability is invalid"
            )
        runtime_fields = (
            "principal",
            "user_id",
            "company_id",
            "odoo_instance_id",
            "database_name",
            "database_uuid",
            "environment",
            "registry_digest",
            "release_digest",
        )
        if any(
            getattr(origin, field) != getattr(recovery, field)
            for field in runtime_fields
        ):
            raise PersistenceIntegrityError(
                "recovery operation binding has a different runtime binding from its origin"
            )

    @staticmethod
    def _validate_recovery_operation_parameters(
        origin: Operation,
        recovery: Operation,
        *,
        plan_digest: str,
    ) -> None:
        parameters = recovery.parameters
        if (
            parameters.get("origin_operation_id") != origin.operation_id
            or parameters.get("expected_recovery_plan_digest") != plan_digest
            or parameters.get("company_id") != origin.company_id
        ):
            raise PersistenceIntegrityError(
                "recovery operation binding parameters do not match the origin receipt"
            )

    @classmethod
    def _validated_receipt_recovery_plan(
        cls,
        connection: sqlite3.Connection,
        origin: Operation,
        origin_receipt: StoredFinalWriteReceipt,
        *,
        expected_plan_digest: str,
    ) -> StoredTrustedResultRecord:
        receipt_details = origin_receipt.body.get("receipt_details")
        plan = (
            receipt_details.get("recovery_plan")
            if type(receipt_details) is dict
            else None
        )
        try:
            validate_recovery_plan(plan)
        except WriteReceiptError as exc:
            raise PersistenceIntegrityError(
                "recovery operation binding receipt plan is invalid"
            ) from exc
        if plan["status"] != "available":
            raise PersistenceIntegrityError(
                "recovery operation binding requires an available recovery plan"
            )
        if plan["requires_approval"] is not True:
            raise PersistenceIntegrityError(
                "recovery operation binding requires approval"
            )
        if (
            plan["origin_operation_id"] != origin.operation_id
            or plan["recovery_capability_id"] != "acct.recovery.execute.v1"
            or not hmac.compare_digest(
                plan["plan_digest"], expected_plan_digest
            )
        ):
            raise PersistenceIntegrityError(
                "recovery operation binding plan does not match its origin"
            )
        if any(
            target["company_id"] != origin.company_id
            for target in plan["target_records"]
        ):
            raise PersistenceIntegrityError(
                "recovery operation binding target company differs from its origin"
            )
        execution_rows = tuple(
            connection.execute(
                "SELECT result_id FROM trusted_result_records "
                "WHERE operation_id = ? AND kind = 'execution'",
                (origin.operation_id,),
            )
        )
        if len(execution_rows) != 1:
            raise PersistenceIntegrityError(
                "recovery operation binding origin has no unique execution result"
            )
        execution = cls._load_trusted_result_record(
            connection, execution_rows[0]["result_id"]
        )
        if canonical_json(
            execution.evidence.get("recovery_plan")
        ) != canonical_json(plan):
            raise PersistenceIntegrityError(
                "recovery operation binding plan differs from signed execution evidence"
            )
        return execution

    @classmethod
    def _load_origin_receipt_for_recovery_binding(
        cls,
        connection: sqlite3.Connection,
        origin: Operation,
        *,
        receipt_id: str | None = None,
        operation_revision: int | None = None,
        terminal_state: str | None = None,
    ) -> StoredFinalWriteReceipt:
        if receipt_id is None:
            rows = tuple(
                connection.execute(
                    "SELECT receipt_id FROM final_write_receipts "
                    "WHERE operation_id = ? AND operation_revision = ? "
                    "AND terminal_state = ?",
                    (
                        origin.operation_id,
                        operation_revision,
                        terminal_state,
                    ),
                )
            )
            if len(rows) != 1:
                raise PersistenceIntegrityError(
                    "origin terminal operation has no unique final receipt"
                )
            receipt_id = rows[0]["receipt_id"]
        receipt = cls._load_final_write_receipt_by_id(connection, receipt_id)
        if (
            receipt.operation_id != origin.operation_id
            or receipt.operation_digest != origin.digest
            or receipt.terminal_state not in {
                State.COMPLETED.value,
                State.FAILED.value,
            }
            or (
                operation_revision is not None
                and receipt.operation_revision != operation_revision
            )
            or (
                terminal_state is not None
                and receipt.terminal_state != terminal_state
            )
        ):
            raise PersistenceIntegrityError(
                "origin final receipt does not match the recovery binding"
            )
        return receipt

    @classmethod
    def _load_recovery_operation_binding_event(
        cls,
        connection: sqlite3.Connection,
        event: StoredAuditEvent,
    ) -> StoredRecoveryOperationBinding:
        try:
            payload = event.payload
            if type(payload) is not dict or set(payload) != _RECOVERY_BINDING_FIELDS:
                raise PersistenceIntegrityError(
                    "stored recovery operation binding fields are invalid"
                )
            if (
                type(payload["binding_version"]) is not int
                or payload["binding_version"] != 1
            ):
                raise PersistenceIntegrityError(
                    "stored recovery operation binding version is invalid"
                )
            origin_operation_id = _required_text(
                payload["origin_operation_id"], "origin_operation_id"
            )
            recovery_operation_id = _required_text(
                payload["recovery_operation_id"], "recovery_operation_id"
            )
            plan_digest = _required_digest(payload["plan_digest"], "plan_digest")
            if (
                event.event_id
                != _recovery_operation_binding_event_id(recovery_operation_id)
                or event.event_type != _RECOVERY_BINDING_EVENT_TYPE
                or event.operation_id != recovery_operation_id
                or type(payload["origin_operation_revision"]) is not int
                or payload["origin_operation_revision"] <= 0
                or type(payload["recovery_operation_revision"]) is not int
                or payload["recovery_operation_revision"] != 0
            ):
                raise PersistenceIntegrityError(
                    "stored recovery operation binding identity is invalid"
                )
            for field in (
                "origin_execution_evidence_digest",
                "origin_final_receipt_body_digest",
                "origin_operation_digest",
                "origin_result_evidence_digest",
                "recovery_operation_digest",
                "registry_digest",
                "release_digest",
            ):
                _required_digest(payload[field], field)
            for field in (
                "database_name",
                "database_uuid",
                "environment",
                "odoo_instance_id",
                "origin_final_receipt_id",
                "origin_execution_result_id",
                "origin_request_id",
                "origin_result_id",
                "origin_terminal_state",
                "principal",
                "recovery_request_id",
            ):
                _required_text(payload[field], field)
            if (
                type(payload["user_id"]) is not int
                or payload["user_id"] <= 0
                or type(payload["company_id"]) is not int
                or payload["company_id"] <= 0
            ):
                raise PersistenceIntegrityError(
                    "stored recovery operation binding actor is invalid"
                )

            origin = cls._load_operation_with_evidence(
                connection, origin_operation_id
            )
            recovery = cls._load_operation_with_evidence(
                connection, recovery_operation_id
            )
            cls._validate_recovery_operation_runtime_binding(origin, recovery)
            cls._validate_recovery_operation_parameters(
                origin, recovery, plan_digest=plan_digest
            )
            if recovery.protocol_version != SCHEMA_VERSION:
                raise PersistenceIntegrityError(
                    "stored recovery operation binding protocol is invalid"
                )
            origin_receipt = cls._load_origin_receipt_for_recovery_binding(
                connection,
                origin,
                receipt_id=payload["origin_final_receipt_id"],
                operation_revision=payload["origin_operation_revision"],
                terminal_state=payload["origin_terminal_state"],
            )
            origin_execution = cls._validated_receipt_recovery_plan(
                connection,
                origin,
                origin_receipt,
                expected_plan_digest=plan_digest,
            )
            if event.occurred_at < origin_receipt.recorded_at:
                raise PersistenceIntegrityError(
                    "stored recovery operation binding predates its origin receipt"
                )
            recovery_events = tuple(
                item
                for item in cls._load_audit_events(connection)
                if item.operation_id == recovery.operation_id
                and item.event_type.startswith("operation.")
            )
            if recovery.revision == 0:
                if recovery.state != State.PREPARED or recovery_events:
                    raise PersistenceIntegrityError(
                        "stored recovery operation was not pristine when bound"
                    )
            elif (
                not recovery_events
                or recovery_events[0].event_type != "operation.prechecked"
                or any(item.sequence <= event.sequence for item in recovery_events)
                or any(
                    item.occurred_at < event.occurred_at
                    for item in recovery_events
                )
            ):
                raise PersistenceIntegrityError(
                    "stored recovery operation binding does not precede its lifecycle"
                )
            expected_payload = _recovery_operation_binding_payload(
                origin=origin,
                recovery=recovery,
                origin_receipt=origin_receipt,
                origin_execution=origin_execution,
                plan_digest=plan_digest,
            )
            if canonical_json(payload) != canonical_json(expected_payload):
                raise PersistenceIntegrityError(
                    "stored recovery operation binding content is invalid"
                )
            return StoredRecoveryOperationBinding(
                binding_id=event.event_id,
                origin_operation_id=payload["origin_operation_id"],
                origin_request_id=payload["origin_request_id"],
                origin_operation_digest=payload["origin_operation_digest"],
                origin_operation_revision=payload["origin_operation_revision"],
                origin_terminal_state=payload["origin_terminal_state"],
                origin_final_receipt_id=payload["origin_final_receipt_id"],
                origin_final_receipt_body_digest=payload[
                    "origin_final_receipt_body_digest"
                ],
                origin_execution_result_id=payload[
                    "origin_execution_result_id"
                ],
                origin_execution_evidence_digest=payload[
                    "origin_execution_evidence_digest"
                ],
                origin_result_id=payload["origin_result_id"],
                origin_result_evidence_digest=payload[
                    "origin_result_evidence_digest"
                ],
                recovery_operation_id=payload["recovery_operation_id"],
                recovery_request_id=payload["recovery_request_id"],
                recovery_operation_digest=payload["recovery_operation_digest"],
                recovery_operation_revision=payload[
                    "recovery_operation_revision"
                ],
                plan_digest=payload["plan_digest"],
                principal=payload["principal"],
                user_id=payload["user_id"],
                company_id=payload["company_id"],
                odoo_instance_id=payload["odoo_instance_id"],
                database_name=payload["database_name"],
                database_uuid=payload["database_uuid"],
                environment=payload["environment"],
                registry_digest=payload["registry_digest"],
                release_digest=payload["release_digest"],
                audit_event=event,
            )
        except PersistenceIntegrityError:
            raise
        except (PersistenceError, TypeError, ValueError) as exc:
            raise PersistenceIntegrityError(
                "stored recovery operation binding is invalid"
            ) from exc

    @classmethod
    def _load_recovery_record(
        cls, connection: sqlite3.Connection, recovery_id: str
    ) -> StoredRecoveryRecord:
        row = connection.execute(
            f"SELECT {', '.join(_RECOVERY_RECORD_COLUMNS)} "
            "FROM recovery_records WHERE recovery_id = ?",
            (recovery_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("recovery record does not exist")
        payload = {
            column: row[column] for column in _RECOVERY_RECORD_COLUMNS[:-1]
        }
        if type(row["record_hash"]) is not str or not hmac.compare_digest(
            _recovery_record_hash(payload), row["record_hash"]
        ):
            raise PersistenceIntegrityError(
                "stored recovery record hash mismatch"
            )
        try:
            initiated_at = _parse_datetime(
                row["initiated_at"], "recovery initiated_at"
            )
            record = StoredRecoveryRecord(
                recovery_id=row["recovery_id"],
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                operation_digest=row["operation_digest"],
                operation_revision=row["operation_revision"],
                from_state=row["from_state"],
                actor_principal=row["actor_principal"],
                actor_user_id=row["actor_user_id"],
                company_id=row["company_id"],
                approval_record_hash=row["approval_record_hash"],
                plan_digest=row["plan_digest"],
                plan_json=row["plan_json"],
                initiated_at=initiated_at,
                audit_event_id=row["audit_event_id"],
                record_hash=row["record_hash"],
            )
        except (PersistenceError, TypeError, ValueError) as exc:
            raise PersistenceIntegrityError(
                "stored recovery record is invalid"
            ) from exc
        canonical_payload = {
            **{
                column: getattr(record, column)
                for column in _RECOVERY_RECORD_COLUMNS[:-1]
                if column != "initiated_at"
            },
            "initiated_at": _utc_text(
                record.initiated_at, "recovery initiated_at"
            ),
        }
        operation = cls._load_operation(connection, record.operation_id)
        approval = cls._load_approval_record(connection, record.operation_id)
        try:
            from_state = State(record.from_state)
            pre_operation = replace(
                operation,
                state=from_state,
                revision=record.operation_revision,
            )
            pre_operation.assert_integrity()
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored recovery operation state is invalid"
            ) from exc
        event = next(
            (
                item
                for item in cls._load_audit_events(connection)
                if item.event_id == record.audit_event_id
            ),
            None,
        )
        expected_payload = _recovery_audit_payload(
            pre_operation,
            approval,
            recovery_id=record.recovery_id,
            recovery_record_hash=record.record_hash,
            plan_digest=record.plan_digest,
            actor_principal=record.actor_principal,
            actor_user_id=record.actor_user_id,
        )
        try:
            recovery_plan = json.loads(record.plan_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError(
                "stored recovery plan is invalid"
            ) from exc
        if (
            payload != canonical_payload
            or _SHA256.fullmatch(record.operation_digest) is None
            or _SHA256.fullmatch(record.approval_record_hash) is None
            or _SHA256.fullmatch(record.plan_digest) is None
            or type(recovery_plan) is not dict
            or canonical_json(recovery_plan).decode("utf-8") != record.plan_json
            or hashlib.sha256(record.plan_json.encode("utf-8")).hexdigest()
            != record.plan_digest
            or type(record.operation_revision) is not int
            or record.operation_revision < 0
            or type(record.actor_user_id) is not int
            or record.actor_user_id <= 0
            or type(record.company_id) is not int
            or record.company_id <= 0
            or type(record.actor_principal) is not str
            or not record.actor_principal.strip()
            or record.recovery_id
            != _recovery_id(
                pre_operation,
                plan_digest=record.plan_digest,
                actor_principal=record.actor_principal,
                actor_user_id=record.actor_user_id,
            )
            or record.request_id != operation.request_id
            or record.operation_digest != operation.digest
            or record.actor_principal != operation.principal
            or record.actor_user_id != operation.user_id
            or record.company_id != operation.company_id
            or record.approval_record_hash != approval.record_hash
            or record.audit_event_id != _recovery_event_id(record.recovery_id)
            or event is None
            or event.event_type != "operation.recovering"
            or event.operation_id != operation.operation_id
            or event.occurred_at != record.initiated_at
            or canonical_json(event.payload) != canonical_json(expected_payload)
        ):
            raise PersistenceIntegrityError(
                "stored recovery audit evidence is invalid"
            )
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
    def _expected_generic_transition_events(
        cls, operation: Operation
    ) -> dict[str, tuple[str, dict[str, Any]]]:
        if operation.revision == 0:
            return {}
        pristine = replace(
            operation,
            state=State.PREPARED,
            revision=0,
            precheck_digest=None,
            approval_signature=None,
            approval_nonce_digest=None,
            approval_issued_at=None,
            approval_expires_at=None,
            approval_revision=None,
            approver_user_id=None,
            execution_result_digest=None,
            verification_result_digest=None,
        )
        try:
            pristine.assert_integrity()
            if operation.protocol_version >= SCHEMA_VERSION:
                if operation.precheck_digest is None:
                    raise PersistenceIntegrityError(
                        "native operation has no precheck digest"
                    )
                prechecked = validate_record_precheck(
                    pristine,
                    precheck_digest=operation.precheck_digest,
                    expected_revision=0,
                )
            else:
                prechecked = pristine._apply_transition(State.PRECHECKED)
            awaiting = prechecked.transition(
                State.AWAITING_APPROVAL, expected_revision=1
            )
        except Exception as exc:
            raise PersistenceIntegrityError(
                "stored operation cannot reconstruct generic transitions"
            ) from exc
        expected: dict[str, tuple[str, dict[str, Any]]] = {}
        if (
            operation.protocol_version == RESULT_SCHEMA_VERSION
            and operation.revision >= 1
        ):
            event_id = _generic_transition_event_id(
                pristine, State.PRECHECKED
            )
            expected[event_id] = (
                "operation.prechecked",
                _generic_transition_audit_payload(pristine, prechecked),
            )
        if operation.revision >= 2:
            event_id = _generic_transition_event_id(
                prechecked, State.AWAITING_APPROVAL
            )
            expected[event_id] = (
                "operation.awaiting_approval",
                _generic_transition_audit_payload(prechecked, awaiting),
            )
        return expected

    @classmethod
    def _verify_generic_transition_events(
        cls, connection: sqlite3.Connection, operation: Operation
    ) -> None:
        expected = cls._expected_generic_transition_events(operation)
        for event in cls._load_audit_events(connection):
            generic_types = {"operation.awaiting_approval"}
            if operation.protocol_version == RESULT_SCHEMA_VERSION:
                generic_types.add("operation.prechecked")
            if (
                event.operation_id != operation.operation_id
                or event.event_type not in generic_types
            ):
                continue
            evidence = expected.get(event.event_id)
            if (
                evidence is None
                or event.event_type != evidence[0]
                or canonical_json(event.payload) != canonical_json(evidence[1])
            ):
                raise PersistenceIntegrityError(
                    "stored generic transition audit evidence is invalid"
                )

    @classmethod
    def _load_operation_with_evidence(
        cls, connection: sqlite3.Connection, operation_id: str
    ) -> Operation:
        operation = cls._load_operation(connection, operation_id)
        cls._verify_generic_transition_events(connection, operation)
        if operation.approval_signature is None:
            return operation
        approval_record = cls._load_approval_record(connection, operation_id)
        if (
            approval_record.record_origin in {"native_v2", "native_v3"}
            and operation.state
            in {
                State.EXECUTING,
                State.VERIFYING,
                State.COMPLETED,
                State.FAILED,
                State.RECOVERING,
                State.RECOVERED,
            }
        ):
            cls._verify_execution_audit(
                connection, operation, approval_record
            )
        if cls._table_exists(connection, "trusted_result_records"):
            for row in connection.execute(
                "SELECT result_id FROM trusted_result_records "
                "WHERE operation_id = ? ORDER BY operation_revision",
                (operation_id,),
            ):
                cls._load_trusted_result_record(connection, row["result_id"])
            for row in connection.execute(
                "SELECT recovery_id FROM recovery_records "
                "WHERE operation_id = ? ORDER BY operation_revision",
                (operation_id,),
            ):
                cls._load_recovery_record(connection, row["recovery_id"])
            cls._verify_result_and_recovery_state(connection, operation)
        return operation

    def get_operation(self, operation_id: str) -> Operation:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_operation_with_evidence(connection, operation_id)

    def find_operation_by_idempotency(
        self,
        *,
        odoo_instance_id: str,
        database_uuid: str,
        environment: str,
        company_id: int,
        capability_id: str,
        idempotency_key: str,
        scope: str | None = None,
    ) -> Operation | None:
        """Resolve a retained operation without depending on its release digest.

        A retry may arrive after the current release changes.  The stable Odoo,
        database, environment, company, capability, and idempotency identities
        therefore select the durable operation before release routing.  ``scope``
        is optional so callers can also recover a request whose registry version
        changed the scope calculation; the mandatory idempotency key remains a
        release-independent lookup key.
        """

        odoo_instance_id = _required_text(odoo_instance_id, "odoo_instance_id")
        capability_id = _required_text(capability_id, "capability_id")
        idempotency_key = _required_text(idempotency_key, "idempotency_key")
        environment = _required_text(environment, "environment")
        if environment not in {"test", "sandbox", "production"}:
            raise PersistenceError("environment is invalid")
        if type(company_id) is not int or company_id <= 0:
            raise PersistenceError("company_id must be a positive integer")
        try:
            normalized_database_uuid = str(uuid.UUID(database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise PersistenceError("database_uuid must be a UUID") from exc
        if normalized_database_uuid != database_uuid:
            raise PersistenceError("database_uuid must be canonical")
        if scope is not None:
            scope = _required_text(scope, "scope")

        identity = (
            odoo_instance_id,
            database_uuid,
            environment,
            company_id,
            capability_id,
        )
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            if scope is None:
                rows = tuple(
                    connection.execute(
                        """
                        SELECT * FROM idempotency_keys
                        WHERE odoo_instance_id = ? AND database_uuid = ?
                          AND environment = ? AND company_id = ?
                          AND capability_id = ? AND idempotency_key = ?
                        """,
                        (*identity, idempotency_key),
                    )
                )
            else:
                rows = tuple(
                    connection.execute(
                        """
                        SELECT * FROM idempotency_keys
                        WHERE odoo_instance_id = ? AND database_uuid = ?
                          AND environment = ? AND company_id = ?
                          AND capability_id = ?
                          AND (idempotency_key = ? OR scope = ?)
                        """,
                        (*identity, idempotency_key, scope),
                    )
                )
            if not rows:
                return None
            if len(rows) != 1:
                raise IdempotencyConflict(
                    "idempotency key and scope resolve to different operations"
                )

            row = rows[0]
            operation = self._load_operation_with_evidence(
                connection, row["operation_id"]
            )
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
            return operation

    def get_approval_record(self, operation_id: str) -> StoredApprovalRecord:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_approval_record(connection, operation_id)

    def get_precheck_record(self, operation_id: str) -> StoredPrecheckRecord:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            operation = self._load_operation_with_evidence(
                connection, operation_id
            )
            return self._load_precheck_record(
                connection, operation_id, operation=operation
            )

    def get_or_create_operation(
        self, operation: Operation, *, scope: str
    ) -> tuple[Operation, bool]:
        _operation_payload(operation)
        if (
            operation.state != State.PREPARED
            or operation.revision != 0
            or operation.protocol_version != SCHEMA_VERSION
            or operation.precheck_digest is not None
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

    def record_precheck(
        self,
        *,
        operation_id: str,
        evidence: dict[str, Any],
        occurred_at: datetime,
        expected_revision: int,
    ) -> PrecheckAcceptance:
        operation_id = _required_text(operation_id, "operation_id")
        evidence_json, evidence_digest = _canonical_object_digest(
            evidence, "evidence"
        )
        _utc_text(occurred_at, "occurred_at")
        if (
            type(expected_revision) is not int
            or expected_revision < 0
        ):
            raise PersistenceError(
                "expected_revision must be a non-negative integer"
            )
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)
                current = self._load_operation_with_evidence(
                    connection, operation_id
                )
                try:
                    prechecked = validate_record_precheck(
                        current,
                        precheck_digest=evidence_digest,
                        expected_revision=expected_revision,
                    )
                except OperationConcurrentUpdate as exc:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    ) from exc
                event_id = _precheck_event_id(current, evidence_digest)
                record_payload = _precheck_record_payload(
                    operation=current,
                    evidence_digest=evidence_digest,
                    evidence_json=evidence_json,
                    occurred_at=occurred_at,
                    audit_event_id=event_id,
                )
                record_hash = _precheck_record_hash(record_payload)
                values = tuple(
                    record_payload[column]
                    for column in _PRECHECK_RECORD_COLUMNS[:-1]
                )
                connection.execute(
                    f"INSERT INTO precheck_records("
                    f"{', '.join(_PRECHECK_RECORD_COLUMNS)}) "
                    f"VALUES({', '.join('?' for _ in _PRECHECK_RECORD_COLUMNS)})",
                    (*values, record_hash),
                )
                audit_event = self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type="operation.prechecked",
                    operation_id=current.operation_id,
                    occurred_at=occurred_at,
                    payload=_precheck_audit_payload(
                        current,
                        evidence_digest=evidence_digest,
                        record_hash=record_hash,
                    ),
                )
                self._update_operation_row(
                    connection, current, prechecked
                )
                stored_operation = self._load_operation_with_evidence(
                    connection, operation_id
                )
                stored_record = self._load_precheck_record(
                    connection,
                    operation_id,
                    operation=stored_operation,
                )
                acceptance = PrecheckAcceptance(
                    operation=stored_operation,
                    precheck_record=stored_record,
                    audit_event=audit_event,
                )
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("precheck transaction failed") from exc
        return acceptance

    def cas_update_operation(
        self,
        operation: Operation,
        *,
        expected_revision: int,
        occurred_at: datetime | None = None,
    ) -> Operation:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise PersistenceError("expected_revision must be a non-negative integer")
        if operation.revision != expected_revision + 1:
            raise ConcurrentUpdate("operation revision must advance by exactly one")
        transition_time = (
            datetime.now(timezone.utc) if occurred_at is None else occurred_at
        )
        _utc_text(transition_time, "occurred_at")
        if operation.state in {
            State.PRECHECKED,
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
            if (
                current.protocol_version != operation.protocol_version
                or current.precheck_digest != operation.precheck_digest
            ):
                raise PersistenceIntegrityError(
                    "operation precheck binding changed during generic CAS"
                )
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
            try:
                self._append_audit_event(
                    connection,
                    event_id=_generic_transition_event_id(
                        current, operation.state
                    ),
                    event_type=f"operation.{operation.state.value}",
                    operation_id=current.operation_id,
                    occurred_at=transition_time,
                    payload=_generic_transition_audit_payload(
                        current, operation
                    ),
                )
                cursor = connection.execute(
                    f"UPDATE operations SET {assignments}, record_hash = ? "
                    "WHERE operation_id = ? AND revision = ?",
                    values,
                )
            except sqlite3.IntegrityError as exc:
                raise PersistenceError(
                    "operation CAS transaction failed"
                ) from exc
            if cursor.rowcount != 1:
                raise ConcurrentUpdate("stored operation revision has changed")
            return self._load_operation_with_evidence(
                connection, operation.operation_id
            )

    @staticmethod
    def _update_operation_row(
        connection: sqlite3.Connection,
        current: Operation,
        updated: Operation,
    ) -> None:
        if updated.revision != current.revision + 1:
            raise ConcurrentUpdate(
                "operation revision must advance by exactly one"
            )
        if any(
            getattr(current, field) != getattr(updated, field)
            for field in _IMMUTABLE_OPERATION_FIELDS
        ):
            raise PersistenceIntegrityError(
                "operation immutable fields changed during transition"
            )
        if current.protocol_version != updated.protocol_version:
            raise PersistenceIntegrityError(
                "operation protocol changed during transition"
            )
        if not (
            current.state == State.PREPARED
            and updated.state == State.PRECHECKED
        ) and current.precheck_digest != updated.precheck_digest:
            raise PersistenceIntegrityError(
                "operation precheck binding changed during transition"
            )
        payload = _operation_payload(updated)
        mutable_columns = _OPERATION_COLUMNS[1:]
        assignments = ", ".join(
            f"{column} = ?" for column in mutable_columns
        )
        values = tuple(payload[column] for column in mutable_columns) + (
            _operation_record_hash(payload),
            current.operation_id,
            current.revision,
        )
        cursor = connection.execute(
            f"UPDATE operations SET {assignments}, record_hash = ? "
            "WHERE operation_id = ? AND revision = ?",
            values,
        )
        if cursor.rowcount != 1:
            raise ConcurrentUpdate("stored operation revision has changed")

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
                if current.revision != expected_revision:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    )
                approval_record = self._load_approval_record(
                    connection, operation_id
                )
                if approval_record.record_origin == "legacy_v1_unverifiable":
                    raise PersistenceIntegrityError(
                        "legacy approval evidence cannot authorize execution"
                    )
                if not _approval_origin_matches_operation(
                    current, approval_record.record_origin
                ):
                    raise PersistenceIntegrityError(
                        "approval protocol cannot authorize execution"
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

    def _record_trusted_result_transition(
        self,
        result: TrustedResult,
        *,
        expected_kind: ResultKind,
        evidence: dict[str, Any],
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        allowed_issuers: frozenset[str],
        expected_revision: int,
        receipt_factory: Callable[[Operation], dict[str, Any]] | None,
    ) -> ResultAcceptance:
        if not isinstance(result, TrustedResult):
            raise PersistenceError("result must be a TrustedResult")
        if type(result.kind) is not ResultKind or result.kind != expected_kind:
            raise PersistenceError(
                f"result kind must be {expected_kind.value}"
            )
        evidence_json, evidence_digest = _canonical_object_digest(
            evidence, "evidence"
        )
        if (
            type(result.evidence_digest) is not str
            or not hmac.compare_digest(result.evidence_digest, evidence_digest)
        ):
            raise PersistenceIntegrityError(
                "evidence content digest does not match trusted result"
            )
        operation_id = _required_text(result.operation_id, "result.operation_id")
        terminal_result = (
            expected_kind != ResultKind.EXECUTION or not result.succeeded
        )
        if terminal_result and not callable(receipt_factory):
            raise PersistenceError(
                "terminal result requires a final receipt factory"
            )
        if not terminal_result and receipt_factory is not None:
            raise PersistenceError(
                "nonterminal result cannot have a final receipt factory"
            )
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)
                current = self._load_operation_with_evidence(
                    connection, operation_id
                )
                if current.revision != expected_revision:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    )
                approval_record = self._load_approval_record(
                    connection, operation_id
                )
                if approval_record.record_origin == "legacy_v1_unverifiable":
                    raise PersistenceIntegrityError(
                        "legacy approval evidence cannot authorize a result"
                    )
                if not _approval_origin_matches_operation(
                    current, approval_record.record_origin
                ):
                    raise PersistenceIntegrityError(
                        "approval protocol cannot authorize a result"
                    )
                if expected_kind == ResultKind.EXECUTION:
                    predecessor_at = self._verify_execution_audit(
                        connection, current, approval_record
                    ).occurred_at
                elif expected_kind == ResultKind.VERIFICATION:
                    predecessor = connection.execute(
                        "SELECT accepted_at FROM trusted_result_records "
                        "WHERE operation_id = ? AND operation_revision = ? "
                        "AND kind = 'execution'",
                        (operation_id, current.revision - 1),
                    ).fetchone()
                    if predecessor is None:
                        raise PersistenceIntegrityError(
                            "verification has no durable execution predecessor"
                        )
                    predecessor_at = _parse_datetime(
                        predecessor["accepted_at"],
                        "execution result accepted_at",
                    )
                else:
                    predecessor = connection.execute(
                        "SELECT initiated_at FROM recovery_records "
                        "WHERE operation_id = ? AND operation_revision = ?",
                        (operation_id, current.revision - 1),
                    ).fetchone()
                    if predecessor is None:
                        raise PersistenceIntegrityError(
                            "recovery result has no durable plan predecessor"
                        )
                    predecessor_at = _parse_datetime(
                        predecessor["initiated_at"],
                        "recovery initiated_at",
                    )
                try:
                    if expected_kind == ResultKind.EXECUTION:
                        updated = validate_execution_result(
                            current,
                            result,
                            now=now,
                            secret=secret,
                            expected_key_id=expected_key_id,
                            allowed_issuers=allowed_issuers,
                            expected_revision=expected_revision,
                        )
                    elif expected_kind == ResultKind.VERIFICATION:
                        updated = validate_complete_operation(
                            current,
                            result,
                            now=now,
                            secret=secret,
                            expected_key_id=expected_key_id,
                            allowed_issuers=allowed_issuers,
                            expected_revision=expected_revision,
                        )
                    else:
                        recovery_row = connection.execute(
                            "SELECT plan_digest FROM recovery_records "
                            "WHERE operation_id = ? AND operation_revision = ?",
                            (operation_id, current.revision - 1),
                        ).fetchone()
                        if recovery_row is None:
                            raise PersistenceIntegrityError(
                                "recovering operation has no durable recovery plan"
                            )
                        updated = validate_complete_recovery(
                            current,
                            result,
                            recovery_plan_digest=recovery_row["plan_digest"],
                            now=now,
                            secret=secret,
                            expected_key_id=expected_key_id,
                            allowed_issuers=allowed_issuers,
                            expected_revision=expected_revision,
                        )
                except OperationConcurrentUpdate as exc:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    ) from exc
                if result.issued_at < predecessor_at:
                    raise PersistenceIntegrityError(
                        "trusted result predates its durable predecessor"
                    )

                event_id = _result_event_id(current, result, updated.state)
                record_payload = _trusted_result_payload(
                    operation=current,
                    approval_record=approval_record,
                    result=result,
                    evidence_json=evidence_json,
                    accepted_at=now,
                    audit_event_id=event_id,
                )
                record_hash = _trusted_result_record_hash(record_payload)
                values = tuple(
                    record_payload[column]
                    for column in _TRUSTED_RESULT_RECORD_COLUMNS[:-1]
                )
                connection.execute(
                    f"INSERT INTO trusted_result_records("
                    f"{', '.join(_TRUSTED_RESULT_RECORD_COLUMNS)}) "
                    f"VALUES({', '.join('?' for _ in _TRUSTED_RESULT_RECORD_COLUMNS)})",
                    (*values, record_hash),
                )
                receipt_details = None
                receipt_details_digest = None
                if terminal_result:
                    try:
                        receipt_details_value = receipt_factory(updated)
                    except PersistenceError:
                        raise
                    except Exception as exc:
                        raise PersistenceError(
                            "final receipt factory failed"
                        ) from exc
                    details_json, receipt_details_digest = (
                        _canonical_object_digest(
                            receipt_details_value,
                            "final receipt details",
                        )
                    )
                    receipt_details = json.loads(details_json)
                audit_event = self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type=f"operation.{updated.state.value}",
                    operation_id=current.operation_id,
                    occurred_at=now,
                    payload=_result_audit_payload(
                        current,
                        approval_record,
                        result,
                        target=updated.state,
                        result_record_hash=record_hash,
                        final_receipt_required=terminal_result,
                        final_receipt_details_digest=(
                            receipt_details_digest
                        ),
                    ),
                )
                final_receipt_payload = None
                if terminal_result:
                    body = _final_receipt_body(
                        operation=updated,
                        result=result,
                        evidence=json.loads(evidence_json),
                        result_id=record_payload["result_id"],
                        result_record_hash=record_hash,
                        receipt_details=receipt_details,
                        audit_event=audit_event,
                    )
                    body_json = canonical_json(body).decode("utf-8")
                    body_digest = hashlib.sha256(
                        body_json.encode("utf-8")
                    ).hexdigest()
                    final_receipt_payload = _final_receipt_payload(
                        operation=updated,
                        result=result,
                        body_json=body_json,
                        body_digest=body_digest,
                        recorded_at=now,
                        audit_event_id=audit_event.event_id,
                    )
                    receipt_hash = _final_receipt_record_hash(
                        final_receipt_payload
                    )
                    receipt_values = tuple(
                        final_receipt_payload[column]
                        for column in _FINAL_WRITE_RECEIPT_COLUMNS[:-1]
                    )
                    connection.execute(
                        f"INSERT INTO final_write_receipts("
                        f"{', '.join(_FINAL_WRITE_RECEIPT_COLUMNS)}) "
                        f"VALUES({', '.join('?' for _ in _FINAL_WRITE_RECEIPT_COLUMNS)})",
                        (*receipt_values, receipt_hash),
                    )
                self._update_operation_row(connection, current, updated)
                stored_operation = self._load_operation_with_evidence(
                    connection, operation_id
                )
                stored_result = self._load_trusted_result_record(
                    connection, record_payload["result_id"]
                )
                stored_receipt = None
                if final_receipt_payload is not None:
                    stored_receipt = self._load_final_write_receipt(
                        connection,
                        final_receipt_payload["receipt_id"],
                        terminal_operation=stored_operation,
                        result_record=stored_result,
                        trusted_result=result,
                        audit_event=audit_event,
                    )
                acceptance = ResultAcceptance(
                    operation=stored_operation,
                    approval_record=approval_record,
                    result_record=stored_result,
                    audit_event=audit_event,
                    final_receipt=stored_receipt,
                )
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("result transaction failed") from exc
        return acceptance

    def record_execution_result(
        self,
        result: TrustedResult,
        *,
        evidence: dict[str, Any],
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        allowed_issuers: frozenset[str],
        expected_revision: int,
        receipt_factory: Callable[[Operation], dict[str, Any]] | None = None,
    ) -> ResultAcceptance:
        return self._record_trusted_result_transition(
            result,
            expected_kind=ResultKind.EXECUTION,
            evidence=evidence,
            now=now,
            secret=secret,
            expected_key_id=expected_key_id,
            allowed_issuers=allowed_issuers,
            expected_revision=expected_revision,
            receipt_factory=receipt_factory,
        )

    def complete_operation(
        self,
        result: TrustedResult,
        *,
        evidence: dict[str, Any],
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        allowed_issuers: frozenset[str],
        expected_revision: int,
        receipt_factory: Callable[[Operation], dict[str, Any]],
    ) -> ResultAcceptance:
        return self._record_trusted_result_transition(
            result,
            expected_kind=ResultKind.VERIFICATION,
            evidence=evidence,
            now=now,
            secret=secret,
            expected_key_id=expected_key_id,
            allowed_issuers=allowed_issuers,
            expected_revision=expected_revision,
            receipt_factory=receipt_factory,
        )

    def begin_recovery(
        self,
        *,
        operation_id: str,
        recovery_plan: dict[str, Any],
        recovery_plan_digest: str,
        actor_principal: str,
        actor_user_id: int,
        actor_company_id: int,
        occurred_at: datetime,
        expected_revision: int,
    ) -> RecoveryAcceptance:
        operation_id = _required_text(operation_id, "operation_id")
        _required_digest(recovery_plan_digest, "recovery_plan_digest")
        plan_json, plan_digest = _canonical_object_digest(
            recovery_plan, "recovery_plan"
        )
        if not hmac.compare_digest(plan_digest, recovery_plan_digest):
            raise PersistenceIntegrityError(
                "recovery plan content digest mismatch"
            )
        _utc_text(occurred_at, "occurred_at")
        try:
            with self._transaction() as connection:
                self._verify_audit_chain_connection(connection)
                current = self._load_operation_with_evidence(
                    connection, operation_id
                )
                if current.revision != expected_revision:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    )
                approval_record = self._load_approval_record(
                    connection, operation_id
                )
                if approval_record.record_origin == "legacy_v1_unverifiable":
                    raise PersistenceIntegrityError(
                        "legacy approval evidence cannot authorize recovery"
                    )
                if not _approval_origin_matches_operation(
                    current, approval_record.record_origin
                ):
                    raise PersistenceIntegrityError(
                        "approval protocol cannot authorize recovery"
                    )
                predecessor = connection.execute(
                    "SELECT accepted_at FROM trusted_result_records "
                    "WHERE operation_id = ? AND operation_revision = ?",
                    (operation_id, current.revision - 1),
                ).fetchone()
                if predecessor is None:
                    raise PersistenceIntegrityError(
                        "recovery has no durable result predecessor"
                    )
                predecessor_at = _parse_datetime(
                    predecessor["accepted_at"],
                    "recovery predecessor accepted_at",
                )
                if occurred_at < predecessor_at:
                    raise PersistenceIntegrityError(
                        "recovery predates its durable predecessor"
                    )
                try:
                    recovering = validate_begin_recovery(
                        current,
                        recovery_plan_digest=recovery_plan_digest,
                        actor_principal=actor_principal,
                        actor_user_id=actor_user_id,
                        actor_company_id=actor_company_id,
                        expected_revision=expected_revision,
                    )
                except OperationConcurrentUpdate as exc:
                    raise ConcurrentUpdate(
                        "stored operation revision has changed"
                    ) from exc

                recovery_id = _recovery_id(
                    current,
                    plan_digest=recovery_plan_digest,
                    actor_principal=actor_principal,
                    actor_user_id=actor_user_id,
                )
                event_id = _recovery_event_id(recovery_id)
                record_payload = _recovery_payload(
                    operation=current,
                    approval_record=approval_record,
                    plan_digest=recovery_plan_digest,
                    plan_json=plan_json,
                    actor_principal=actor_principal,
                    actor_user_id=actor_user_id,
                    initiated_at=occurred_at,
                    audit_event_id=event_id,
                )
                record_hash = _recovery_record_hash(record_payload)
                values = tuple(
                    record_payload[column]
                    for column in _RECOVERY_RECORD_COLUMNS[:-1]
                )
                connection.execute(
                    f"INSERT INTO recovery_records("
                    f"{', '.join(_RECOVERY_RECORD_COLUMNS)}) "
                    f"VALUES({', '.join('?' for _ in _RECOVERY_RECORD_COLUMNS)})",
                    (*values, record_hash),
                )
                audit_event = self._append_audit_event(
                    connection,
                    event_id=event_id,
                    event_type="operation.recovering",
                    operation_id=current.operation_id,
                    occurred_at=occurred_at,
                    payload=_recovery_audit_payload(
                        current,
                        approval_record,
                        recovery_id=recovery_id,
                        recovery_record_hash=record_hash,
                        plan_digest=recovery_plan_digest,
                        actor_principal=actor_principal,
                        actor_user_id=actor_user_id,
                    ),
                )
                self._update_operation_row(connection, current, recovering)
                stored_operation = self._load_operation_with_evidence(
                    connection, operation_id
                )
                stored_record = self._load_recovery_record(
                    connection, recovery_id
                )
                acceptance = RecoveryAcceptance(
                    operation=stored_operation,
                    approval_record=approval_record,
                    recovery_record=stored_record,
                    audit_event=audit_event,
                )
        except sqlite3.IntegrityError as exc:
            raise PersistenceError("recovery transaction failed") from exc
        return acceptance

    def complete_recovery(
        self,
        result: TrustedResult,
        *,
        evidence: dict[str, Any],
        now: datetime,
        secret: bytes,
        expected_key_id: str,
        allowed_issuers: frozenset[str],
        expected_revision: int,
        receipt_factory: Callable[[Operation], dict[str, Any]],
    ) -> ResultAcceptance:
        return self._record_trusted_result_transition(
            result,
            expected_kind=ResultKind.RECOVERY,
            evidence=evidence,
            now=now,
            secret=secret,
            expected_key_id=expected_key_id,
            allowed_issuers=allowed_issuers,
            expected_revision=expected_revision,
            receipt_factory=receipt_factory,
        )

    def bind_recovery_operation(
        self,
        *,
        origin_operation_id: str,
        recovery_operation_id: str,
        expected_origin_revision: int,
        plan_digest: str,
        occurred_at: datetime,
    ) -> StoredRecoveryOperationBinding:
        """Bind a fresh recovery operation to one immutable terminal receipt."""

        origin_operation_id = _required_text(
            origin_operation_id, "origin_operation_id"
        )
        recovery_operation_id = _required_text(
            recovery_operation_id, "recovery_operation_id"
        )
        plan_digest = _required_digest(plan_digest, "plan_digest")
        if (
            type(expected_origin_revision) is not int
            or expected_origin_revision < 0
        ):
            raise PersistenceError(
                "expected_origin_revision must be a non-negative integer"
            )
        occurred_text = _utc_text(occurred_at, "occurred_at")
        normalized_occurred_at = _parse_datetime(occurred_text, "occurred_at")
        event_id = _recovery_operation_binding_event_id(
            recovery_operation_id
        )
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._verify_reserved_audit_namespaces(connection)
            existing_event = next(
                (
                    event
                    for event in self._load_audit_events(connection)
                    if event.event_id == event_id
                ),
                None,
            )
            if existing_event is not None:
                binding = self._load_recovery_operation_binding_event(
                    connection, existing_event
                )
                if (
                    binding.origin_operation_id != origin_operation_id
                    or binding.origin_operation_revision
                    != expected_origin_revision
                    or not hmac.compare_digest(
                        binding.plan_digest, plan_digest
                    )
                    or binding.audit_event.occurred_at
                    != normalized_occurred_at
                ):
                    raise IdempotencyConflict(
                        "recovery operation binding conflicts with durable evidence"
                    )
                return binding

            origin = self._load_operation_with_evidence(
                connection, origin_operation_id
            )
            if origin.revision != expected_origin_revision:
                raise ConcurrentUpdate("origin operation revision has changed")
            if origin.state not in {State.COMPLETED, State.FAILED}:
                raise PersistenceIntegrityError(
                    "origin operation must be terminal before recovery is bound"
                )
            recovery = self._load_operation_with_evidence(
                connection, recovery_operation_id
            )
            if (
                recovery.state != State.PREPARED
                or recovery.revision != 0
                or recovery.protocol_version != SCHEMA_VERSION
                or recovery.precheck_digest is not None
            ):
                raise PersistenceIntegrityError(
                    "recovery operation must be pristine prepared revision zero"
                )
            self._validate_recovery_operation_runtime_binding(origin, recovery)
            self._validate_recovery_operation_parameters(
                origin, recovery, plan_digest=plan_digest
            )
            origin_receipt = self._load_origin_receipt_for_recovery_binding(
                connection,
                origin,
                operation_revision=origin.revision,
                terminal_state=origin.state.value,
            )
            origin_execution = self._validated_receipt_recovery_plan(
                connection,
                origin,
                origin_receipt,
                expected_plan_digest=plan_digest,
            )
            if normalized_occurred_at < origin_receipt.recorded_at:
                raise PersistenceIntegrityError(
                    "recovery operation binding predates its origin receipt"
                )
            event = self._append_audit_event(
                connection,
                event_id=event_id,
                event_type=_RECOVERY_BINDING_EVENT_TYPE,
                operation_id=recovery.operation_id,
                occurred_at=normalized_occurred_at,
                payload=_recovery_operation_binding_payload(
                    origin=origin,
                    recovery=recovery,
                    origin_receipt=origin_receipt,
                    origin_execution=origin_execution,
                    plan_digest=plan_digest,
                ),
            )
            return self._load_recovery_operation_binding_event(
                connection, event
            )

    def get_recovery_operation_binding(
        self, recovery_operation_id: str
    ) -> StoredRecoveryOperationBinding:
        recovery_operation_id = _required_text(
            recovery_operation_id, "recovery_operation_id"
        )
        event_id = _recovery_operation_binding_event_id(
            recovery_operation_id
        )
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._verify_reserved_audit_namespaces(connection)
            event = next(
                (
                    item
                    for item in self._load_audit_events(connection)
                    if item.event_id == event_id
                ),
                None,
            )
            if event is None:
                raise OperationNotFound(
                    "recovery operation binding does not exist"
                )
            return self._load_recovery_operation_binding_event(
                connection, event
            )

    def get_trusted_result_records(
        self, operation_id: str
    ) -> tuple[StoredTrustedResultRecord, ...]:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._load_operation_with_evidence(connection, operation_id)
            return tuple(
                self._load_trusted_result_record(connection, row["result_id"])
                for row in connection.execute(
                    "SELECT result_id FROM trusted_result_records "
                    "WHERE operation_id = ? ORDER BY operation_revision",
                    (operation_id,),
                )
            )

    def get_trusted_result_record(
        self, result_id: str
    ) -> StoredTrustedResultRecord:
        result_id = _required_text(result_id, "result_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_trusted_result_record(connection, result_id)

    def get_final_write_receipt(
        self, receipt_id: str
    ) -> StoredFinalWriteReceipt:
        receipt_id = _required_text(receipt_id, "receipt_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_final_write_receipt_by_id(
                connection, receipt_id
            )

    def get_final_write_receipts(
        self, operation_id: str
    ) -> tuple[StoredFinalWriteReceipt, ...]:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._load_operation_with_evidence(connection, operation_id)
            return tuple(
                self._load_final_write_receipt_by_id(
                    connection, row["receipt_id"]
                )
                for row in connection.execute(
                    "SELECT receipt_id FROM final_write_receipts "
                    "WHERE operation_id = ? ORDER BY operation_revision",
                    (operation_id,),
                )
            )

    def get_recovery_records(
        self, operation_id: str
    ) -> tuple[StoredRecoveryRecord, ...]:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._load_operation_with_evidence(connection, operation_id)
            return tuple(
                self._load_recovery_record(connection, row["recovery_id"])
                for row in connection.execute(
                    "SELECT recovery_id FROM recovery_records "
                    "WHERE operation_id = ? ORDER BY operation_revision",
                    (operation_id,),
                )
            )

    def get_recovery_plan(self, recovery_id: str) -> StoredRecoveryRecord:
        recovery_id = _required_text(recovery_id, "recovery_id")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            return self._load_recovery_record(connection, recovery_id)

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
    "PREVIOUS_SCHEMA_VERSION",
    "PrecheckAcceptance",
    "RecoveryAcceptance",
    "ReplayRejected",
    "RESULT_SCHEMA_VERSION",
    "ResultAcceptance",
    "SCHEMA_VERSION",
    "SQLitePersistence",
    "StoredApprovalRecord",
    "StoredAuditEvent",
    "StoredFinalWriteReceipt",
    "StoredPrecheckRecord",
    "StoredRecoveryRecord",
    "StoredRecoveryOperationBinding",
    "StoredTrustedResultRecord",
]
