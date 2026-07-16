import hashlib
import hmac
import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from odoo_accounting_cli_v3.operations import (
    Approval,
    ApprovalRejected,
    Operation,
    State,
    approve_operation,
    begin_recovery,
    begin_execution,
    canonical_json,
    complete_operation,
    record_precheck,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_recovery_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.persistence import (
    GENESIS_HASH,
    MAX_DIAGNOSTIC_AUDIT_PAYLOAD_BYTES,
    ConcurrentUpdate,
    IdempotencyConflict,
    PersistenceError,
    PersistenceIntegrityError,
    ReplayRejected,
    SQLitePersistence,
    _OPERATION_COLUMNS,
    _APPROVAL_RECORD_COLUMNS,
    _FINAL_WRITE_RECEIPT_COLUMNS,
    _TRUSTED_RESULT_RECORD_COLUMNS,
    _SCHEMA_V1,
    _SCHEMA_V2,
    _TRIGGER_SCHEMAS_V2,
    _TRIGGER_SCHEMAS_V3,
    _TRIGGER_SCHEMAS_V4,
    _TABLE_SCHEMAS_V3,
    _approval_audit_payload,
    _approval_event_id,
    _approval_record_hash,
    _execution_audit_payload,
    _execution_event_id,
    _final_receipt_id,
    _final_receipt_record_hash,
    _audit_hash,
    _normalize_schema_sql,
    _generic_transition_audit_payload,
    _generic_transition_event_id,
    _result_audit_payload,
    _result_event_id,
    _trusted_result_payload,
    _trusted_result_record_hash,
    _operation_payload,
    _operation_record_hash,
    _recovery_operation_binding_event_id,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan


NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
OTHER_DATABASE_UUID = "22222222-2222-4222-8222-222222222222"
REGISTRY_DIGEST = "c" * 64
RELEASE_DIGEST = "d" * 64
APPROVAL_SECRET = b"approval-secret-material-32-byte!"
APPROVAL_KEY_ID = "approval-key-v2"
EXECUTION_SECRET = b"execution-secret-material-32-byte"
VERIFICATION_SECRET = b"verify-secret-material-at-least-32"
RECOVERY_SECRET = b"recovery-secret-material-at-least-32"
RECEIPT_SECRET = b"receipt-secret-material-at-least-32"
RECEIPT_KEY_ID = "receipt-key-v1"


def content_digest(value: dict) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def precheck_evidence(operation: Operation) -> dict:
    return {
        "acl_allowed": True,
        "company_id": operation.company_id,
        "odoo_checked": True,
        "operation_digest": operation.digest,
        "user_id": operation.user_id,
    }


def final_receipt_details(operation: Operation) -> dict:
    return {
        "odoo_receipt": f"{operation.operation_id}:{operation.revision}",
        "terminal_state": operation.state.value,
    }


def prepared_operation(
    operation_id: str,
    request_id: str,
    *,
    amount: str = "100.00",
    database_uuid: str = DATABASE_UUID,
    idempotency_key: str = "idem-1",
) -> Operation:
    return Operation.prepare(
        operation_id=operation_id,
        request_id=request_id,
        capability_id="acct.invoice.customer_create.v1",
        parameters={
            "company_id": 7,
            "amount": amount,
            "idempotency_key": idempotency_key,
        },
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key=idempotency_key,
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_test",
        database_uuid=database_uuid,
        environment="test",
        registry_digest=REGISTRY_DIGEST,
        release_digest=RELEASE_DIGEST,
    )


def completed_operation() -> Operation:
    operation = prepared_operation("op-complete", "request-complete")
    operation = record_precheck(
        operation,
        precheck_digest=content_digest(precheck_evidence(operation)),
        expected_revision=0,
    )
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    approval = sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce="approval-nonce",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=900,
        key_id=APPROVAL_KEY_ID,
        secret=APPROVAL_SECRET,
    )
    operation = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        consume_nonce=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=2,
    )
    operation = begin_execution(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=3,
    )
    execution = sign_execution_result(
        operation=operation,
        issuer="odoo-executor",
        key_id="execution-v1",
        succeeded=True,
        evidence_digest="a" * 64,
        issued_at=NOW,
        secret=EXECUTION_SECRET,
    )
    operation = record_execution_result(
        operation,
        execution,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id="execution-v1",
        allowed_issuers=frozenset({"odoo-executor"}),
        expected_revision=4,
    )
    verification = sign_verification_result(
        operation=operation,
        issuer="odoo-verifier",
        key_id="verification-v1",
        succeeded=True,
        evidence_digest="b" * 64,
        issued_at=NOW,
        secret=VERIFICATION_SECRET,
    )
    return complete_operation(
        operation,
        verification,
        now=NOW,
        secret=VERIFICATION_SECRET,
        expected_key_id="verification-v1",
        allowed_issuers=frozenset({"odoo-verifier"}),
        expected_revision=5,
    )


def persist_awaiting(
    store: SQLitePersistence,
    suffix: str,
    *,
    amount: str = "100.00",
) -> Operation:
    operation = prepared_operation(
        f"op-{suffix}",
        f"request-{suffix}",
        amount=amount,
        idempotency_key=f"idem-{suffix}",
    )
    store.get_or_create_operation(operation, scope=f"scope-{suffix}")
    operation = store.record_precheck(
        operation_id=operation.operation_id,
        evidence=precheck_evidence(operation),
        occurred_at=NOW - timedelta(minutes=3),
        expected_revision=0,
    ).operation
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    return store.cas_update_operation(
        operation,
        expected_revision=1,
        occurred_at=NOW - timedelta(minutes=2),
    )


def signed_approval(
    operation: Operation,
    nonce: str,
    *,
    issued_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=5),
):
    return sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        approval_ttl_seconds=900,
        key_id=APPROVAL_KEY_ID,
        secret=APPROVAL_SECRET,
    )


def accept_approval(store: SQLitePersistence, approval, *, authorized=True):
    return store.accept_approval(
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: authorized,
        approval_ttl_seconds=900,
        expected_revision=2,
    )


def persist_executing(store: SQLitePersistence, suffix: str):
    awaiting = persist_awaiting(store, suffix)
    approval = signed_approval(awaiting, f"{suffix}-nonce")
    accepted = accept_approval(store, approval)
    return store.begin_execution(
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=accepted.operation.revision,
    )


def persist_completed_with_recovery_plan(
    store: SQLitePersistence,
    suffix: str,
    *,
    status: str = "available",
    requires_approval: bool = True,
    target_company_id: int = 7,
    signed_plan_method: str = "reverse_move",
):
    started = persist_executing(store, suffix)
    origin = started.operation
    recovery_plan = create_recovery_plan(
        origin_operation_id=origin.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status=status,
        method="reverse_move",
        requires_approval=requires_approval,
        target_records=[
            {
                "model": "account.move",
                "record_id": 9101,
                "company_id": target_company_id,
                "record_state": "posted",
                "record_fingerprint": "e" * 64,
            }
        ],
        parameters={"move_id": 9101, "company_id": target_company_id},
    )
    signed_recovery_plan = (
        recovery_plan
        if signed_plan_method == "reverse_move"
        else create_recovery_plan(
            origin_operation_id=origin.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status=status,
            method=signed_plan_method,
            requires_approval=requires_approval,
            target_records=recovery_plan["target_records"],
            parameters={"move_id": 9101, "company_id": target_company_id},
        )
    )
    execution_evidence = {
        "model": "account.move",
        "record_id": 9101,
        "recovery_plan": signed_recovery_plan,
    }
    execution = sign_execution_result(
        operation=origin,
        issuer="odoo-executor",
        key_id="execution-v1",
        succeeded=True,
        evidence_digest=content_digest(execution_evidence),
        issued_at=NOW,
        secret=EXECUTION_SECRET,
    )
    verifying = store.record_execution_result(
        execution,
        evidence=execution_evidence,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id="execution-v1",
        allowed_issuers=frozenset({"odoo-executor"}),
        expected_revision=origin.revision,
    )
    verification_evidence = {"record_id": 9101, "state": "posted"}
    verification = sign_verification_result(
        operation=verifying.operation,
        issuer="odoo-verifier",
        key_id="verification-v1",
        succeeded=True,
        evidence_digest=content_digest(verification_evidence),
        issued_at=NOW,
        secret=VERIFICATION_SECRET,
    )
    completed = store.complete_operation(
        verification,
        evidence=verification_evidence,
        now=NOW,
        secret=VERIFICATION_SECRET,
        expected_key_id="verification-v1",
        allowed_issuers=frozenset({"odoo-verifier"}),
        expected_revision=verifying.operation.revision,
        receipt_factory=lambda operation: {
            "operation_id": operation.operation_id,
            "operation_state": operation.state.value,
            "recovery_plan": recovery_plan,
        },
    )
    return completed.operation, recovery_plan


def prepared_recovery_operation(
    origin: Operation,
    recovery_plan: dict,
    suffix: str,
    *,
    company_id: int | None = None,
    origin_operation_id: str | None = None,
    plan_digest: str | None = None,
    capability_id: str = "acct.recovery.execute.v1",
) -> Operation:
    bound_company_id = origin.company_id if company_id is None else company_id
    idempotency_key = f"idem-recovery-{suffix}"
    return Operation.prepare(
        operation_id=f"op-recovery-{suffix}",
        request_id=f"request-recovery-{suffix}",
        capability_id=capability_id,
        parameters={
            "company_id": bound_company_id,
            "origin_operation_id": (
                origin.operation_id
                if origin_operation_id is None
                else origin_operation_id
            ),
            "expected_recovery_plan_digest": (
                recovery_plan["plan_digest"]
                if plan_digest is None
                else plan_digest
            ),
            "recovery_date": "2026-07-16",
            "reason": "Reverse a duplicate sandbox move",
            "idempotency_key": idempotency_key,
        },
        principal=origin.principal,
        user_id=origin.user_id,
        company_id=bound_company_id,
        idempotency_key=idempotency_key,
        odoo_instance_id=origin.odoo_instance_id,
        database_name=origin.database_name,
        database_uuid=origin.database_uuid,
        environment=origin.environment,
        registry_digest=origin.registry_digest,
        release_digest=origin.release_digest,
    )


def create_v1_schema(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
        for statement in _SCHEMA_V1:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', '1')"
        )
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    path.chmod(0o600)


def create_v2_schema(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
        for statement in _SCHEMA_V2:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', '2')"
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    path.chmod(0o600)


def insert_v1_operation(
    connection: sqlite3.Connection,
    operation: Operation,
    *,
    payload_override: dict | None = None,
    scope: str = "legacy-scope",
) -> dict:
    payload = _operation_payload(operation) if payload_override is None else payload_override
    columns = (*_OPERATION_COLUMNS, "record_hash")
    connection.execute(
        f"INSERT INTO operations({', '.join(columns)}) "
        f"VALUES({', '.join('?' for _ in columns)})",
        tuple(payload[column] for column in _OPERATION_COLUMNS)
        + (_operation_record_hash(payload),),
    )
    connection.execute(
        """
        INSERT INTO idempotency_keys(
            odoo_instance_id, database_uuid, environment, company_id,
            capability_id, scope, idempotency_key, operation_id, operation_digest
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operation.odoo_instance_id,
            operation.database_uuid,
            operation.environment,
            operation.company_id,
            operation.capability_id,
            scope,
            operation.idempotency_key,
            operation.operation_id,
            operation.digest,
        ),
    )
    return payload


def rewrite_audit_payload(
    path: Path,
    event,
    payload: dict,
) -> None:
    payload_json = canonical_json(payload).decode("utf-8")
    occurred_at = event.occurred_at.isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    event_hash = _audit_hash(
        sequence=event.sequence,
        event_id=event.event_id,
        event_type=event.event_type,
        operation_id=event.operation_id,
        occurred_at=occurred_at,
        payload_json=payload_json,
        previous_hash=event.previous_hash,
    )
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("DROP TRIGGER audit_events_no_update")
        connection.execute(
            "UPDATE audit_events SET payload_json = ?, event_hash = ? "
            "WHERE event_id = ?",
            (payload_json, event_hash, event.event_id),
        )
        connection.execute(_TRIGGER_SCHEMAS_V2["audit_events_no_update"])


def legacy_approved_operation() -> Operation:
    operation = replace(
        prepared_operation(
            "op-legacy-approved",
            "request-legacy-approved",
            idempotency_key="idem-legacy-approved",
        ),
        protocol_version=3,
    )
    operation = operation._apply_transition(State.PRECHECKED)
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    nonce = "legacy-v1-nonce-not-stored"
    issued_at = NOW - timedelta(minutes=1)
    expires_at = NOW + timedelta(minutes=5)
    legacy_payload = {
        "approver_user_id": 99,
        "company_id": operation.company_id,
        "expires_at": expires_at.isoformat(),
        "issued_at": issued_at.isoformat(),
        "nonce": nonce,
        "operation_digest": operation.digest,
        "operation_id": operation.operation_id,
        "operation_revision": operation.revision,
        "purpose": "approval_v1",
        "user_id": operation.user_id,
        "version": 1,
    }
    signature = hmac.new(
        APPROVAL_SECRET,
        canonical_json(legacy_payload),
        hashlib.sha256,
    ).hexdigest()
    return operation._apply_transition(
        State.APPROVED,
        approval_signature=signature,
        approval_nonce_digest=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        approval_issued_at=issued_at,
        approval_expires_at=expires_at,
        approval_revision=operation.revision,
        approver_user_id=99,
    )


def adversarial_v2_approval_in_v1_pair():
    operation = prepared_operation(
        "op-legacy-approved",
        "request-legacy-approved",
        idempotency_key="idem-legacy-approved",
    )
    operation = record_precheck(
        operation,
        precheck_digest=content_digest(precheck_evidence(operation)),
        expected_revision=0,
    )
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    approval = signed_approval(operation, "legacy-nonce-not-stored")
    approved = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        consume_nonce=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=2,
    )
    return approved, approval


def _auth_consume_worker(path: str, start, queue) -> None:
    start.wait()
    try:
        SQLitePersistence(path).consume_auth_token(
            token_id="shared-token",
            request_digest="1" * 64,
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
        queue.put("consumed")
    except ReplayRejected:
        queue.put("rejected")
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(f"error:{type(exc).__name__}:{exc}")


def _idempotency_worker(path: str, worker_id: int, start, queue) -> None:
    start.wait()
    try:
        candidate = prepared_operation(f"op-worker-{worker_id}", f"request-worker-{worker_id}")
        operation, created = SQLitePersistence(path).get_or_create_operation(
            candidate, scope="shared-idempotency-scope"
        )
        queue.put((operation.operation_id, created))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put((f"error:{type(exc).__name__}:{exc}", False))


def _approval_accept_worker(path: str, approval, start, queue) -> None:
    start.wait()
    try:
        acceptance = SQLitePersistence(path).accept_approval(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        queue.put(("accepted", acceptance.operation.revision))
    except (ReplayRejected, ApprovalRejected, ConcurrentUpdate) as exc:
        queue.put(("rejected", type(exc).__name__))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


def _execution_begin_worker(path: str, approval, start, queue) -> None:
    start.wait()
    try:
        acceptance = SQLitePersistence(path).begin_execution(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=3,
        )
        queue.put(("started", acceptance.operation.revision))
    except ConcurrentUpdate as exc:
        queue.put(("rejected", type(exc).__name__))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


def _execution_result_worker(path: str, result, evidence, start, queue) -> None:
    start.wait(timeout=20)
    try:
        acceptance = SQLitePersistence(path).record_execution_result(
            result,
            evidence=evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=4,
        )
        queue.put(("recorded", acceptance.operation.revision))
    except ConcurrentUpdate as exc:
        queue.put(("rejected", type(exc).__name__))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


def _precheck_worker(path: str, operation: Operation, start, queue) -> None:
    start.wait(timeout=20)
    try:
        acceptance = SQLitePersistence(path).record_precheck(
            operation_id=operation.operation_id,
            evidence=precheck_evidence(operation),
            occurred_at=NOW,
            expected_revision=0,
        )
        queue.put(("recorded", acceptance.operation.revision))
    except ConcurrentUpdate as exc:
        queue.put(("rejected", type(exc).__name__))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


def _terminal_result_worker(path: str, result, evidence, start, queue) -> None:
    start.wait(timeout=20)
    try:
        acceptance = SQLitePersistence(path).complete_operation(
            result,
            evidence=evidence,
            now=NOW,
            secret=VERIFICATION_SECRET,
            expected_key_id="verification-v1",
            allowed_issuers=frozenset({"odoo-verifier"}),
            expected_revision=5,
            receipt_factory=final_receipt_details,
        )
        queue.put(("completed", acceptance.final_receipt.receipt_id))
    except ConcurrentUpdate as exc:
        queue.put(("rejected", type(exc).__name__))
    except Exception as exc:  # pragma: no cover - reported to the parent assertion
        queue.put(("error", f"{type(exc).__name__}:{exc}"))


class SQLitePersistenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "persistence.sqlite3"
        self.store = SQLitePersistence(self.path)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_fixed_schema_uses_wal_and_append_only_triggers(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            triggers = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                )
            }
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(mode, "wal")
        self.assertEqual(version, 4)
        self.assertTrue(
            {
                "schema_meta",
                "consumed_auth_tokens",
                "consumed_receipts",
                "operations",
                "idempotency_keys",
                "audit_events",
                "approval_records",
                "trusted_result_records",
                "recovery_records",
                "operation_protocols",
                "precheck_records",
                "final_write_receipts",
            }.issubset(tables)
        )
        self.assertEqual(
            triggers,
            {
                "approval_records_bind_awaiting_operation",
                "approval_records_native_only",
                "approval_records_no_delete",
                "approval_records_no_update",
                "audit_events_no_delete",
                "audit_events_no_update",
                "operations_approved_requires_native_approval",
                "operations_executing_requires_native_approval",
                "operations_insert_pristine",
                "operations_prechecked_requires_record",
                "operations_awaiting_requires_precheck",
                "operations_completed_requires_result",
                "operations_failed_requires_result",
                "operations_recovered_requires_result",
                "operations_recovering_requires_record",
                "operations_verifying_requires_result",
                "recovery_records_bind_operation",
                "recovery_records_no_delete",
                "recovery_records_no_update",
                "trusted_result_records_bind_operation",
                "trusted_result_records_no_delete",
                "trusted_result_records_no_update",
                "operation_protocols_no_delete",
                "operation_protocols_no_update",
                "precheck_records_bind_operation",
                "precheck_records_no_delete",
                "precheck_records_no_update",
                "final_write_receipts_bind_result",
                "final_write_receipts_no_delete",
                "final_write_receipts_no_update",
            },
        )

    def test_v1_schema_anchor_and_atomic_migration_preserve_evidence(self) -> None:
        fingerprint = hashlib.sha256(
            "\n".join(
                _normalize_schema_sql(statement) for statement in _SCHEMA_V1
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            fingerprint,
            "47d95682d71925aedf8d2edf10f247bf20d8ab466418099a4748a79580ce351b",
        )

        legacy_path = Path(self.directory.name) / "legacy-v1.sqlite3"
        create_v1_schema(legacy_path)
        operation = legacy_approved_operation()
        occurred_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        audit_payload_json = canonical_json(
            {"revision": operation.revision, "state": operation.state.value}
        ).decode("utf-8")
        audit_hash = _audit_hash(
            sequence=1,
            event_id="legacy-event-1",
            event_type="operation.approved.legacy",
            operation_id=operation.operation_id,
            occurred_at=occurred_at,
            payload_json=audit_payload_json,
            previous_hash=GENESIS_HASH,
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(connection, operation)
            connection.execute(
                """
                INSERT INTO consumed_auth_tokens(
                    token_id, request_digest, expires_at, consumed_at
                ) VALUES('legacy-auth', ?, ?, ?)
                """,
                ("1" * 64, occurred_at, occurred_at),
            )
            connection.execute(
                """
                INSERT INTO consumed_receipts(
                    receipt_id, request_digest, observed_at, consumed_at
                ) VALUES('legacy-receipt', ?, ?, ?)
                """,
                ("2" * 64, occurred_at, occurred_at),
            )
            connection.execute(
                """
                INSERT INTO audit_events(
                    sequence, event_id, event_type, operation_id, occurred_at,
                    payload_json, previous_hash, event_hash
                ) VALUES(1, 'legacy-event-1', 'operation.approved.legacy', ?, ?, ?, ?, ?)
                """,
                (
                    operation.operation_id,
                    occurred_at,
                    audit_payload_json,
                    GENESIS_HASH,
                    audit_hash,
                ),
            )
            before_operation = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation.operation_id,),
            ).fetchone()
            before_audit = connection.execute(
                "SELECT * FROM audit_events WHERE sequence = 1"
            ).fetchone()
            before_idempotency = connection.execute(
                "SELECT * FROM idempotency_keys WHERE operation_id = ?",
                (operation.operation_id,),
            ).fetchone()

        migrated = SQLitePersistence(legacy_path)
        self.assertEqual(
            migrated.get_operation(operation.operation_id),
            replace(operation, protocol_version=3, precheck_digest=None),
        )
        legacy_record = migrated.get_approval_record(operation.operation_id)
        self.assertEqual(legacy_record.record_origin, "legacy_v1_unverifiable")
        self.assertEqual(legacy_record.signature_version, 1)
        self.assertEqual(legacy_record.signature_purpose, "approval_v1")
        self.assertIsNone(legacy_record.key_id)
        self.assertIsNone(legacy_record.accepted_at)
        self.assertIsNone(legacy_record.audit_event_id)
        self.assertEqual(migrated.verify_chain(), 1)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "4",
            )
            after_operation = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation.operation_id,),
            ).fetchone()
            after_audit = connection.execute(
                "SELECT * FROM audit_events WHERE sequence = 1"
            ).fetchone()
            after_idempotency = connection.execute(
                "SELECT * FROM idempotency_keys WHERE operation_id = ?",
                (operation.operation_id,),
            ).fetchone()
            self.assertEqual(tuple(after_operation), tuple(before_operation))
            self.assertEqual(tuple(after_audit), tuple(before_audit))
            self.assertEqual(tuple(after_idempotency), tuple(before_idempotency))
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM consumed_auth_tokens "
                    "WHERE token_id = 'legacy-auth'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM consumed_receipts "
                    "WHERE receipt_id = 'legacy-receipt'"
                ).fetchone()[0],
                1,
            )

    def test_v2_to_v3_migration_is_atomic_and_preserves_operation_bytes(self) -> None:
        legacy_path = Path(self.directory.name) / "legacy-v2.sqlite3"
        create_v2_schema(legacy_path)
        operation = prepared_operation(
            "op-v2-migration",
            "request-v2-migration",
            idempotency_key="idem-v2-migration",
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(
                connection,
                operation,
                scope="scope-v2-migration",
            )
            before = tuple(
                connection.execute(
                    "SELECT * FROM operations WHERE operation_id = ?",
                    (operation.operation_id,),
                ).fetchone()
            )

        migrated = SQLitePersistence(legacy_path)
        self.assertEqual(
            migrated.get_operation(operation.operation_id),
            replace(operation, protocol_version=3),
        )
        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], 4
            )
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "4",
            )
            self.assertEqual(
                tuple(
                    connection.execute(
                        "SELECT * FROM operations WHERE operation_id = ?",
                        (operation.operation_id,),
                    ).fetchone()
                ),
                before,
            )
            self.assertEqual(
                {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }.issuperset(
                    {
                        "trusted_result_records",
                        "recovery_records",
                        "operation_protocols",
                        "precheck_records",
                        "final_write_receipts",
                    }
                ),
                True,
            )

    def test_v3_native_v2_approval_migrates_verbatim_but_cannot_authorize_v4(
        self,
    ) -> None:
        legacy_path = Path(self.directory.name) / "legacy-v3-approval.sqlite3"
        prepared = replace(
            prepared_operation(
                "op-v3-approval",
                "request-v3-approval",
                idempotency_key="idem-v3-approval",
            ),
            protocol_version=3,
        )
        prechecked = prepared._apply_transition(State.PRECHECKED)
        awaiting = prechecked.transition(
            State.AWAITING_APPROVAL, expected_revision=1
        )
        issued_at = NOW - timedelta(minutes=1)
        expires_at = NOW + timedelta(minutes=5)
        nonce = "legacy-native-v2-nonce"
        nonce_digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        historical_payload = {
            "approver_user_id": 99,
            "company_id": awaiting.company_id,
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "key_id": APPROVAL_KEY_ID,
            "nonce": nonce,
            "operation_digest": awaiting.digest,
            "operation_id": awaiting.operation_id,
            "operation_revision": awaiting.revision,
            "purpose": "approval_v2",
            "request_id": awaiting.request_id,
            "user_id": awaiting.user_id,
            "version": 2,
        }
        signature = hmac.new(
            APPROVAL_SECRET,
            canonical_json(historical_payload),
            hashlib.sha256,
        ).hexdigest()
        approval = Approval(
            operation_id=awaiting.operation_id,
            request_id=awaiting.request_id,
            operation_digest=awaiting.digest,
            precheck_digest=None,
            user_id=awaiting.user_id,
            company_id=awaiting.company_id,
            operation_revision=awaiting.revision,
            approver_user_id=99,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            signature_version=2,
            signature_purpose="approval_v2",
            key_id=APPROVAL_KEY_ID,
            signature=signature,
        )
        approved = awaiting._apply_transition(
            State.APPROVED,
            approval_signature=signature,
            approval_nonce_digest=nonce_digest,
            approval_issued_at=issued_at,
            approval_expires_at=expires_at,
            approval_revision=awaiting.revision,
            approver_user_id=99,
        )
        approval_event_id = _approval_event_id(
            awaiting.operation_id, awaiting.revision, nonce_digest
        )
        approval_payload = {
            "operation_id": awaiting.operation_id,
            "request_id": awaiting.request_id,
            "operation_digest": awaiting.digest,
            "operation_revision": awaiting.revision,
            "requester_user_id": awaiting.user_id,
            "company_id": awaiting.company_id,
            "approver_user_id": approval.approver_user_id,
            "nonce_digest": nonce_digest,
            "signature_version": 2,
            "signature_purpose": "approval_v2",
            "key_id": APPROVAL_KEY_ID,
            "issued_at": issued_at.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "approval_signature": signature,
            "accepted_at": NOW.isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "audit_event_id": approval_event_id,
            "record_origin": "native_v2",
        }
        approval_hash = _approval_record_hash(approval_payload)
        approval_record = SimpleNamespace(
            operation_revision=awaiting.revision,
            approver_user_id=99,
            record_hash=approval_hash,
        )
        executing = approved._apply_transition(State.EXECUTING)
        execution_evidence = {"model": "account.move", "record_id": 3001}
        execution = sign_execution_result(
            operation=executing,
            issuer="legacy-odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        execution_result_event_id = _result_event_id(
            executing, execution, State.VERIFYING
        )
        execution_result_payload = _trusted_result_payload(
            operation=executing,
            approval_record=approval_record,
            result=execution,
            evidence_json=canonical_json(execution_evidence).decode("utf-8"),
            accepted_at=NOW,
            audit_event_id=execution_result_event_id,
        )
        execution_result_hash = _trusted_result_record_hash(
            execution_result_payload
        )
        verifying = record_execution_result(
            executing,
            execution,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"legacy-odoo-executor"}),
            expected_revision=executing.revision,
        )
        verification_evidence = {"record_id": 3001, "state": "posted"}
        verification = sign_verification_result(
            operation=verifying,
            issuer="legacy-odoo-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=content_digest(verification_evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        verification_event_id = _result_event_id(
            verifying, verification, State.COMPLETED
        )
        verification_result_payload = _trusted_result_payload(
            operation=verifying,
            approval_record=approval_record,
            result=verification,
            evidence_json=canonical_json(verification_evidence).decode("utf-8"),
            accepted_at=NOW,
            audit_event_id=verification_event_id,
        )
        verification_result_hash = _trusted_result_record_hash(
            verification_result_payload
        )
        completed = complete_operation(
            verifying,
            verification,
            now=NOW,
            secret=VERIFICATION_SECRET,
            expected_key_id="verification-v1",
            allowed_issuers=frozenset({"legacy-odoo-verifier"}),
            expected_revision=verifying.revision,
        )
        execution_event_id = _execution_event_id(
            approved.operation_id, awaiting.revision, approval_hash
        )
        event_specs = (
            (
                _generic_transition_event_id(prepared, State.PRECHECKED),
                "operation.prechecked",
                NOW - timedelta(minutes=3),
                _generic_transition_audit_payload(prepared, prechecked),
            ),
            (
                _generic_transition_event_id(
                    prechecked, State.AWAITING_APPROVAL
                ),
                "operation.awaiting_approval",
                NOW - timedelta(minutes=2),
                _generic_transition_audit_payload(prechecked, awaiting),
            ),
            (
                approval_event_id,
                "operation.approved",
                NOW,
                _approval_audit_payload(
                    awaiting,
                    approval_revision=awaiting.revision,
                    approver_user_id=99,
                    nonce_digest=nonce_digest,
                    key_id=APPROVAL_KEY_ID,
                    signature_purpose="approval_v2",
                    signature_version=2,
                    approval_signature=signature,
                    record_hash=approval_hash,
                ),
            ),
            (
                execution_event_id,
                "operation.executing",
                NOW,
                _execution_audit_payload(approved, approval_record),
            ),
            (
                execution_result_event_id,
                "operation.verifying",
                NOW,
                _result_audit_payload(
                    executing,
                    approval_record,
                    execution,
                    target=State.VERIFYING,
                    result_record_hash=execution_result_hash,
                ),
            ),
            (
                verification_event_id,
                "operation.completed",
                NOW,
                _result_audit_payload(
                    verifying,
                    approval_record,
                    verification,
                    target=State.COMPLETED,
                    result_record_hash=verification_result_hash,
                ),
            ),
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA foreign_keys = ON")
            for statement in _TABLE_SCHEMAS_V3.values():
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_meta(key, value) "
                "VALUES('schema_version', '3')"
            )
            insert_v1_operation(
                connection, completed, scope="scope-v3-approval"
            )
            previous_hash = GENESIS_HASH
            for sequence, (event_id, event_type, occurred, payload) in enumerate(
                event_specs, start=1
            ):
                occurred_text = occurred.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
                payload_json = canonical_json(payload).decode("utf-8")
                event_hash = _audit_hash(
                    sequence=sequence,
                    event_id=event_id,
                    event_type=event_type,
                    operation_id=completed.operation_id,
                    occurred_at=occurred_text,
                    payload_json=payload_json,
                    previous_hash=previous_hash,
                )
                connection.execute(
                    "INSERT INTO audit_events("
                    "sequence, event_id, event_type, operation_id, occurred_at, "
                    "payload_json, previous_hash, event_hash) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sequence,
                        event_id,
                        event_type,
                        completed.operation_id,
                        occurred_text,
                        payload_json,
                        previous_hash,
                        event_hash,
                    ),
                )
                previous_hash = event_hash
            connection.execute(
                f"INSERT INTO approval_records("
                f"{', '.join(_APPROVAL_RECORD_COLUMNS)}) "
                f"VALUES({', '.join('?' for _ in _APPROVAL_RECORD_COLUMNS)})",
                tuple(
                    approval_payload[column]
                    for column in _APPROVAL_RECORD_COLUMNS[:-1]
                )
                + (approval_hash,),
            )
            for result_payload, result_hash in (
                (execution_result_payload, execution_result_hash),
                (verification_result_payload, verification_result_hash),
            ):
                connection.execute(
                    f"INSERT INTO trusted_result_records("
                    f"{', '.join(_TRUSTED_RESULT_RECORD_COLUMNS)}) "
                    f"VALUES({', '.join('?' for _ in _TRUSTED_RESULT_RECORD_COLUMNS)})",
                    tuple(
                        result_payload[column]
                        for column in _TRUSTED_RESULT_RECORD_COLUMNS[:-1]
                    )
                    + (result_hash,),
                )
            for statement in _TRIGGER_SCHEMAS_V3.values():
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 3")
            before_record = tuple(
                connection.execute(
                    "SELECT * FROM approval_records"
                ).fetchone()
            )
        legacy_path.chmod(0o600)

        migrated = SQLitePersistence(legacy_path)
        stored = migrated.get_approval_record(completed.operation_id)
        self.assertEqual(stored.record_origin, "native_v2")
        self.assertEqual(stored.signature_version, 2)
        self.assertEqual(stored.signature_purpose, "approval_v2")
        self.assertEqual(
            migrated.get_operation(completed.operation_id).protocol_version, 3
        )
        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(
                tuple(connection.execute("SELECT * FROM approval_records").fetchone()),
                before_record,
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], 4
            )
        migrated_operation = migrated.get_operation(completed.operation_id)
        self.assertEqual(migrated_operation.state, State.COMPLETED)
        self.assertEqual(
            migrated.get_final_write_receipts(completed.operation_id), ()
        )
        native_v4 = persist_awaiting(self.store, "reject-v2-approval")
        v3_approval = signed_approval(native_v4, "native-v4-approval-nonce")
        with self.assertRaises(ApprovalRejected):
            self.store.accept_approval(
                replace(
                    v3_approval,
                    signature_version=2,
                    signature_purpose="approval_v2",
                ),
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=native_v4.revision,
            )

    def test_v3_to_v4_migration_failure_rolls_back_atomically(self) -> None:
        legacy_path = Path(self.directory.name) / "v3-rollback.sqlite3"
        operation = replace(
            prepared_operation(
                "op-v3-rollback",
                "request-v3-rollback",
                idempotency_key="idem-v3-rollback",
            ),
            protocol_version=3,
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA foreign_keys = ON")
            for statement in _TABLE_SCHEMAS_V3.values():
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_meta(key, value) "
                "VALUES('schema_version', '3')"
            )
            insert_v1_operation(
                connection, operation, scope="scope-v3-rollback"
            )
            for statement in _TRIGGER_SCHEMAS_V3.values():
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 3")
        legacy_path.chmod(0o600)

        with patch(
            "odoo_accounting_cli_v3.persistence._operation_protocol_record_hash",
            side_effect=RuntimeError("injected migration crash"),
        ), self.assertRaisesRegex(RuntimeError, "migration crash"):
            SQLitePersistence(legacy_path)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], 3
            )
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key = 'schema_version'"
                ).fetchone()[0],
                "3",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'operation_protocols'"
                ).fetchone()
            )
            approval_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'approval_records'"
            ).fetchone()[0]
            self.assertNotIn("native_v3", approval_sql)

    def test_unsafe_v1_migration_rolls_back_and_remains_v1(self) -> None:
        legacy_path = Path(self.directory.name) / "unsafe-v1.sqlite3"
        create_v1_schema(legacy_path)
        operation = prepared_operation(
            "op-partial-legacy",
            "request-partial-legacy",
            idempotency_key="idem-partial-legacy",
        )
        payload = _operation_payload(operation)
        payload["approval_signature"] = "a" * 64
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(
                connection,
                operation,
                payload_override=payload,
                scope="partial-legacy-scope",
            )

        with self.assertRaisesRegex(PersistenceIntegrityError, "operation"):
            SQLitePersistence(legacy_path)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "1",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'approval_records'"
                ).fetchone()
            )

    def test_v1_reserved_business_audit_event_is_not_migrated(self) -> None:
        legacy_path = Path(self.directory.name) / "reserved-v1.sqlite3"
        create_v1_schema(legacy_path)
        occurred_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        payload_json = canonical_json({"forged": True}).decode("utf-8")
        event_hash = _audit_hash(
            sequence=1,
            event_id="read:forged-v1",
            event_type="read.verified",
            operation_id=None,
            occurred_at=occurred_at,
            payload_json=payload_json,
            previous_hash=GENESIS_HASH,
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            connection.execute(
                """
                INSERT INTO audit_events(
                    sequence, event_id, event_type, operation_id, occurred_at,
                    payload_json, previous_hash, event_hash
                ) VALUES(1, 'read:forged-v1', 'read.verified', NULL, ?, ?, ?, ?)
                """,
                (occurred_at, payload_json, GENESIS_HASH, event_hash),
            )

        with self.assertRaisesRegex(PersistenceIntegrityError, "reserved audit"):
            SQLitePersistence(legacy_path)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "1",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'approval_records'"
                ).fetchone()
            )

    def test_v1_mismatched_idempotency_binding_is_not_migrated(self) -> None:
        legacy_path = Path(self.directory.name) / "idempotency-mismatch-v1.sqlite3"
        create_v1_schema(legacy_path)
        operation = prepared_operation(
            "op-idempotency-mismatch",
            "request-idempotency-mismatch",
            idempotency_key="idem-idempotency-mismatch",
        )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(connection, operation, scope="original-scope")
            connection.execute(
                "UPDATE idempotency_keys SET company_id = ?, scope = ? "
                "WHERE operation_id = ?",
                (operation.company_id + 1, "wrong-scope", operation.operation_id),
            )

        with self.assertRaisesRegex(PersistenceIntegrityError, "idempotency"):
            SQLitePersistence(legacy_path)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'approval_records'"
                ).fetchone()
            )

    def test_v1_mismatched_diagnostic_namespace_is_not_migrated(self) -> None:
        occurred_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        payload_json = canonical_json({"legacy": True}).decode("utf-8")
        for suffix, event_id, event_type in (
            ("id", "diagnostic:ambiguous", "legacy.event"),
            ("type", "legacy-event", "diagnostic.ambiguous"),
        ):
            with self.subTest(suffix=suffix):
                path = Path(self.directory.name) / f"diagnostic-{suffix}-v1.sqlite3"
                create_v1_schema(path)
                event_hash = _audit_hash(
                    sequence=1,
                    event_id=event_id,
                    event_type=event_type,
                    operation_id=None,
                    occurred_at=occurred_at,
                    payload_json=payload_json,
                    previous_hash=GENESIS_HASH,
                )
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        """
                        INSERT INTO audit_events(
                            sequence, event_id, event_type, operation_id,
                            occurred_at, payload_json, previous_hash, event_hash
                        ) VALUES(1, ?, ?, NULL, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            event_type,
                            occurred_at,
                            payload_json,
                            GENESIS_HASH,
                            event_hash,
                        ),
                    )
                with self.assertRaisesRegex(
                    PersistenceIntegrityError, "diagnostic namespace"
                ):
                    SQLitePersistence(path)
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0], 1
                    )

    def test_v1_duplicate_approval_nonce_fails_with_stable_integrity_error(self) -> None:
        legacy_path = Path(self.directory.name) / "duplicate-v1-nonce.sqlite3"
        create_v1_schema(legacy_path)
        operations: list[Operation] = []
        for suffix in ("first", "second"):
            operation = prepared_operation(
                f"op-legacy-{suffix}",
                f"request-legacy-{suffix}",
                idempotency_key=f"idem-legacy-{suffix}",
            )
            operation = record_precheck(
                operation,
                precheck_digest=content_digest(precheck_evidence(operation)),
                expected_revision=0,
            )
            operation = operation.transition(
                State.AWAITING_APPROVAL, expected_revision=1
            )
            approval = signed_approval(operation, "duplicate-legacy-nonce")
            operations.append(
                approve_operation(
                    operation,
                    approval,
                    now=NOW,
                    secret=APPROVAL_SECRET,
                    expected_key_id=APPROVAL_KEY_ID,
                    is_approver_authorized=lambda *_: True,
                    consume_nonce=lambda *_: True,
                    approval_ttl_seconds=900,
                    expected_revision=2,
                )
            )
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            for index, operation in enumerate(operations):
                insert_v1_operation(
                    connection,
                    operation,
                    scope=f"legacy-duplicate-scope-{index}",
                )

        with self.assertRaisesRegex(
            PersistenceIntegrityError, "duplicate approval nonce"
        ):
            SQLitePersistence(legacy_path)
        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'approval_records'"
                ).fetchone()
            )

    def test_accept_approval_is_atomic_durable_and_secret_free(self) -> None:
        operation = persist_awaiting(self.store, "accept")
        raw_nonce = "raw-approval-nonce-must-never-persist"
        approval = signed_approval(operation, raw_nonce)

        accepted = accept_approval(self.store, approval)

        self.assertEqual(accepted.operation.state, State.APPROVED)
        self.assertEqual(accepted.operation.revision, 3)
        self.assertEqual(accepted.approval_record.operation_id, operation.operation_id)
        self.assertEqual(accepted.approval_record.record_origin, "native_v3")
        self.assertEqual(accepted.approval_record.signature_version, 3)
        self.assertEqual(accepted.approval_record.signature_purpose, "approval_v3")
        self.assertEqual(
            accepted.approval_record.audit_event_id, accepted.audit_event.event_id
        )
        self.assertEqual(accepted.audit_event.event_type, "operation.approved")
        self.assertEqual(accepted.audit_event.payload["from_state"], "awaiting_approval")
        self.assertEqual(accepted.audit_event.payload["to_state"], "approved")
        self.assertEqual(
            accepted.audit_event.payload["precheck_digest"],
            operation.precheck_digest,
        )
        self.assertNotIn("nonce", accepted.audit_event.payload)
        self.assertEqual(self.store.verify_chain(), 3)

        restarted = SQLitePersistence(self.path)
        self.assertEqual(restarted.get_operation(operation.operation_id), accepted.operation)
        self.assertEqual(
            restarted.get_approval_record(operation.operation_id),
            accepted.approval_record,
        )
        self.assertEqual(restarted.audit_events()[-1], accepted.audit_event)

        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if candidate.exists():
                content = candidate.read_bytes()
                self.assertNotIn(raw_nonce.encode("utf-8"), content)
                self.assertNotIn(APPROVAL_SECRET, content)

    def test_native_approval_rejects_hash_valid_but_wrong_audit_payload(self) -> None:
        operation = persist_awaiting(self.store, "audit-binding")
        accepted = accept_approval(
            self.store,
            signed_approval(operation, "audit-binding-nonce"),
        )
        wrong_payload_json = canonical_json(
            {
                "from_state": "prepared",
                "operation_id": "different-operation",
                "to_state": "completed",
            }
        ).decode("utf-8")
        event = accepted.audit_event
        occurred_at = event.occurred_at.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        wrong_hash = _audit_hash(
            sequence=event.sequence,
            event_id=event.event_id,
            event_type=event.event_type,
            operation_id=event.operation_id,
            occurred_at=occurred_at,
            payload_json=wrong_payload_json,
            previous_hash=event.previous_hash,
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET payload_json = ?, event_hash = ? "
                "WHERE event_id = ?",
                (wrong_payload_json, wrong_hash, event.event_id),
            )
            connection.execute(_TRIGGER_SCHEMAS_V2["audit_events_no_update"])

        self.assertEqual(self.store.verify_chain(), 3)
        with self.assertRaisesRegex(PersistenceIntegrityError, "audit"):
            self.store.get_approval_record(operation.operation_id)
        with self.assertRaisesRegex(PersistenceIntegrityError, "audit"):
            SQLitePersistence(self.path)

    def test_native_approval_audit_rejects_json_numeric_type_confusion(self) -> None:
        operation = persist_awaiting(self.store, "approval-json-type")
        accepted = accept_approval(
            self.store,
            signed_approval(operation, "approval-json-type-nonce"),
        )
        forged_payload = dict(accepted.audit_event.payload)
        forged_payload["company_id"] = float(operation.company_id)
        rewrite_audit_payload(self.path, accepted.audit_event, forged_payload)

        self.assertEqual(self.store.verify_chain(), 3)
        with self.assertRaisesRegex(PersistenceIntegrityError, "approval audit"):
            self.store.get_operation(operation.operation_id)
        with self.assertRaisesRegex(PersistenceIntegrityError, "approval audit"):
            SQLitePersistence(self.path)

    def test_begin_execution_requires_native_durable_approval_and_audits(self) -> None:
        operation = persist_awaiting(self.store, "begin-execution")
        approval = signed_approval(operation, "begin-execution-nonce")
        accepted = accept_approval(self.store, approval)

        started = self.store.begin_execution(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=accepted.operation.revision,
        )

        self.assertEqual(started.operation.state, State.EXECUTING)
        self.assertEqual(started.operation.revision, 4)
        self.assertEqual(started.approval_record.record_origin, "native_v3")
        self.assertEqual(started.audit_event.event_type, "operation.executing")
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(operation.operation_id), started.operation
        )
        self.assertEqual(
            [event.event_type for event in restarted.audit_events()],
            [
                "operation.prechecked",
                "operation.awaiting_approval",
                "operation.approved",
                "operation.executing",
            ],
        )
        self.assertEqual(restarted.verify_chain(), 4)

    def test_begin_execution_rolls_back_when_audit_append_fails(self) -> None:
        operation = persist_awaiting(self.store, "execution-rollback")
        approval = signed_approval(operation, "execution-rollback-nonce")
        accepted = accept_approval(self.store, approval)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_execution_audit_failure
                BEFORE INSERT ON audit_events
                WHEN NEW.event_type = 'operation.executing'
                BEGIN
                    SELECT RAISE(ABORT, 'forced execution audit failure');
                END
                """
            )

        with self.assertRaisesRegex(PersistenceError, "execution transaction"):
            self.store.begin_execution(
                approval,
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=accepted.operation.revision,
            )
        self.assertEqual(
            self.store.get_operation(operation.operation_id), accepted.operation
        )
        self.assertEqual(
            [event.event_type for event in self.store.audit_events()],
            [
                "operation.prechecked",
                "operation.awaiting_approval",
                "operation.approved",
            ],
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_execution_audit_failure")
        started = self.store.begin_execution(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=accepted.operation.revision,
        )
        self.assertEqual(started.operation.state, State.EXECUTING)

    def test_begin_execution_rolls_back_when_state_update_fails(self) -> None:
        operation = persist_awaiting(self.store, "execution-state-rollback")
        approval = signed_approval(
            operation,
            "execution-state-rollback-nonce",
        )
        accepted = accept_approval(self.store, approval)
        events_before = self.store.audit_events()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_execution_state_failure
                BEFORE UPDATE OF state ON operations
                WHEN NEW.state = 'executing'
                BEGIN
                    SELECT RAISE(ABORT, 'forced execution state failure');
                END
                """
            )

        with self.assertRaisesRegex(PersistenceError, "execution transaction"):
            self.store.begin_execution(
                approval,
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=accepted.operation.revision,
            )

        self.assertEqual(
            self.store.get_operation(operation.operation_id),
            accepted.operation,
        )
        self.assertEqual(self.store.audit_events(), events_before)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_execution_state_failure")

        self.assertEqual(
            self.store.begin_execution(
                approval,
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=accepted.operation.revision,
            ).operation.state,
            State.EXECUTING,
        )

    def test_begin_execution_policy_rejections_have_zero_side_effects(self) -> None:
        cases = (
            (
                "expired",
                NOW + timedelta(minutes=6),
                APPROVAL_KEY_ID,
                lambda *_: True,
            ),
            ("wrong-key", NOW, "retired-key", lambda *_: True),
            ("truthy-auth", NOW, APPROVAL_KEY_ID, lambda *_: 1),
        )
        for suffix, now, expected_key_id, authorize in cases:
            with self.subTest(suffix=suffix):
                awaiting = persist_awaiting(self.store, f"begin-{suffix}")
                approval = signed_approval(
                    awaiting,
                    f"begin-{suffix}-nonce",
                )
                accepted = accept_approval(self.store, approval)
                events_before = self.store.audit_events()

                with self.assertRaises(ApprovalRejected):
                    self.store.begin_execution(
                        approval,
                        now=now,
                        secret=APPROVAL_SECRET,
                        expected_key_id=expected_key_id,
                        is_approver_authorized=authorize,
                        approval_ttl_seconds=900,
                        expected_revision=accepted.operation.revision,
                    )

                self.assertEqual(
                    self.store.get_operation(awaiting.operation_id),
                    accepted.operation,
                )
                self.assertEqual(
                    self.store.get_approval_record(awaiting.operation_id),
                    accepted.approval_record,
                )
                self.assertEqual(self.store.audit_events(), events_before)

    def test_result_verification_and_recovery_lifecycle_is_atomic_and_restart_safe(self) -> None:
        started = persist_executing(self.store, "durable-lifecycle")
        execution_evidence = {"model": "account.move", "record_id": 501}
        execution = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        verifying = self.store.record_execution_result(
            execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
        )
        self.assertEqual(verifying.operation.state, State.VERIFYING)
        verification_evidence = {"record_id": 501, "state": "posted"}
        verification = sign_verification_result(
            operation=verifying.operation,
            issuer="odoo-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=content_digest(verification_evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        completed = self.store.complete_operation(
            verification,
            evidence=verification_evidence,
            now=NOW,
            secret=VERIFICATION_SECRET,
            expected_key_id="verification-v1",
            allowed_issuers=frozenset({"odoo-verifier"}),
            expected_revision=verifying.operation.revision,
            receipt_factory=final_receipt_details,
        )
        self.assertIsNotNone(completed.final_receipt)
        self.assertEqual(
            completed.final_receipt.body["audit_event_hash"],
            completed.audit_event.event_hash,
        )
        self.assertEqual(
            completed.final_receipt.body["audit_sequence"],
            completed.audit_event.sequence,
        )
        self.assertEqual(
            completed.audit_event.payload["final_receipt_details_digest"],
            content_digest(final_receipt_details(completed.operation)),
        )
        recovery_plan = {"action": "reverse", "record_id": 501}
        plan_digest = content_digest(recovery_plan)
        with self.assertRaisesRegex(PersistenceIntegrityError, "plan content digest"):
            self.store.begin_recovery(
                operation_id=completed.operation.operation_id,
                recovery_plan={"action": "tampered"},
                recovery_plan_digest=plan_digest,
                actor_principal=completed.operation.principal,
                actor_user_id=completed.operation.user_id,
                actor_company_id=completed.operation.company_id,
                occurred_at=NOW,
                expected_revision=completed.operation.revision,
            )
        recovering = self.store.begin_recovery(
            operation_id=completed.operation.operation_id,
            recovery_plan=recovery_plan,
            recovery_plan_digest=plan_digest,
            actor_principal=completed.operation.principal,
            actor_user_id=completed.operation.user_id,
            actor_company_id=completed.operation.company_id,
            occurred_at=NOW,
            expected_revision=completed.operation.revision,
        )
        recovery_evidence = {"reversal_record_id": 502, "state": "posted"}
        recovery_result = sign_recovery_result(
            operation=recovering.operation,
            recovery_plan_digest=plan_digest,
            issuer="odoo-recovery-verifier",
            key_id="recovery-v1",
            succeeded=True,
            evidence_digest=content_digest(recovery_evidence),
            issued_at=NOW,
            secret=RECOVERY_SECRET,
        )
        recovered = self.store.complete_recovery(
            recovery_result,
            evidence=recovery_evidence,
            now=NOW,
            secret=RECOVERY_SECRET,
            expected_key_id="recovery-v1",
            allowed_issuers=frozenset({"odoo-recovery-verifier"}),
            expected_revision=recovering.operation.revision,
            receipt_factory=final_receipt_details,
        )
        self.assertEqual(recovered.operation.state, State.RECOVERED)
        self.assertIsNotNone(recovered.final_receipt)
        self.assertEqual(
            recovered.final_receipt.body["audit_event_hash"],
            recovered.audit_event.event_hash,
        )
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(recovered.operation.operation_id),
            recovered.operation,
        )
        self.assertEqual(
            [record.kind for record in restarted.get_trusted_result_records(
                recovered.operation.operation_id
            )],
            ["execution", "verification", "recovery"],
        )
        self.assertEqual(
            restarted.get_recovery_records(recovered.operation.operation_id)[0].plan_digest,
            plan_digest,
        )
        final_receipts = restarted.get_final_write_receipts(
            recovered.operation.operation_id
        )
        self.assertEqual(
            [receipt.terminal_state for receipt in final_receipts],
            [State.COMPLETED.value, State.RECOVERED.value],
        )
        self.assertEqual(
            restarted.get_final_write_receipt(
                recovered.final_receipt.receipt_id
            ),
            recovered.final_receipt,
        )
        self.assertEqual(
            restarted.get_trusted_result_record(
                recovered.result_record.result_id
            ).evidence_json,
            canonical_json(recovery_evidence).decode("utf-8"),
        )
        self.assertEqual(
            restarted.get_recovery_plan(
                recovering.recovery_record.recovery_id
            ).plan_json,
            canonical_json(recovery_plan).decode("utf-8"),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE trusted_result_records SET evidence_json = '{}' "
                    "WHERE result_id = ?",
                    (recovered.result_record.result_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE recovery_records SET plan_json = '{}' "
                    "WHERE recovery_id = ?",
                    (recovering.recovery_record.recovery_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE final_write_receipts SET body_json = '{}' "
                    "WHERE receipt_id = ?",
                    (recovered.final_receipt.receipt_id,),
                )

    def test_negative_execution_and_recovery_results_remain_failed(self) -> None:
        started = persist_executing(self.store, "negative-results")
        execution_evidence = {"error": "odoo validation failed", "retryable": False}
        negative_execution = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=False,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        failed = self.store.record_execution_result(
            negative_execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
            receipt_factory=final_receipt_details,
        )
        self.assertEqual(failed.operation.state, State.FAILED)
        recovery_plan = {"action": "rollback_savepoint", "attempt": 1}
        plan_digest = content_digest(recovery_plan)
        recovering = self.store.begin_recovery(
            operation_id=failed.operation.operation_id,
            recovery_plan=recovery_plan,
            recovery_plan_digest=plan_digest,
            actor_principal=failed.operation.principal,
            actor_user_id=failed.operation.user_id,
            actor_company_id=failed.operation.company_id,
            occurred_at=NOW,
            expected_revision=failed.operation.revision,
        )
        recovery_evidence = {"error": "rollback rejected", "retryable": True}
        negative_recovery = sign_recovery_result(
            operation=recovering.operation,
            recovery_plan_digest=plan_digest,
            issuer="odoo-recovery-verifier",
            key_id="recovery-v1",
            succeeded=False,
            evidence_digest=content_digest(recovery_evidence),
            issued_at=NOW,
            secret=RECOVERY_SECRET,
        )
        failed_again = self.store.complete_recovery(
            negative_recovery,
            evidence=recovery_evidence,
            now=NOW,
            secret=RECOVERY_SECRET,
            expected_key_id="recovery-v1",
            allowed_issuers=frozenset({"odoo-recovery-verifier"}),
            expected_revision=recovering.operation.revision,
            receipt_factory=final_receipt_details,
        )
        self.assertEqual(failed_again.operation.state, State.FAILED)

    def test_final_write_receipt_tampering_is_detected_on_restart(self) -> None:
        started = persist_executing(self.store, "receipt-tamper")
        evidence = {"error": "Odoo rejected write", "retryable": False}
        result = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=False,
            evidence_digest=content_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        failed = self.store.record_execution_result(
            result,
            evidence=evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
            receipt_factory=final_receipt_details,
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER final_write_receipts_no_update")
            connection.execute(
                "UPDATE final_write_receipts SET body_json = '{}' "
                "WHERE receipt_id = ?",
                (failed.final_receipt.receipt_id,),
            )
            connection.execute(
                _TRIGGER_SCHEMAS_V4["final_write_receipts_no_update"]
            )
        with self.assertRaisesRegex(
            PersistenceIntegrityError, "final write receipt hash"
        ):
            SQLitePersistence(self.path)

    def test_rehashed_receipt_details_are_rejected_by_terminal_audit_binding(
        self,
    ) -> None:
        started = persist_executing(self.store, "receipt-rehashed-tamper")
        evidence = {"error": "Odoo rejected write", "retryable": False}
        result = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=False,
            evidence_digest=content_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        failed = self.store.record_execution_result(
            result,
            evidence=evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
            receipt_factory=final_receipt_details,
        )
        original_receipt_id = failed.final_receipt.receipt_id
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                f"SELECT {', '.join(_FINAL_WRITE_RECEIPT_COLUMNS)} "
                "FROM final_write_receipts WHERE receipt_id = ?",
                (original_receipt_id,),
            ).fetchone()
            forged_body = json.loads(row["body_json"])
            forged_body["receipt_details"]["odoo_receipt"] = "forged"
            forged_body_json = canonical_json(forged_body).decode("utf-8")
            forged_body_digest = hashlib.sha256(
                forged_body_json.encode("utf-8")
            ).hexdigest()
            forged_receipt_id = _final_receipt_id(
                failed.operation,
                result_id=row["result_id"],
                body_digest=forged_body_digest,
            )
            forged_payload = {
                column: row[column]
                for column in _FINAL_WRITE_RECEIPT_COLUMNS[:-1]
            }
            forged_payload.update(
                {
                    "receipt_id": forged_receipt_id,
                    "body_digest": forged_body_digest,
                    "body_json": forged_body_json,
                }
            )
            forged_record_hash = _final_receipt_record_hash(forged_payload)
            connection.execute("DROP TRIGGER final_write_receipts_no_update")
            connection.execute(
                "UPDATE final_write_receipts "
                "SET receipt_id = ?, body_digest = ?, body_json = ?, "
                "record_hash = ? WHERE receipt_id = ?",
                (
                    forged_receipt_id,
                    forged_body_digest,
                    forged_body_json,
                    forged_record_hash,
                    original_receipt_id,
                ),
            )
            connection.execute(
                _TRIGGER_SCHEMAS_V4["final_write_receipts_no_update"]
            )
        with self.assertRaisesRegex(
            PersistenceIntegrityError, "final write receipt is invalid"
        ):
            SQLitePersistence(self.path)

    def test_negative_verification_result_is_persisted_and_remains_failed(self) -> None:
        started = persist_executing(self.store, "negative-verification")
        execution_evidence = {"model": "account.move", "record_id": 991}
        execution = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        verifying = self.store.record_execution_result(
            execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
        )
        failure_evidence = {
            "error": "posted totals differ from preview",
            "expected": "100.00",
            "observed": "101.00",
        }
        verification = sign_verification_result(
            operation=verifying.operation,
            issuer="odoo-verifier",
            key_id="verification-v1",
            succeeded=False,
            evidence_digest=content_digest(failure_evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        failed = self.store.complete_operation(
            verification,
            evidence=failure_evidence,
            now=NOW,
            secret=VERIFICATION_SECRET,
            expected_key_id="verification-v1",
            allowed_issuers=frozenset({"odoo-verifier"}),
            expected_revision=verifying.operation.revision,
            receipt_factory=final_receipt_details,
        )
        self.assertEqual(failed.operation.state, State.FAILED)
        restarted = SQLitePersistence(self.path)
        records = restarted.get_trusted_result_records(
            failed.operation.operation_id
        )
        self.assertEqual([record.kind for record in records], ["execution", "verification"])
        self.assertFalse(records[-1].succeeded)
        self.assertEqual(records[-1].evidence, failure_evidence)

    def test_execution_result_transaction_rolls_back_record_audit_and_state(self) -> None:
        started = persist_executing(self.store, "result-rollback")
        evidence = {"model": "account.move", "record_id": 777}
        result = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_result_audit_failure
                BEFORE INSERT ON audit_events
                WHEN NEW.event_type = 'operation.verifying'
                BEGIN
                    SELECT RAISE(ABORT, 'forced result audit failure');
                END
                """
            )
        with self.assertRaisesRegex(PersistenceError, "result transaction"):
            self.store.record_execution_result(
                result,
                evidence=evidence,
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id="execution-v1",
                allowed_issuers=frozenset({"odoo-executor"}),
                expected_revision=started.operation.revision,
            )
        self.assertEqual(
            self.store.get_operation(started.operation.operation_id),
            started.operation,
        )
        self.assertEqual(
            self.store.get_trusted_result_records(started.operation.operation_id),
            (),
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_result_audit_failure")
            connection.execute(
                """
                CREATE TRIGGER force_result_state_failure
                BEFORE UPDATE OF state ON operations
                WHEN NEW.state = 'verifying'
                BEGIN
                    SELECT RAISE(ABORT, 'forced result state failure');
                END
                """
            )
        events_before = self.store.audit_events()
        with self.assertRaisesRegex(PersistenceError, "result transaction"):
            self.store.record_execution_result(
                result,
                evidence=evidence,
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id="execution-v1",
                allowed_issuers=frozenset({"odoo-executor"}),
                expected_revision=started.operation.revision,
            )
        self.assertEqual(
            self.store.get_operation(started.operation.operation_id),
            started.operation,
        )
        self.assertEqual(self.store.audit_events(), events_before)
        self.assertEqual(
            self.store.get_trusted_result_records(started.operation.operation_id),
            (),
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_result_state_failure")

    def test_terminal_factory_and_state_failures_roll_back_receipt_result_audit_and_state(
        self,
    ) -> None:
        started = persist_executing(self.store, "terminal-rollback")
        execution_evidence = {"model": "account.move", "record_id": 778}
        execution = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        verifying = self.store.record_execution_result(
            execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
        )
        verification_evidence = {"record_id": 778, "state": "posted"}
        verification = sign_verification_result(
            operation=verifying.operation,
            issuer="odoo-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=content_digest(verification_evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        baseline_events = self.store.audit_events()
        baseline_results = self.store.get_trusted_result_records(
            verifying.operation.operation_id
        )

        with self.assertRaisesRegex(PersistenceError, "receipt factory"):
            self.store.complete_operation(
                verification,
                evidence=verification_evidence,
                now=NOW,
                secret=VERIFICATION_SECRET,
                expected_key_id="verification-v1",
                allowed_issuers=frozenset({"odoo-verifier"}),
                expected_revision=verifying.operation.revision,
                receipt_factory=None,
            )

        def crashing_factory(_operation):
            raise RuntimeError("simulated process crash")

        with self.assertRaisesRegex(PersistenceError, "factory failed"):
            self.store.complete_operation(
                verification,
                evidence=verification_evidence,
                now=NOW,
                secret=VERIFICATION_SECRET,
                expected_key_id="verification-v1",
                allowed_issuers=frozenset({"odoo-verifier"}),
                expected_revision=verifying.operation.revision,
                receipt_factory=crashing_factory,
            )
        self.assertEqual(
            self.store.get_operation(verifying.operation.operation_id),
            verifying.operation,
        )
        self.assertEqual(self.store.audit_events(), baseline_events)
        self.assertEqual(
            self.store.get_trusted_result_records(
                verifying.operation.operation_id
            ),
            baseline_results,
        )
        self.assertEqual(
            self.store.get_final_write_receipts(
                verifying.operation.operation_id
            ),
            (),
        )

        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_terminal_state_failure
                BEFORE UPDATE OF state ON operations
                WHEN NEW.state = 'completed'
                BEGIN
                    SELECT RAISE(ABORT, 'forced terminal state failure');
                END
                """
            )
        with self.assertRaisesRegex(PersistenceError, "result transaction"):
            self.store.complete_operation(
                verification,
                evidence=verification_evidence,
                now=NOW,
                secret=VERIFICATION_SECRET,
                expected_key_id="verification-v1",
                allowed_issuers=frozenset({"odoo-verifier"}),
                expected_revision=verifying.operation.revision,
                receipt_factory=final_receipt_details,
            )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_terminal_state_failure")
        self.assertEqual(
            self.store.get_operation(verifying.operation.operation_id),
            verifying.operation,
        )
        self.assertEqual(self.store.audit_events(), baseline_events)
        self.assertEqual(
            self.store.get_trusted_result_records(
                verifying.operation.operation_id
            ),
            baseline_results,
        )
        self.assertEqual(
            self.store.get_final_write_receipts(
                verifying.operation.operation_id
            ),
            (),
        )

    def test_result_evidence_digest_mismatch_has_zero_side_effects(self) -> None:
        started = persist_executing(self.store, "result-content-mismatch")
        signed_evidence = {"record_id": 901}
        result = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(signed_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        before_events = self.store.audit_events()
        with self.assertRaisesRegex(PersistenceIntegrityError, "digest"):
            self.store.record_execution_result(
                result,
                evidence={"record_id": 902},
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id="execution-v1",
                allowed_issuers=frozenset({"odoo-executor"}),
                expected_revision=started.operation.revision,
            )
        self.assertEqual(
            self.store.get_operation(started.operation.operation_id),
            started.operation,
        )
        self.assertEqual(self.store.audit_events(), before_events)
        self.assertEqual(
            self.store.get_trusted_result_records(started.operation.operation_id),
            (),
        )

    def test_executing_operation_rejects_hash_valid_wrong_audit_payload(self) -> None:
        operation = persist_awaiting(self.store, "execution-audit-binding")
        approval = signed_approval(operation, "execution-audit-binding-nonce")
        accepted = accept_approval(self.store, approval)
        started = self.store.begin_execution(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=accepted.operation.revision,
        )
        event = started.audit_event
        wrong_payload_json = canonical_json({"bogus": True}).decode("utf-8")
        occurred_at = event.occurred_at.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        wrong_hash = _audit_hash(
            sequence=event.sequence,
            event_id=event.event_id,
            event_type=event.event_type,
            operation_id=event.operation_id,
            occurred_at=occurred_at,
            payload_json=wrong_payload_json,
            previous_hash=event.previous_hash,
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET payload_json = ?, event_hash = ? "
                "WHERE event_id = ?",
                (wrong_payload_json, wrong_hash, event.event_id),
            )
            connection.execute(_TRIGGER_SCHEMAS_V2["audit_events_no_update"])

        self.assertEqual(self.store.verify_chain(), 4)
        with self.assertRaisesRegex(PersistenceIntegrityError, "execution audit"):
            self.store.get_operation(operation.operation_id)

    def test_execution_audit_rejects_json_numeric_type_confusion(self) -> None:
        operation = persist_awaiting(self.store, "execution-json-type")
        approval = signed_approval(operation, "execution-json-type-nonce")
        accepted = accept_approval(self.store, approval)
        started = self.store.begin_execution(
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=accepted.operation.revision,
        )
        forged_payload = dict(started.audit_event.payload)
        forged_payload["company_id"] = float(operation.company_id)
        rewrite_audit_payload(self.path, started.audit_event, forged_payload)

        self.assertEqual(self.store.verify_chain(), 4)
        with self.assertRaisesRegex(PersistenceIntegrityError, "execution audit"):
            self.store.get_operation(operation.operation_id)
        with self.assertRaisesRegex(PersistenceIntegrityError, "execution audit"):
            SQLitePersistence(self.path)

    def test_protected_state_load_requires_durable_approval_record(self) -> None:
        operation = persist_awaiting(self.store, "missing-evidence")
        approval = signed_approval(operation, "missing-evidence-nonce")
        approved = approve_operation(
            operation,
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        executing = begin_execution(
            approved,
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=3,
        )
        payload = _operation_payload(executing)
        mutable_columns = _OPERATION_COLUMNS[1:]
        assignments = ", ".join(f"{column} = ?" for column in mutable_columns)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "DROP TRIGGER operations_executing_requires_native_approval"
            )
            connection.execute(
                f"UPDATE operations SET {assignments}, record_hash = ? "
                "WHERE operation_id = ?",
                tuple(payload[column] for column in mutable_columns)
                + (_operation_record_hash(payload), operation.operation_id),
            )
            connection.execute(
                _TRIGGER_SCHEMAS_V2[
                    "operations_executing_requires_native_approval"
                ]
            )

        with self.assertRaisesRegex(PersistenceError, "approval record"):
            self.store.get_operation(operation.operation_id)

    def test_legacy_approval_cannot_begin_execution(self) -> None:
        legacy_path = Path(self.directory.name) / "legacy-execution.sqlite3"
        create_v1_schema(legacy_path)
        operation, approval = adversarial_v2_approval_in_v1_pair()
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(connection, operation)

        migrated = SQLitePersistence(legacy_path)
        self.assertEqual(
            migrated.get_approval_record(operation.operation_id).record_origin,
            "legacy_v1_unverifiable",
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "legacy"):
            migrated.begin_execution(
                approval,
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=operation.revision,
            )
        self.assertEqual(
            migrated.get_operation(operation.operation_id),
            replace(operation, protocol_version=3, precheck_digest=None),
        )
        self.assertEqual(migrated.verify_chain(), 0)

    def test_v1_legacy_approval_in_execution_state_is_not_migrated(self) -> None:
        legacy_path = Path(self.directory.name) / "legacy-already-executing.sqlite3"
        create_v1_schema(legacy_path)
        operation = legacy_approved_operation()._apply_transition(State.EXECUTING)
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            insert_v1_operation(connection, operation)

        with self.assertRaisesRegex(PersistenceIntegrityError, "legacy.*state"):
            SQLitePersistence(legacy_path)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'approval_records'"
                ).fetchone()
            )

    def test_v1_unaudited_failure_and_recovery_states_are_not_migrated(self) -> None:
        for target in (State.FAILED, State.RECOVERING, State.RECOVERED):
            with self.subTest(target=target):
                legacy_path = (
                    Path(self.directory.name)
                    / f"legacy-unsupported-{target.value}.sqlite3"
                )
                create_v1_schema(legacy_path)
                operation = prepared_operation(
                    f"op-legacy-{target.value}",
                    f"request-legacy-{target.value}",
                    idempotency_key=f"idem-legacy-{target.value}",
                )
                operation = replace(operation, protocol_version=3)
                failed = operation._apply_transition(State.FAILED)
                recovering = failed._apply_transition(State.RECOVERING)
                states = {
                    State.FAILED: failed,
                    State.RECOVERING: recovering,
                    State.RECOVERED: recovering._apply_transition(State.RECOVERED),
                }
                with closing(sqlite3.connect(legacy_path)) as connection, connection:
                    insert_v1_operation(connection, states[target])

                with self.assertRaisesRegex(
                    PersistenceIntegrityError, "legacy operation state"
                ):
                    SQLitePersistence(legacy_path)

                with closing(sqlite3.connect(legacy_path)) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        1,
                    )
                    self.assertIsNone(
                        connection.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE type = 'table' AND name = 'approval_records'"
                        ).fetchone()
                    )

    def test_approval_nonce_is_global_durable_and_content_bound(self) -> None:
        first = persist_awaiting(self.store, "nonce-first", amount="100.00")
        second = persist_awaiting(self.store, "nonce-second", amount="200.00")
        shared_nonce = "one-global-nonce"
        accept_approval(self.store, signed_approval(first, shared_nonce))

        restarted = SQLitePersistence(self.path)
        with self.assertRaisesRegex(ReplayRejected, "nonce"):
            accept_approval(restarted, signed_approval(second, shared_nonce))

        self.assertEqual(restarted.get_operation(second.operation_id), second)
        with closing(sqlite3.connect(self.path)) as connection:
            records = connection.execute(
                "SELECT COUNT(*) FROM approval_records"
            ).fetchone()[0]
            events = connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'operation.approved'"
            ).fetchone()[0]
        self.assertEqual((records, events), (1, 1))

    def test_accept_approval_rolls_back_when_audit_append_fails(self) -> None:
        operation = persist_awaiting(self.store, "rollback")
        approval = signed_approval(operation, "rollback-retry-nonce")
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_approval_audit_failure
                BEFORE INSERT ON audit_events
                WHEN NEW.event_type = 'operation.approved'
                BEGIN
                    SELECT RAISE(ABORT, 'forced approval audit failure');
                END
                """
            )

        with self.assertRaisesRegex(PersistenceError, "approval transaction"):
            accept_approval(self.store, approval)

        self.assertEqual(self.store.get_operation(operation.operation_id), operation)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM approval_records").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
                2,
            )
            connection.execute("DROP TRIGGER force_approval_audit_failure")
            connection.commit()

        accepted = accept_approval(self.store, approval)
        self.assertEqual(accepted.operation.state, State.APPROVED)

    def test_accept_approval_rolls_back_when_state_update_fails(self) -> None:
        operation = persist_awaiting(self.store, "approval-state-rollback")
        approval = signed_approval(
            operation,
            "approval-state-rollback-nonce",
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_approval_state_failure
                BEFORE UPDATE OF state ON operations
                WHEN NEW.state = 'approved'
                BEGIN
                    SELECT RAISE(ABORT, 'forced approval state failure');
                END
                """
            )

        with self.assertRaisesRegex(PersistenceError, "approval transaction"):
            accept_approval(self.store, approval)

        self.assertEqual(self.store.get_operation(operation.operation_id), operation)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM approval_records").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
                2,
            )
            connection.execute("DROP TRIGGER force_approval_state_failure")

        self.assertEqual(
            accept_approval(self.store, approval).operation.state,
            State.APPROVED,
        )

    def test_sql_cannot_bypass_approval_and_records_are_append_only(self) -> None:
        operation = persist_awaiting(self.store, "sql-guard")
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "native v3 approval"):
                connection.execute(
                    "UPDATE operations SET state = 'approved', revision = 3 "
                    "WHERE operation_id = ?",
                    (operation.operation_id,),
                )
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "executing transition"):
                connection.execute(
                    "UPDATE operations SET state = 'executing', revision = 4 "
                    "WHERE operation_id = ?",
                    (operation.operation_id,),
                )

        accept_approval(
            self.store, signed_approval(operation, "append-only-approval-nonce")
        )
        for target in (
            "failed",
            "verifying",
            "completed",
            "recovering",
            "recovered",
        ):
            with self.subTest(target=target), closing(
                sqlite3.connect(self.path)
            ) as connection:
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "requires"
                ):
                    connection.execute(
                        "UPDATE operations SET state = ?, revision = revision + 1 "
                        "WHERE operation_id = ?",
                        (target, operation.operation_id),
                    )
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE approval_records SET key_id = 'changed' "
                    "WHERE operation_id = ?",
                    (operation.operation_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "DELETE FROM approval_records WHERE operation_id = ?",
                    (operation.operation_id,),
                )

    def test_invalid_approvals_leave_no_database_side_effects(self) -> None:
        operation = persist_awaiting(self.store, "invalid")
        valid = signed_approval(operation, "invalid-cases-nonce")
        expired = signed_approval(
            operation,
            "expired-nonce",
            issued_at=NOW - timedelta(minutes=10),
            expires_at=NOW - timedelta(minutes=5),
        )
        cases = (
            (replace(valid, signature_version=1), True),
            (replace(valid, signature_purpose="approval_v1"), True),
            (replace(valid, key_id="retired-key"), True),
            (replace(valid, request_id="tampered-request"), True),
            (expired, True),
            (valid, False),
            (valid, 1),
        )

        for approval, authorized in cases:
            with self.subTest(approval=approval, authorized=authorized):
                with self.assertRaises((ApprovalRejected, ReplayRejected)):
                    accept_approval(
                        self.store, approval, authorized=authorized
                    )
                self.assertEqual(self.store.get_operation(operation.operation_id), operation)
                with closing(sqlite3.connect(self.path)) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM approval_records"
                        ).fetchone()[0],
                        0,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM audit_events"
                        ).fetchone()[0],
                        2,
                    )

    def test_auth_token_is_single_use_and_content_bound(self) -> None:
        self.store.consume_auth_token(
            token_id="token-1",
            request_digest="1" * 64,
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
        with self.assertRaisesRegex(ReplayRejected, "already consumed"):
            self.store.consume_auth_token(
                token_id="token-1",
                request_digest="1" * 64,
                expires_at=NOW + timedelta(minutes=5),
                now=NOW,
            )
        with self.assertRaisesRegex(ReplayRejected, "different request"):
            self.store.consume_auth_token(
                token_id="token-1",
                request_digest="2" * 64,
                expires_at=NOW + timedelta(minutes=5),
                now=NOW,
            )
        with self.assertRaisesRegex(ReplayRejected, "expired"):
            self.store.consume_auth_token(
                token_id="expired",
                request_digest="3" * 64,
                expires_at=NOW,
                now=NOW,
            )

    def test_receipt_is_single_use_content_bound_and_not_from_future(self) -> None:
        self.store.consume_receipt(
            receipt_id="receipt-1",
            request_digest="4" * 64,
            observed_at=NOW - timedelta(seconds=1),
            now=NOW,
        )
        with self.assertRaisesRegex(ReplayRejected, "already consumed"):
            self.store.consume_receipt(
                receipt_id="receipt-1",
                request_digest="4" * 64,
                observed_at=NOW - timedelta(seconds=1),
                now=NOW,
            )
        with self.assertRaisesRegex(ReplayRejected, "different request"):
            self.store.consume_receipt(
                receipt_id="receipt-1",
                request_digest="5" * 64,
                observed_at=NOW - timedelta(seconds=1),
                now=NOW,
            )
        with self.assertRaisesRegex(ReplayRejected, "future"):
            self.store.consume_receipt(
                receipt_id="future",
                request_digest="6" * 64,
                observed_at=NOW + timedelta(seconds=1),
                now=NOW,
            )

    def test_verified_read_receipt_and_audit_are_validated_and_atomic(self) -> None:
        observed_at = NOW - timedelta(seconds=1)
        parameters = {"company_id": 7, "date_to": "2026-07-13"}
        result_body = {"lines": [], "page": {"total_count": 0}}
        read_store = SQLitePersistence(
            self.path,
            receipt_key_id=RECEIPT_KEY_ID,
            receipt_secret=RECEIPT_SECRET,
        )

        def receipt(receipt_id: str):
            return create_read_receipt(
                receipt_id=receipt_id,
                capability_id="acct.gl.trial_balance.v1",
                parameters=parameters,
                result_body=result_body,
                auth_token_id="auth-read-1",
                principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2",
                database_name="odoo_test",
                database_uuid=DATABASE_UUID,
                company_id=7,
                user_id=42,
                registry_digest=REGISTRY_DIGEST,
                release_digest=RELEASE_DIGEST,
                environment="test",
                capability_channel="staged",
                record_count=0,
                observed_at=observed_at,
                key_id=RECEIPT_KEY_ID,
                secret=RECEIPT_SECRET,
            )

        def record(candidate):
            return read_store.record_verified_read(
                receipt=candidate,
                capability_id="acct.gl.trial_balance.v1",
                parameters=parameters,
                result_body=result_body,
                auth_token_id="auth-read-1",
                principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2",
                database_name="odoo_test",
                database_uuid=DATABASE_UUID,
                company_id=7,
                user_id=42,
                registry_digest=REGISTRY_DIGEST,
                release_digest=RELEASE_DIGEST,
                environment="test",
                capability_channel="staged",
                expected_record_count=0,
                now=NOW,
            )

        first_receipt = receipt("receipt-read-1")
        event = record(first_receipt)
        self.assertEqual(event.event_id, "read:receipt-read-1")
        self.assertEqual(event.event_type, "read.verified")
        self.assertEqual(event.payload["receipt"], first_receipt)
        self.assertEqual(event.payload["principal"], "pi:user-42")
        self.assertEqual(event.payload["odoo_instance_id"], "odoo19@tokyo2")
        self.assertEqual(self.store.verify_chain(), 1)
        with self.assertRaisesRegex(ReplayRejected, "already consumed"):
            record(first_receipt)

        forged = {
            **receipt("receipt-read-forged"),
            "signature": "f" * 64,
        }
        with self.assertRaisesRegex(PersistenceIntegrityError, "receipt rejected"):
            record(forged)
        self.assertEqual(self.store.verify_chain(), 1)

        with self.assertRaisesRegex(PersistenceIntegrityError, "verifier binding"):
            SQLitePersistence(
                self.path,
                receipt_key_id="attacker-key",
                receipt_secret=b"attacker-selected-receipt-secret!!",
            )
        with self.assertRaisesRegex(PersistenceError, "verifier is not configured"):
            self.store.record_verified_read(
                receipt=first_receipt,
                capability_id="acct.gl.trial_balance.v1",
                parameters=parameters,
                result_body=result_body,
                auth_token_id="auth-read-1",
                principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2",
                database_name="odoo_test",
                database_uuid=DATABASE_UUID,
                company_id=7,
                user_id=42,
                registry_digest=REGISTRY_DIGEST,
                release_digest=RELEASE_DIGEST,
                environment="test",
                capability_channel="staged",
                expected_record_count=0,
                now=NOW,
            )

        retryable = receipt("receipt-read-atomic")
        with patch.object(
            SQLitePersistence,
            "_append_audit_event",
            side_effect=sqlite3.IntegrityError("injected audit failure"),
        ), self.assertRaisesRegex(PersistenceError, "audit transaction"):
            record(retryable)
        recovered = record(retryable)
        self.assertEqual(recovered.event_id, "read:receipt-read-atomic")
        self.assertEqual(self.store.verify_chain(), 2)

        with closing(sqlite3.connect(self.path)) as connection:
            consumed = connection.execute(
                "SELECT request_digest, observed_at FROM consumed_receipts "
                "WHERE receipt_id = ?",
                (retryable["id"],),
            ).fetchone()
        self.assertEqual(
            consumed,
            (
                retryable["request_digest"],
                observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
        )

    def test_prepared_operation_round_trip_survives_restart(self) -> None:
        expected = prepared_operation("op-restart", "request-restart")
        stored, created = self.store.get_or_create_operation(expected, scope="complete-scope")
        self.assertTrue(created)
        self.assertEqual(stored, expected)

        restarted = SQLitePersistence(self.path)
        loaded = restarted.get_operation(expected.operation_id)
        self.assertEqual(loaded, expected)

    def test_precheck_evidence_is_canonical_durable_and_tamper_evident(self) -> None:
        operation = prepared_operation(
            "op-precheck-evidence", "request-precheck-evidence"
        )
        self.store.get_or_create_operation(
            operation, scope="precheck-evidence-scope"
        )
        evidence = {
            **precheck_evidence(operation),
            "checks": {"period_open": True, "journal_allowed": True},
        }
        accepted = self.store.record_precheck(
            operation_id=operation.operation_id,
            evidence=evidence,
            occurred_at=NOW,
            expected_revision=0,
        )
        self.assertEqual(
            accepted.operation.precheck_digest, content_digest(evidence)
        )
        restarted = SQLitePersistence(self.path)
        record = restarted.get_precheck_record(operation.operation_id)
        self.assertEqual(record.evidence, evidence)
        self.assertEqual(
            record.evidence_json,
            canonical_json(evidence).decode("utf-8"),
        )
        self.assertEqual(record.evidence_digest, accepted.operation.precheck_digest)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE precheck_records SET evidence_json = '{}' "
                    "WHERE operation_id = ?",
                    (operation.operation_id,),
                )
            connection.execute("DROP TRIGGER precheck_records_no_update")
            connection.execute(
                "UPDATE precheck_records SET evidence_json = '{}' "
                "WHERE operation_id = ?",
                (operation.operation_id,),
            )
            connection.execute(
                _TRIGGER_SCHEMAS_V4["precheck_records_no_update"]
            )
        with self.assertRaisesRegex(
            PersistenceIntegrityError, "precheck record hash"
        ):
            SQLitePersistence(self.path)

    def test_completed_insert_and_direct_approved_cas_are_rejected(self) -> None:
        with self.assertRaisesRegex(PersistenceIntegrityError, "pristine prepared"):
            self.store.get_or_create_operation(
                completed_operation(), scope="completed-scope"
            )

        original = prepared_operation("op-guarded", "request-guarded")
        self.store.get_or_create_operation(original, scope="guarded-scope")
        prechecked = self.store.record_precheck(
            operation_id=original.operation_id,
            evidence=precheck_evidence(original),
            occurred_at=NOW - timedelta(minutes=3),
            expected_revision=0,
        ).operation
        awaiting = prechecked.transition(State.AWAITING_APPROVAL, expected_revision=1)
        self.store.cas_update_operation(awaiting, expected_revision=1)
        approval = signed_approval(awaiting, "generic-cas-bypass-nonce")
        forged = approve_operation(
            awaiting,
            approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=lambda *_: True,
            consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "specialized transactional"):
            self.store.cas_update_operation(forged, expected_revision=2)

    def test_generic_cas_cannot_forge_or_clear_approved_evidence(self) -> None:
        for suffix, changes in (
            (
                "forged-results",
                {
                    "execution_result_digest": "a" * 64,
                    "verification_result_digest": "b" * 64,
                },
            ),
            (
                "cleared-approval",
                {
                    "approval_signature": None,
                    "approval_nonce_digest": None,
                    "approval_issued_at": None,
                    "approval_expires_at": None,
                    "approval_revision": None,
                    "approver_user_id": None,
                },
            ),
        ):
            with self.subTest(suffix=suffix):
                awaiting = persist_awaiting(self.store, suffix)
                accepted = accept_approval(
                    self.store,
                    signed_approval(awaiting, f"{suffix}-nonce"),
                )
                forged = replace(
                    accepted.operation,
                    state=State.FAILED,
                    revision=accepted.operation.revision + 1,
                    **changes,
                )

                with self.assertRaisesRegex(
                    PersistenceIntegrityError, "specialized transactional"
                ):
                    self.store.cas_update_operation(
                        forged,
                        expected_revision=accepted.operation.revision,
                    )

                self.assertEqual(
                    self.store.get_operation(awaiting.operation_id),
                    accepted.operation,
                )
                self.assertEqual(
                    self.store.get_approval_record(awaiting.operation_id),
                    accepted.approval_record,
                )

    def test_cas_updates_once_and_rejects_stale_revision(self) -> None:
        original = prepared_operation("op-cas", "request-cas")
        self.store.get_or_create_operation(original, scope="cas-scope")
        forged = original._apply_transition(
            State.PRECHECKED,
            precheck_digest=content_digest({"forged": True}),
        )
        with self.assertRaisesRegex(
            PersistenceIntegrityError, "specialized transactional"
        ):
            self.store.cas_update_operation(forged, expected_revision=0)
        accepted = self.store.record_precheck(
            operation_id=original.operation_id,
            evidence=precheck_evidence(original),
            occurred_at=NOW,
            expected_revision=0,
        )
        prechecked = accepted.operation
        with self.assertRaisesRegex(ConcurrentUpdate, "revision"):
            self.store.record_precheck(
                operation_id=original.operation_id,
                evidence=precheck_evidence(original),
                occurred_at=NOW,
                expected_revision=0,
            )
        self.assertEqual(self.store.get_operation(original.operation_id), prechecked)
        event = self.store.audit_events()[0]
        self.assertEqual(event.event_type, "operation.prechecked")
        self.assertEqual(event.payload["from_revision"], 0)
        self.assertEqual(event.payload["to_revision"], 1)
        self.assertEqual(event.payload["principal"], original.principal)
        self.assertRegex(event.payload["content_digest"], r"^[0-9a-f]{64}$")

        rollback = prepared_operation(
            "op-cas-rollback",
            "request-cas-rollback",
            idempotency_key="idem-cas-rollback",
        )
        self.store.get_or_create_operation(rollback, scope="cas-rollback-scope")
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TRIGGER force_generic_cas_state_failure
                BEFORE UPDATE OF state ON operations
                WHEN NEW.operation_id = 'op-cas-rollback'
                BEGIN
                    SELECT RAISE(ABORT, 'forced generic CAS state failure');
                END
                """
            )
        with self.assertRaisesRegex(PersistenceError, "precheck transaction"):
            self.store.record_precheck(
                operation_id=rollback.operation_id,
                evidence=precheck_evidence(rollback),
                occurred_at=NOW,
                expected_revision=0,
            )
        self.assertEqual(self.store.get_operation(rollback.operation_id), rollback)
        self.assertEqual(
            [
                event
                for event in self.store.audit_events()
                if event.operation_id == rollback.operation_id
            ],
            [],
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER force_generic_cas_state_failure")

    def test_idempotency_is_atomic_content_bound_and_database_scoped(self) -> None:
        first = prepared_operation("op-first", "request-first")
        stored, created = self.store.get_or_create_operation(first, scope="invoice-scope")
        self.assertTrue(created)
        retry = prepared_operation("op-retry", "request-retry")
        existing, created = self.store.get_or_create_operation(retry, scope="invoice-scope")
        self.assertFalse(created)
        self.assertEqual(existing.operation_id, stored.operation_id)

        same_key_different_scope = prepared_operation(
            "op-scope-bypass", "request-scope-bypass"
        )
        with self.assertRaisesRegex(IdempotencyConflict, "already exists"):
            self.store.get_or_create_operation(
                same_key_different_scope, scope="different-scope"
            )

        conflict = prepared_operation("op-conflict", "request-conflict", amount="999.00")
        with self.assertRaisesRegex(IdempotencyConflict, "different request content"):
            self.store.get_or_create_operation(conflict, scope="invoice-scope")

        other_database = prepared_operation(
            "op-other-db", "request-other-db", database_uuid=OTHER_DATABASE_UUID
        )
        distinct, created = self.store.get_or_create_operation(
            other_database, scope="invoice-scope"
        )
        self.assertTrue(created)
        self.assertEqual(distinct.operation_id, "op-other-db")

    def test_retained_operation_resolves_by_stable_idempotency_identity(self) -> None:
        first = prepared_operation("op-retained", "request-retained")
        self.store.get_or_create_operation(first, scope="old-release-scope")

        arguments = {
            "odoo_instance_id": first.odoo_instance_id,
            "database_uuid": first.database_uuid,
            "environment": first.environment,
            "company_id": first.company_id,
            "capability_id": first.capability_id,
            "idempotency_key": first.idempotency_key,
        }
        found = self.store.find_operation_by_idempotency(**arguments)
        self.assertEqual(found, first)

        restarted = SQLitePersistence(self.path)
        found_after_release_scope_change = restarted.find_operation_by_idempotency(
            **arguments,
            scope="new-release-scope",
        )
        self.assertEqual(found_after_release_scope_change, first)
        found_by_old_scope = restarted.find_operation_by_idempotency(
            **{**arguments, "idempotency_key": "changed-key"},
            scope="old-release-scope",
        )
        self.assertEqual(found_by_old_scope, first)

        self.assertIsNone(
            restarted.find_operation_by_idempotency(
                **{**arguments, "database_uuid": OTHER_DATABASE_UUID}
            )
        )
        self.assertIsNone(
            restarted.find_operation_by_idempotency(
                **{**arguments, "company_id": first.company_id + 1}
            )
        )

    def test_idempotency_resolver_rejects_ambiguous_key_and_scope(self) -> None:
        first = prepared_operation("op-resolve-first", "request-resolve-first")
        second = prepared_operation(
            "op-resolve-second",
            "request-resolve-second",
            idempotency_key="idem-2",
        )
        self.store.get_or_create_operation(first, scope="scope-1")
        self.store.get_or_create_operation(second, scope="scope-2")

        with self.assertRaisesRegex(IdempotencyConflict, "different operations"):
            self.store.find_operation_by_idempotency(
                odoo_instance_id=first.odoo_instance_id,
                database_uuid=first.database_uuid,
                environment=first.environment,
                company_id=first.company_id,
                capability_id=first.capability_id,
                idempotency_key=first.idempotency_key,
                scope="scope-2",
            )

    def test_idempotency_resolver_rejects_tampered_binding(self) -> None:
        operation = prepared_operation("op-resolve-tamper", "request-resolve-tamper")
        self.store.get_or_create_operation(operation, scope="scope-tamper")
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE idempotency_keys SET idempotency_key = ? WHERE operation_id = ?",
                ("tampered-key", operation.operation_id),
            )

        with self.assertRaisesRegex(
            PersistenceIntegrityError, "does not match its operation"
        ):
            self.store.find_operation_by_idempotency(
                odoo_instance_id=operation.odoo_instance_id,
                database_uuid=operation.database_uuid,
                environment=operation.environment,
                company_id=operation.company_id,
                capability_id=operation.capability_id,
                idempotency_key="tampered-key",
            )

    def test_recovery_operation_binding_is_deterministic_idempotent_and_restart_safe(self) -> None:
        origin, plan = persist_completed_with_recovery_plan(
            self.store, "fresh-recovery-binding"
        )
        recovery = prepared_recovery_operation(origin, plan, "fresh-binding")
        self.store.get_or_create_operation(recovery, scope="recovery-fresh-binding")

        binding = self.store.bind_recovery_operation(
            origin_operation_id=origin.operation_id,
            recovery_operation_id=recovery.operation_id,
            expected_origin_revision=origin.revision,
            plan_digest=plan["plan_digest"],
            occurred_at=NOW + timedelta(seconds=1),
        )

        self.assertEqual(
            binding.binding_id,
            _recovery_operation_binding_event_id(recovery.operation_id),
        )
        self.assertEqual(binding.origin_operation_id, origin.operation_id)
        self.assertEqual(binding.origin_operation_digest, origin.digest)
        self.assertEqual(binding.origin_operation_revision, origin.revision)
        self.assertEqual(binding.origin_terminal_state, State.COMPLETED.value)
        self.assertEqual(binding.recovery_operation_id, recovery.operation_id)
        self.assertEqual(binding.recovery_operation_digest, recovery.digest)
        self.assertEqual(binding.recovery_operation_revision, 0)
        self.assertEqual(binding.plan_digest, plan["plan_digest"])
        self.assertEqual(binding.company_id, origin.company_id)
        self.assertEqual(binding.database_uuid, origin.database_uuid)
        self.assertEqual(binding.release_digest, origin.release_digest)
        self.assertEqual(binding.audit_event.event_type, "recovery.binding.created")
        event_count = len(self.store.audit_events())

        replay = self.store.bind_recovery_operation(
            origin_operation_id=origin.operation_id,
            recovery_operation_id=recovery.operation_id,
            expected_origin_revision=origin.revision,
            plan_digest=plan["plan_digest"],
            occurred_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(replay, binding)
        self.assertEqual(len(self.store.audit_events()), event_count)

        self.store.record_precheck(
            operation_id=recovery.operation_id,
            evidence=precheck_evidence(recovery),
            occurred_at=NOW + timedelta(seconds=2),
            expected_revision=0,
        )

        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_recovery_operation_binding(recovery.operation_id),
            binding,
        )
        self.assertEqual(
            restarted.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=recovery.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            ),
            binding,
        )
        with self.assertRaisesRegex(IdempotencyConflict, "binding conflicts"):
            restarted.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=recovery.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest="f" * 64,
                occurred_at=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(IdempotencyConflict, "binding conflicts"):
            restarted.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=recovery.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=2),
            )

    def test_recovery_operation_binding_accepts_failed_origin_with_signed_plan(self) -> None:
        started = persist_executing(self.store, "failed-origin-binding")
        origin = started.operation
        plan = create_recovery_plan(
            origin_operation_id=origin.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method="cancel_partial_write",
            requires_approval=True,
            target_records=[{
                "model": "account.move",
                "record_id": 9201,
                "company_id": origin.company_id,
                "record_state": "draft",
                "record_fingerprint": "f" * 64,
            }],
            parameters={"move_id": 9201, "company_id": origin.company_id},
        )
        execution_evidence = {
            "error": "posting failed after a durable draft was created",
            "recovery_plan": plan,
        }
        execution = sign_execution_result(
            operation=origin,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=False,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        failed = self.store.record_execution_result(
            execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=origin.revision,
            receipt_factory=lambda operation: {
                "operation_id": operation.operation_id,
                "operation_state": operation.state.value,
                "recovery_plan": plan,
            },
        )
        recovery = prepared_recovery_operation(
            failed.operation, plan, "failed-origin"
        )
        self.store.get_or_create_operation(
            recovery, scope="recovery-failed-origin"
        )

        binding = self.store.bind_recovery_operation(
            origin_operation_id=failed.operation.operation_id,
            recovery_operation_id=recovery.operation_id,
            expected_origin_revision=failed.operation.revision,
            plan_digest=plan["plan_digest"],
            occurred_at=NOW + timedelta(seconds=1),
        )

        self.assertEqual(binding.origin_terminal_state, State.FAILED.value)
        self.assertEqual(
            binding.origin_execution_result_id,
            binding.origin_result_id,
        )
        self.assertEqual(
            SQLitePersistence(self.path).get_recovery_operation_binding(
                recovery.operation_id
            ),
            binding,
        )

    def test_recovery_operation_binding_fails_closed_on_origin_plan_and_context_drift(self) -> None:
        origin, plan = persist_completed_with_recovery_plan(
            self.store, "recovery-binding-guards"
        )
        valid = prepared_recovery_operation(origin, plan, "guard-valid")
        self.store.get_or_create_operation(valid, scope="recovery-guard-valid")
        with self.assertRaisesRegex(ConcurrentUpdate, "origin operation revision"):
            self.store.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=valid.operation_id,
                expected_origin_revision=origin.revision - 1,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            )

        wrong_plan = prepared_recovery_operation(
            origin, plan, "guard-plan", plan_digest="f" * 64
        )
        self.store.get_or_create_operation(wrong_plan, scope="recovery-guard-plan")
        with self.assertRaisesRegex(PersistenceIntegrityError, "parameters"):
            self.store.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=wrong_plan.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            )

        other_company = prepared_recovery_operation(
            origin, plan, "guard-company", company_id=8
        )
        self.store.get_or_create_operation(
            other_company, scope="recovery-guard-company"
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "runtime binding"):
            self.store.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=other_company.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            )

        prechecked = prepared_recovery_operation(origin, plan, "guard-state")
        self.store.get_or_create_operation(prechecked, scope="recovery-guard-state")
        self.store.record_precheck(
            operation_id=prechecked.operation_id,
            evidence=precheck_evidence(prechecked),
            occurred_at=NOW,
            expected_revision=0,
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "pristine prepared"):
            self.store.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=prechecked.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            )

        nonterminal = prepared_operation(
            "op-nonterminal-origin",
            "request-nonterminal-origin",
            idempotency_key="idem-nonterminal-origin",
        )
        self.store.get_or_create_operation(nonterminal, scope="nonterminal-origin")
        nonterminal_plan = create_recovery_plan(
            origin_operation_id=nonterminal.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method="reverse_move",
            requires_approval=True,
            target_records=[{
                "model": "account.move",
                "record_id": 9102,
                "company_id": nonterminal.company_id,
                "record_state": "posted",
                "record_fingerprint": "e" * 64,
            }],
            parameters={"move_id": 9102},
        )
        nonterminal_recovery = prepared_recovery_operation(
            nonterminal, nonterminal_plan, "guard-nonterminal"
        )
        self.store.get_or_create_operation(
            nonterminal_recovery, scope="recovery-guard-nonterminal"
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "terminal"):
            self.store.bind_recovery_operation(
                origin_operation_id=nonterminal.operation_id,
                recovery_operation_id=nonterminal_recovery.operation_id,
                expected_origin_revision=nonterminal.revision,
                plan_digest=nonterminal_plan["plan_digest"],
                occurred_at=NOW + timedelta(seconds=1),
            )

    def test_recovery_operation_binding_rejects_unavailable_or_cross_company_receipt_plan(self) -> None:
        for suffix, options, message in (
            ("manual", {"status": "manual_escalation"}, "available"),
            ("no-approval", {"requires_approval": False}, "approval"),
            ("foreign-target", {"target_company_id": 8}, "target company"),
            (
                "signed-drift",
                {"signed_plan_method": "cancel_move"},
                "signed execution",
            ),
        ):
            with self.subTest(suffix=suffix):
                path = Path(self.directory.name) / f"binding-{suffix}.sqlite3"
                store = SQLitePersistence(path)
                origin, plan = persist_completed_with_recovery_plan(
                    store, f"binding-{suffix}", **options
                )
                recovery = prepared_recovery_operation(origin, plan, suffix)
                store.get_or_create_operation(
                    recovery, scope=f"recovery-{suffix}"
                )
                with self.assertRaisesRegex(PersistenceIntegrityError, message):
                    store.bind_recovery_operation(
                        origin_operation_id=origin.operation_id,
                        recovery_operation_id=recovery.operation_id,
                        expected_origin_revision=origin.revision,
                        plan_digest=plan["plan_digest"],
                        occurred_at=NOW + timedelta(seconds=1),
                    )

    def test_recovery_binding_reserved_evidence_rejects_rehashed_tamper_and_orphan(self) -> None:
        origin, plan = persist_completed_with_recovery_plan(
            self.store, "recovery-binding-tamper"
        )
        recovery = prepared_recovery_operation(origin, plan, "tamper")
        self.store.get_or_create_operation(recovery, scope="recovery-tamper")
        binding = self.store.bind_recovery_operation(
            origin_operation_id=origin.operation_id,
            recovery_operation_id=recovery.operation_id,
            expected_origin_revision=origin.revision,
            plan_digest=plan["plan_digest"],
            occurred_at=NOW + timedelta(seconds=1),
        )
        forged_payload = dict(binding.audit_event.payload)
        forged_payload["plan_digest"] = "f" * 64
        rewrite_audit_payload(self.path, binding.audit_event, forged_payload)
        with self.assertRaisesRegex(PersistenceIntegrityError, "recovery operation binding"):
            SQLitePersistence(self.path)

        orphan_path = Path(self.directory.name) / "orphan-recovery-binding.sqlite3"
        SQLitePersistence(orphan_path)
        orphan_operation_id = "op-orphan-recovery"
        event_id = _recovery_operation_binding_event_id(orphan_operation_id)
        payload_json = canonical_json({
            "binding_version": 1,
            "origin_operation_id": "op-missing-origin",
            "recovery_operation_id": orphan_operation_id,
        }).decode("utf-8")
        occurred_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        event_hash = _audit_hash(
            sequence=1,
            event_id=event_id,
            event_type="recovery.binding.created",
            operation_id=orphan_operation_id,
            occurred_at=occurred_at,
            payload_json=payload_json,
            previous_hash=GENESIS_HASH,
        )
        with closing(sqlite3.connect(orphan_path)) as connection, connection:
            connection.execute(
                "INSERT INTO audit_events(sequence, event_id, event_type, "
                "operation_id, occurred_at, payload_json, previous_hash, event_hash) "
                "VALUES(1, ?, 'recovery.binding.created', ?, ?, ?, ?, ?)",
                (
                    event_id,
                    orphan_operation_id,
                    occurred_at,
                    payload_json,
                    GENESIS_HASH,
                    event_hash,
                ),
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "recovery operation binding"):
            SQLitePersistence(orphan_path)

        clean_path = Path(self.directory.name) / "public-recovery-binding.sqlite3"
        clean = SQLitePersistence(clean_path)
        with self.assertRaisesRegex(PersistenceIntegrityError, "reserved"):
            clean.append_audit_event(
                event_id=_recovery_operation_binding_event_id("op-forged"),
                event_type="recovery.binding.created",
                operation_id="op-forged",
                occurred_at=NOW,
                payload={"forged": True},
            )

    def test_audit_chain_survives_restart_and_is_append_only(self) -> None:
        first = self.store.append_audit_event(
            event_id="diagnostic:event-1",
            event_type="diagnostic.first",
            operation_id="op-audit",
            occurred_at=NOW,
            payload={"revision": 0},
        )
        second = self.store.append_audit_event(
            event_id="diagnostic:event-2",
            event_type="diagnostic.second",
            operation_id="op-audit",
            occurred_at=NOW + timedelta(seconds=1),
            payload={"revision": 1},
        )
        self.assertEqual(first.previous_hash, GENESIS_HASH)
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertEqual(SQLitePersistence(self.path).verify_chain(), 2)
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE audit_events SET event_type = 'tampered' WHERE sequence = 1"
                )

    def test_diagnostic_audit_payload_size_is_bounded(self) -> None:
        with self.assertRaisesRegex(PersistenceError, "payload exceeds"):
            self.store.append_audit_event(
                event_id="diagnostic:oversized",
                event_type="diagnostic.oversized",
                operation_id=None,
                occurred_at=NOW,
                payload={"value": "x" * MAX_DIAGNOSTIC_AUDIT_PAYLOAD_BYTES},
            )
        self.assertEqual(self.store.verify_chain(), 0)

    def test_public_audit_api_rejects_transaction_reserved_event_types(self) -> None:
        for event_type in (
            "operation.approved",
            "operation.executing",
            "operation.completed",
            "operation.failed",
            "operation.recovered",
            "read.verified",
        ):
            with self.subTest(event_type=event_type), self.assertRaisesRegex(
                PersistenceIntegrityError, "reserved"
            ):
                self.store.append_audit_event(
                    event_id=f"diagnostic:forged:{event_type}",
                    event_type=event_type,
                    operation_id="nonexistent-operation",
                    occurred_at=NOW,
                    payload={"forged": True},
                )
        for event_id in (
            "operation.approved:preempted",
            "operation.executing:preempted",
            "read:preempted",
        ):
            with self.subTest(event_id=event_id), self.assertRaisesRegex(
                PersistenceIntegrityError, "reserved"
            ):
                self.store.append_audit_event(
                    event_id=event_id,
                    event_type="diagnostic.preemption",
                    operation_id=None,
                    occurred_at=NOW,
                    payload={"forged": True},
                )
        self.assertEqual(self.store.verify_chain(), 0)

    def test_audit_namespace_checks_reject_string_subclasses(self) -> None:
        class PrefixSpoof(str):
            def startswith(self, *_args, **_kwargs):
                return True

        with self.assertRaisesRegex(PersistenceError, "string"):
            self.store.append_audit_event(
                event_id=PrefixSpoof("read:forged-subclass"),
                event_type=PrefixSpoof("read.verified"),
                operation_id=None,
                occurred_at=NOW,
                payload={"forged": True},
            )
        self.assertEqual(self.store.verify_chain(), 0)

    def test_audit_timestamp_representation_is_hash_bound(self) -> None:
        event = self.store.append_audit_event(
            event_id="diagnostic:event-time-canonical",
            event_type="diagnostic.timestamp",
            operation_id="op-time-canonical",
            occurred_at=NOW,
            payload={"revision": 0},
        )
        equivalent_noncanonical = event.occurred_at.isoformat(
            timespec="microseconds"
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET occurred_at = ? WHERE event_id = ?",
                (equivalent_noncanonical, event.event_id),
            )
            connection.execute(_TRIGGER_SCHEMAS_V2["audit_events_no_update"])

        with self.assertRaisesRegex(PersistenceIntegrityError, "occurred_at.*canonical"):
            self.store.verify_chain()
        with self.assertRaisesRegex(PersistenceIntegrityError, "occurred_at.*canonical"):
            SQLitePersistence(self.path)

    def test_orphan_reserved_events_are_rejected_on_restart(self) -> None:
        occurred_at = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
        payload_json = canonical_json({"forged": True}).decode("utf-8")
        for suffix, event_id, event_type in (
            ("read", "read:orphan", "read.verified"),
            ("approval", "operation.approved:orphan", "operation.approved"),
            ("execution", "operation.executing:orphan", "operation.executing"),
        ):
            with self.subTest(event_type=event_type):
                path = Path(self.directory.name) / f"orphan-{suffix}.sqlite3"
                SQLitePersistence(path)
                event_hash = _audit_hash(
                    sequence=1,
                    event_id=event_id,
                    event_type=event_type,
                    operation_id=None,
                    occurred_at=occurred_at,
                    payload_json=payload_json,
                    previous_hash=GENESIS_HASH,
                )
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        """
                        INSERT INTO audit_events(
                            sequence, event_id, event_type, operation_id,
                            occurred_at, payload_json, previous_hash, event_hash
                        ) VALUES(1, ?, ?, NULL, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            event_type,
                            occurred_at,
                            payload_json,
                            GENESIS_HASH,
                            event_hash,
                        ),
                    )
                with self.assertRaisesRegex(
                    PersistenceIntegrityError, "(reserved|verified read)"
                ):
                    SQLitePersistence(path)

    def test_operation_apis_reject_a_corrupt_global_audit_chain(self) -> None:
        awaiting = persist_awaiting(self.store, "corrupt-global-chain")
        accepted = accept_approval(
            self.store,
            signed_approval(awaiting, "corrupt-global-chain-nonce"),
        )
        independent = prepared_operation(
            "op-independent-cas",
            "request-independent-cas",
            idempotency_key="idem-independent-cas",
        )
        self.store.get_or_create_operation(
            independent,
            scope="scope-independent-cas",
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET event_hash = ? WHERE event_id = ?",
                ("0" * 64, accepted.audit_event.event_id),
            )
            connection.execute(_TRIGGER_SCHEMAS_V2["audit_events_no_update"])

        retry = prepared_operation(
            "op-corrupt-global-chain-retry",
            "request-corrupt-global-chain-retry",
            idempotency_key="idem-corrupt-global-chain",
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "hash chain"):
            self.store.get_or_create_operation(
                retry,
                scope="scope-corrupt-global-chain",
            )
        new_candidate = prepared_operation(
            "op-corrupt-chain-new",
            "request-corrupt-chain-new",
            idempotency_key="idem-corrupt-chain-new",
        )
        with self.assertRaisesRegex(PersistenceIntegrityError, "hash chain"):
            self.store.get_or_create_operation(
                new_candidate,
                scope="scope-corrupt-chain-new",
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "hash chain"):
            self.store.record_precheck(
                operation_id=independent.operation_id,
                evidence=precheck_evidence(independent),
                occurred_at=NOW,
                expected_revision=0,
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "hash chain"):
            self.store.audit_events()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM operations WHERE operation_id = ?",
                    (independent.operation_id,),
                ).fetchone()[0],
                State.PREPARED.value,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                    (new_candidate.operation_id,),
                ).fetchone()[0],
                0,
            )

    def test_operation_and_audit_tampering_are_detected(self) -> None:
        operation = prepared_operation("op-tamper", "request-tamper")
        self.store.get_or_create_operation(operation, scope="tamper-scope")
        self.store.append_audit_event(
            event_id="diagnostic:event-tamper",
            event_type="diagnostic.tamper",
            operation_id=operation.operation_id,
            occurred_at=NOW,
            payload={"state": "prepared"},
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE operations SET principal = 'tampered-principal' "
                "WHERE operation_id = ?",
                (operation.operation_id,),
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "record hash"):
            self.store.get_operation(operation.operation_id)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET payload_json = ? WHERE sequence = 1",
                ('{"state":"completed"}',),
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "hash chain"):
            self.store.verify_chain()

    def test_replaced_append_only_trigger_is_rejected_on_restart(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                """
                CREATE TRIGGER audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT 1;
                END
                """
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "trigger schema"):
            SQLitePersistence(self.path)

    def test_trigger_string_literal_case_change_is_rejected_on_restart(self) -> None:
        trigger_name = "operations_failed_requires_result"
        weakened = _TRIGGER_SCHEMAS_V4[trigger_name].replace(
            "'failed'", "'FAILED'", 1
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(f"DROP TRIGGER {trigger_name}")
            connection.execute(weakened)

        with self.assertRaisesRegex(PersistenceIntegrityError, "trigger schema"):
            SQLitePersistence(self.path)

    def test_weakened_table_constraints_are_rejected_on_restart(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TABLE consumed_auth_tokens")
            connection.execute(
                """
                CREATE TABLE consumed_auth_tokens (
                    token_id TEXT,
                    request_digest TEXT,
                    expires_at TEXT,
                    consumed_at TEXT
                ) STRICT
                """
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "table schema"):
            SQLitePersistence(self.path)

    def test_cross_process_auth_token_consumption_has_one_winner(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(target=_auth_consume_worker, args=(str(self.path), start, queue))
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(results.count("consumed"), 1, results)
        self.assertEqual(results.count("rejected"), 3, results)

    def test_cross_process_idempotency_get_or_create_has_one_winner(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_idempotency_worker,
                args=(str(self.path), worker_id, start, queue),
            )
            for worker_id in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        operation_ids = {operation_id for operation_id, _created in results}
        self.assertEqual(len(operation_ids), 1, results)
        self.assertEqual(sum(1 for _operation_id, created in results if created), 1, results)

    def test_cross_process_precheck_has_one_atomic_winner(self) -> None:
        operation = prepared_operation(
            "op-concurrent-precheck", "request-concurrent-precheck"
        )
        self.store.get_or_create_operation(
            operation, scope="concurrent-precheck-scope"
        )
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_precheck_worker,
                args=(str(self.path), operation, start, queue),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(item[0] == "recorded" for item in results), 1, results)
        self.assertEqual(sum(item[0] == "rejected" for item in results), 3, results)
        self.assertNotIn("error", {item[0] for item in results}, results)
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(operation.operation_id).state,
            State.PRECHECKED,
        )
        self.assertEqual(
            restarted.get_precheck_record(operation.operation_id).evidence,
            precheck_evidence(operation),
        )
        self.assertEqual(restarted.verify_chain(), 1)

    def test_cross_process_approval_acceptance_has_one_winner(self) -> None:
        operation = persist_awaiting(self.store, "concurrent-approval")
        approval = signed_approval(operation, "concurrent-approval-nonce")
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_approval_accept_worker,
                args=(str(self.path), approval, start, queue),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)

        self.assertEqual(sum(result[0] == "accepted" for result in results), 1, results)
        self.assertEqual(sum(result[0] == "rejected" for result in results), 3, results)
        self.assertNotIn("error", {result[0] for result in results}, results)
        restarted = SQLitePersistence(self.path)
        self.assertEqual(restarted.get_operation(operation.operation_id).state, State.APPROVED)
        self.assertEqual(restarted.get_operation(operation.operation_id).revision, 3)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM approval_records WHERE operation_id = ?",
                    (operation.operation_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE event_type = 'operation.approved' AND operation_id = ?",
                    (operation.operation_id,),
                ).fetchone()[0],
                1,
            )
        self.assertEqual(restarted.verify_chain(), 3)

    def test_cross_process_begin_execution_has_one_winner(self) -> None:
        operation = persist_awaiting(self.store, "concurrent-execution")
        approval = signed_approval(
            operation,
            "concurrent-execution-nonce",
        )
        accept_approval(self.store, approval)
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_execution_begin_worker,
                args=(str(self.path), approval, start, queue),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)

        self.assertEqual(sum(result[0] == "started" for result in results), 1, results)
        self.assertEqual(sum(result[0] == "rejected" for result in results), 3, results)
        self.assertNotIn("error", {result[0] for result in results}, results)
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(operation.operation_id).state,
            State.EXECUTING,
        )
        self.assertEqual(
            [event.event_type for event in restarted.audit_events()],
            [
                "operation.prechecked",
                "operation.awaiting_approval",
                "operation.approved",
                "operation.executing",
            ],
        )

    def test_cross_process_execution_result_has_one_atomic_winner(self) -> None:
        started = persist_executing(self.store, "concurrent-result")
        evidence = {"model": "account.move", "record_id": 8801}
        result = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_execution_result_worker,
                args=(str(self.path), result, evidence, start, queue),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(item[0] == "recorded" for item in results), 1, results)
        self.assertEqual(sum(item[0] == "rejected" for item in results), 3, results)
        self.assertNotIn("error", {item[0] for item in results}, results)
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(started.operation.operation_id).state,
            State.VERIFYING,
        )
        self.assertEqual(
            len(restarted.get_trusted_result_records(started.operation.operation_id)),
            1,
        )

    def test_cross_process_terminal_receipt_has_one_atomic_winner(self) -> None:
        started = persist_executing(self.store, "concurrent-terminal")
        execution_evidence = {"model": "account.move", "record_id": 8802}
        execution = sign_execution_result(
            operation=started.operation,
            issuer="odoo-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=content_digest(execution_evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        verifying = self.store.record_execution_result(
            execution,
            evidence=execution_evidence,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-executor"}),
            expected_revision=started.operation.revision,
        )
        verification_evidence = {"record_id": 8802, "state": "posted"}
        verification = sign_verification_result(
            operation=verifying.operation,
            issuer="odoo-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=content_digest(verification_evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(
                target=_terminal_result_worker,
                args=(
                    str(self.path),
                    verification,
                    verification_evidence,
                    start,
                    queue,
                ),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(item[0] == "completed" for item in results), 1, results)
        self.assertEqual(sum(item[0] == "rejected" for item in results), 3, results)
        self.assertNotIn("error", {item[0] for item in results}, results)
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(started.operation.operation_id).state,
            State.COMPLETED,
        )
        receipts = restarted.get_final_write_receipts(
            started.operation.operation_id
        )
        self.assertEqual(len(receipts), 1)
        terminal_event = restarted.audit_events()[-1]
        self.assertEqual(
            receipts[0].body["audit_event_hash"], terminal_event.event_hash
        )


if __name__ == "__main__":
    unittest.main()
