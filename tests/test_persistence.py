import hashlib
import hmac
import multiprocessing
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from odoo_accounting_cli_v3.operations import (
    ApprovalRejected,
    Operation,
    State,
    approve_operation,
    begin_execution,
    canonical_json,
    complete_operation,
    record_execution_result,
    sign_approval,
    sign_execution_result,
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
    _SCHEMA_V1,
    _TRIGGER_SCHEMAS_V2,
    _audit_hash,
    _normalize_schema_sql,
    _operation_payload,
    _operation_record_hash,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt


NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
OTHER_DATABASE_UUID = "22222222-2222-4222-8222-222222222222"
REGISTRY_DIGEST = "c" * 64
RELEASE_DIGEST = "d" * 64
APPROVAL_SECRET = b"approval-secret-material-32-byte!"
APPROVAL_KEY_ID = "approval-key-v2"
EXECUTION_SECRET = b"execution-secret-material-32-byte"
VERIFICATION_SECRET = b"verify-secret-material-at-least-32"
RECEIPT_SECRET = b"receipt-secret-material-at-least-32"
RECEIPT_KEY_ID = "receipt-key-v1"


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
    operation = operation.transition(State.PRECHECKED, expected_revision=0)
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
    operation = operation.transition(State.PRECHECKED, expected_revision=0)
    store.cas_update_operation(operation, expected_revision=0)
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    return store.cas_update_operation(operation, expected_revision=1)


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
    operation = prepared_operation(
        "op-legacy-approved",
        "request-legacy-approved",
        idempotency_key="idem-legacy-approved",
    )
    operation = operation.transition(State.PRECHECKED, expected_revision=0)
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
    operation = operation.transition(State.PRECHECKED, expected_revision=0)
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
        self.assertEqual(version, 2)
        self.assertTrue(
            {
                "schema_meta",
                "consumed_auth_tokens",
                "consumed_receipts",
                "operations",
                "idempotency_keys",
                "audit_events",
                "approval_records",
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
                "operations_unimplemented_protected_states_closed",
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
        self.assertEqual(migrated.get_operation(operation.operation_id), operation)
        legacy_record = migrated.get_approval_record(operation.operation_id)
        self.assertEqual(legacy_record.record_origin, "legacy_v1_unverifiable")
        self.assertEqual(legacy_record.signature_version, 1)
        self.assertEqual(legacy_record.signature_purpose, "approval_v1")
        self.assertIsNone(legacy_record.key_id)
        self.assertIsNone(legacy_record.accepted_at)
        self.assertIsNone(legacy_record.audit_event_id)
        self.assertEqual(migrated.verify_chain(), 1)

        with closing(sqlite3.connect(legacy_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "2",
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
            operation = operation.transition(State.PRECHECKED, expected_revision=0)
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
        self.assertEqual(accepted.approval_record.record_origin, "native_v2")
        self.assertEqual(
            accepted.approval_record.audit_event_id, accepted.audit_event.event_id
        )
        self.assertEqual(accepted.audit_event.event_type, "operation.approved")
        self.assertEqual(accepted.audit_event.payload["from_state"], "awaiting_approval")
        self.assertEqual(accepted.audit_event.payload["to_state"], "approved")
        self.assertNotIn("nonce", accepted.audit_event.payload)
        self.assertEqual(self.store.verify_chain(), 1)

        restarted = SQLitePersistence(self.path)
        self.assertEqual(restarted.get_operation(operation.operation_id), accepted.operation)
        self.assertEqual(
            restarted.get_approval_record(operation.operation_id),
            accepted.approval_record,
        )
        self.assertEqual(restarted.audit_events(), (accepted.audit_event,))

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

        self.assertEqual(self.store.verify_chain(), 1)
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

        self.assertEqual(self.store.verify_chain(), 1)
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
        self.assertEqual(started.approval_record.record_origin, "native_v2")
        self.assertEqual(started.audit_event.event_type, "operation.executing")
        restarted = SQLitePersistence(self.path)
        self.assertEqual(
            restarted.get_operation(operation.operation_id), started.operation
        )
        self.assertEqual(
            [event.event_type for event in restarted.audit_events()],
            ["operation.approved", "operation.executing"],
        )
        self.assertEqual(restarted.verify_chain(), 2)

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
            ["operation.approved"],
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

        self.assertEqual(self.store.verify_chain(), 2)
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

        self.assertEqual(self.store.verify_chain(), 2)
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
        self.assertEqual(migrated.get_operation(operation.operation_id), operation)
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
                0,
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
                0,
            )
            connection.execute("DROP TRIGGER force_approval_state_failure")

        self.assertEqual(
            accept_approval(self.store, approval).operation.state,
            State.APPROVED,
        )

    def test_sql_cannot_bypass_approval_and_records_are_append_only(self) -> None:
        operation = persist_awaiting(self.store, "sql-guard")
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "native approval"):
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
                    sqlite3.IntegrityError, "implemented transaction"
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
                        0,
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

    def test_completed_insert_and_direct_approved_cas_are_rejected(self) -> None:
        with self.assertRaisesRegex(PersistenceIntegrityError, "pristine prepared"):
            self.store.get_or_create_operation(
                completed_operation(), scope="completed-scope"
            )

        original = prepared_operation("op-guarded", "request-guarded")
        self.store.get_or_create_operation(original, scope="guarded-scope")
        prechecked = original.transition(State.PRECHECKED, expected_revision=0)
        self.store.cas_update_operation(prechecked, expected_revision=0)
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
        prechecked = original.transition(State.PRECHECKED, expected_revision=0)
        self.assertEqual(
            self.store.cas_update_operation(prechecked, expected_revision=0), prechecked
        )
        competing = original.transition(State.PRECHECKED, expected_revision=0)
        with self.assertRaisesRegex(ConcurrentUpdate, "revision"):
            self.store.cas_update_operation(competing, expected_revision=0)
        self.assertEqual(self.store.get_operation(original.operation_id), prechecked)

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
            self.store.cas_update_operation(
                independent.transition(State.PRECHECKED, expected_revision=0),
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
        trigger_name = "operations_unimplemented_protected_states_closed"
        weakened = _TRIGGER_SCHEMAS_V2[trigger_name].replace(
            "'failed'", "'FAILED'"
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
        self.assertEqual(restarted.verify_chain(), 1)

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
            ["operation.approved", "operation.executing"],
        )


if __name__ == "__main__":
    unittest.main()
