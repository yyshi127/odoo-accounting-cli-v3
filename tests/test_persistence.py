import multiprocessing
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    approve_operation,
    begin_execution,
    complete_operation,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.persistence import (
    GENESIS_HASH,
    ConcurrentUpdate,
    IdempotencyConflict,
    PersistenceIntegrityError,
    ReplayRejected,
    SQLitePersistence,
)


NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
OTHER_DATABASE_UUID = "22222222-2222-4222-8222-222222222222"
REGISTRY_DIGEST = "c" * 64
RELEASE_DIGEST = "d" * 64
APPROVAL_SECRET = b"approval-secret-material-32-byte!"
EXECUTION_SECRET = b"execution-secret-material-32-byte"
VERIFICATION_SECRET = b"verify-secret-material-at-least-32"


def prepared_operation(
    operation_id: str,
    request_id: str,
    *,
    amount: str = "100.00",
    database_uuid: str = DATABASE_UUID,
) -> Operation:
    return Operation.prepare(
        operation_id=operation_id,
        request_id=request_id,
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "amount": amount, "idempotency_key": "idem-1"},
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="idem-1",
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
        secret=APPROVAL_SECRET,
    )
    operation = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
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
        self.assertEqual(version, 1)
        self.assertTrue(
            {
                "schema_meta",
                "consumed_auth_tokens",
                "consumed_receipts",
                "operations",
                "idempotency_keys",
                "audit_events",
            }.issubset(tables)
        )
        self.assertEqual(
            triggers, {"audit_events_no_update", "audit_events_no_delete"}
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
        forged = awaiting._apply_transition(State.APPROVED)
        with self.assertRaisesRegex(PersistenceIntegrityError, "specialized transactional"):
            self.store.cas_update_operation(forged, expected_revision=2)

    def test_cas_updates_once_and_rejects_stale_revision(self) -> None:
        original = prepared_operation("op-cas", "request-cas")
        self.store.get_or_create_operation(original, scope="cas-scope")
        prechecked = original.transition(State.PRECHECKED, expected_revision=0)
        self.assertEqual(
            self.store.cas_update_operation(prechecked, expected_revision=0), prechecked
        )
        competing = original.transition(State.FAILED, expected_revision=0)
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
            event_id="event-1",
            event_type="operation.prepared",
            operation_id="op-audit",
            occurred_at=NOW,
            payload={"revision": 0},
        )
        second = self.store.append_audit_event(
            event_id="event-2",
            event_type="operation.prechecked",
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

    def test_operation_and_audit_tampering_are_detected(self) -> None:
        operation = prepared_operation("op-tamper", "request-tamper")
        self.store.get_or_create_operation(operation, scope="tamper-scope")
        self.store.append_audit_event(
            event_id="event-tamper",
            event_type="operation.prepared",
            operation_id=operation.operation_id,
            occurred_at=NOW,
            payload={"state": "prepared"},
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE operations SET state = 'completed' WHERE operation_id = ?",
                (operation.operation_id,),
            )
            connection.execute("DROP TRIGGER audit_events_no_update")
            connection.execute(
                "UPDATE audit_events SET payload_json = ? WHERE sequence = 1",
                ('{"state":"completed"}',),
            )
        with self.assertRaisesRegex(PersistenceIntegrityError, "record hash"):
            self.store.get_operation(operation.operation_id)
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


if __name__ == "__main__":
    unittest.main()
