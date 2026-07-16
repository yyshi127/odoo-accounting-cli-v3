from __future__ import annotations

import errno
import hashlib
import multiprocessing
import os
import sqlite3
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import odoo_accounting_cli_v3.trusted_session_sqlite as trusted_session_sqlite
from odoo_accounting_cli_v3.trusted_session_sqlite import (
    SQLiteTrustedSessionStore,
    TrustedSessionCommitOutcomeUnknownError,
    TrustedSessionIdentity,
    TrustedSessionKnownCommittedError,
    TrustedSessionReconciliationRequiredError,
    TrustedSessionStoreError,
)

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - POSIX-only lock tests are skipped on Windows
    fcntl = None  # type: ignore[assignment]


DATABASE_UUID = "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _identity(
    *, company_id: int = 7, allowed_company_ids: frozenset[int] | None = None
) -> TrustedSessionIdentity:
    return TrustedSessionIdentity(
        principal="odoo:user:42",
        odoo_instance_id="odoo-prod-01",
        database_name="accounting",
        database_uuid=DATABASE_UUID,
        user_id=42,
        company_id=company_id,
        allowed_company_ids=(
            frozenset({7, 9})
            if allowed_company_ids is None
            else allowed_company_ids
        ),
        environment="sandbox",
    )


def _process_resolve(
    path: str,
    handle: str,
    start: multiprocessing.synchronize.Event,
    ready: multiprocessing.queues.Queue,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        store = SQLiteTrustedSessionStore(Path(path))
        ready.put(True)
        if not start.wait(15):
            raise TimeoutError("concurrent resolve start signal was not received")
        results.put(store.resolve(handle) is not None)
    except BaseException as exc:  # pragma: no cover - child diagnostic
        diagnostic = f"{type(exc).__name__}: {exc}"
        if exc.__cause__ is not None:
            diagnostic += f"; caused by {type(exc.__cause__).__name__}: {exc.__cause__}"
            notes = getattr(exc.__cause__, "__notes__", ())
            if notes:
                diagnostic += "; notes: " + " | ".join(notes)
        ready.put(diagnostic)
        results.put(diagnostic)


def _process_initialize(
    path: str,
    start: multiprocessing.synchronize.Event,
    ready: multiprocessing.queues.Queue,
    results: multiprocessing.queues.Queue,
) -> None:
    ready.put(True)
    try:
        if not start.wait(15):
            raise TimeoutError("concurrent initialization start signal was not received")
        SQLiteTrustedSessionStore(Path(path))
        results.put(True)
    except BaseException as exc:  # pragma: no cover - child diagnostic
        diagnostic = f"{type(exc).__name__}: {exc}"
        if exc.__cause__ is not None:
            diagnostic += f"; caused by {type(exc.__cause__).__name__}: {exc.__cause__}"
        results.put(diagnostic)


def _operational_error(message: str, error_code: int) -> sqlite3.OperationalError:
    error = sqlite3.OperationalError(message)
    error.sqlite_errorcode = error_code
    return error


def test_issue_is_server_generated_opaque_and_survives_restart(tmp_path: Path) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    now = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
    clock = MutableClock(now)
    store = SQLiteTrustedSessionStore(path, clock=clock)

    issued = store.issue(_identity(), ttl_seconds=120, max_uses=2)

    assert len(issued.handle) == 43
    assert issued.handle not in repr(issued)
    assert issued.session.session_id != issued.handle
    assert issued.session.issued_at == now
    assert issued.session.expires_at == now + timedelta(seconds=120)
    assert issued.session.company_id == 7
    assert issued.session.allowed_company_ids == frozenset({7, 9})

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT handle_digest, company_id, allowed_company_ids_json "
            "FROM trusted_sessions"
        ).fetchone()
    assert row == (
        hashlib.sha256(issued.handle.encode("ascii")).hexdigest(),
        7,
        "[7,9]",
    )
    assert issued.handle.encode("ascii") not in path.read_bytes()

    restarted = SQLiteTrustedSessionStore(path, clock=clock)
    resolved = restarted.resolve(issued.handle)
    assert resolved == issued.session
    assert restarted.verify_integrity() is True


def test_established_wal_store_restart_is_read_only_and_not_renegotiated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    issued = SQLiteTrustedSessionStore(path).issue(
        _identity(), ttl_seconds=120, max_uses=1
    )
    real_connect = sqlite3.connect
    journal_mode_writes: list[tuple[str | None, str | None]] = []
    transaction_statements: list[str] = []

    def instrumented_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)

        def authorize(
            action: int,
            argument1: str | None,
            argument2: str | None,
            _database: str | None,
            _source: str | None,
        ) -> int:
            if (
                action == sqlite3.SQLITE_PRAGMA
                and argument1 is not None
                and argument1.lower() == "journal_mode"
                and argument2 is not None
            ):
                journal_mode_writes.append((argument1, argument2))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize)
        connection.set_trace_callback(transaction_statements.append)
        return connection

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", instrumented_connect)

    restarted = SQLiteTrustedSessionStore(path)
    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", real_connect)
    assert all(
        statement.strip().upper() != "BEGIN IMMEDIATE"
        for statement in transaction_statements
    )
    assert journal_mode_writes == []
    assert restarted.resolve(issued.handle) == issued.session
    assert restarted.verify_integrity() is True


def test_nonempty_wal_header_without_committed_schema_is_initialized(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    with sqlite3.connect(path, isolation_level=None) as connection:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
    path.chmod(0o600)
    assert path.stat().st_size > 0

    store = SQLiteTrustedSessionStore(path)

    assert store.verify_integrity() is True


def test_empty_store_initialization_is_atomic_across_processes(tmp_path: Path) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = context.Queue()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_initialize,
            args=(str(path), start, ready, results),
        )
        for _ in range(12)
    ]
    for process in processes:
        process.start()
    readiness = [ready.get(timeout=30) for _ in processes]
    start.set()
    values = [results.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    assert readiness == [True] * len(processes), readiness
    assert values == [True] * len(processes), values
    assert SQLiteTrustedSessionStore(path).verify_integrity() is True


def test_issue_rejects_request_mapping_and_cross_company_identity(
    tmp_path: Path,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())

    with pytest.raises(TrustedSessionStoreError, match="server-established"):
        store.issue(  # type: ignore[arg-type]
            {
                "user_id": 42,
                "company_id": 7,
                "allowed_company_ids": [7],
            },
            ttl_seconds=60,
        )

    with pytest.raises(TrustedSessionStoreError, match="allowed companies"):
        store.issue(
            _identity(company_id=8, allowed_company_ids=frozenset({7, 9})),
            ttl_seconds=60,
        )


def test_single_use_resolution_is_atomic_across_processes(tmp_path: Path) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    issued = SQLiteTrustedSessionStore(path).issue(
        _identity(), ttl_seconds=120, max_uses=1
    )
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = context.Queue()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_resolve,
            args=(str(path), issued.handle, start, ready, results),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    readiness = [ready.get(timeout=30) for _ in processes]
    start.set()
    values = [results.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    assert readiness == [True] * len(processes), readiness
    assert values.count(True) == 1
    assert values.count(False) == 5
    assert all(isinstance(value, bool) for value in values), values
    store = SQLiteTrustedSessionStore(path)
    assert store.resolve(issued.handle) is None
    assert store.verify_integrity() is True
    assert [event.event_type for event in store.security_events()].count(
        "session.resolved"
    ) == 1


def test_busy_writer_fails_within_configured_deadline_without_consuming_handle(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path, busy_timeout_ms=50)
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    lock = sqlite3.connect(path, timeout=1, isolation_level=None)
    lock.execute("PRAGMA journal_mode = WAL")
    lock.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        with pytest.raises(TrustedSessionStoreError, match="transaction failed"):
            store.resolve(issued.handle)
    finally:
        lock.rollback()
        lock.close()

    assert time.monotonic() - started < 1
    assert store.resolve(issued.handle) == issued.session
    assert store.resolve(issued.handle) is None
    assert store.verify_integrity() is True


def test_transient_setup_failure_rebuilds_connection_before_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    real_connect = sqlite3.connect
    real_configure = store._configure
    connections: list[sqlite3.Connection] = []
    configure_calls = 0

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    def transient_configure(
        connection: sqlite3.Connection,
        *,
        write: bool,
        retry_deadline: float | None = None,
    ) -> None:
        nonlocal configure_calls
        configure_calls += 1
        if configure_calls <= 2:
            raise _operational_error("locking protocol", sqlite3.SQLITE_PROTOCOL)
        real_configure(
            connection,
            write=write,
            retry_deadline=retry_deadline,
        )

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", recording_connect)
    monkeypatch.setattr(store, "_configure", transient_configure)

    assert store.resolve(issued.handle) == issued.session
    assert configure_calls == 3
    assert len(connections) == 3
    assert len({id(connection) for connection in connections}) == 3
    for connection in connections[:2]:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_non_transient_setup_failure_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    real_configure = store._configure
    configure_calls = 0

    def fail_configure(
        _connection: sqlite3.Connection,
        *,
        write: bool,
        retry_deadline: float | None = None,
    ) -> None:
        del write, retry_deadline
        nonlocal configure_calls
        configure_calls += 1
        raise _operational_error("disk I/O error", sqlite3.SQLITE_IOERR)

    monkeypatch.setattr(store, "_configure", fail_configure)
    with pytest.raises(TrustedSessionStoreError, match="transaction failed") as caught:
        store.resolve(issued.handle)
    assert configure_calls == 1
    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert caught.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_IOERR

    monkeypatch.setattr(store, "_configure", real_configure)
    assert store.resolve(issued.handle) == issued.session


def test_setup_cleanup_failure_rejects_retry_before_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    real_connect = sqlite3.connect
    real_configure = store._configure
    configure_calls = 0

    class CloseFailureConnection(sqlite3.Connection):
        def close(self) -> None:
            super().close()
            raise sqlite3.OperationalError("simulated setup close failure")

    def failing_close_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = CloseFailureConnection
        return real_connect(*args, **kwargs)

    def fail_configure(
        _connection: sqlite3.Connection,
        *,
        write: bool,
        retry_deadline: float | None = None,
    ) -> None:
        del write, retry_deadline
        nonlocal configure_calls
        configure_calls += 1
        raise _operational_error("locking protocol", sqlite3.SQLITE_PROTOCOL)

    monkeypatch.setattr(
        trusted_session_sqlite.sqlite3,
        "connect",
        failing_close_connect,
    )
    monkeypatch.setattr(store, "_configure", fail_configure)
    with pytest.raises(TrustedSessionStoreError, match="cleanup failed"):
        store.resolve(issued.handle)
    assert configure_calls == 1

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", real_connect)
    monkeypatch.setattr(store, "_configure", real_configure)
    assert store.resolve(issued.handle) == issued.session


def test_setup_retry_uses_one_bounded_monotonic_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteTrustedSessionStore(
        (tmp_path / "sessions.sqlite3").resolve(), busy_timeout_ms=250
    )
    now = {"value": 100.0}
    sleeps: list[float] = []
    attempt_budgets: list[int] = []
    attempt_starts: list[float] = []

    def monotonic() -> float:
        return now["value"]

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now["value"] += seconds

    def consume_writer_lock_budget(
        retry_deadline: float,
    ) -> tuple[int, tuple[int, int]] | None:
        assert retry_deadline == pytest.approx(100.25)
        now["value"] += 0.1
        return None

    def fail_attempt(
        *, retry_deadline: float
    ) -> tuple[sqlite3.Connection, tuple[int, int]]:
        attempt_starts.append(now["value"])
        attempt_budgets.append(
            store._remaining_transaction_busy_timeout_ms(
                retry_deadline,
                maximum_ms=100,
            )
        )
        raise _operational_error("locking protocol", sqlite3.SQLITE_PROTOCOL)

    monkeypatch.setattr(trusted_session_sqlite.time, "monotonic", monotonic)
    monkeypatch.setattr(trusted_session_sqlite.time, "sleep", sleep)
    monkeypatch.setattr(store, "_acquire_writer_lock", consume_writer_lock_budget)
    monkeypatch.setattr(store, "_write_transaction_attempt", fail_attempt)

    with pytest.raises(
        TrustedSessionStoreError, match="transaction (?:failed|deadline)"
    ):
        with store._transaction():
            raise AssertionError("retry budget admitted a transaction")

    assert attempt_budgets[0] <= 100
    assert attempt_budgets == sorted(attempt_budgets, reverse=True)
    assert all(0 <= value <= 100 for value in attempt_budgets)
    assert all(start < 100.25 for start in attempt_starts)
    assert 0 < sum(sleeps) <= 0.1500001
    assert now["value"] - 100.0 <= 0.2500001


def test_expired_budget_after_writer_lock_never_starts_sqlite_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteTrustedSessionStore(
        (tmp_path / "sessions.sqlite3").resolve(), busy_timeout_ms=250
    )
    now = {"value": 100.0}
    setup_calls = 0

    def monotonic() -> float:
        return now["value"]

    def consume_entire_budget(
        retry_deadline: float,
    ) -> tuple[int, tuple[int, int]] | None:
        now["value"] = retry_deadline
        return None

    def forbidden_attempt(
        *, retry_deadline: float
    ) -> tuple[sqlite3.Connection, tuple[int, int]]:
        del retry_deadline
        nonlocal setup_calls
        setup_calls += 1
        raise AssertionError("expired budget started SQLite setup")

    monkeypatch.setattr(trusted_session_sqlite.time, "monotonic", monotonic)
    monkeypatch.setattr(store, "_acquire_writer_lock", consume_entire_budget)
    monkeypatch.setattr(store, "_write_transaction_attempt", forbidden_attempt)

    with pytest.raises(TrustedSessionStoreError, match="transaction deadline"):
        with store._transaction():
            raise AssertionError("expired transaction was yielded")

    assert setup_calls == 0


def test_setup_statement_is_not_started_when_busy_handler_consumes_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    now = {"value": 100.0}
    statements: list[str] = []

    class DeadlineConsumingConnection:
        def execute(self, statement: str) -> object:
            statements.append(statement)
            now["value"] = 100.1
            return object()

    monkeypatch.setattr(
        trusted_session_sqlite.time,
        "monotonic",
        lambda: now["value"],
    )
    with pytest.raises(TrustedSessionStoreError, match="transaction deadline"):
        store._execute_transaction_setup(
            DeadlineConsumingConnection(),  # type: ignore[arg-type]
            "BEGIN IMMEDIATE",
            100.1,
        )

    assert len(statements) == 1
    assert statements[0].startswith("PRAGMA busy_timeout = ")


def test_retryable_error_after_yield_never_replays_caller_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    real_open = store._open_write_transaction
    open_calls = 0
    caller_runs = 0

    def recording_open(
        *, retry_deadline: float
    ) -> tuple[sqlite3.Connection, tuple[int, int]]:
        nonlocal open_calls
        open_calls += 1
        return real_open(retry_deadline=retry_deadline)

    monkeypatch.setattr(store, "_open_write_transaction", recording_open)
    with pytest.raises(TrustedSessionStoreError, match="transaction failed") as caught:
        with store._transaction():
            caller_runs += 1
            raise _operational_error("locking protocol", sqlite3.SQLITE_PROTOCOL)

    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert caught.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_PROTOCOL
    assert open_calls == 1
    assert caller_runs == 1
    assert store.verify_integrity() is True


@pytest.mark.parametrize(
    "cleanup_phase",
    ("database_verification", "close", "writer_unlock"),
)
def test_post_commit_cleanup_failure_explicitly_requires_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_phase: str,
) -> None:
    path = (tmp_path / f"sessions-{cleanup_phase}.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    real_connect = sqlite3.connect
    real_release = store._release_writer_lock
    real_verify_database = store._verify_database_file

    if cleanup_phase == "database_verification":
        verification_calls = 0

        def fail_post_commit_database_verification(
            expected: tuple[int, int],
        ) -> None:
            nonlocal verification_calls
            verification_calls += 1
            real_verify_database(expected)
            if verification_calls == 2:
                raise TrustedSessionStoreError(
                    "simulated post-commit database verification failure"
                )

        monkeypatch.setattr(
            store,
            "_verify_database_file",
            fail_post_commit_database_verification,
        )
    elif cleanup_phase == "close":

        class CloseFailureConnection(sqlite3.Connection):
            def close(self) -> None:
                super().close()
                raise sqlite3.OperationalError("simulated post-commit close failure")

        def failing_close_connect(
            *args: object, **kwargs: object
        ) -> sqlite3.Connection:
            kwargs["factory"] = CloseFailureConnection
            return real_connect(*args, **kwargs)

        monkeypatch.setattr(
            trusted_session_sqlite.sqlite3,
            "connect",
            failing_close_connect,
        )
    else:

        def fail_after_writer_unlock(
            lock: tuple[int, tuple[int, int]] | None,
        ) -> None:
            real_release(lock)
            raise TrustedSessionStoreError(
                "simulated post-commit writer unlock failure"
            )

        monkeypatch.setattr(store, "_release_writer_lock", fail_after_writer_unlock)

    with pytest.raises(TrustedSessionKnownCommittedError) as caught:
        store.issue(_identity(), ttl_seconds=120, max_uses=1)

    assert caught.value.committed is True
    assert caught.value.retryable is False
    assert caught.value.reconciliation_required is True
    assert "do not replay" in str(caught.value)

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", real_connect)
    monkeypatch.setattr(store, "_release_writer_lock", real_release)
    monkeypatch.setattr(store, "_verify_database_file", real_verify_database)
    with real_connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM trusted_sessions").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM trusted_session_security_events "
            "WHERE event_type='session.issued' AND outcome='accepted'"
        ).fetchone()[0] == 1
    assert SQLiteTrustedSessionStore(path).verify_integrity() is True


def test_commit_that_may_have_completed_requires_reconciliation_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    real_connect = sqlite3.connect

    class CommitThenRaiseConnection(sqlite3.Connection):
        def commit(self) -> None:
            super().commit()
            raise sqlite3.OperationalError("simulated post-commit exception")

    def uncertain_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = CommitThenRaiseConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", uncertain_connect)
    with pytest.raises(TrustedSessionCommitOutcomeUnknownError) as caught:
        store.issue(_identity(), ttl_seconds=120, max_uses=1)

    assert isinstance(caught.value, TrustedSessionReconciliationRequiredError)
    assert caught.value.committed is None
    assert caught.value.commit_outcome == "unknown"
    assert caught.value.retryable is False
    assert caught.value.reconciliation_required is True
    assert "do not replay" in str(caught.value)

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", real_connect)
    with real_connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM trusted_sessions").fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM trusted_session_security_events "
            "WHERE event_type='session.issued' AND outcome='accepted'"
        ).fetchone()[0] == 1
    assert SQLiteTrustedSessionStore(path).verify_integrity() is True


def test_commit_failure_with_confirmed_rollback_is_safe_to_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    real_connect = sqlite3.connect

    class CommitBeforeDurableFailureConnection(sqlite3.Connection):
        def commit(self) -> None:
            raise sqlite3.OperationalError("simulated pre-commit failure")

    def failed_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = CommitBeforeDurableFailureConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", failed_connect)
    with pytest.raises(TrustedSessionStoreError, match="transaction failed") as caught:
        store.issue(_identity(), ttl_seconds=120, max_uses=1)
    assert not isinstance(caught.value, TrustedSessionReconciliationRequiredError)

    monkeypatch.setattr(trusted_session_sqlite.sqlite3, "connect", real_connect)
    with real_connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM trusted_sessions").fetchone()[0] == 0
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    assert store.resolve(issued.handle) == issued.session


def test_expired_and_revoked_handles_fail_closed_with_security_events(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
    clock = MutableClock(now)
    store = SQLiteTrustedSessionStore(
        (tmp_path / "sessions.sqlite3").resolve(), clock=clock
    )
    expired = store.issue(_identity(), ttl_seconds=10, max_uses=2)
    revoked = store.issue(_identity(), ttl_seconds=60, max_uses=2)

    assert store.revoke_session(revoked.session.session_id, reason="logout") is True
    assert store.revoke_session(revoked.session.session_id, reason="logout") is False
    assert store.resolve(revoked.handle) is None

    clock.value = now + timedelta(seconds=10)
    assert store.resolve(expired.handle) is None

    event_pairs = [(event.event_type, event.outcome) for event in store.security_events()]
    assert ("session.revoked", "accepted") in event_pairs
    assert ("session.revoke_rejected", "already_revoked") in event_pairs
    assert ("session.resolve_rejected", "revoked") in event_pairs
    assert ("session.resolve_rejected", "expired") in event_pairs
    assert store.verify_integrity() is True


def test_schema_and_binding_tampering_are_detected(tmp_path: Path) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    issued = SQLiteTrustedSessionStore(path).issue(
        _identity(), ttl_seconds=60, max_uses=2
    )

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE trusted_sessions SET company_id=9 WHERE session_id=?",
                (issued.session.session_id,),
            )

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER trusted_sessions_immutable")
        connection.execute(
            "UPDATE trusted_sessions SET company_id=9 WHERE session_id=?",
            (issued.session.session_id,),
        )

    with pytest.raises(TrustedSessionStoreError, match="schema"):
        SQLiteTrustedSessionStore(path)


def test_security_events_are_append_only(tmp_path: Path) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    issued = store.issue(_identity(), ttl_seconds=60, max_uses=1)
    assert store.resolve(issued.handle) == issued.session

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE trusted_session_security_events "
                "SET outcome='forged' WHERE sequence=1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM trusted_session_security_events WHERE sequence=1"
            )

    assert store.verify_integrity() is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX writer lock contract")
def test_posix_writer_lock_is_persistent_private_and_rejects_unsafe_files(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    lock_path = Path(f"{path}.writer.lock")
    metadata = lock_path.lstat()
    original_identity = (metadata.st_dev, metadata.st_ino)
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_mode & 0o777 == 0o600
    assert metadata.st_nlink == 1

    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    assert store.resolve(issued.handle) == issued.session
    assert lock_path.exists()
    assert (lock_path.stat().st_dev, lock_path.stat().st_ino) == original_identity

    unsafe_parent = tmp_path / "unsafe-lock"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_path = (unsafe_parent / "sessions.sqlite3").resolve()
    unsafe_lock = Path(f"{unsafe_path}.writer.lock")
    unsafe_lock.write_bytes(b"")
    unsafe_lock.chmod(0o640)
    with pytest.raises(TrustedSessionStoreError, match="writer lock file is invalid"):
        SQLiteTrustedSessionStore(unsafe_path)
    assert unsafe_lock.exists()
    assert unsafe_lock.stat().st_mode & 0o777 == 0o640

    symlink_parent = tmp_path / "symlink-lock"
    symlink_parent.mkdir(mode=0o700)
    symlink_path = (symlink_parent / "sessions.sqlite3").resolve()
    symlink_lock = Path(f"{symlink_path}.writer.lock")
    target = symlink_parent / "target"
    target.write_bytes(b"")
    target.chmod(0o600)
    symlink_lock.symlink_to(target)
    with pytest.raises(
        TrustedSessionStoreError, match="writer lock file cannot be secured"
    ):
        SQLiteTrustedSessionStore(symlink_path)
    assert symlink_lock.is_symlink()

    hardlink_parent = tmp_path / "hardlink-lock"
    hardlink_parent.mkdir(mode=0o700)
    hardlink_path = (hardlink_parent / "sessions.sqlite3").resolve()
    hardlink_lock = Path(f"{hardlink_path}.writer.lock")
    hardlink_target = hardlink_parent / "target"
    hardlink_target.write_bytes(b"")
    hardlink_target.chmod(0o600)
    os.link(hardlink_target, hardlink_lock)
    with pytest.raises(TrustedSessionStoreError, match="writer lock file is invalid"):
        SQLiteTrustedSessionStore(hardlink_path)
    assert hardlink_lock.stat().st_nlink == 2

    fifo_parent = tmp_path / "fifo-lock"
    fifo_parent.mkdir(mode=0o700)
    fifo_path = (fifo_parent / "sessions.sqlite3").resolve()
    fifo_lock = Path(f"{fifo_path}.writer.lock")
    os.mkfifo(fifo_lock, mode=0o600)
    with pytest.raises(TrustedSessionStoreError, match="writer lock file is invalid"):
        SQLiteTrustedSessionStore(fifo_path)
    assert stat.S_ISFIFO(fifo_lock.lstat().st_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX writer lock contract")
def test_posix_writer_lock_deadline_does_not_consume_handle(tmp_path: Path) -> None:
    assert fcntl is not None
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path, busy_timeout_ms=50)
    issued = store.issue(_identity(), ttl_seconds=120, max_uses=1)
    lock_path = Path(f"{path}.writer.lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    started = time.monotonic()
    try:
        with pytest.raises(TrustedSessionStoreError, match="lock deadline"):
            store.resolve(issued.handle)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert time.monotonic() - started < 1
    assert store.resolve(issued.handle) == issued.session
    assert store.resolve(issued.handle) is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX writer lock contract")
def test_posix_writer_lock_retries_interrupted_flock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert fcntl is not None
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path, busy_timeout_ms=250)
    real_flock = fcntl.flock
    interruptions = 0

    def interrupted_once(descriptor: int, operation: int) -> object:
        nonlocal interruptions
        if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB) and interruptions == 0:
            interruptions += 1
            raise OSError(errno.EINTR, "interrupted")
        return real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", interrupted_once)
    with store._transaction():
        pass

    assert interruptions == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX writer lock contract")
def test_posix_writer_lock_spans_yield_commit_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert fcntl is not None
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    descriptor = os.open(
        Path(f"{path}.writer.lock"), os.O_RDWR | os.O_NOFOLLOW
    )

    def assert_locked() -> None:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_released() -> None:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)

    real_connect = sqlite3.connect
    commit_probes = 0
    rollback_probes = 0

    class LockProbeConnection(sqlite3.Connection):
        def commit(self) -> None:
            nonlocal commit_probes
            commit_probes += 1
            assert_locked()
            super().commit()

        def rollback(self) -> None:
            nonlocal rollback_probes
            rollback_probes += 1
            assert_locked()
            super().rollback()

    def probing_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = LockProbeConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(
        trusted_session_sqlite.sqlite3,
        "connect",
        probing_connect,
    )
    try:
        with store._transaction():
            assert_locked()
        assert_released()

        with pytest.raises(RuntimeError, match="force rollback"):
            with store._transaction():
                assert_locked()
                raise RuntimeError("force rollback")
        assert_released()
    finally:
        os.close(descriptor)

    assert commit_probes == 1
    assert rollback_probes == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link contract")
def test_database_hardlink_alias_is_rejected_before_lock_derivation(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    alias = (tmp_path / "sessions-alias.sqlite3").resolve()
    os.link(path, alias)

    with pytest.raises(TrustedSessionStoreError, match="exactly one hard link"):
        SQLiteTrustedSessionStore(alias)
    with pytest.raises(TrustedSessionStoreError, match="exactly one hard link"):
        store.verify_integrity()

    alias.unlink()
    assert store.verify_integrity() is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode contract")
def test_database_requires_private_parent_and_mode(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = (private / "sessions.sqlite3").resolve()
    SQLiteTrustedSessionStore(path)
    assert path.stat().st_mode & 0o777 == 0o600

    os.chmod(private, 0o755)
    with pytest.raises(TrustedSessionStoreError, match="parent directory is not private"):
        SQLiteTrustedSessionStore(path)
