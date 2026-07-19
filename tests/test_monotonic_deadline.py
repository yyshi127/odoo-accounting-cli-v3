from __future__ import annotations

import contextvars
import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, ContextManager

import pytest

import odoo_accounting_cli_v3.monotonic_deadline as deadline
from odoo_accounting_cli_v3.broker_audit import BrokerAuditError, SQLiteBrokerAuditSink
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.trusted_authority import AuthorityError
from odoo_accounting_cli_v3.trusted_authority_sqlite import (
    SQLiteApprovalChallengeStore,
)
from odoo_accounting_cli_v3.trusted_session_sqlite import (
    SQLiteTrustedSessionStore,
    TrustedSessionStoreError,
)


StoreFactory = Callable[[Path], Any]
ConnectionFactory = Callable[[Any], ContextManager[sqlite3.Connection]]


STORE_CASES: tuple[tuple[str, StoreFactory, ConnectionFactory], ...] = (
    (
        "write",
        lambda path: SQLitePersistence(path, busy_timeout_ms=1_000),
        lambda store: store._transaction(),
    ),
    (
        "session",
        lambda path: SQLiteTrustedSessionStore(path, busy_timeout_ms=1_000),
        lambda store: store._transaction(),
    ),
    (
        "audit",
        lambda path: SQLiteBrokerAuditSink(path, busy_timeout_ms=1_000),
        lambda store: store._connection(write=True),
    ),
    (
        "approval",
        lambda path: SQLiteApprovalChallengeStore(path, busy_timeout_ms=1_000),
        lambda store: store._transaction(),
    ),
)


def test_nested_deadline_scope_can_only_shorten_never_extend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deadline, "_monotonic", lambda: 100.0)

    with deadline.monotonic_deadline_scope(105.0):
        assert deadline.current_monotonic_deadline() == 105.0
        assert deadline.bounded_sqlite_connect_timeout_seconds(10_000) == 5.0
        assert deadline.bounded_sqlite_busy_timeout_ms(10_000) == 5_000
        with deadline.monotonic_deadline_scope(110.0):
            assert deadline.current_monotonic_deadline() == 105.0
        with deadline.monotonic_deadline_scope(102.0):
            assert deadline.current_monotonic_deadline() == 102.0
        assert deadline.current_monotonic_deadline() == 105.0

    assert deadline.current_monotonic_deadline() is None


def test_bounded_operation_deadline_samples_once_and_preserves_outer_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_calls = 0

    def monotonic() -> float:
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls > 1:
            raise AssertionError("operation deadline sampled the clock more than once")
        return 100.0

    monkeypatch.setattr(deadline, "_monotonic", monotonic)

    with deadline.monotonic_deadline_scope(101.0):
        operation_deadline = deadline.bounded_sqlite_operation_deadline(5_000)

    assert operation_deadline == 101.0
    assert clock_calls == 1


def test_thread_deadline_context_requires_an_explicit_copy() -> None:
    observed: queue.Queue[float | None] = queue.Queue()

    def observe() -> None:
        observed.put(deadline.current_monotonic_deadline())

    outer = time.monotonic() + 30
    with deadline.monotonic_deadline_scope(outer):
        plain = threading.Thread(target=observe)
        plain.start()
        plain.join(timeout=1)

        copied: contextvars.Context = deadline.copy_monotonic_deadline_context()
        propagated = threading.Thread(target=lambda: copied.run(observe))
        propagated.start()
        propagated.join(timeout=1)

    assert not plain.is_alive()
    assert not propagated.is_alive()
    assert observed.get_nowait() is None
    assert observed.get_nowait() == outer


@pytest.mark.parametrize("name,store_factory,connection_factory", STORE_CASES)
def test_expired_deadline_rejects_each_store_before_sqlite_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    store_factory: StoreFactory,
    connection_factory: ConnectionFactory,
) -> None:
    store = store_factory((tmp_path / f"{name}.sqlite3").resolve())
    calls = 0
    original = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    with deadline.monotonic_deadline_scope(time.monotonic() - 1):
        with pytest.raises(deadline.MonotonicDeadlineExceeded):
            with connection_factory(store):
                raise AssertionError("expired scope opened a SQLite connection")

    assert calls == 0


@pytest.mark.parametrize("name,store_factory,connection_factory", STORE_CASES)
def test_each_store_bounds_connect_and_pragma_to_current_remaining_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    store_factory: StoreFactory,
    connection_factory: ConnectionFactory,
) -> None:
    store = store_factory((tmp_path / f"{name}.sqlite3").resolve())
    observed_connect_timeouts: list[float] = []
    original = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        observed_connect_timeouts.append(float(kwargs["timeout"]))
        return original(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    with deadline.monotonic_deadline_scope(time.monotonic() + 0.5):
        with connection_factory(store) as connection:
            pragma_timeout_ms = int(
                connection.execute("PRAGMA busy_timeout").fetchone()[0]
            )

    assert len(observed_connect_timeouts) == 1
    assert 0 < observed_connect_timeouts[0] <= 0.5
    assert 0 <= pragma_timeout_ms <= 500


@pytest.mark.parametrize("name,store_factory,connection_factory", STORE_CASES)
def test_locked_store_wait_is_cut_short_by_the_absolute_deadline(
    tmp_path: Path,
    name: str,
    store_factory: StoreFactory,
    connection_factory: ConnectionFactory,
) -> None:
    path = (tmp_path / f"{name}.sqlite3").resolve()
    store = store_factory(path)
    lock = sqlite3.connect(path, timeout=1, isolation_level=None)
    lock.execute("PRAGMA journal_mode = WAL")
    lock.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        with deadline.monotonic_deadline_scope(started + 0.05):
            with pytest.raises(
                (
                    sqlite3.OperationalError,
                    deadline.MonotonicDeadlineExceeded,
                    TrustedSessionStoreError,
                    BrokerAuditError,
                    AuthorityError,
                )
            ):
                with connection_factory(store):
                    raise AssertionError("locked database admitted a second writer")
    finally:
        lock.rollback()
        lock.close()

    assert time.monotonic() - started < 0.5
