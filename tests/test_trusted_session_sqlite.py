from __future__ import annotations

import hashlib
import multiprocessing
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.trusted_session_sqlite import (
    SQLiteTrustedSessionStore,
    TrustedSessionIdentity,
    TrustedSessionStoreError,
)


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
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        store = SQLiteTrustedSessionStore(Path(path))
        start.wait(15)
        results.put(store.resolve(handle) is not None)
    except BaseException as exc:  # pragma: no cover - child diagnostic
        results.put(f"{type(exc).__name__}: {exc}")


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
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_resolve,
            args=(str(path), issued.handle, start, results),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    start.set()
    values = [results.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    assert values.count(True) == 1
    assert values.count(False) == 5
    assert all(isinstance(value, bool) for value in values), values
    store = SQLiteTrustedSessionStore(path)
    assert store.resolve(issued.handle) is None
    assert store.verify_integrity() is True
    assert [event.event_type for event in store.security_events()].count(
        "session.resolved"
    ) == 1


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
