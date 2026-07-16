from __future__ import annotations

import hashlib
import inspect
import json
import multiprocessing
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock, Thread

import pytest

from odoo_accounting_cli_v3 import sqlite_process_lifecycle, trusted_authority_sqlite
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    canonical_json,
    record_precheck,
    sign_approval,
)
from odoo_accounting_cli_v3.trusted_authority import (
    ApprovalChallenge,
    ApprovalChallengeState,
    ApprovalDecision,
    AuthorityAuditDraft,
    AuthorityCommitOutcomeUnknownError,
    AuthorityConcurrentUpdate,
    AuthorityError,
    AuthorityKnownCommittedError,
    AuthorityKeys,
    AuthorityReconciliationRequiredError,
    TrustedAuthority,
    TrustedSession,
    _operation_binding_digest,
)
from odoo_accounting_cli_v3.trusted_authority_sqlite import (
    AUTHORITY_STORE_SCHEMA_VERSION,
    SQLiteApprovalChallengeStore,
)


NOW = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
DATABASE_UUID = "b4ac5547-f101-49ca-b9a7-e9793394a237"
APPROVAL_SECRET = b"a" * 32
CONTEXT_SECRET_SENTINEL = b"context-secret-must-never-enter-sqlite-1"
APPROVAL_SECRET_SENTINEL = b"approval-secret-must-never-enter-sqlite"


class _ObservableMutex:
    def __init__(self) -> None:
        self._lock = Lock()
        self.blocked = Event()

    def acquire(self, *, timeout: float = -1) -> bool:
        if self._lock.acquire(blocking=False):
            return True
        self.blocked.set()
        return self._lock.acquire(timeout=timeout)

    def release(self) -> None:
        self._lock.release()


@pytest.fixture(autouse=True)
def _isolate_process_sqlite_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> sqlite_process_lifecycle._ProcessSQLiteLifecycle:
    gate = sqlite_process_lifecycle._ProcessSQLiteLifecycle()
    monkeypatch.setattr(
        sqlite_process_lifecycle, "_PROCESS_SQLITE_LIFECYCLE", gate
    )
    return gate


def awaiting_operation(operation_id: str = "op-1") -> Operation:
    operation = Operation.prepare(
        operation_id=operation_id,
        request_id=f"request-{operation_id}",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "partner_id": 101},
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key=f"idempotency-{operation_id}",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest="b" * 64,
        release_digest="c" * 64,
    )
    operation = record_precheck(
        operation, precheck_digest="d" * 64, expected_revision=0
    )
    return operation.transition(State.AWAITING_APPROVAL, expected_revision=1)


def pending_challenge(
    operation_id: str = "op-1", *, challenge_id: str | None = None
) -> ApprovalChallenge:
    operation = awaiting_operation(operation_id)
    return ApprovalChallenge(
        challenge_id=challenge_id or f"challenge-{operation_id}",
        binding_digest=_operation_binding_digest(operation),
        operation=operation,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
        ttl_seconds=120,
    )


def draft(
    challenge: ApprovalChallenge | None,
    event_id: str,
    *,
    occurred_at: datetime = NOW,
    event_type: str = "approval.challenge_created",
    payload: dict[str, object] | None = None,
) -> AuthorityAuditDraft:
    return AuthorityAuditDraft(
        event_id=event_id,
        event_type=event_type,
        occurred_at=occurred_at,
        challenge_id=None if challenge is None else challenge.challenge_id,
        operation_id=None if challenge is None else challenge.operation.operation_id,
        binding_digest=None if challenge is None else challenge.binding_digest,
        actor_user_id=42,
        payload_json=canonical_json(payload or {"state": "pending"}).decode("utf-8"),
    )


def denied(
    challenge: ApprovalChallenge, *, decided_at: datetime = NOW + timedelta(seconds=1)
) -> ApprovalChallenge:
    return replace(
        challenge,
        state=ApprovalChallengeState.DENIED,
        version=challenge.version + 1,
        decided_at=decided_at,
        decider_user_id=84,
        denial_reason="evidence incomplete",
    )


def approved(
    challenge: ApprovalChallenge,
    *,
    nonce: str,
    decided_at: datetime = NOW + timedelta(seconds=1),
) -> ApprovalChallenge:
    approval = sign_approval(
        operation=challenge.operation,
        approver_user_id=84,
        nonce=nonce,
        issued_at=decided_at,
        expires_at=challenge.expires_at,
        approval_ttl_seconds=challenge.ttl_seconds,
        key_id="approval-key-1",
        secret=APPROVAL_SECRET,
    )
    return replace(
        challenge,
        state=ApprovalChallengeState.APPROVED,
        version=challenge.version + 1,
        decided_at=decided_at,
        decider_user_id=84,
        approval=approval,
    )


def _process_create_challenge(
    path: str,
    challenge_id: str,
    event_id: str,
    start: object,
    results: object,
) -> None:
    try:
        store = SQLiteApprovalChallengeStore(Path(path))
        challenge = pending_challenge(challenge_id=challenge_id)
        start.wait(timeout=15)
        stored, created = store.create_challenge(
            challenge, draft(challenge, event_id)
        )
        results.put(("ok", stored.challenge_id, created))
    except BaseException as exc:  # pragma: no cover - asserted in parent process
        results.put(("error", type(exc).__name__, str(exc)))


def _process_approve_with_shared_nonce(
    path: str,
    operation_id: str,
    event_id: str,
    start: object,
    results: object,
) -> None:
    try:
        store = SQLiteApprovalChallengeStore(Path(path))
        challenge = store.get_challenge(f"challenge-{operation_id}")
        candidate = approved(
            challenge,
            nonce="cross-process-shared-nonce",
            decided_at=NOW + timedelta(seconds=2),
        )
        start.wait(timeout=15)
        store.transition_challenge(
            candidate,
            expected_version=0,
            event=draft(
                challenge,
                event_id,
                occurred_at=candidate.decided_at,
                event_type="approval.challenge_approved",
            ),
        )
        results.put(("approved", operation_id))
    except AuthorityError as exc:
        results.put(("rejected", operation_id, str(exc)))
    except BaseException as exc:  # pragma: no cover - asserted in parent process
        results.put(("error", type(exc).__name__, str(exc)))


def _run_processes(
    target: object, argument_pairs: tuple[tuple[str, str], ...], database_path: Path
) -> tuple[tuple[object, ...], ...]:
    context = multiprocessing.get_context("spawn")
    start = context.Barrier(len(argument_pairs) + 1)
    results = context.Queue()
    processes = [
        context.Process(
            target=target,
            args=(str(database_path), first, second, start, results),
        )
        for first, second in argument_pairs
    ]
    for process in processes:
        process.start()
    start.wait(timeout=20)
    output = tuple(results.get(timeout=20) for _ in processes)
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    return output


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return (tmp_path / "authority.sqlite3").absolute()


def test_requires_absolute_regular_non_symlink_private_database_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(AuthorityError, match="absolute"):
        SQLiteApprovalChallengeStore(Path("authority.sqlite3"))

    if os.name == "posix":
        permissive = (tmp_path / "permissive.sqlite3").absolute()
        permissive.touch(mode=0o644)
        permissive.chmod(0o644)
        with pytest.raises(AuthorityError, match="private"):
            SQLiteApprovalChallengeStore(permissive)

    target = (tmp_path / "target.sqlite3").absolute()
    target.touch()
    link = (tmp_path / "link.sqlite3").absolute()
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(AuthorityError, match="non-symlink"):
        SQLiteApprovalChallengeStore(link)


def test_database_hardlink_is_rejected(tmp_path: Path) -> None:
    database = (tmp_path / "hardlinked.sqlite3").absolute()
    database.touch(mode=0o600)
    database.chmod(0o600)
    alias = (tmp_path / "database-alias.sqlite3").absolute()
    try:
        os.link(database, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(AuthorityError, match="exactly one hard link"):
        SQLiteApprovalChallengeStore(database)


@pytest.mark.skipif(os.name != "posix", reason="POSIX database race contract")
def test_database_path_replacement_after_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = (tmp_path / "replace.sqlite3").absolute()
    database.touch(mode=0o600)
    database.chmod(0o600)
    real_open = os.open

    def replace_after_open(
        candidate: str | bytes | os.PathLike[str], flags: int, *args: object
    ) -> int:
        descriptor = real_open(candidate, flags, *args)
        if Path(candidate) == database:
            database.unlink()
            database.write_bytes(b"replacement authority database")
            database.chmod(0o600)
        return descriptor

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", replace_after_open)

    with pytest.raises(AuthorityError, match="regular non-symlink"):
        SQLiteApprovalChallengeStore(database)


@pytest.mark.skipif(os.name != "posix", reason="POSIX database permission contract")
def test_database_permission_change_between_fstat_and_lstat_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = (tmp_path / "permission-race.sqlite3").absolute()
    database.touch(mode=0o600)
    database.chmod(0o600)
    real_lstat = Path.lstat
    database_lstats = 0

    def make_public_on_second_lstat(candidate: Path):
        nonlocal database_lstats
        if candidate == database:
            database_lstats += 1
            if database_lstats == 2:
                candidate.chmod(0o644)
        return real_lstat(candidate)

    monkeypatch.setattr(
        trusted_authority_sqlite.Path, "lstat", make_public_on_second_lstat
    )

    with pytest.raises(AuthorityError, match="database file is not private"):
        SQLiteApprovalChallengeStore(database)


def test_initializes_versioned_private_wal_database(database_path: Path) -> None:
    store = SQLiteApprovalChallengeStore(database_path, busy_timeout_ms=3_000)

    assert store.path == database_path
    if os.name == "posix":
        assert stat.S_IMODE(database_path.stat().st_mode) & 0o077 == 0
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute(
            "SELECT value FROM authority_schema_meta WHERE key='schema_version'"
        ).fetchone()[0] == str(AUTHORITY_STORE_SCHEMA_VERSION)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"approval_challenges", "authority_audit_events"} <= tables

    signature = inspect.signature(SQLiteApprovalChallengeStore)
    assert not {"secret", "context_secret", "approval_secret"}.intersection(signature.parameters)
    assert "secret" not in database_path.read_bytes().decode("utf-8", errors="ignore").lower()


def test_create_round_trips_canonical_content_across_store_instances(
    database_path: Path,
) -> None:
    first = SQLiteApprovalChallengeStore(database_path)
    challenge = pending_challenge()

    stored, created = first.create_challenge(challenge, draft(challenge, "event-1"))
    second = SQLiteApprovalChallengeStore(database_path)

    assert created is True
    assert stored == challenge
    assert second.get_challenge(challenge.challenge_id) == challenge
    assert second.find_challenge(challenge.challenge_id) == challenge
    assert second.find_challenge("challenge-does-not-exist") is None
    assert second.find_by_binding(challenge.binding_digest) == challenge
    assert second.find_by_operation_revision("op-1", 2) == challenge
    assert second.challenges() == (challenge,)
    assert second.verify_audit_chain() is True

    with sqlite3.connect(database_path) as connection:
        operation_json, issued_at = connection.execute(
            "SELECT operation_json, issued_at FROM approval_challenges"
        ).fetchone()
        payload_json, occurred_at = connection.execute(
            "SELECT payload_json, occurred_at FROM authority_audit_events"
        ).fetchone()
    assert canonical_json(json.loads(operation_json)).decode("utf-8") == operation_json
    assert canonical_json(json.loads(payload_json)).decode("utf-8") == payload_json
    assert issued_at.endswith("+00:00")
    assert occurred_at.endswith("+00:00")


def test_trusted_authority_survives_restart_without_persisting_hmac_secrets(
    database_path: Path,
) -> None:
    operation = awaiting_operation()
    requester = TrustedSession(
        session_id="requester-session",
        principal=operation.principal,
        odoo_instance_id=operation.odoo_instance_id,
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        user_id=operation.user_id,
        company_id=operation.company_id,
        allowed_company_ids=frozenset({operation.company_id}),
        environment=operation.environment,
        release_digest=operation.release_digest,
        registry_digest=operation.registry_digest,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    approver = replace(
        requester,
        session_id="approver-session",
        principal="pi:user-84",
        user_id=84,
    )
    sessions = {"requester": requester, "approver": approver}
    keys = AuthorityKeys(
        context_key_id="context-key-1",
        context_secret=CONTEXT_SECRET_SENTINEL,
        approval_key_id="approval-key-1",
        approval_secret=APPROVAL_SECRET_SENTINEL,
    )
    event_ids = iter(("created", "approved"))
    first = TrustedAuthority(
        session_resolver=sessions.get,
        operation_resolver=lambda operation_id: (
            operation if operation_id == operation.operation_id else None
        ),
        approver_authorizer=lambda session, candidate: session.user_id == 84,
        approval_ttl_resolver=lambda candidate: 120,
        keys=keys,
        store=SQLiteApprovalChallengeStore(database_path),
        clock=lambda: NOW,
        challenge_id_factory=lambda: "durable-challenge",
        event_id_factory=lambda: next(event_ids),
        nonce_factory=lambda: "durable-one-time-nonce",
    )
    challenge = first.request_approval("requester", operation.operation_id)
    approved_challenge = first.decide_approval(
        "approver", challenge.challenge_id, ApprovalDecision.APPROVE
    )

    restarted = TrustedAuthority(
        session_resolver=sessions.get,
        operation_resolver=lambda operation_id: (
            operation if operation_id == operation.operation_id else None
        ),
        approver_authorizer=lambda session, candidate: session.user_id == 84,
        approval_ttl_resolver=lambda candidate: 120,
        keys=keys,
        store=SQLiteApprovalChallengeStore(database_path),
        clock=lambda: NOW,
        event_id_factory=lambda: "execute-context",
    )
    action = restarted.issue_approved_execute("requester", challenge.challenge_id)

    assert action.request["approval"]["nonce"] == "durable-one-time-nonce"
    assert approved_challenge == SQLiteApprovalChallengeStore(
        database_path
    ).get_challenge(challenge.challenge_id)
    persisted = database_path.read_bytes()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{database_path}{suffix}")
        if sidecar.exists():
            persisted += sidecar.read_bytes()
    assert CONTEXT_SECRET_SENTINEL not in persisted
    assert APPROVAL_SECRET_SENTINEL not in persisted


def test_concurrent_create_reuses_one_binding_with_one_event(
    database_path: Path,
) -> None:
    left = SQLiteApprovalChallengeStore(database_path)
    right = SQLiteApprovalChallengeStore(database_path)
    operation = awaiting_operation()
    barrier = Barrier(2)

    def create(
        store: SQLiteApprovalChallengeStore, challenge_id: str, event_id: str
    ) -> tuple[ApprovalChallenge, bool]:
        candidate = ApprovalChallenge(
            challenge_id=challenge_id,
            binding_digest=_operation_binding_digest(operation),
            operation=operation,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
            ttl_seconds=120,
        )
        barrier.wait()
        return store.create_challenge(candidate, draft(candidate, event_id))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(
            future.result()
            for future in (
                pool.submit(create, left, "challenge-left", "event-left"),
                pool.submit(create, right, "challenge-right", "event-right"),
            )
        )

    assert sorted(created for _, created in results) == [False, True]
    assert results[0][0] == results[1][0]
    assert len(left.challenges()) == 1
    assert len(left.audit_events()) == 1


def test_cross_process_create_reuses_one_binding_with_one_event(
    database_path: Path,
) -> None:
    SQLiteApprovalChallengeStore(database_path)

    results = _run_processes(
        _process_create_challenge,
        (("challenge-process-1", "event-process-1"),
         ("challenge-process-2", "event-process-2")),
        database_path,
    )

    assert sorted(result[0] for result in results) == ["ok", "ok"]
    assert sorted(result[2] for result in results) == [False, True]
    assert results[0][1] == results[1][1]
    store = SQLiteApprovalChallengeStore(database_path)
    assert len(store.challenges()) == 1
    assert len(store.audit_events()) == 1


def test_create_rolls_back_challenge_when_audit_insert_fails(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    store.append_audit_event(draft(None, "duplicate-event"))
    challenge = pending_challenge()

    with pytest.raises(AuthorityError, match="event ID already exists"):
        store.create_challenge(challenge, draft(challenge, "duplicate-event"))

    with pytest.raises(AuthorityError, match="unknown"):
        store.get_challenge(challenge.challenge_id)
    assert len(store.audit_events()) == 1


def test_optimistic_transition_is_atomic_across_two_instances(
    database_path: Path,
) -> None:
    left = SQLiteApprovalChallengeStore(database_path)
    right = SQLiteApprovalChallengeStore(database_path)
    challenge = pending_challenge()
    left.create_challenge(challenge, draft(challenge, "created"))
    candidate = denied(challenge)
    barrier = Barrier(2)

    def transition(store: SQLiteApprovalChallengeStore, event_id: str) -> object:
        barrier.wait()
        try:
            return store.transition_challenge(
                candidate,
                expected_version=0,
                event=draft(
                    challenge,
                    event_id,
                    occurred_at=candidate.decided_at,
                    event_type="approval.challenge_denied",
                    payload={"state": "denied"},
                ),
            )
        except Exception as exc:  # result is asserted below
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            future.result()
            for future in (
                pool.submit(transition, left, "denied-left"),
                pool.submit(transition, right, "denied-right"),
            )
        )

    assert sum(isinstance(item, ApprovalChallenge) for item in outcomes) == 1
    assert sum(isinstance(item, AuthorityConcurrentUpdate) for item in outcomes) == 1
    assert left.get_challenge(challenge.challenge_id) == candidate
    assert len(left.audit_events()) == 2


def test_transition_rolls_back_on_duplicate_event_and_duplicate_approval_nonce(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    first = pending_challenge("op-1")
    second = pending_challenge("op-2")
    store.create_challenge(first, draft(first, "created-1"))
    store.create_challenge(
        second,
        draft(second, "created-2", occurred_at=NOW + timedelta(microseconds=1)),
    )

    duplicate_event_candidate = denied(first, decided_at=NOW + timedelta(seconds=1))
    with pytest.raises(AuthorityError, match="event ID already exists"):
        store.transition_challenge(
            duplicate_event_candidate,
            expected_version=0,
            event=draft(
                first,
                "created-2",
                occurred_at=duplicate_event_candidate.decided_at,
                event_type="approval.challenge_denied",
            ),
        )
    assert store.get_challenge(first.challenge_id).state is ApprovalChallengeState.PENDING

    first_approved = approved(
        first, nonce="one-time-nonce", decided_at=NOW + timedelta(seconds=2)
    )
    store.transition_challenge(
        first_approved,
        expected_version=0,
        event=draft(
            first,
            "approved-1",
            occurred_at=first_approved.decided_at,
            event_type="approval.challenge_approved",
        ),
    )
    second_approved = approved(
        second, nonce="one-time-nonce", decided_at=NOW + timedelta(seconds=3)
    )
    with pytest.raises(AuthorityError, match="nonce was already issued"):
        store.transition_challenge(
            second_approved,
            expected_version=0,
            event=draft(
                second,
                "approved-2",
                occurred_at=second_approved.decided_at,
                event_type="approval.challenge_approved",
            ),
        )

    assert store.get_challenge(second.challenge_id).state is ApprovalChallengeState.PENDING
    assert [event.event_id for event in store.audit_events()] == [
        "created-1",
        "created-2",
        "approved-1",
    ]


def test_cross_process_approval_nonce_is_unique_without_partial_transition(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    first = pending_challenge("op-1")
    second = pending_challenge("op-2")
    store.create_challenge(first, draft(first, "created-1"))
    store.create_challenge(
        second,
        draft(second, "created-2", occurred_at=NOW + timedelta(microseconds=1)),
    )

    results = _run_processes(
        _process_approve_with_shared_nonce,
        (("op-1", "approved-process-1"), ("op-2", "approved-process-2")),
        database_path,
    )

    assert sorted(result[0] for result in results) == ["approved", "rejected"]
    rejected = next(result for result in results if result[0] == "rejected")
    assert "nonce was already issued" in rejected[2]
    states = {challenge.state for challenge in store.challenges()}
    assert states == {
        ApprovalChallengeState.APPROVED,
        ApprovalChallengeState.PENDING,
    }
    assert len(store.audit_events()) == 3


def test_cross_process_challenge_can_transition_only_once(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    challenge = pending_challenge("op-1")
    store.create_challenge(challenge, draft(challenge, "created"))

    results = _run_processes(
        _process_approve_with_shared_nonce,
        (("op-1", "approved-process-1"), ("op-1", "approved-process-2")),
        database_path,
    )

    assert sorted(result[0] for result in results) == ["approved", "rejected"]
    rejected = next(result for result in results if result[0] == "rejected")
    assert "version changed" in rejected[2]
    stored = store.get_challenge(challenge.challenge_id)
    assert stored.state is ApprovalChallengeState.APPROVED
    assert stored.version == 1
    assert len(store.audit_events()) == 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_wal_sidecars_are_private_and_insecure_sidecar_fails_before_append(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    with sqlite3.connect(database_path) as keeper:
        assert keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        keeper.execute("SELECT * FROM authority_schema_meta").fetchall()
        store.append_audit_event(draft(None, "event-1"))
        sidecars = [
            Path(f"{database_path}{suffix}")
            for suffix in ("-wal", "-shm")
            if Path(f"{database_path}{suffix}").exists()
        ]
        assert sidecars
        assert all(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0 for path in sidecars)

        sidecars[0].chmod(0o644)
        try:
            with pytest.raises(AuthorityError, match="sidecar is not private"):
                store.append_audit_event(
                    draft(None, "event-2", occurred_at=NOW + timedelta(seconds=1))
                )
        finally:
            sidecars[0].chmod(0o600)

    assert [event.event_id for event in store.audit_events()] == ["event-1"]


def test_precommit_identity_failure_rolls_back_without_durable_event(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    verify = store._verify_database_path
    calls = 0

    def fail_second(expected: tuple[int, int]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise AuthorityError("forced precommit identity failure")
        verify(expected)

    monkeypatch.setattr(store, "_verify_database_path", fail_second)

    with pytest.raises(AuthorityError, match="forced precommit identity failure"):
        store.append_audit_event(draft(None, "must-not-commit"))

    monkeypatch.setattr(store, "_verify_database_path", verify)
    assert store.audit_events() == ()


@pytest.mark.parametrize("cleanup_phase", ("database_verification", "close"))
def test_post_commit_cleanup_failure_requires_authority_reconciliation(
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_phase: str,
) -> None:
    gate = sqlite_process_lifecycle._ProcessSQLiteLifecycle()
    monkeypatch.setattr(
        sqlite_process_lifecycle, "_PROCESS_SQLITE_LIFECYCLE", gate
    )
    store = SQLiteApprovalChallengeStore(database_path)
    real_connect = sqlite3.connect
    real_verify = store._verify_database_file

    if cleanup_phase == "database_verification":
        verification_calls = 0

        def fail_post_commit_verification(
            expected: tuple[int, int],
            lease: sqlite_process_lifecycle.SQLiteProcessLifecycleLease | None = None,
        ) -> None:
            nonlocal verification_calls
            verification_calls += 1
            real_verify(expected, lease)
            if verification_calls == 1:
                raise AuthorityError("simulated post-commit verification failure")

        monkeypatch.setattr(
            store, "_verify_database_file", fail_post_commit_verification
        )
    else:

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
            trusted_authority_sqlite.sqlite3,
            "connect",
            failing_close_connect,
        )

    with pytest.raises(AuthorityKnownCommittedError) as caught:
        store.append_audit_event(draft(None, f"event-{cleanup_phase}"))

    assert caught.value.committed is True
    assert caught.value.retryable is False
    assert caught.value.reconciliation_required is True
    assert "do not replay" in str(caught.value)
    assert gate.poisoned is (cleanup_phase == "close")

    monkeypatch.setattr(trusted_authority_sqlite.sqlite3, "connect", real_connect)
    with real_connect(database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM authority_audit_events"
        ).fetchone()[0] == 1

    if cleanup_phase == "close":
        with pytest.raises(AuthorityError, match="process lifecycle is unsafe"):
            store.audit_events()
        monkeypatch.setattr(
            sqlite_process_lifecycle,
            "_PROCESS_SQLITE_LIFECYCLE",
            sqlite_process_lifecycle._ProcessSQLiteLifecycle(),
        )
    monkeypatch.setattr(store, "_verify_database_file", real_verify)
    assert SQLiteApprovalChallengeStore(database_path).verify_audit_chain() is True


def test_commit_that_may_have_completed_requires_authority_reconciliation(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    real_connect = sqlite3.connect

    class CommitThenRaiseConnection(sqlite3.Connection):
        def commit(self) -> None:
            super().commit()
            raise sqlite3.OperationalError("simulated post-commit exception")

    def uncertain_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = CommitThenRaiseConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(
        trusted_authority_sqlite.sqlite3, "connect", uncertain_connect
    )
    with pytest.raises(AuthorityCommitOutcomeUnknownError) as caught:
        store.append_audit_event(draft(None, "commit-outcome-unknown"))

    assert isinstance(caught.value, AuthorityReconciliationRequiredError)
    assert caught.value.committed is None
    assert caught.value.commit_outcome == "unknown"
    assert caught.value.retryable is False
    assert caught.value.reconciliation_required is True
    assert "do not replay" in str(caught.value)

    monkeypatch.setattr(trusted_authority_sqlite.sqlite3, "connect", real_connect)
    with real_connect(database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM authority_audit_events"
        ).fetchone()[0] == 1
    assert SQLiteApprovalChallengeStore(database_path).verify_audit_chain() is True


def test_commit_failure_with_confirmed_rollback_is_retry_safe(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    real_connect = sqlite3.connect

    class CommitBeforeDurableFailureConnection(sqlite3.Connection):
        def commit(self) -> None:
            raise sqlite3.OperationalError("simulated pre-commit failure")

    def failed_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = CommitBeforeDurableFailureConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(trusted_authority_sqlite.sqlite3, "connect", failed_connect)
    with pytest.raises(AuthorityError, match="transaction failed") as caught:
        store.append_audit_event(draft(None, "must-roll-back"))
    assert not isinstance(caught.value, AuthorityReconciliationRequiredError)

    monkeypatch.setattr(trusted_authority_sqlite.sqlite3, "connect", real_connect)
    with real_connect(database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM authority_audit_events"
        ).fetchone()[0] == 0
    store.append_audit_event(draft(None, "safe-retry"))
    assert [event.event_id for event in store.audit_events()] == ["safe-retry"]


@pytest.mark.parametrize("state_failure", ("after_commit", "after_rollback"))
def test_unverifiable_transaction_state_requires_authority_reconciliation(
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_failure: str,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    real_connect = sqlite3.connect

    class UnverifiableStateConnection(sqlite3.Connection):
        fail_state_inspection = False

        @property
        def in_transaction(self) -> bool:
            if self.fail_state_inspection:
                raise sqlite3.OperationalError(
                    "simulated transaction state inspection failure"
                )
            return super().in_transaction

        def commit(self) -> None:
            if state_failure == "after_commit":
                super().commit()
                self.fail_state_inspection = True
                raise sqlite3.OperationalError("simulated post-commit exception")
            raise sqlite3.OperationalError("simulated pre-commit failure")

        def rollback(self) -> None:
            super().rollback()
            if state_failure == "after_rollback":
                self.fail_state_inspection = True

    def unverifiable_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = UnverifiableStateConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(
        trusted_authority_sqlite.sqlite3,
        "connect",
        unverifiable_connect,
    )
    with pytest.raises(AuthorityCommitOutcomeUnknownError) as caught:
        store.append_audit_event(draft(None, f"state-{state_failure}"))

    assert caught.value.committed is None
    assert caught.value.retryable is False
    assert caught.value.reconciliation_required is True

    monkeypatch.setattr(trusted_authority_sqlite.sqlite3, "connect", real_connect)
    connection = real_connect(database_path)
    try:
        count = connection.execute(
            "SELECT count(*) FROM authority_audit_events"
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == (1 if state_failure == "after_commit" else 0)


def test_process_coordination_blocks_a_second_store_while_connection_is_live(
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = SQLiteApprovalChallengeStore(database_path)
    second = SQLiteApprovalChallengeStore(database_path)
    connection_live = Event()
    release_connection = Event()
    second_started = Event()
    second_finished = Event()
    failures: list[BaseException] = []
    observable = _ObservableMutex()
    monkeypatch.setattr(
        sqlite_process_lifecycle._PROCESS_SQLITE_LIFECYCLE,
        "_mutex",
        observable,
    )

    def hold_connection() -> None:
        try:
            with first._read_connection():
                connection_live.set()
                if not release_connection.wait(5):
                    raise TimeoutError("authority connection release was not signalled")
        except BaseException as exc:
            failures.append(exc)

    def open_second_store() -> None:
        try:
            if not connection_live.wait(5):
                raise TimeoutError("authority connection did not become live")
            second_started.set()
            second.audit_events()
        except BaseException as exc:
            failures.append(exc)
        finally:
            second_finished.set()

    holder = Thread(target=hold_connection)
    contender = Thread(target=open_second_store)
    holder.start()
    contender.start()
    try:
        assert second_started.wait(5)
        assert observable.blocked.wait(5)
        assert not second_finished.is_set()
    finally:
        release_connection.set()
        holder.join(5)
        contender.join(5)

    assert not holder.is_alive()
    assert not contender.is_alive()
    assert failures == []
    assert second_finished.is_set()


def test_same_thread_file_checks_fail_before_open_during_live_connection(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    real_open = os.open
    nested_attempt = False
    nested_descriptor_opens = 0

    def observe_open(
        path: str | bytes | os.PathLike[str], flags: int, *args: object
    ) -> int:
        nonlocal nested_descriptor_opens
        if nested_attempt:
            nested_descriptor_opens += 1
        return real_open(path, flags, *args)

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", observe_open)
    with store._transaction():
        nested_attempt = True
        try:
            with pytest.raises(AuthorityError, match="process lifecycle is unsafe"):
                store._verify_sidecars()
            with pytest.raises(AuthorityError, match="process lifecycle is unsafe"):
                store._secure_database_file()
        finally:
            nested_attempt = False

    assert nested_descriptor_opens == 0
    assert store.audit_events() == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar race contract")
def test_sidecar_disappearance_during_verification_is_safe_sqlite_cleanup(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"closing SQLite sidecar")
    sidecar.chmod(0o600)
    real_open = os.open

    def disappear(path: str | bytes | os.PathLike[str], flags: int, *args: object) -> int:
        if Path(path) == sidecar:
            sidecar.unlink()
            raise FileNotFoundError(str(sidecar))
        return real_open(path, flags, *args)

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", disappear)

    store._verify_sidecars()


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar race contract")
def test_sidecar_reappearance_after_missing_open_is_reverified(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"original SQLite sidecar")
    sidecar.chmod(0o600)
    real_open = os.open
    replaced = False

    def replace(path: str | bytes | os.PathLike[str], flags: int, *args: object) -> int:
        nonlocal replaced
        if Path(path) == sidecar and not replaced:
            replaced = True
            sidecar.unlink()
            sidecar.write_bytes(b"replacement SQLite sidecar")
            sidecar.chmod(0o600)
            raise FileNotFoundError(str(sidecar))
        return real_open(path, flags, *args)

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", replace)

    store._verify_sidecars()
    assert replaced is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar race contract")
def test_valid_sidecar_path_replacement_after_open_is_reverified(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"original SQLite sidecar")
    sidecar.chmod(0o600)
    real_open = os.open
    replaced = False

    def replace_after_open(
        candidate: str | bytes | os.PathLike[str], flags: int, *args: object
    ) -> int:
        nonlocal replaced
        descriptor = real_open(candidate, flags, *args)
        if Path(candidate) == sidecar and not replaced:
            replaced = True
            sidecar.unlink()
            sidecar.write_bytes(b"replacement SQLite sidecar")
            sidecar.chmod(0o600)
        return descriptor

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", replace_after_open)

    store._verify_sidecars()
    assert replaced is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar race contract")
def test_continuously_replaced_sidecar_fails_closed(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"unstable SQLite sidecar")
    sidecar.chmod(0o600)
    real_open = os.open

    def keep_replacing(
        candidate: str | bytes | os.PathLike[str], flags: int, *args: object
    ) -> int:
        descriptor = real_open(candidate, flags, *args)
        if Path(candidate) == sidecar:
            sidecar.unlink()
            sidecar.write_bytes(b"another unstable SQLite sidecar")
            sidecar.chmod(0o600)
        return descriptor

    monkeypatch.setattr(trusted_authority_sqlite.os, "open", keep_replacing)

    with pytest.raises(AuthorityError, match="changed while checked"):
        store._verify_sidecars()


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar hard-link contract")
def test_sidecar_hardlink_is_rejected(
    database_path: Path, tmp_path: Path
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"hardlinked SQLite sidecar")
    sidecar.chmod(0o600)
    alias = tmp_path / "sidecar-alias"
    try:
        os.link(sidecar, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(AuthorityError, match="sidecar is not private"):
        store._verify_sidecars()


@pytest.mark.skipif(os.name != "posix", reason="POSIX sidecar permission contract")
def test_sidecar_permission_change_between_fstat_and_lstat_fails_closed(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    sidecar = Path(f"{database_path}-shm")
    sidecar.write_bytes(b"permission-raced SQLite sidecar")
    sidecar.chmod(0o600)
    real_lstat = Path.lstat
    changed = False

    def make_public(candidate: Path):
        nonlocal changed
        if candidate == sidecar and not changed:
            candidate.chmod(0o644)
            changed = True
        return real_lstat(candidate)

    monkeypatch.setattr(trusted_authority_sqlite.Path, "lstat", make_public)

    with pytest.raises(AuthorityError, match="sidecar is not private"):
        store._verify_sidecars()


@pytest.mark.skipif(os.name != "posix", reason="POSIX O_NOFOLLOW contract")
def test_sidecar_verification_requires_o_nofollow(
    database_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    monkeypatch.delattr(trusted_authority_sqlite.os, "O_NOFOLLOW")

    with pytest.raises(AuthorityError, match="O_NOFOLLOW"):
        store._verify_sidecars()


def test_audit_is_canonical_monotonic_append_only_and_hash_verified(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    first = store.append_audit_event(draft(None, "event-1"))
    second = store.append_audit_event(
        draft(None, "event-2", occurred_at=NOW + timedelta(microseconds=1))
    )
    assert second.previous_hash == first.event_hash
    assert store.verify_audit_chain() is True

    with pytest.raises(AuthorityError, match="time moved backwards"):
        store.append_audit_event(
            draft(None, "backdated", occurred_at=NOW - timedelta(seconds=1))
        )
    noncanonical = replace(
        draft(None, "noncanonical", occurred_at=NOW + timedelta(seconds=1)),
        payload_json='{ "state": "pending" }',
    )
    with pytest.raises(AuthorityError, match="not canonical"):
        store.append_audit_event(noncanonical)
    assert len(store.audit_events()) == 2

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE authority_audit_events SET event_type='tampered' WHERE sequence=1"
            )


def test_tampered_hash_chain_is_rejected_before_another_append(
    database_path: Path,
) -> None:
    store = SQLiteApprovalChallengeStore(database_path)
    store.append_audit_event(draft(None, "event-1"))
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER authority_audit_events_no_update")
        connection.execute(
            "UPDATE authority_audit_events SET event_hash=? WHERE sequence=1",
            (hashlib.sha256(b"tampered").hexdigest(),),
        )
        connection.commit()

    with pytest.raises(AuthorityError, match="hash chain"):
        store.verify_audit_chain()
    with pytest.raises(AuthorityError, match="hash chain"):
        store.append_audit_event(
            draft(None, "event-2", occurred_at=NOW + timedelta(seconds=1))
        )
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM authority_audit_events"
        ).fetchone()[0] == 1


def test_rejects_unsupported_schema_version(database_path: Path) -> None:
    SQLiteApprovalChallengeStore(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER authority_schema_meta_no_update")
        connection.execute(
            "UPDATE authority_schema_meta SET value='999' WHERE key='schema_version'"
        )
        connection.commit()

    with pytest.raises(AuthorityError, match="schema version"):
        SQLiteApprovalChallengeStore(database_path)
