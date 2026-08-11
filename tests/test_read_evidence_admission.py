from __future__ import annotations

import errno
import hashlib
import inspect
import json
import multiprocessing
import os
import queue
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - exercised by the Windows test matrix
    fcntl = None  # type: ignore[assignment]

from odoo_accounting_cli_v3 import (
    read_evidence_admission as admission_module,
    sqlite_process_lifecycle,
)
from odoo_accounting_cli_v3.read_evidence_admission import (
    ACTIVE_ADMISSION_SCHEMA,
    ADMISSION_ARTIFACT_SIGNATURE_PATH,
    ADMISSION_INDEX_PATH,
    ADMISSION_INDEX_SIGNATURE_PATH,
    ADMISSION_PAYLOAD_SCHEMA,
    DEFAULT_READ_EVIDENCE_ADMISSION_PATH,
    READ_EVIDENCE_ADMISSION_SCHEMA_VERSION,
    AdmissionState,
    ReadEvidenceAdmissionCommitOutcomeUnknown,
    ReadEvidenceAdmissionConflict,
    ReadEvidenceAdmissionError,
    ReadEvidenceAdmissionRequest,
    SQLiteReadEvidenceAdmissionStore,
)


NOW = datetime(2026, 8, 3, 8, 9, 10, tzinfo=timezone.utc)


def _release_identity() -> dict[str, str]:
    return {
        "commit": "1" * 40,
        "manifest_sha256": "2" * 64,
        "package_sha256": "3" * 64,
        "registry_digest": "4" * 64,
        "release": "0.1.0.dev263-test",
    }


def _request(**changes: object) -> ReadEvidenceAdmissionRequest:
    values: dict[str, object] = {
        "release_identity": _release_identity(),
        "index_path": ADMISSION_INDEX_PATH,
        "index_sha256": "5" * 64,
        "index_size": 4_096,
        "index_signature_path": ADMISSION_INDEX_SIGNATURE_PATH,
        "index_signature_sha256": "6" * 64,
        "index_signature_size": 256,
        "closure_tree_sha256": "a" * 64,
        "closure_file_count": 37,
        "closure_total_bytes": 123_456,
        "scope_sha256": "b" * 64,
        "authorization_id": "authz-dev263-0001",
        "authorization_sha256": "7" * 64,
        "nonce_sha256": "8" * 64,
        "run_id": "run-dev263-0001",
        "authorization_not_before": NOW - timedelta(minutes=1),
        "authorization_expires_at": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    return ReadEvidenceAdmissionRequest(**values)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _fixed_system_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admission_module, "_system_utc_now", lambda: NOW)


def _store(tmp_path: Path) -> SQLiteReadEvidenceAdmissionStore:
    return SQLiteReadEvidenceAdmissionStore(
        (tmp_path / "private" / "admission.sqlite3").resolve()
    )


def _bootstrap_path(tmp_path: Path, name: str) -> Path:
    parent = tmp_path / name
    parent.mkdir(mode=0o700)
    if os.name == "posix":
        os.chmod(parent, 0o700)
    return (parent / "admission.sqlite3").resolve()


def _create_zero_byte_bootstrap(path: Path) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_initialized_schema(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        objects = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT type, name FROM sqlite_master ORDER BY type, name"
            )
        }
        assert ("table", "read_evidence_admission_schema_meta") in objects
        assert ("table", "read_evidence_admissions") in objects
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]


def _mark_published(
    store: SQLiteReadEvidenceAdmissionStore,
    payload_sha256: str,
    *,
    signature_sha256: str = "d" * 64,
):
    return store.mark_published(
        authorization_id=_request().authorization_id,
        payload_sha256=payload_sha256,
        admission_signature_path=ADMISSION_ARTIFACT_SIGNATURE_PATH,
        admission_signature_sha256=signature_sha256,
        admission_signature_size=512,
    )


def test_public_api_has_no_private_key_or_caller_clock() -> None:
    init_parameters = inspect.signature(SQLiteReadEvidenceAdmissionStore).parameters
    consume_parameters = inspect.signature(
        SQLiteReadEvidenceAdmissionStore.consume
    ).parameters
    publish_parameters = inspect.signature(
        SQLiteReadEvidenceAdmissionStore.mark_published
    ).parameters
    lookup_parameters = inspect.signature(
        SQLiteReadEvidenceAdmissionStore.require_published
    ).parameters

    for parameters in (
        init_parameters,
        consume_parameters,
        publish_parameters,
        lookup_parameters,
    ):
        assert "private_key" not in parameters
        assert "now" not in parameters
        assert "clock" not in parameters

    assert DEFAULT_READ_EVIDENCE_ADMISSION_PATH == Path(
        "/var/lib/odoo-accounting-cli-v3/read-evidence-v3/admissions.sqlite3"
    )


def test_consume_commits_canonical_fixed_payload_before_return(tmp_path: Path) -> None:
    store = _store(tmp_path)
    request = _request()

    decision = store.consume(request)

    assert decision.state is AdmissionState.CONSUMED
    assert decision.recovered is False
    assert decision.payload == {
        "admitted_at": "2026-08-03T08:09:10Z",
        "authorization_id": request.authorization_id,
        "authorization_sha256": request.authorization_sha256,
        "closure_file_count": request.closure_file_count,
        "closure_total_bytes": request.closure_total_bytes,
        "closure_tree_sha256": request.closure_tree_sha256,
        "index_path": request.index_path,
        "index_sha256": request.index_sha256,
        "index_signature_path": request.index_signature_path,
        "index_signature_sha256": request.index_signature_sha256,
        "index_signature_size": request.index_signature_size,
        "index_size": request.index_size,
        "nonce_sha256": request.nonce_sha256,
        "release_identity": _release_identity(),
        "run_id": request.run_id,
        "schema_version": ADMISSION_PAYLOAD_SCHEMA,
        "sequence": 1,
        "scope_sha256": request.scope_sha256,
    }
    assert decision.payload_json == json.dumps(
        decision.payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ) + "\n"
    assert ADMISSION_PAYLOAD_SCHEMA == ACTIVE_ADMISSION_SCHEMA
    assert ACTIVE_ADMISSION_SCHEMA.endswith("active-admission.v3")
    assert decision.payload_sha256 == hashlib.sha256(
        decision.payload_json.encode("utf-8")
    ).hexdigest()

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT state, payload_json, payload_sha256 FROM read_evidence_admissions"
        ).fetchone()
    assert row == (
        "consumed",
        decision.payload_json,
        decision.payload_sha256,
    )


def test_exact_retry_recovers_only_the_original_fixed_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.consume(_request())

    recovered = store.consume(_request())

    assert recovered.recovered is True
    assert recovered.state is AdmissionState.CONSUMED
    assert recovered.payload_json == first.payload_json
    assert recovered.payload_sha256 == first.payload_sha256
    assert recovered.sequence == first.sequence


def test_crash_after_commit_recovers_fixed_payload_without_reconsumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    original_hook = admission_module._after_consume_commit
    calls = 0

    def crash_once() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt("simulated process crash")
        original_hook()

    monkeypatch.setattr(admission_module, "_after_consume_commit", crash_once)
    with pytest.raises(KeyboardInterrupt, match="simulated process crash"):
        store.consume(_request())

    recovered = store.consume(_request())
    assert recovered.recovered is True
    assert recovered.sequence == 1
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 1


def test_same_authorization_cannot_recover_with_changed_index(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = store.consume(_request())

    with pytest.raises(ReadEvidenceAdmissionConflict, match="conflicts"):
        store.consume(_request(index_sha256="a" * 64))

    recovered = store.consume(_request())
    assert recovered.payload_sha256 == original.payload_sha256


@pytest.mark.parametrize(
    "duplicate_field",
    ["authorization_id", "nonce_sha256", "run_id", "index_sha256"],
)
def test_each_replay_binding_is_independently_unique(
    tmp_path: Path, duplicate_field: str
) -> None:
    store = _store(tmp_path)
    original = _request()
    store.consume(original)
    second_values: dict[str, object] = {
        "authorization_id": "authz-dev263-0002",
        "authorization_sha256": "9" * 64,
        "nonce_sha256": "a" * 64,
        "run_id": "run-dev263-0002",
        "index_path": ADMISSION_INDEX_PATH,
        "index_sha256": "c" * 64,
        "index_signature_path": ADMISSION_INDEX_SIGNATURE_PATH,
        "index_signature_sha256": "d" * 64,
        "closure_tree_sha256": "e" * 64,
        "scope_sha256": "f" * 64,
    }
    second_values[duplicate_field] = getattr(original, duplicate_field)

    with pytest.raises(ReadEvidenceAdmissionConflict, match=duplicate_field):
        store.consume(_request(**second_values))


def test_concurrent_exact_requests_have_one_consumption_and_fixed_recoveries(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        decisions = list(executor.map(lambda _item: store.consume(_request()), range(8)))

    assert sum(not decision.recovered for decision in decisions) == 1
    assert len({decision.payload_sha256 for decision in decisions}) == 1
    assert {decision.sequence for decision in decisions} == {1}
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX rollback sidecar race")
def test_writer_accepts_journal_deleted_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    journal = Path(f"{store.path}-journal")
    journal.write_bytes(b"")
    os.chmod(journal, 0o600)
    real_open = admission_module.os.open
    deleted = False

    def delete_before_open(path: object, flags: int, *args: object) -> int:
        nonlocal deleted
        if Path(path) == journal and not deleted:
            deleted = True
            journal.unlink()
        return real_open(path, flags, *args)

    monkeypatch.setattr(admission_module.os, "open", delete_before_open)
    metadata = store.path.stat()

    with store._database_lifecycle() as lease:
        assert store._secure_database_file(lease=lease) == (
            metadata.st_dev,
            metadata.st_ino,
        )
    assert deleted is True
    assert not journal.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX rollback sidecar race")
def test_writer_rejects_journal_replacement_after_disappearing_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    journal = Path(f"{store.path}-journal")
    replacement = store.path.parent / "replacement-journal"
    journal.write_bytes(b"")
    replacement.write_bytes(b"replacement")
    os.chmod(journal, 0o600)
    os.chmod(replacement, 0o600)
    real_open = admission_module.os.open
    replaced = False

    def replace_before_open(path: object, flags: int, *args: object) -> int:
        nonlocal replaced
        if Path(path) == journal and not replaced:
            replaced = True
            journal.unlink()
            journal.symlink_to(replacement)
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                str(journal),
            )
        return real_open(path, flags, *args)

    monkeypatch.setattr(admission_module.os, "open", replace_before_open)

    with pytest.raises(ReadEvidenceAdmissionError, match="journal changed"):
        with store._database_lifecycle() as lease:
            store._secure_database_file(lease=lease)
    assert replaced is True
    assert journal.is_symlink()


def test_direct_fd_check_is_rejected_in_connection_phase_without_poisoning(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    metadata = store.path.stat()

    with pytest.raises(ReadEvidenceAdmissionError, match="lifecycle"):
        with store._database_lifecycle() as lease:
            with lease.connection_phase():
                store._verify_sidecars(
                    expected_identity=(metadata.st_dev, metadata.st_ino),
                    lease=lease,
                )

    decision = store.consume(_request())
    assert decision.recovered is False
    assert decision.sequence == 1


def test_unconfirmed_database_descriptor_close_poisons_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_close = admission_module.os.close
    for label, close_error in (
        ("os-error", OSError("simulated unconfirmed database descriptor close")),
        ("keyboard-interrupt", KeyboardInterrupt()),
    ):
        gate = sqlite_process_lifecycle._ProcessSQLiteLifecycle()
        monkeypatch.setattr(
            sqlite_process_lifecycle,
            "_PROCESS_SQLITE_LIFECYCLE",
            gate,
        )
        case_root = tmp_path / label
        case_root.mkdir()
        store = _store(case_root)
        database = store.path.stat()
        leaked: list[int] = []

        def fail_database_close(descriptor: int) -> None:
            opened = os.fstat(descriptor)
            if not leaked and (opened.st_dev, opened.st_ino) == (
                database.st_dev,
                database.st_ino,
            ):
                leaked.append(descriptor)
                raise close_error
            real_close(descriptor)

        monkeypatch.setattr(admission_module.os, "close", fail_database_close)
        try:
            if isinstance(close_error, OSError):
                with pytest.raises(ReadEvidenceAdmissionError, match="descriptor close"):
                    store.consume(_request())
            else:
                with pytest.raises(KeyboardInterrupt):
                    store.consume(_request())
            assert leaked
            assert gate.poisoned is True
            monkeypatch.setattr(admission_module.os, "close", real_close)
            with pytest.raises(
                ReadEvidenceAdmissionError, match="lifecycle is unavailable"
            ):
                store.consume(_request())
        finally:
            monkeypatch.setattr(admission_module.os, "close", real_close)
            for descriptor in leaked:
                real_close(descriptor)


def test_concurrent_preflight_waits_for_active_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    real_commit = admission_module._commit_connection
    real_secure = store._secure_database_file
    commit_entered = threading.Event()
    release_commit = threading.Event()
    contender_started = threading.Event()
    contender_preflight = threading.Event()
    contender_thread_id: list[int] = []

    def blocking_first_commit(connection: sqlite3.Connection) -> None:
        if not commit_entered.is_set():
            commit_entered.set()
            if not release_commit.wait(timeout=5):
                raise AssertionError("timed out waiting to release the first commit")
        real_commit(connection)

    def recording_secure(*args: object, **kwargs: object) -> tuple[int, int]:
        if contender_thread_id and threading.get_ident() == contender_thread_id[0]:
            contender_preflight.set()
        return real_secure(*args, **kwargs)

    def consume_as_contender():
        contender_thread_id.append(threading.get_ident())
        contender_started.set()
        return store.consume(_request())

    monkeypatch.setattr(admission_module, "_commit_connection", blocking_first_commit)
    monkeypatch.setattr(store, "_secure_database_file", recording_secure)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(store.consume, _request())
        assert commit_entered.wait(timeout=5)
        second = executor.submit(consume_as_contender)
        assert contender_started.wait(timeout=5)
        try:
            assert not contender_preflight.wait(timeout=0.25)
        finally:
            release_commit.set()
        decisions = [first.result(timeout=5), second.result(timeout=5)]

    assert sum(not decision.recovered for decision in decisions) == 1
    assert len({decision.payload_sha256 for decision in decisions}) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX process concurrency contract")
def test_concurrent_exact_requests_are_atomic_across_processes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    start = store.path.parent / "process-start"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    not_before = (now - timedelta(minutes=1)).isoformat()
    expires_at = (now + timedelta(minutes=5)).isoformat()
    child = r"""
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from odoo_accounting_cli_v3.read_evidence_admission import (
    ADMISSION_INDEX_PATH,
    ADMISSION_INDEX_SIGNATURE_PATH,
    ReadEvidenceAdmissionRequest,
    SQLiteReadEvidenceAdmissionStore,
)

path = Path(sys.argv[1])
ready = Path(sys.argv[2])
start = Path(sys.argv[3])
store = SQLiteReadEvidenceAdmissionStore.open_existing(path)
ready.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 15
while not start.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("process start barrier timed out")
    time.sleep(0.005)
request = ReadEvidenceAdmissionRequest(
    release_identity={
        "commit": "1" * 40,
        "manifest_sha256": "2" * 64,
        "package_sha256": "3" * 64,
        "registry_digest": "4" * 64,
        "release": "0.1.0.dev263-test",
    },
    index_path=ADMISSION_INDEX_PATH,
    index_sha256="5" * 64,
    index_size=4096,
    index_signature_path=ADMISSION_INDEX_SIGNATURE_PATH,
    index_signature_sha256="6" * 64,
    index_signature_size=256,
    closure_tree_sha256="a" * 64,
    closure_file_count=37,
    closure_total_bytes=123456,
    scope_sha256="b" * 64,
    authorization_id="authz-dev263-0001",
    authorization_sha256="7" * 64,
    nonce_sha256="8" * 64,
    run_id="run-dev263-0001",
    authorization_not_before=datetime.fromisoformat(sys.argv[4]),
    authorization_expires_at=datetime.fromisoformat(sys.argv[5]),
)
decision = store.consume(request)
print(json.dumps({
    "payload_sha256": decision.payload_sha256,
    "recovered": decision.recovered,
    "sequence": decision.sequence,
}, sort_keys=True))
"""
    environment = os.environ.copy()
    source_root = str(Path(admission_module.__file__).resolve().parents[1])
    environment["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (source_root, environment.get("PYTHONPATH", ""))
        if part
    )
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                child,
                str(store.path),
                str(store.path.parent / f"process-ready-{index}"),
                str(start),
                not_before,
                expires_at,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(8)
    ]
    results: list[dict[str, object]] = []
    try:
        ready_paths = [
            store.path.parent / f"process-ready-{index}" for index in range(8)
        ]
        deadline = time.monotonic() + 15
        while not all(path.exists() for path in ready_paths):
            statuses = [process.poll() for process in processes]
            assert all(status is None for status in statuses), (
                f"admission child exited before barrier: {statuses}"
            )
            assert time.monotonic() < deadline, "admission children missed barrier"
            time.sleep(0.005)
        start.write_text("start", encoding="utf-8")
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            results.append(json.loads(stdout))
    finally:
        start.touch(exist_ok=True)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    assert sum(not result["recovered"] for result in results) == 1
    assert len({result["payload_sha256"] for result in results}) == 1
    assert {result["sequence"] for result in results} == {1}


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX writer lock contract",
)
def test_distinct_process_writers_wait_through_post_close_confirmation(
    tmp_path: Path,
) -> None:
    assert fcntl is not None
    store = _store(tmp_path)
    release_first = store.path.parent / "release-first"
    first_after_close = store.path.parent / "first-after-close"
    second_started = store.path.parent / "second-started"
    second_entered_database = store.path.parent / "second-entered-database"
    child = r"""
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from odoo_accounting_cli_v3.read_evidence_admission import (
    ADMISSION_INDEX_PATH,
    ADMISSION_INDEX_SIGNATURE_PATH,
    ReadEvidenceAdmissionRequest,
    SQLiteReadEvidenceAdmissionStore,
)

path = Path(sys.argv[1])
role = sys.argv[2]
first_after_close = Path(sys.argv[3])
release_first = Path(sys.argv[4])
second_started = Path(sys.argv[5])
second_entered_database = Path(sys.argv[6])
if role == "second":
    second_started.write_text("started", encoding="utf-8")
store = SQLiteReadEvidenceAdmissionStore.open_existing(path, busy_timeout_ms=10000)

if role == "first":
    real_fsync_database = store._fsync_database

    def wait_after_close(*args, **kwargs):
        first_after_close.write_text("ready", encoding="utf-8")
        deadline = time.monotonic() + 20
        while not release_first.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("first writer release barrier timed out")
            time.sleep(0.005)
        return real_fsync_database(*args, **kwargs)

    store._fsync_database = wait_after_close
    values = {
        "authorization_id": "authz-dev266-distinct-1",
        "authorization_sha256": "7" * 64,
        "nonce_sha256": "8" * 64,
        "run_id": "run-dev266-distinct-1",
        "index_sha256": "5" * 64,
        "index_signature_sha256": "6" * 64,
        "closure_tree_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
    }
else:
    real_secure_database = store._secure_database_file

    def record_database_entry(*args, **kwargs):
        second_entered_database.write_text("entered", encoding="utf-8")
        return real_secure_database(*args, **kwargs)

    store._secure_database_file = record_database_entry
    values = {
        "authorization_id": "authz-dev266-distinct-2",
        "authorization_sha256": "9" * 64,
        "nonce_sha256": "0" * 64,
        "run_id": "run-dev266-distinct-2",
        "index_sha256": "c" * 64,
        "index_signature_sha256": "d" * 64,
        "closure_tree_sha256": "e" * 64,
        "scope_sha256": "f" * 64,
    }
now = datetime.now(timezone.utc).replace(microsecond=0)
decision = store.consume(ReadEvidenceAdmissionRequest(
    release_identity={
        "commit": "1" * 40,
        "manifest_sha256": "2" * 64,
        "package_sha256": "3" * 64,
        "registry_digest": "4" * 64,
        "release": "0.1.0.dev266-test",
    },
    index_path=ADMISSION_INDEX_PATH,
    index_sha256=values["index_sha256"],
    index_size=4096,
    index_signature_path=ADMISSION_INDEX_SIGNATURE_PATH,
    index_signature_sha256=values["index_signature_sha256"],
    index_signature_size=256,
    closure_tree_sha256=values["closure_tree_sha256"],
    closure_file_count=37,
    closure_total_bytes=123456,
    scope_sha256=values["scope_sha256"],
    authorization_id=values["authorization_id"],
    authorization_sha256=values["authorization_sha256"],
    nonce_sha256=values["nonce_sha256"],
    run_id=values["run_id"],
    authorization_not_before=now - timedelta(minutes=1),
    authorization_expires_at=now + timedelta(minutes=5),
))
print(json.dumps({
    "authorization_id": values["authorization_id"],
    "recovered": decision.recovered,
    "sequence": decision.sequence,
}, sort_keys=True))
"""
    environment = os.environ.copy()
    source_root = str(Path(admission_module.__file__).resolve().parents[1])
    environment["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (source_root, environment.get("PYTHONPATH", ""))
        if part
    )

    def start_child(role: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                sys.executable,
                "-c",
                child,
                str(store.path),
                role,
                str(first_after_close),
                str(release_first),
                str(second_started),
                str(second_entered_database),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_for(path: Path, processes: tuple[subprocess.Popen[str], ...]) -> None:
        deadline = time.monotonic() + 15
        while not path.exists():
            assert all(process.poll() is None for process in processes)
            assert time.monotonic() < deadline, f"barrier timed out: {path.name}"
            time.sleep(0.005)

    first = start_child("first")
    second: subprocess.Popen[str] | None = None
    outputs: list[dict[str, object]] = []
    try:
        wait_for(first_after_close, (first,))
        lock_descriptor = os.open(
            store._writer_lock_path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
        )
        try:
            with pytest.raises(BlockingIOError) as caught:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert caught.value.errno in (errno.EACCES, errno.EAGAIN)
        finally:
            os.close(lock_descriptor)

        second = start_child("second")
        wait_for(second_started, (first, second))
        time.sleep(0.25)
        assert second.poll() is None
        assert not second_entered_database.exists()

        release_first.write_text("release", encoding="utf-8")
        for process in (first, second):
            stdout, stderr = process.communicate(timeout=30)
            assert process.returncode == 0, stderr
            outputs.append(json.loads(stdout))
    finally:
        release_first.touch(exist_ok=True)
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    assert {output["sequence"] for output in outputs} == {1, 2}
    assert {output["recovered"] for output in outputs} == {False}
    assert {output["authorization_id"] for output in outputs} == {
        "authz-dev266-distinct-1",
        "authz-dev266-distinct-2",
    }
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT sequence, authorization_id FROM read_evidence_admissions "
            "ORDER BY sequence"
        ).fetchall() == [
            (1, "authz-dev266-distinct-1"),
            (2, "authz-dev266-distinct-2"),
        ]


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX writer lock contract",
)
def test_writer_lock_is_persistent_private_bounded_and_rejects_unsafe_files(
    tmp_path: Path,
) -> None:
    assert fcntl is not None
    store = _store(tmp_path)
    lock_path = store._writer_lock_path
    metadata = lock_path.lstat()
    original_identity = (metadata.st_dev, metadata.st_ino)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid == os.geteuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1

    store.consume(_request())
    assert (lock_path.stat().st_dev, lock_path.stat().st_ino) == original_identity

    contender = SQLiteReadEvidenceAdmissionStore.open_existing(
        store.path, busy_timeout_ms=250
    )
    held = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    timed_request = _request(
        authorization_id="authz-dev266-lock-timeout",
        authorization_sha256="9" * 64,
        nonce_sha256="0" * 64,
        run_id="run-dev266-lock-timeout",
        index_sha256="c" * 64,
        index_signature_sha256="d" * 64,
        closure_tree_sha256="e" * 64,
        scope_sha256="f" * 64,
    )
    started = time.monotonic()
    try:
        with pytest.raises(ReadEvidenceAdmissionError, match="lock deadline"):
            contender.consume(timed_request)
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)
    assert time.monotonic() - started < 2
    assert contender.consume(timed_request).sequence == 2

    cases: list[tuple[str, str]] = []
    wrong_mode_parent = tmp_path / "wrong-mode-lock"
    wrong_mode_parent.mkdir(mode=0o700)
    wrong_mode_lock = wrong_mode_parent / "admission.sqlite3.writer.lock"
    wrong_mode_lock.write_bytes(b"")
    wrong_mode_lock.chmod(0o640)
    cases.append(("wrong-mode-lock", "invalid"))

    symlink_parent = tmp_path / "symlink-lock"
    symlink_parent.mkdir(mode=0o700)
    symlink_target = symlink_parent / "target"
    symlink_target.write_bytes(b"")
    symlink_target.chmod(0o600)
    (symlink_parent / "admission.sqlite3.writer.lock").symlink_to(symlink_target)
    cases.append(("symlink-lock", "cannot be secured"))

    hardlink_parent = tmp_path / "hardlink-lock"
    hardlink_parent.mkdir(mode=0o700)
    hardlink_target = hardlink_parent / "target"
    hardlink_target.write_bytes(b"")
    hardlink_target.chmod(0o600)
    os.link(hardlink_target, hardlink_parent / "admission.sqlite3.writer.lock")
    cases.append(("hardlink-lock", "invalid"))

    fifo_parent = tmp_path / "fifo-lock"
    fifo_parent.mkdir(mode=0o700)
    os.mkfifo(fifo_parent / "admission.sqlite3.writer.lock", mode=0o600)
    cases.append(("fifo-lock", "invalid"))

    for parent_name, message in cases:
        path = (tmp_path / parent_name / "admission.sqlite3").resolve()
        with pytest.raises(ReadEvidenceAdmissionError, match=message):
            SQLiteReadEvidenceAdmissionStore(path)


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX writer lock contract",
)
def test_published_reader_waits_for_post_close_confirmation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    context = multiprocessing.get_context("fork")
    writer_paused = context.Event()
    release_writer = context.Event()
    reader_started = context.Event()
    results = context.Queue()

    def publish_then_fail_confirmation() -> None:
        child_store = SQLiteReadEvidenceAdmissionStore.open_existing(store.path)

        def fail_after_release(*args: object, **kwargs: object) -> None:
            del args, kwargs
            writer_paused.set()
            if not release_writer.wait(timeout=20):
                raise RuntimeError("writer release barrier timed out")
            raise OSError("simulated post-close confirmation failure")

        child_store._fsync_database = fail_after_release  # type: ignore[method-assign]
        try:
            _mark_published(child_store, consumed.payload_sha256)
        except ReadEvidenceAdmissionCommitOutcomeUnknown:
            results.put(("writer", "outcome-unknown"))
        else:  # pragma: no cover - the injected confirmation failure is mandatory
            results.put(("writer", "unexpected-success"))

    def verify_published() -> None:
        reader_started.set()
        child_store = SQLiteReadEvidenceAdmissionStore.open_existing(store.path)
        published = child_store.require_published(
            authorization_id=_request().authorization_id,
            payload_sha256=consumed.payload_sha256,
            sequence=consumed.sequence,
            admission_signature_sha256="d" * 64,
        )
        results.put(("reader", published.state.value))

    writer = context.Process(target=publish_then_fail_confirmation)
    reader: multiprocessing.Process | None = None
    writer.start()
    try:
        assert writer_paused.wait(timeout=15)
        reader = context.Process(target=verify_published)
        reader.start()
        assert reader_started.wait(timeout=15)
        with pytest.raises(queue.Empty):
            results.get(timeout=0.25)
        assert writer.is_alive()
        assert reader.is_alive()

        release_writer.set()
        outcomes = {results.get(timeout=20), results.get(timeout=20)}
        writer.join(timeout=20)
        reader.join(timeout=20)
    finally:
        release_writer.set()
        for process in (writer, reader):
            if process is not None and process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert writer.exitcode == 0
    assert reader is not None and reader.exitcode == 0
    assert outcomes == {
        ("writer", "outcome-unknown"),
        ("reader", AdmissionState.PUBLISHED.value),
    }


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX writer lock contract",
)
def test_writer_lock_release_failure_returns_unknown_and_exact_retry_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert fcntl is not None
    store = _store(tmp_path)
    real_flock = fcntl.flock
    release_errors: list[BaseException] = []
    failed_descriptors: list[int] = []

    def fail_first_release(descriptor: int, operation: int) -> object:
        if operation == fcntl.LOCK_UN and release_errors:
            failed_descriptors.append(descriptor)
            raise release_errors.pop(0)
        return real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_first_release)
    release_errors.append(OSError(errno.EIO, "simulated writer lock release failure"))
    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown):
        store.consume(_request())

    assert not release_errors
    with pytest.raises(OSError) as closed:
        os.fstat(failed_descriptors[-1])
    assert closed.value.errno == errno.EBADF
    recovered = store.consume(_request())
    assert recovered.sequence == 1
    assert recovered.recovered is True

    release_errors.append(KeyboardInterrupt())
    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown):
        store.consume(_request())
    assert not release_errors
    with pytest.raises(OSError) as closed:
        os.fstat(failed_descriptors[-1])
    assert closed.value.errno == errno.EBADF
    recovered = store.consume(_request())
    assert recovered.sequence == 1
    assert recovered.recovered is True

    published = _mark_published(store, recovered.payload_sha256)
    release_errors.append(KeyboardInterrupt())
    with pytest.raises(ReadEvidenceAdmissionError, match="read lock release"):
        store.require_published(
            authorization_id=_request().authorization_id,
            payload_sha256=published.payload_sha256,
            sequence=published.sequence,
            admission_signature_sha256="d" * 64,
        )
    assert not release_errors
    with pytest.raises(OSError) as closed:
        os.fstat(failed_descriptors[-1])
    assert closed.value.errno == errno.EBADF
    assert (
        store.require_published(
            authorization_id=_request().authorization_id,
            payload_sha256=published.payload_sha256,
            sequence=published.sequence,
            admission_signature_sha256="d" * 64,
        ).state
        is AdmissionState.PUBLISHED
    )
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 1


def test_writer_reuses_remaining_deadline_for_sqlite_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteReadEvidenceAdmissionStore(
        (tmp_path / "private" / "admission.sqlite3").resolve(),
        busy_timeout_ms=250,
    )
    now = {"value": 100.0}
    observed_connect_timeouts: list[float] = []
    deadline_events: list[tuple[str, int | None]] = []
    deadline_mode: dict[str, int | bool | None] = {
        "expire_after_busy_timeout": None,
        "advance_at_begin": True,
    }
    real_acquire = store._acquire_writer_lock
    real_connect = admission_module.sqlite3.connect

    def consume_lock_budget(*args: object, **kwargs: object):
        lock = real_acquire(*args, **kwargs)
        now["value"] = 100.1
        return lock

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        observed_connect_timeouts.append(float(kwargs["timeout"]))
        connection = real_connect(*args, **kwargs)
        busy_timeout_count = 0

        def record(statement: str) -> None:
            nonlocal busy_timeout_count
            normalized = statement.strip().upper()
            prefix = "PRAGMA BUSY_TIMEOUT = "
            if normalized.startswith(prefix):
                busy_timeout_count += 1
                deadline_events.append(
                    ("busy-timeout", int(normalized.removeprefix(prefix)))
                )
                if (
                    deadline_mode["expire_after_busy_timeout"]
                    == busy_timeout_count
                ):
                    now["value"] = 100.251
            elif normalized == "BEGIN IMMEDIATE":
                deadline_events.append(("begin", None))
                if deadline_mode["advance_at_begin"]:
                    now["value"] = 100.2495
            elif normalized == "COMMIT":
                deadline_events.append(("commit", None))

        connection.set_trace_callback(record)
        return connection

    monkeypatch.setattr(
        admission_module,
        "bounded_sqlite_operation_deadline",
        lambda _configured_ms: 100.25,
    )
    monkeypatch.setattr(admission_module.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(store, "_acquire_writer_lock", consume_lock_budget)
    monkeypatch.setattr(admission_module.sqlite3, "connect", recording_connect)

    assert store.consume(_request()).sequence == 1
    assert observed_connect_timeouts == [pytest.approx(0.15)]
    assert deadline_events == [
        ("busy-timeout", 150),
        ("busy-timeout", 150),
        ("begin", None),
        ("busy-timeout", 0),
        ("commit", None),
    ]

    deadline_events.clear()
    deadline_mode.update(expire_after_busy_timeout=2, advance_at_begin=False)
    now["value"] = 100.0
    with pytest.raises(ReadEvidenceAdmissionError, match="deadline was exceeded"):
        store.consume(_request())
    assert deadline_events == [
        ("busy-timeout", 150),
        ("busy-timeout", 150),
    ]

    deadline_events.clear()
    deadline_mode.update(expire_after_busy_timeout=3, advance_at_begin=False)
    now["value"] = 100.0
    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown) as caught:
        store.consume(_request())
    assert isinstance(caught.value.__cause__, ReadEvidenceAdmissionError)
    assert "deadline was exceeded" in str(caught.value.__cause__)
    assert deadline_events == [
        ("busy-timeout", 150),
        ("busy-timeout", 150),
        ("begin", None),
        ("busy-timeout", 150),
    ]


def test_concurrent_collision_allows_only_one_new_admission(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _request()
    second = _request(
        authorization_id="authz-dev263-0002",
        authorization_sha256="9" * 64,
        run_id="run-dev263-0002",
        index_path=ADMISSION_INDEX_PATH,
        index_sha256="c" * 64,
        index_signature_path=ADMISSION_INDEX_SIGNATURE_PATH,
        index_signature_sha256="d" * 64,
        closure_tree_sha256="e" * 64,
        scope_sha256="f" * 64,
        # The shared nonce is the deliberate cross-request collision.
        nonce_sha256=first.nonce_sha256,
    )

    def attempt(request: ReadEvidenceAdmissionRequest) -> str:
        try:
            store.consume(request)
        except ReadEvidenceAdmissionConflict:
            return "conflict"
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, (first, second)))

    assert sorted(outcomes) == ["conflict", "consumed"]


def test_committed_sequences_are_monotonic_and_never_reused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.consume(_request())
    second = store.consume(
        _request(
            authorization_id="authz-dev263-0002",
            authorization_sha256="9" * 64,
            nonce_sha256="a" * 64,
            run_id="run-dev263-0002",
            index_path=ADMISSION_INDEX_PATH,
            index_sha256="c" * 64,
            index_signature_path=ADMISSION_INDEX_SIGNATURE_PATH,
            index_signature_sha256="d" * 64,
            closure_tree_sha256="e" * 64,
            scope_sha256="f" * 64,
        )
    )

    assert (first.sequence, second.sequence) == (1, 2)


def test_mark_published_is_one_way_and_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())

    published = _mark_published(store, consumed.payload_sha256)
    repeated = _mark_published(store, consumed.payload_sha256)

    assert published.state is AdmissionState.PUBLISHED
    assert published.recovered is False
    assert repeated.state is AdmissionState.PUBLISHED
    assert repeated.recovered is True
    assert published.payload_json == consumed.payload_json == repeated.payload_json
    assert published.admission_signature_path == ADMISSION_ARTIFACT_SIGNATURE_PATH
    assert published.admission_signature_sha256 == "d" * 64
    assert published.admission_signature_size == 512
    assert published.published_at == NOW
    with pytest.raises(ReadEvidenceAdmissionConflict, match="payload_sha256"):
        store.mark_published(
            authorization_id=_request().authorization_id,
            payload_sha256="f" * 64,
            admission_signature_path=ADMISSION_ARTIFACT_SIGNATURE_PATH,
            admission_signature_sha256="d" * 64,
            admission_signature_size=512,
        )
    with pytest.raises(ReadEvidenceAdmissionConflict, match="signature"):
        store.mark_published(
            authorization_id=_request().authorization_id,
            payload_sha256=consumed.payload_sha256,
            admission_signature_path=ADMISSION_ARTIFACT_SIGNATURE_PATH,
            admission_signature_sha256="e" * 64,
            admission_signature_size=512,
        )


def test_consumed_and_published_rows_are_immutable_and_not_deletable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="transition"):
            connection.execute(
                "UPDATE read_evidence_admissions SET index_sha256=?",
                ("a" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute("DELETE FROM read_evidence_admissions")

    _mark_published(store, consumed.payload_sha256)
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="transition"):
            connection.execute(
                "UPDATE read_evidence_admissions SET state='consumed', published_at=NULL"
            )


def test_require_published_is_exact_read_only_and_rejects_consumed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())

    with pytest.raises(ReadEvidenceAdmissionError, match="not published"):
        store.require_published(
            authorization_id=_request().authorization_id,
            payload_sha256=consumed.payload_sha256,
            sequence=consumed.sequence,
            admission_signature_sha256="d" * 64,
        )

    _mark_published(store, consumed.payload_sha256)
    reopened = SQLiteReadEvidenceAdmissionStore.open_existing(store.path)
    published = reopened.require_published(
        authorization_id=_request().authorization_id,
        payload_sha256=consumed.payload_sha256,
        sequence=consumed.sequence,
        admission_signature_sha256="d" * 64,
    )

    assert published.state is AdmissionState.PUBLISHED
    assert published.recovered is True
    assert published.payload_sha256 == consumed.payload_sha256
    assert published.admission_signature_path == ADMISSION_ARTIFACT_SIGNATURE_PATH
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT state FROM read_evidence_admissions WHERE sequence=1"
        ).fetchone()[0] == "published"


def test_existing_lookup_uses_mode_ro_query_only_without_file_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    _mark_published(store, consumed.payload_sha256)
    tracked_paths = (
        store.path.parent,
        store.path,
        store._writer_lock_path,
        Path(f"{store.path}-journal"),
        Path(f"{store.path}-wal"),
        Path(f"{store.path}-shm"),
    )

    def snapshot() -> dict[str, tuple[int, int, int] | None]:
        return {
            str(path): (
                (path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ino)
                if path.exists()
                else None
            )
            for path in tracked_paths
        }

    before = snapshot()
    real_connect = admission_module.sqlite3.connect
    targets: list[tuple[object, dict[str, object]]] = []
    statements: list[str] = []

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        targets.append((args[0], dict(kwargs)))
        connection = real_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(admission_module.sqlite3, "connect", recording_connect)
    reopened = SQLiteReadEvidenceAdmissionStore.open_existing(store.path)
    published = reopened.require_published(
        authorization_id=_request().authorization_id,
        payload_sha256=consumed.payload_sha256,
        sequence=consumed.sequence,
        admission_signature_sha256="d" * 64,
    )
    assert published.state is AdmissionState.PUBLISHED
    after = snapshot()

    assert targets
    assert all(
        isinstance(target, str)
        and target.startswith("file:")
        and target.endswith("?mode=ro")
        and options.get("uri") is True
        for target, options in targets
    )
    normalized = [statement.strip().upper() for statement in statements]
    assert "PRAGMA QUERY_ONLY = ON" in normalized
    assert "BEGIN" in normalized
    assert "BEGIN IMMEDIATE" not in normalized
    assert not any(statement.startswith("PRAGMA JOURNAL_MODE =") for statement in normalized)
    assert after == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX read-only file contract")
def test_require_published_accepts_private_read_only_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    _mark_published(store, consumed.payload_sha256)
    os.chmod(store.path, 0o400)
    real_open = admission_module.os.open
    database_open_flags: list[int] = []

    def recording_open(path: object, flags: int, *args: object) -> int:
        if Path(path) == store.path:
            database_open_flags.append(flags)
        return real_open(path, flags, *args)

    try:
        monkeypatch.setattr(admission_module.os, "open", recording_open)
        reopened = SQLiteReadEvidenceAdmissionStore.open_existing(store.path)
        published = reopened.require_published(
            authorization_id=_request().authorization_id,
            payload_sha256=consumed.payload_sha256,
            sequence=consumed.sequence,
            admission_signature_sha256="d" * 64,
        )
        assert published.state is AdmissionState.PUBLISHED
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o400
        assert database_open_flags
        assert all(flags & os.O_RDWR == 0 for flags in database_open_flags)
    finally:
        os.chmod(store.path, 0o600)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_id", "authz-dev263-wrong"),
        ("payload_sha256", "e" * 64),
        ("sequence", 2),
        ("admission_signature_sha256", "e" * 64),
    ],
)
def test_require_published_rejects_every_binding_mismatch(
    tmp_path: Path, field: str, value: object
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    _mark_published(store, consumed.payload_sha256)
    arguments: dict[str, object] = {
        "authorization_id": _request().authorization_id,
        "payload_sha256": consumed.payload_sha256,
        "sequence": consumed.sequence,
        "admission_signature_sha256": "d" * 64,
    }
    arguments[field] = value

    with pytest.raises(ReadEvidenceAdmissionError):
        store.require_published(**arguments)  # type: ignore[arg-type]


def test_open_existing_never_creates_a_missing_or_empty_ledger(tmp_path: Path) -> None:
    missing = (tmp_path / "missing" / "admissions.sqlite3").absolute()
    with pytest.raises(ReadEvidenceAdmissionError, match="does not exist"):
        SQLiteReadEvidenceAdmissionStore.open_existing(missing)
    assert not missing.parent.exists()

    empty_parent = tmp_path / "empty"
    empty_parent.mkdir(mode=0o700)
    empty = empty_parent / "admissions.sqlite3"
    empty.touch(mode=0o600)
    with pytest.raises(ReadEvidenceAdmissionError, match="schema|writer lock"):
        SQLiteReadEvidenceAdmissionStore.open_existing(empty.absolute())
    assert empty.stat().st_size == 0
    assert not Path(f"{empty}.writer.lock").exists()

    if os.name == "posix":
        created = SQLiteReadEvidenceAdmissionStore(
            (tmp_path / "created" / "admissions.sqlite3").resolve()
        )
        copied_parent = tmp_path / "valid-without-lock"
        copied_parent.mkdir(mode=0o700)
        copied = (copied_parent / "admissions.sqlite3").resolve()
        copied.write_bytes(created.path.read_bytes())
        copied.chmod(0o600)
        with pytest.raises(ReadEvidenceAdmissionError, match="writer lock"):
            SQLiteReadEvidenceAdmissionStore.open_existing(copied)
        assert not Path(f"{copied}.writer.lock").exists()


def test_hot_rollback_journal_is_read_only_fail_closed_then_writer_recovers(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    _mark_published(store, consumed.payload_sha256)
    child = r"""
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA journal_mode = DELETE")
connection.execute("PRAGMA synchronous = FULL")
connection.execute("PRAGMA cache_size = 1")
connection.execute("PRAGMA cache_spill = ON")
connection.execute("BEGIN IMMEDIATE")
connection.execute("CREATE TABLE crash_probe(id INTEGER PRIMARY KEY, body TEXT)")
connection.executemany(
    "INSERT INTO crash_probe(id, body) VALUES(?, ?)",
    ((number, "x" * 2048) for number in range(1, 1025)),
)
os._exit(0)
"""
    subprocess.run(
        [sys.executable, "-c", child, str(store.path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    journal = Path(f"{store.path}-journal")
    assert journal.is_file()
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8] == bytes.fromhex("d9d505f920a163d7")

    tracked_paths = (store.path.parent, store.path, journal)

    def snapshot() -> dict[str, tuple[int, int, int]]:
        return {
            str(path): (
                path.stat().st_size,
                path.stat().st_mtime_ns,
                path.stat().st_ino,
            )
            for path in tracked_paths
        }

    before = snapshot()
    with pytest.raises(ReadEvidenceAdmissionError, match="writer recovery"):
        SQLiteReadEvidenceAdmissionStore.open_existing(store.path)
    assert snapshot() == before

    recovered_store = SQLiteReadEvidenceAdmissionStore(store.path)
    assert not journal.exists()
    recovered = recovered_store.require_published(
        authorization_id=_request().authorization_id,
        payload_sha256=consumed.payload_sha256,
        sequence=consumed.sequence,
        admission_signature_sha256="d" * 64,
    )
    assert recovered.state is AdmissionState.PUBLISHED
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='crash_probe'"
        ).fetchone() is None


def test_mark_published_rejects_clock_before_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    monkeypatch.setattr(
        admission_module,
        "_system_utc_now",
        lambda: NOW - timedelta(seconds=1),
    )

    with pytest.raises(ReadEvidenceAdmissionError, match="before admitted_at"):
        _mark_published(store, consumed.payload_sha256)

    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT state FROM read_evidence_admissions"
        ).fetchone()[0] == "consumed"


@pytest.mark.parametrize(
    "publication_time",
    [
        NOW + timedelta(minutes=5),
        NOW + timedelta(minutes=5, microseconds=1),
        NOW + timedelta(days=30),
    ],
)
def test_first_publication_at_or_after_expiry_is_rejected_without_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication_time: datetime,
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    monkeypatch.setattr(
        admission_module,
        "_system_utc_now",
        lambda: publication_time,
    )

    with pytest.raises(ReadEvidenceAdmissionError, match="expired for publication"):
        _mark_published(store, consumed.payload_sha256)

    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT state, published_at FROM read_evidence_admissions"
        ).fetchone() == ("consumed", None)


def test_expired_exact_retry_recovers_an_already_published_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    published = _mark_published(store, consumed.payload_sha256)
    monkeypatch.setattr(
        admission_module,
        "_system_utc_now",
        lambda: NOW + timedelta(days=30),
    )

    recovered = _mark_published(store, consumed.payload_sha256)

    assert recovered.recovered is True
    assert recovered.state is AdmissionState.PUBLISHED
    assert recovered.payload_sha256 == published.payload_sha256
    assert recovered.published_at == published.published_at == NOW


def test_schema_version_is_exact_and_immutable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT value FROM read_evidence_admission_schema_meta "
            "WHERE key='schema_version'"
        ).fetchone()[0] == str(READ_EVIDENCE_ADMISSION_SCHEMA_VERSION)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE read_evidence_admission_schema_meta SET value='999'"
            )


def test_unknown_or_tampered_schema_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER read_evidence_admissions_no_delete")

    with pytest.raises(ReadEvidenceAdmissionError, match="schema"):
        SQLiteReadEvidenceAdmissionStore(store.path)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_delete_journal_store_rejects_legacy_wal_sidecars(
    tmp_path: Path, suffix: str
) -> None:
    store = _store(tmp_path)
    Path(f"{store.path}{suffix}").write_bytes(b"legacy sidecar")

    with pytest.raises(ReadEvidenceAdmissionError, match="legacy WAL sidecar"):
        SQLiteReadEvidenceAdmissionStore.open_existing(store.path)


def test_inactive_authorization_window_is_rejected_without_consuming(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with pytest.raises(ReadEvidenceAdmissionError, match="not active"):
        store.consume(_request(authorization_not_before=NOW + timedelta(seconds=1)))
    with pytest.raises(ReadEvidenceAdmissionError, match="expired"):
        store.consume(_request(authorization_expires_at=NOW))

    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 0


def test_authorization_window_is_inclusive_at_not_before(tmp_path: Path) -> None:
    store = _store(tmp_path)

    consumed = store.consume(_request(authorization_not_before=NOW))

    assert consumed.state is AdmissionState.CONSUMED
    assert consumed.payload["admitted_at"] == "2026-08-03T08:09:10Z"


def test_existing_consumption_can_be_recovered_after_auth_window_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    first = store.consume(_request())
    monkeypatch.setattr(
        admission_module,
        "_system_utc_now",
        lambda: NOW + timedelta(hours=1),
    )

    recovered = store.consume(_request())

    assert recovered.recovered is True
    assert recovered.payload_sha256 == first.payload_sha256


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_id", "bad id with spaces"),
        ("run_id", ""),
        ("index_sha256", "A" * 64),
        ("closure_tree_sha256", "0" * 63),
        ("authorization_sha256", "not-a-digest"),
        ("nonce_sha256", "f" * 65),
        ("scope_sha256", "f" * 63),
        ("index_path", "/var/lib/evidence/index.json"),
        ("index_signature_path", "index.json.sig"),
        ("index_size", True),
        ("index_signature_size", 0),
        ("closure_file_count", 0),
        ("closure_total_bytes", -1),
        ("authorization_not_before", datetime(2026, 8, 3, 8, 0, 0)),
    ],
)
def test_request_contract_rejects_noncanonical_values(
    field: str, value: object
) -> None:
    with pytest.raises(ReadEvidenceAdmissionError):
        _request(**{field: value})


def test_request_copies_release_identity_and_rejects_extra_fields() -> None:
    mutable = _release_identity()
    request = _request(release_identity=mutable)
    mutable["release"] = "tampered"
    assert request.release_identity["release"] == "0.1.0.dev263-test"

    extra = _release_identity()
    extra["unexpected"] = "value"
    with pytest.raises(ReadEvidenceAdmissionError, match="release identity"):
        _request(release_identity=extra)


def test_commit_failure_returns_no_signable_payload(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    real_commit = admission_module._commit_connection

    def fail_commit(_connection: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("simulated durable commit failure")

    monkeypatch.setattr(admission_module, "_commit_connection", fail_commit)
    with pytest.raises(ReadEvidenceAdmissionError, match="commit outcome"):
        store.consume(_request())
    monkeypatch.setattr(admission_module, "_commit_connection", real_commit)

    decision = store.consume(_request())
    assert decision.recovered is False
    assert decision.sequence == 1


def test_unknown_commit_outcome_survives_connection_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    gate = sqlite_process_lifecycle._ProcessSQLiteLifecycle()
    monkeypatch.setattr(
        sqlite_process_lifecycle,
        "_PROCESS_SQLITE_LIFECYCLE",
        gate,
    )
    real_connect = admission_module.sqlite3.connect
    real_commit = admission_module._commit_connection
    connections: list[sqlite3.Connection] = []

    class CloseFailingConnection(sqlite3.Connection):
        def close(self) -> None:
            raise sqlite3.OperationalError("simulated connection close failure")

    def close_failing_connect(
        *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        kwargs["factory"] = CloseFailingConnection
        connection = real_connect(*args, **kwargs)  # type: ignore[arg-type]
        connections.append(connection)
        return connection

    def commit_then_raise(connection: sqlite3.Connection) -> None:
        real_commit(connection)
        raise sqlite3.OperationalError("simulated lost commit acknowledgement")

    monkeypatch.setattr(admission_module.sqlite3, "connect", close_failing_connect)
    monkeypatch.setattr(admission_module, "_commit_connection", commit_then_raise)
    try:
        with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown) as caught:
            store.consume(_request())

        assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
        assert "lost commit acknowledgement" in str(caught.value.__cause__)
        assert any(
            "connection close also failed: simulated connection close failure" in note
            for note in getattr(caught.value, "__notes__", ())
        )
        assert gate.poisoned is True
        monkeypatch.setattr(admission_module.sqlite3, "connect", real_connect)
        monkeypatch.setattr(admission_module, "_commit_connection", real_commit)
        with pytest.raises(ReadEvidenceAdmissionError, match="lifecycle is unavailable"):
            store.consume(_request())
    finally:
        monkeypatch.setattr(admission_module.sqlite3, "connect", real_connect)
        monkeypatch.setattr(admission_module, "_commit_connection", real_commit)
        for connection in connections:
            sqlite3.Connection.close(connection)


def test_missing_sqlite_serialize_rejects_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    real_connect = admission_module.sqlite3.connect

    class NoSerializeConnection(sqlite3.Connection):
        serialize = None

    def connect_without_serialize(
        *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        kwargs["factory"] = NoSerializeConnection
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        admission_module.sqlite3,
        "connect",
        connect_without_serialize,
    )

    with pytest.raises(ReadEvidenceAdmissionError, match="serialization"):
        store.consume(_request())

    with real_connect(store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    ("failure_method", "failure_message"),
    [
        ("_verify_database_file", "simulated post-close verification failure"),
        ("_fsync_database", "simulated post-close fsync failure"),
    ],
)
def test_unknown_commit_outcome_survives_post_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_method: str,
    failure_message: str,
) -> None:
    store = _store(tmp_path)
    real_commit = admission_module._commit_connection

    def commit_then_raise(connection: sqlite3.Connection) -> None:
        real_commit(connection)
        raise sqlite3.OperationalError("simulated lost commit acknowledgement")

    def fail_post_close(*_args: object, **_kwargs: object) -> None:
        raise OSError(failure_message)

    monkeypatch.setattr(admission_module, "_commit_connection", commit_then_raise)
    monkeypatch.setattr(store, failure_method, fail_post_close)

    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown) as caught:
        store.consume(_request())

    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert "lost commit acknowledgement" in str(caught.value.__cause__)
    assert any(
        f"post-close durability verification also failed: {failure_message}" in note
        for note in getattr(caught.value, "__notes__", ())
    )


def test_post_commit_durability_failure_returns_no_payload_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    original_fsync = store._fsync_database
    calls = 0

    def fail_once(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated fsync confirmation failure")
        original_fsync(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "_fsync_database", fail_once)
    with pytest.raises(ReadEvidenceAdmissionError, match="committed"):
        store.consume(_request())

    recovered = store.consume(_request())
    assert recovered.recovered is True
    assert recovered.sequence == 1


def test_post_close_path_swap_before_fsync_returns_no_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    committed_path = store.path.with_name("committed-admissions.sqlite3")
    original_fstat = os.fstat
    original_lstat = Path.lstat
    original_open = os.open
    original_verify = store._verify_database_file
    durable_metadata: object | None = None
    replacement_descriptors: set[int] = set()
    swapped = False

    def verify_then_swap(*args: object, **kwargs: object) -> None:
        nonlocal durable_metadata, swapped
        original_verify(*args, **kwargs)  # type: ignore[arg-type]
        if not swapped:
            durable_metadata = original_lstat(store.path)
            swapped = True
            os.replace(store.path, committed_path)
            _create_zero_byte_bootstrap(store.path)
            os.truncate(store.path, durable_metadata.st_size)

    def reused_identity_lstat(path: Path) -> object:
        metadata = original_lstat(path)
        if swapped and path == store.path:
            assert durable_metadata is not None
            return SimpleNamespace(
                st_mode=durable_metadata.st_mode,
                st_dev=durable_metadata.st_dev,
                st_ino=durable_metadata.st_ino,
                st_nlink=durable_metadata.st_nlink,
                st_uid=durable_metadata.st_uid,
                st_gid=durable_metadata.st_gid,
                st_size=durable_metadata.st_size,
                st_mtime_ns=durable_metadata.st_mtime_ns,
                st_ctime_ns=durable_metadata.st_ctime_ns,
            )
        return metadata

    def track_replacement_open(
        path: object, flags: int, mode: int = 0o777
    ) -> int:
        descriptor = original_open(path, flags, mode)
        if swapped and Path(path) == store.path:
            replacement_descriptors.add(descriptor)
        return descriptor

    def reused_identity_fstat(descriptor: int) -> object:
        metadata = original_fstat(descriptor)
        if descriptor in replacement_descriptors:
            assert durable_metadata is not None
            return SimpleNamespace(
                st_mode=durable_metadata.st_mode,
                st_dev=durable_metadata.st_dev,
                st_ino=durable_metadata.st_ino,
                st_nlink=durable_metadata.st_nlink,
                st_uid=durable_metadata.st_uid,
                st_gid=durable_metadata.st_gid,
                st_size=durable_metadata.st_size,
                st_mtime_ns=durable_metadata.st_mtime_ns,
                st_ctime_ns=durable_metadata.st_ctime_ns,
            )
        return metadata

    monkeypatch.setattr(store, "_verify_database_file", verify_then_swap)
    monkeypatch.setattr(os, "fstat", reused_identity_fstat)
    monkeypatch.setattr(os, "open", track_replacement_open)
    monkeypatch.setattr(Path, "lstat", reused_identity_lstat)

    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown) as caught:
        store.consume(_request())

    assert swapped is True
    assert durable_metadata is not None
    assert isinstance(caught.value.__cause__, ReadEvidenceAdmissionError)
    assert "content changed" in str(caught.value.__cause__)
    assert store.path.stat().st_size == durable_metadata.st_size
    with sqlite3.connect(committed_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 1


def test_durability_close_rejects_reused_inode_with_changed_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    committed_path = store.path.with_name("committed-reused-inode.sqlite3")
    original_close = store._close_descriptor
    original_fstat = os.fstat
    original_lstat = Path.lstat
    original_open = os.open
    durable_metadata: object | None = None
    replacement_descriptors: set[int] = set()
    swapped = False

    def close_then_replace(
        descriptor: int,
        lease: object,
        *,
        label: str,
    ) -> None:
        nonlocal durable_metadata, swapped
        if label == "read evidence admission durability database":
            durable_metadata = os.fstat(descriptor)
        original_close(descriptor, lease, label=label)  # type: ignore[arg-type]
        if label == "read evidence admission durability database" and not swapped:
            assert durable_metadata is not None
            os.replace(store.path, committed_path)
            _create_zero_byte_bootstrap(store.path)
            os.truncate(store.path, durable_metadata.st_size)
            swapped = True

    def reused_identity_lstat(path: Path) -> object:
        metadata = original_lstat(path)
        if swapped and path == store.path:
            assert durable_metadata is not None
            return SimpleNamespace(
                st_mode=durable_metadata.st_mode,
                st_dev=durable_metadata.st_dev,
                st_ino=durable_metadata.st_ino,
                st_nlink=durable_metadata.st_nlink,
                st_uid=durable_metadata.st_uid,
                st_gid=durable_metadata.st_gid,
                st_size=durable_metadata.st_size,
                st_mtime_ns=durable_metadata.st_mtime_ns,
                st_ctime_ns=durable_metadata.st_ctime_ns,
            )
        return metadata

    def track_replacement_open(
        path: object, flags: int, mode: int = 0o777
    ) -> int:
        descriptor = original_open(path, flags, mode)
        if swapped and Path(path) == store.path:
            replacement_descriptors.add(descriptor)
        return descriptor

    def reused_identity_fstat(descriptor: int) -> object:
        metadata = original_fstat(descriptor)
        if descriptor in replacement_descriptors:
            assert durable_metadata is not None
            return SimpleNamespace(
                st_mode=durable_metadata.st_mode,
                st_dev=durable_metadata.st_dev,
                st_ino=durable_metadata.st_ino,
                st_nlink=durable_metadata.st_nlink,
                st_uid=durable_metadata.st_uid,
                st_gid=durable_metadata.st_gid,
                st_size=durable_metadata.st_size,
                st_mtime_ns=durable_metadata.st_mtime_ns,
                st_ctime_ns=durable_metadata.st_ctime_ns,
            )
        return metadata

    monkeypatch.setattr(store, "_close_descriptor", close_then_replace)
    monkeypatch.setattr(os, "fstat", reused_identity_fstat)
    monkeypatch.setattr(os, "open", track_replacement_open)
    monkeypatch.setattr(Path, "lstat", reused_identity_lstat)

    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown) as caught:
        store.consume(_request())

    assert swapped is True
    assert durable_metadata is not None
    assert isinstance(caught.value.__cause__, ReadEvidenceAdmissionError)
    assert "content changed" in str(caught.value.__cause__)
    assert store.path.stat().st_size == durable_metadata.st_size
    with sqlite3.connect(committed_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM read_evidence_admissions"
        ).fetchone()[0] == 1


def test_published_commit_confirmation_failure_recovers_exactly_after_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    consumed = store.consume(_request())
    original_fsync = store._fsync_database
    calls = 0

    def fail_once(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated publication fsync confirmation failure")
        original_fsync(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "_fsync_database", fail_once)
    with pytest.raises(ReadEvidenceAdmissionError, match="committed"):
        _mark_published(store, consumed.payload_sha256)

    monkeypatch.setattr(
        admission_module,
        "_system_utc_now",
        lambda: NOW + timedelta(days=30),
    )
    recovered = _mark_published(store, consumed.payload_sha256)

    assert recovered.state is AdmissionState.PUBLISHED
    assert recovered.recovered is True
    assert recovered.published_at == NOW


def test_mutations_use_begin_immediate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statements: list[str] = []
    real_connect = admission_module.sqlite3.connect

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(admission_module.sqlite3, "connect", recording_connect)
    store = _store(tmp_path)
    store.consume(_request())

    assert any(statement.strip().upper() == "BEGIN IMMEDIATE" for statement in statements)


def test_store_creates_private_parent_database_with_full_delete_journaling(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.consume(_request())

    assert store.path.parent.is_dir()
    assert store.path.is_file()
    assert not Path(f"{store.path}-journal").exists()
    assert store.path.read_bytes()[18:20] == b"\x01\x01"
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
    if os.name == "posix":
        assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        assert store.path.stat().st_uid == os.geteuid()


def test_writer_recovers_exclusive_zero_byte_bootstrap_in_place(
    tmp_path: Path,
) -> None:
    path = _bootstrap_path(tmp_path, "exclusive-crash")
    _create_zero_byte_bootstrap(path)
    before = path.stat()

    store = SQLiteReadEvidenceAdmissionStore(path)

    after = path.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert store.path == path
    assert path.stat().st_size > 0
    _assert_initialized_schema(path)


def test_writer_recovers_valid_empty_sqlite_bootstrap_in_place(
    tmp_path: Path,
) -> None:
    path = _bootstrap_path(tmp_path, "sqlite-header-crash")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 0")
    if os.name == "posix":
        os.chmod(path, 0o600)
    assert path.stat().st_size > 20
    before = path.stat()

    SQLiteReadEvidenceAdmissionStore(path)

    after = path.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    _assert_initialized_schema(path)


def test_writer_recovers_real_hot_journal_from_bootstrap_schema_crash(
    tmp_path: Path,
) -> None:
    path = _bootstrap_path(tmp_path, "hot-bootstrap-crash")
    child = r"""
import os
import sqlite3
import sys

from odoo_accounting_cli_v3 import read_evidence_admission as admission

def crash_before_commit(connection):
    connection.execute("PRAGMA cache_size = 1")
    connection.execute("PRAGMA cache_spill = ON")
    connection.execute(
        "CREATE TABLE bootstrap_crash_probe(id INTEGER PRIMARY KEY, body TEXT)"
    )
    connection.executemany(
        "INSERT INTO bootstrap_crash_probe(id, body) VALUES(?, ?)",
        ((number, "x" * 2048) for number in range(1, 1025)),
    )
    os._exit(73)

admission._commit_connection = crash_before_commit
admission.SQLiteReadEvidenceAdmissionStore(sys.argv[1])
"""
    crashed = subprocess.run(
        [sys.executable, "-c", child, str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert crashed.returncode == 73
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8] == bytes.fromhex("d9d505f920a163d7")
    before = {
        item: (item.stat().st_size, item.stat().st_mtime_ns, item.stat().st_ino)
        for item in (path.parent, path, journal)
    }

    with pytest.raises(ReadEvidenceAdmissionError, match="writer recovery"):
        SQLiteReadEvidenceAdmissionStore.open_existing(path)
    assert {
        item: (item.stat().st_size, item.stat().st_mtime_ns, item.stat().st_ino)
        for item in (path.parent, path, journal)
    } == before

    original_inode = path.stat().st_ino
    recovered = SQLiteReadEvidenceAdmissionStore(path)

    assert path.stat().st_ino == original_inode
    assert not journal.exists()
    _assert_initialized_schema(recovered.path)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='bootstrap_crash_probe'"
        ).fetchone() is None


def test_read_only_rejects_interrupted_bootstrap_without_side_effects(
    tmp_path: Path,
) -> None:
    paths = [
        _bootstrap_path(tmp_path, "read-zero"),
        _bootstrap_path(tmp_path, "read-header"),
    ]
    _create_zero_byte_bootstrap(paths[0])
    with sqlite3.connect(paths[1]) as connection:
        connection.execute("PRAGMA user_version = 0")
    if os.name == "posix":
        os.chmod(paths[1], 0o600)

    for path in paths:
        tracked = (
            path.parent,
            path,
            Path(f"{path}-journal"),
            Path(f"{path}-wal"),
            Path(f"{path}-shm"),
        )
        before = {
            item: (
                (item.stat().st_size, item.stat().st_mtime_ns, item.stat().st_ino)
                if item.exists()
                else None
            )
            for item in tracked
        }

        with pytest.raises(ReadEvidenceAdmissionError, match="schema|writer lock"):
            SQLiteReadEvidenceAdmissionStore.open_existing(path)

        after = {
            item: (
                (item.stat().st_size, item.stat().st_mtime_ns, item.stat().st_ino)
                if item.exists()
                else None
            )
            for item in tracked
        }
        assert after == before


def test_writer_does_not_recover_unknown_objects_or_metadata(
    tmp_path: Path,
) -> None:
    cases = {
        "partial": (
            "CREATE TABLE read_evidence_admission_schema_meta(key TEXT)",
        ),
        "view": ("CREATE VIEW unexpected_view AS SELECT 1 AS value",),
        "index-trigger": (
            "CREATE TABLE unexpected_table(id INTEGER PRIMARY KEY)",
            "CREATE INDEX unexpected_index ON unexpected_table(id)",
            "CREATE TRIGGER unexpected_trigger AFTER INSERT ON unexpected_table "
            "BEGIN SELECT 1; END",
        ),
        "user-version": ("PRAGMA user_version = 7",),
        "application-id": ("PRAGMA application_id = 7",),
        "residual-pages": (
            "CREATE TABLE removed_table(id INTEGER PRIMARY KEY)",
            "DROP TABLE removed_table",
        ),
    }
    for name, statements in cases.items():
        path = _bootstrap_path(tmp_path, f"unknown-{name}")
        with sqlite3.connect(path) as connection:
            for statement in statements:
                connection.execute(statement)
        if os.name == "posix":
            os.chmod(path, 0o600)
        before = (path.read_bytes(), path.stat().st_ino)

        with pytest.raises(ReadEvidenceAdmissionError, match="schema|bootstrap"):
            SQLiteReadEvidenceAdmissionStore(path)

        assert (path.read_bytes(), path.stat().st_ino) == before


def test_writer_refuses_zero_byte_bootstrap_with_any_sidecar(
    tmp_path: Path,
) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        path = _bootstrap_path(tmp_path, f"sidecar-{suffix[1:]}")
        _create_zero_byte_bootstrap(path)
        sidecar = Path(f"{path}{suffix}")
        sidecar.write_bytes(b"")
        if os.name == "posix":
            os.chmod(sidecar, 0o600)
        before = (path.read_bytes(), sidecar.read_bytes(), path.stat().st_ino)

        with pytest.raises(ReadEvidenceAdmissionError, match="sidecar|bootstrap"):
            SQLiteReadEvidenceAdmissionStore(path)

        assert sidecar.exists()
        assert (path.read_bytes(), sidecar.read_bytes(), path.stat().st_ino) == before


def test_repeated_bootstrap_commit_failure_is_fail_closed_then_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _bootstrap_path(tmp_path, "repeated-commit-failure")
    real_commit = admission_module._commit_connection
    failures_remaining = 2

    def fail_twice(connection: sqlite3.Connection) -> None:
        nonlocal failures_remaining
        if failures_remaining:
            failures_remaining -= 1
            raise sqlite3.OperationalError("simulated bootstrap commit failure")
        real_commit(connection)

    monkeypatch.setattr(admission_module, "_commit_connection", fail_twice)
    for _ in range(2):
        with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown):
            SQLiteReadEvidenceAdmissionStore(path)
        with pytest.raises(ReadEvidenceAdmissionError, match="schema"):
            SQLiteReadEvidenceAdmissionStore.open_existing(path)

    store = SQLiteReadEvidenceAdmissionStore(path)
    _assert_initialized_schema(store.path)


def test_committed_bootstrap_with_unknown_outcome_requires_exact_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _bootstrap_path(tmp_path, "commit-then-raise")
    real_commit = admission_module._commit_connection
    raised = False

    def commit_then_raise(connection: sqlite3.Connection) -> None:
        nonlocal raised
        real_commit(connection)
        if not raised:
            raised = True
            raise sqlite3.OperationalError("simulated lost commit acknowledgement")

    monkeypatch.setattr(admission_module, "_commit_connection", commit_then_raise)
    with pytest.raises(ReadEvidenceAdmissionCommitOutcomeUnknown):
        SQLiteReadEvidenceAdmissionStore(path)

    recovered = SQLiteReadEvidenceAdmissionStore(path)
    _assert_initialized_schema(recovered.path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path security contract")
def test_store_rejects_group_writable_parent_and_database_hardlink(
    tmp_path: Path,
) -> None:
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o700)
    os.chmod(unsafe_parent, 0o770)
    with pytest.raises(ReadEvidenceAdmissionError, match="ancestor"):
        SQLiteReadEvidenceAdmissionStore((unsafe_parent / "ledger.sqlite3").resolve())

    store = _store(tmp_path)
    alias = store.path.with_name("ledger-alias.sqlite3")
    os.link(store.path, alias)
    with pytest.raises(ReadEvidenceAdmissionError, match="hard link"):
        SQLiteReadEvidenceAdmissionStore(store.path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX rollback sidecar contract")
def test_store_rejects_symlinked_or_hardlinked_rollback_journal(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    journal = Path(f"{store.path}-journal")
    target = store.path.parent / "untrusted-journal"
    target.write_bytes(b"not a SQLite journal")
    os.chmod(target, 0o600)
    try:
        journal.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable")
    with pytest.raises(ReadEvidenceAdmissionError):
        SQLiteReadEvidenceAdmissionStore(store.path)

    journal.unlink()
    os.link(target, journal)
    with pytest.raises(ReadEvidenceAdmissionError, match="sidecar"):
        SQLiteReadEvidenceAdmissionStore(store.path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ancestor security contract")
def test_store_rejects_unsafe_or_symlinked_ancestor(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe-ancestor"
    unsafe.mkdir(mode=0o700)
    os.chmod(unsafe, 0o777)
    unsafe_database = unsafe / "private" / "admissions.sqlite3"
    with pytest.raises(ReadEvidenceAdmissionError, match="ancestor"):
        SQLiteReadEvidenceAdmissionStore(unsafe_database.absolute())
    assert not unsafe_database.parent.exists()

    real = tmp_path / "real-ancestor"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked-ancestor"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    symlink_database = linked / "private" / "admissions.sqlite3"
    with pytest.raises(ReadEvidenceAdmissionError, match="ancestor"):
        SQLiteReadEvidenceAdmissionStore(symlink_database.absolute())
    assert not (real / "private").exists()


def test_relative_memory_and_symlink_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReadEvidenceAdmissionError, match="absolute"):
        SQLiteReadEvidenceAdmissionStore("ledger.sqlite3")
    with pytest.raises(ReadEvidenceAdmissionError, match="absolute"):
        SQLiteReadEvidenceAdmissionStore(":memory:")

    target = tmp_path / "target.sqlite3"
    target.touch()
    symlink = tmp_path / "ledger.sqlite3"
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ReadEvidenceAdmissionError, match="non-symlink"):
        SQLiteReadEvidenceAdmissionStore(symlink.absolute())
