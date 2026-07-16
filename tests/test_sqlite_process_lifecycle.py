from __future__ import annotations

import multiprocessing
import os
import select
import signal
import time
from contextlib import nullcontext
from pathlib import Path
from threading import Event, Lock, Thread

import pytest

from odoo_accounting_cli_v3 import (
    sqlite_process_lifecycle,
    trusted_session_sqlite,
)
from odoo_accounting_cli_v3.sqlite_process_lifecycle import (
    SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE,
    SQLiteProcessLifecycleError,
    process_sqlite_lifecycle,
)
from odoo_accounting_cli_v3.trusted_authority_sqlite import (
    SQLiteApprovalChallengeStore,
)
from odoo_accounting_cli_v3.trusted_session_sqlite import (
    SQLiteTrustedSessionStore,
)

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - POSIX lock behavior is tested on Linux CI
    fcntl = None  # type: ignore[assignment]


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
def _isolate_process_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> sqlite_process_lifecycle._ProcessSQLiteLifecycle:
    gate = sqlite_process_lifecycle._ProcessSQLiteLifecycle()
    monkeypatch.setattr(
        sqlite_process_lifecycle, "_PROCESS_SQLITE_LIFECYCLE", gate
    )
    return gate


def _probe_record_lock(path: str, results: object) -> None:
    assert fcntl is not None
    descriptor = os.open(path, os.O_RDWR)
    acquired = False
    try:
        try:
            fcntl.lockf(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
                1,
                0,
                os.SEEK_SET,
            )
        except BlockingIOError:
            acquired = False
        else:
            acquired = True
            fcntl.lockf(
                descriptor,
                fcntl.LOCK_UN,
                1,
                0,
                os.SEEK_SET,
            )
    finally:
        os.close(descriptor)
    results.put(acquired)


def _probe_flock(path: str, results: object) -> None:
    assert fcntl is not None
    descriptor = os.open(path, os.O_RDWR)
    acquired = False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            acquired = False
        else:
            acquired = True
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
    results.put(acquired)


def _other_process_can_take_flock(path: Path) -> bool:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(target=_probe_flock, args=(str(path), results))
    try:
        process.start()
        acquired = results.get(timeout=15)
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
        return acquired is True
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        results.close()
        results.join_thread()


def _other_process_can_take_lock(path: Path) -> bool:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_probe_record_lock,
        args=(str(path), results),
    )
    try:
        process.start()
        acquired = results.get(timeout=15)
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
        return acquired is True
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        results.close()
        results.join_thread()


def _read_pipe_with_deadline(descriptor: int, label: str) -> bytes:
    ready, _, _ = select.select([descriptor], [], [], 15)
    if not ready:
        raise TimeoutError(f"{label} did not arrive before the test deadline")
    return os.read(descriptor, 64)


def _wait_child_with_deadline(process_id: int, label: str) -> int:
    deadline = time.monotonic() + 15
    while True:
        waited_pid, status = os.waitpid(process_id, os.WNOHANG)
        if waited_pid == process_id:
            return status
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{label} did not exit before the test deadline")
        time.sleep(0.01)


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _terminate_and_reap_child(process_id: int) -> None:
    try:
        os.kill(process_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(process_id, 0)
    except ChildProcessError:
        pass


class _ReleaseParentTransaction(Exception):
    pass


def test_same_thread_nested_lifecycle_fails_fast() -> None:
    with process_sqlite_lifecycle(1):
        with pytest.raises(SQLiteProcessLifecycleError, match="nested"):
            with process_sqlite_lifecycle(0):
                raise AssertionError("unsafe nested lifecycle was admitted")


def test_unconfirmed_connection_close_poisons_process_gate() -> None:
    gate = sqlite_process_lifecycle._PROCESS_SQLITE_LIFECYCLE
    with process_sqlite_lifecycle(1) as lease:
        with lease.connection_phase() as phase:
            phase.connecting()
            phase.opened()

    assert gate.poisoned is True
    with pytest.raises(SQLiteProcessLifecycleError, match="poisoned"):
        with process_sqlite_lifecycle(0):
            raise AssertionError("poisoned lifecycle was admitted")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork contract")
def test_fork_child_cannot_resume_from_poisoned_process_gate() -> None:
    with process_sqlite_lifecycle(1) as lease:
        with lease.connection_phase() as phase:
            phase.connecting()
            phase.opened()

    read_descriptor, write_descriptor = os.pipe()
    process_id: int | None = None
    try:
        process_id = os.fork()
        if process_id == 0:  # pragma: no cover - asserted by parent
            os.close(read_descriptor)
            try:
                os.write(write_descriptor, b"resumed")
            finally:
                os.close(write_descriptor)
                os._exit(99)

        os.close(write_descriptor)
        resumed = _read_pipe_with_deadline(
            read_descriptor, "poisoned fork child resume probe"
        )
        os.close(read_descriptor)
        status = _wait_child_with_deadline(
            process_id, "poisoned fork child safety exit"
        )
        process_id = None
    finally:
        _close_descriptor(read_descriptor)
        _close_descriptor(write_descriptor)
        if process_id is not None:
            _terminate_and_reap_child(process_id)

    assert resumed == b""
    assert (
        os.waitstatus_to_exitcode(status)
        == SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE
    )


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork contract")
@pytest.mark.parametrize("active", (False, True))
def test_fork_child_is_clean_only_when_parent_lifecycle_is_idle(active: bool) -> None:
    read_descriptor, write_descriptor = os.pipe()
    manager = process_sqlite_lifecycle(1) if active else nullcontext()
    process_id: int | None = None
    try:
        with manager:
            process_id = os.fork()
            if process_id == 0:  # pragma: no cover - asserted through the pipe
                os.close(read_descriptor)
                try:
                    try:
                        with process_sqlite_lifecycle(0):
                            outcome = b"admitted"
                    except SQLiteProcessLifecycleError:
                        outcome = b"poisoned"
                    os.write(write_descriptor, outcome)
                finally:
                    os.close(write_descriptor)
                    os._exit(0)

            os.close(write_descriptor)
            outcome = _read_pipe_with_deadline(
                read_descriptor, "fork child lifecycle outcome"
            )
            status = _wait_child_with_deadline(
                process_id, "fork child lifecycle probe"
            )
            process_id = None
    finally:
        _close_descriptor(read_descriptor)
        _close_descriptor(write_descriptor)
        if process_id is not None:
            _terminate_and_reap_child(process_id)

    if active:
        assert (
            os.waitstatus_to_exitcode(status)
            == SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE
        )
        assert outcome == b""
    else:
        assert os.waitstatus_to_exitcode(status) == 0
        assert outcome == b"admitted"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork contract")
@pytest.mark.parametrize("store_kind", ("authority", "session"))
def test_fork_child_exits_before_body_can_touch_inherited_store_connection(
    tmp_path: Path,
    store_kind: str,
) -> None:
    path = (tmp_path / f"fork-{store_kind}.sqlite3").resolve()
    path.parent.chmod(0o700)
    if store_kind == "authority":
        store = SQLiteApprovalChallengeStore(path)
    else:
        store = SQLiteTrustedSessionStore(path)

    original_pid = os.getpid()
    resumed_read, resumed_write = os.pipe()
    child_pid: int | None = None
    try:
        try:
            with store._transaction():
                child_pid = os.fork()
                if child_pid == 0:  # pragma: no cover - asserted by parent
                    os.close(resumed_read)
                    try:
                        os.write(resumed_write, b"resumed")
                    finally:
                        os.close(resumed_write)
                        os._exit(99)

                os.close(resumed_write)
                resumed = _read_pipe_with_deadline(
                    resumed_read, "fork child resume probe"
                )
                os.close(resumed_read)
                assert child_pid is not None
                status = _wait_child_with_deadline(
                    child_pid, "fork child inherited transaction"
                )
                child_pid = None
                raise _ReleaseParentTransaction
        except _ReleaseParentTransaction:
            pass
    finally:
        if os.getpid() == original_pid:
            for descriptor in (resumed_read, resumed_write):
                _close_descriptor(descriptor)
            if child_pid is not None:
                _terminate_and_reap_child(child_pid)

    assert (
        os.waitstatus_to_exitcode(status)
        == SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE
    )
    assert resumed == b""


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock contract")
def test_fork_child_exit_does_not_release_parent_writer_flock(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "fork-writer-lock.sqlite3").resolve()
    path.parent.chmod(0o700)
    store = SQLiteTrustedSessionStore(path)
    lock_path = Path(f"{path}.writer.lock")
    resumed_read, resumed_write = os.pipe()
    child_pid: int | None = None
    try:
        with store._transaction() as connection:
            assert _other_process_can_take_flock(lock_path) is False
            child_pid = os.fork()
            if child_pid == 0:  # pragma: no cover - asserted by parent
                os.close(resumed_read)
                try:
                    os.write(resumed_write, b"resumed")
                finally:
                    os.close(resumed_write)
                    os._exit(99)

            os.close(resumed_write)
            resumed = _read_pipe_with_deadline(
                resumed_read, "fork child writer-lock resume probe"
            )
            os.close(resumed_read)
            status = _wait_child_with_deadline(
                child_pid, "fork child writer-lock safety exit"
            )
            child_pid = None
            assert resumed == b""
            assert (
                os.waitstatus_to_exitcode(status)
                == SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE
            )
            assert _other_process_can_take_flock(lock_path) is False
            assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        _close_descriptor(resumed_read)
        _close_descriptor(resumed_write)
        if child_pid is not None:
            _terminate_and_reap_child(child_pid)

    assert _other_process_can_take_flock(lock_path) is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock contract")
def test_writer_lock_pid_guard_never_opens_or_unlocks_for_another_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert fcntl is not None
    assert trusted_session_sqlite.fcntl is not None
    path = (tmp_path / "writer-owner.sqlite3").resolve()
    path.parent.chmod(0o700)
    store = SQLiteTrustedSessionStore(path)
    owner_process_id = os.getpid()
    open_called = False

    def unexpected_open() -> tuple[int, tuple[int, int]]:
        nonlocal open_called
        open_called = True
        raise AssertionError("mismatched writer owner reached lock-file open")

    with monkeypatch.context() as patch:
        patch.setattr(
            trusted_session_sqlite.os,
            "getpid",
            lambda: owner_process_id + 1,
        )
        patch.setattr(store, "_open_writer_lock_file", unexpected_open)
        with pytest.raises(
            trusted_session_sqlite.TrustedSessionStoreError,
            match="fork child cannot acquire",
        ):
            store._acquire_writer_lock(
                time.monotonic() + 5,
                owner_process_id=owner_process_id,
            )
    assert open_called is False

    lock = store._acquire_writer_lock(
        time.monotonic() + 5,
        owner_process_id=owner_process_id,
    )
    assert lock is not None
    descriptor, _, _ = lock
    retained_descriptor = os.dup(descriptor)
    flock_calls: list[int] = []
    real_flock = fcntl.flock
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                trusted_session_sqlite.os,
                "getpid",
                lambda: owner_process_id + 1,
            )
            patch.setattr(
                trusted_session_sqlite.fcntl,
                "flock",
                lambda _descriptor, operation: flock_calls.append(operation),
            )
            with pytest.raises(
                trusted_session_sqlite.TrustedSessionStoreError,
                match="fork child cannot release",
            ):
                store._release_writer_lock(lock)
        assert flock_calls == []
        with pytest.raises(OSError):
            os.fstat(descriptor)
        assert _other_process_can_take_flock(store._writer_lock_path) is False
    finally:
        real_flock(retained_descriptor, fcntl.LOCK_UN)
        os.close(retained_descriptor)

    assert _other_process_can_take_flock(store._writer_lock_path) is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX record-lock contract")
@pytest.mark.parametrize("store_kind", ("authority", "session"))
def test_second_store_cannot_release_live_process_record_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    store_kind: str,
) -> None:
    assert fcntl is not None
    path = (tmp_path / f"{store_kind}.sqlite3").resolve()
    if store_kind == "authority":
        first = SQLiteApprovalChallengeStore(path)
        second = SQLiteApprovalChallengeStore(path)
        second_read = second.audit_events
    else:
        first = SQLiteTrustedSessionStore(path)
        second = SQLiteTrustedSessionStore(path)
        second_read = second.verify_integrity

    observable = _ObservableMutex()
    monkeypatch.setattr(
        sqlite_process_lifecycle._PROCESS_SQLITE_LIFECYCLE,
        "_mutex",
        observable,
    )
    connection_live = Event()
    release_connection = Event()
    contender_finished = Event()
    failures: list[BaseException] = []

    def hold_connection() -> None:
        try:
            with first._read_connection():
                connection_live.set()
                if not release_connection.wait(15):
                    raise TimeoutError("SQLite connection release was not signalled")
        except BaseException as exc:
            failures.append(exc)

    def contend() -> None:
        try:
            second_read()
        except BaseException as exc:
            failures.append(exc)
        finally:
            contender_finished.set()

    holder = Thread(target=hold_connection)
    contender: Thread | None = None
    holder.start()
    assert connection_live.wait(15)
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.lockf(
            descriptor,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
            1,
            0,
            os.SEEK_SET,
        )
        assert _other_process_can_take_lock(path) is False

        contender = Thread(target=contend)
        contender.start()
        assert observable.blocked.wait(15)
        assert not contender_finished.is_set()
        assert _other_process_can_take_lock(path) is False
    finally:
        release_connection.set()
        holder.join(15)
        if contender is not None:
            contender.join(15)
        fcntl.lockf(
            descriptor,
            fcntl.LOCK_UN,
            1,
            0,
            os.SEEK_SET,
        )
        os.close(descriptor)

    assert not holder.is_alive()
    assert contender is not None
    assert not contender.is_alive()
    assert failures == []
    assert contender_finished.is_set()
