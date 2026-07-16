"""Process-wide guard for SQLite connections and direct file checks.

SQLite's POSIX advisory locks belong to the process.  Closing any unrelated
descriptor for the database or its WAL/SHM sidecars can therefore release
locks held by another SQLite connection in the same process.  This module
serializes every trusted-store connection lifecycle with every direct file
descriptor check.  The deliberately global gate also covers aliases and path
replacement; per-database concurrency can be introduced only with a proven
dual path/inode registry.
"""

from __future__ import annotations

import math
import os
import threading
from contextlib import contextmanager
from typing import Iterator


SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE = 70


class SQLiteProcessLifecycleError(RuntimeError):
    """The process cannot safely start or continue a SQLite lifecycle."""


class SQLiteProcessConnectionPhase:
    """Track whether a connection was absent or confirmed closed."""

    def __init__(
        self,
        coordinator: _ProcessSQLiteLifecycle,
        lease: SQLiteProcessLifecycleLease,
    ) -> None:
        self._coordinator = coordinator
        self._lease = lease
        self._outcome = "idle"

    def connecting(self) -> None:
        if self._outcome != "idle":
            raise SQLiteProcessLifecycleError(
                "another SQLite connection attempt is already active"
            )
        self._coordinator._require_lease(self._lease, phase="connection")
        self._outcome = "connecting"

    def connect_failed(self) -> None:
        if self._outcome != "connecting":
            raise SQLiteProcessLifecycleError(
                "SQLite connection failure has no matching attempt"
            )
        self._coordinator._require_lease(self._lease, phase="connection")
        self._outcome = "idle"

    def opened(self) -> None:
        if self._outcome != "connecting":
            raise SQLiteProcessLifecycleError(
                "SQLite connection open has no matching attempt"
            )
        self._coordinator._require_lease(self._lease, phase="connection")
        self._outcome = "open"

    def require_active(self) -> None:
        if self._outcome != "open":
            raise SQLiteProcessLifecycleError(
                "SQLite connection is not active in this lifecycle"
            )
        self._coordinator._require_lease(self._lease, phase="connection")

    def closed(self) -> None:
        if self._outcome != "open":
            raise SQLiteProcessLifecycleError(
                "SQLite connection was not open when close was recorded"
            )
        self._coordinator._require_lease(self._lease, phase="connection")
        self._outcome = "idle"


class SQLiteProcessLifecycleLease:
    """Unforgeable ownership token for one process SQLite lifecycle."""

    def __init__(
        self,
        coordinator: _ProcessSQLiteLifecycle,
        owner_process_id: int,
        owner_thread_id: int,
    ) -> None:
        self._coordinator = coordinator
        self._owner_process_id = owner_process_id
        self._owner_thread_id = owner_thread_id
        self._phase = "file"

    def require_file_phase(self) -> None:
        self._coordinator._require_lease(self, phase="file")

    def poison(self, reason: str) -> None:
        self._coordinator._poison(self, reason)

    @contextmanager
    def connection_phase(self) -> Iterator[SQLiteProcessConnectionPhase]:
        self._coordinator._begin_connection(self)
        phase = SQLiteProcessConnectionPhase(self._coordinator, self)
        try:
            yield phase
        except BaseException as exc:
            try:
                self._coordinator._finish_connection(self, phase)
            except BaseException as cleanup_error:
                exc.add_note(
                    "SQLite connection phase cleanup also failed: "
                    f"{cleanup_error}"
                )
            raise
        else:
            self._coordinator._finish_connection(self, phase)


class _ProcessSQLiteLifecycle:
    """One non-reentrant mutex shared by all trusted SQLite stores."""

    def __init__(self) -> None:
        self._mutex = threading.Lock()
        self._state_lock = threading.Lock()
        self._owner_thread_id: int | None = None
        self._lease: SQLiteProcessLifecycleLease | None = None
        self._poisoned_reason: str | None = None

    @property
    def poisoned(self) -> bool:
        with self._state_lock:
            return self._poisoned_reason is not None

    def _error_if_unavailable(self, owner_thread_id: int) -> None:
        if self._poisoned_reason is not None:
            raise SQLiteProcessLifecycleError(
                "SQLite process lifecycle is poisoned; restart or exec is required"
            )
        if self._owner_thread_id == owner_thread_id:
            raise SQLiteProcessLifecycleError(
                "nested SQLite lifecycle during an active connection is unsafe"
            )

    @contextmanager
    def acquire(
        self, timeout_seconds: float
    ) -> Iterator[SQLiteProcessLifecycleLease]:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds < 0
        ):
            raise SQLiteProcessLifecycleError(
                "SQLite process lifecycle timeout is invalid"
            )
        owner_process_id = os.getpid()
        owner_thread_id = threading.get_ident()
        with self._state_lock:
            self._error_if_unavailable(owner_thread_id)
        mutex = self._mutex
        if not mutex.acquire(timeout=float(timeout_seconds)):
            raise SQLiteProcessLifecycleError(
                "SQLite process lifecycle acquisition timed out"
            )
        lease: SQLiteProcessLifecycleLease | None = None
        try:
            with self._state_lock:
                self._error_if_unavailable(owner_thread_id)
                if self._owner_thread_id is not None or self._lease is not None:
                    raise SQLiteProcessLifecycleError(
                        "SQLite process lifecycle ownership is inconsistent"
                    )
                lease = SQLiteProcessLifecycleLease(
                    self,
                    owner_process_id,
                    owner_thread_id,
                )
                self._owner_thread_id = owner_thread_id
                self._lease = lease
            yield lease
        finally:
            with self._state_lock:
                if lease is not None and self._lease is lease:
                    if lease._phase != "file":
                        self._poisoned_reason = (
                            "SQLite lifecycle ended without a confirmed close"
                        )
                    self._owner_thread_id = None
                    self._lease = None
            mutex.release()

    def _require_lease(
        self, lease: SQLiteProcessLifecycleLease, *, phase: str
    ) -> None:
        owner_thread_id = threading.get_ident()
        with self._state_lock:
            if (
                self._poisoned_reason is not None
                or lease._owner_process_id != os.getpid()
                or self._owner_thread_id != owner_thread_id
                or self._lease is not lease
                or lease._owner_thread_id != owner_thread_id
                or lease._phase != phase
            ):
                raise SQLiteProcessLifecycleError(
                    "SQLite process lifecycle lease or phase is invalid"
                )

    def _begin_connection(self, lease: SQLiteProcessLifecycleLease) -> None:
        self._require_lease(lease, phase="file")
        with self._state_lock:
            lease._phase = "connection"

    def _finish_connection(
        self,
        lease: SQLiteProcessLifecycleLease,
        phase: SQLiteProcessConnectionPhase,
    ) -> None:
        owner_thread_id = threading.get_ident()
        with self._state_lock:
            if (
                lease._owner_process_id != os.getpid()
                or self._owner_thread_id != owner_thread_id
                or self._lease is not lease
                or lease._phase != "connection"
            ):
                self._poisoned_reason = "SQLite connection phase ownership was lost"
                raise SQLiteProcessLifecycleError(
                    "SQLite connection phase ownership is invalid"
                )
            if phase._outcome != "idle":
                self._poisoned_reason = (
                    "SQLite connection close was not positively confirmed"
                )
            lease._phase = "file"

    def _poison(
        self, lease: SQLiteProcessLifecycleLease, reason: str
    ) -> None:
        if not isinstance(reason, str) or not reason:
            reason = "SQLite process lifecycle was explicitly poisoned"
        with self._state_lock:
            if (
                self._lease is not lease
                or lease._owner_process_id != os.getpid()
            ):
                raise SQLiteProcessLifecycleError(
                    "SQLite process lifecycle lease is invalid"
                )
            self._poisoned_reason = reason

    def _after_fork_child(self) -> None:
        active = self._owner_thread_id is not None or self._lease is not None
        poisoned = self._poisoned_reason is not None
        if active or poisoned:
            # Once this Python at-fork hook begins, fail-stop before returning
            # to the fork caller or running normal cleanup.  Raising is not a
            # boundary here: register_at_fork reports callback exceptions as
            # unraisable and resumes the child.  _exit bypasses finally, GC,
            # sqlite3 destructors, rollback/close, and writer-lock cleanup.
            os._exit(SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE)
        self._mutex = threading.Lock()
        self._state_lock = threading.Lock()
        self._owner_thread_id = None
        self._lease = None
        self._poisoned_reason = None


_PROCESS_SQLITE_LIFECYCLE = _ProcessSQLiteLifecycle()


def _after_fork_child() -> None:
    _PROCESS_SQLITE_LIFECYCLE._after_fork_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


@contextmanager
def process_sqlite_lifecycle(
    timeout_seconds: float,
) -> Iterator[SQLiteProcessLifecycleLease]:
    with _PROCESS_SQLITE_LIFECYCLE.acquire(timeout_seconds) as lease:
        yield lease


__all__ = (
    "SQLITE_PROCESS_FORK_SAFETY_EXIT_CODE",
    "SQLiteProcessConnectionPhase",
    "SQLiteProcessLifecycleError",
    "SQLiteProcessLifecycleLease",
    "process_sqlite_lifecycle",
)
