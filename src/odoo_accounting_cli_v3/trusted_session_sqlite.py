"""Durable opaque-handle storage for server-established trusted sessions.

This module is deliberately below the Pi-facing protocol boundary.  It never
accepts a request mapping or caller-supplied user/company fields.  A privileged
server component first establishes a :class:`TrustedSessionIdentity`, then this
store generates the session ID, 256-bit opaque handle, issue time, and expiry.
Only the SHA-256 digest of the handle is persisted.

Every resolve/revoke decision is made in a separate ``BEGIN IMMEDIATE`` SQLite
transaction.  This makes finite-use handles atomic across processes and keeps a
hash-chained, append-only security event trail in the same commit boundary.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - exercised by the Windows test matrix
    fcntl = None  # type: ignore[assignment]

from .monotonic_deadline import (
    bounded_sqlite_busy_timeout_ms,
    bounded_sqlite_connect_timeout_seconds,
)
from .operations import canonical_json
from .trusted_authority import AuthorityError, TrustedSession


TRUSTED_SESSION_STORE_SCHEMA_VERSION = 1
_HANDLE_BYTES = 32
_HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RETRYABLE_SQLITE_SETUP_BASE_CODES = frozenset(
    {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_PROTOCOL}
)
_SQLITE_SETUP_RETRY_INITIAL_SECONDS = 0.001
_SQLITE_SETUP_RETRY_MAX_SECONDS = 0.025
_SQLITE_SETUP_ATTEMPT_MAX_BUSY_MS = 100
_WRITER_LOCK_SUFFIX = ".writer.lock"


class TrustedSessionStoreError(AuthorityError):
    """The trusted-session store rejected an unsafe or inconsistent action."""


class TrustedSessionReconciliationRequiredError(TrustedSessionStoreError):
    """A session mutation cannot be replayed until durable state is reconciled."""

    retryable = False
    reconciliation_required = True


class TrustedSessionKnownCommittedError(TrustedSessionReconciliationRequiredError):
    """A durable commit completed but cleanup now requires reconciliation.

    Callers must not replay the write represented by this exception.  They must
    reconcile the durable store state instead.
    """

    committed = True
    commit_outcome = "committed"


class TrustedSessionCommitOutcomeUnknownError(
    TrustedSessionReconciliationRequiredError
):
    """Commit raised without a positively confirmed rollback."""

    committed = None
    commit_outcome = "unknown"


@dataclass(frozen=True)
class TrustedSessionIdentity:
    """Identity established by trusted server code, never decoded from Pi input.

    The public store API intentionally accepts this exact type rather than a
    mapping.  The service that constructs it must bind these values from its
    authenticated Odoo/server-side identity source.
    """

    principal: str
    odoo_instance_id: str
    database_name: str
    database_uuid: str
    user_id: int
    company_id: int
    allowed_company_ids: frozenset[int]
    environment: str

    def __post_init__(self) -> None:
        try:
            validated = TrustedSession(
                session_id="identity-validation",
                principal=self.principal,
                odoo_instance_id=self.odoo_instance_id,
                database_name=self.database_name,
                database_uuid=self.database_uuid,
                user_id=self.user_id,
                company_id=self.company_id,
                allowed_company_ids=self.allowed_company_ids,
                environment=self.environment,
                issued_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
                expires_at=datetime(2000, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
            )
        except AuthorityError as exc:
            raise TrustedSessionStoreError(str(exc)) from exc
        object.__setattr__(self, "database_uuid", validated.database_uuid)


@dataclass(frozen=True)
class IssuedTrustedSession:
    """One-time delivery of a newly generated opaque handle and its binding."""

    handle: str = field(repr=False)
    session: TrustedSession
    max_uses: int


@dataclass(frozen=True)
class TrustedSessionSecurityEvent:
    """An immutable, hash-chained decision made by the session store."""

    sequence: int
    event_id: str
    event_type: str
    occurred_at: datetime
    session_id: str | None
    handle_digest: str | None
    binding_digest: str | None
    outcome: str
    details_json: str
    previous_hash: str | None
    event_hash: str


@dataclass(frozen=True)
class _StoredSession:
    session: TrustedSession
    handle_digest: str
    binding_digest: str
    max_uses: int
    use_count: int
    revoked_at: datetime | None
    revocation_reason: str | None
    version: int


_TABLES = {
    "trusted_session_schema_meta": """
        CREATE TABLE trusted_session_schema_meta (
            key TEXT PRIMARY KEY CHECK (key = 'schema_version'),
            value TEXT NOT NULL
        ) STRICT
    """,
    "trusted_sessions": """
        CREATE TABLE trusted_sessions (
            session_id TEXT PRIMARY KEY,
            handle_digest TEXT NOT NULL UNIQUE,
            binding_digest TEXT NOT NULL UNIQUE,
            principal TEXT NOT NULL,
            odoo_instance_id TEXT NOT NULL,
            database_name TEXT NOT NULL,
            database_uuid TEXT NOT NULL,
            user_id INTEGER NOT NULL CHECK (user_id > 0),
            company_id INTEGER NOT NULL CHECK (company_id > 0),
            allowed_company_ids_json TEXT NOT NULL,
            environment TEXT NOT NULL CHECK (
                environment IN ('test', 'sandbox', 'production')
            ),
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            max_uses INTEGER NOT NULL CHECK (max_uses > 0),
            use_count INTEGER NOT NULL DEFAULT 0 CHECK (
                use_count >= 0 AND use_count <= max_uses
            ),
            revoked_at TEXT,
            revocation_reason TEXT,
            version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
            CHECK (
                (revoked_at IS NULL AND revocation_reason IS NULL)
                OR
                (revoked_at IS NOT NULL AND length(revocation_reason) > 0)
            )
        ) STRICT
    """,
    "trusted_session_security_events": """
        CREATE TABLE trusted_session_security_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            session_id TEXT,
            handle_digest TEXT,
            binding_digest TEXT,
            outcome TEXT NOT NULL,
            details_json TEXT NOT NULL,
            previous_hash TEXT,
            event_hash TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES trusted_sessions(session_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        ) STRICT
    """,
}


_TRIGGERS = {
    "trusted_session_schema_meta_no_update": """
        CREATE TRIGGER trusted_session_schema_meta_no_update
        BEFORE UPDATE ON trusted_session_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'trusted session schema metadata is immutable');
        END
    """,
    "trusted_session_schema_meta_no_delete": """
        CREATE TRIGGER trusted_session_schema_meta_no_delete
        BEFORE DELETE ON trusted_session_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'trusted session schema metadata is immutable');
        END
    """,
    "trusted_sessions_no_delete": """
        CREATE TRIGGER trusted_sessions_no_delete
        BEFORE DELETE ON trusted_sessions
        BEGIN
            SELECT RAISE(ABORT, 'trusted sessions cannot be deleted');
        END
    """,
    "trusted_sessions_immutable": """
        CREATE TRIGGER trusted_sessions_immutable
        BEFORE UPDATE ON trusted_sessions
        WHEN NEW.session_id IS NOT OLD.session_id
          OR NEW.handle_digest IS NOT OLD.handle_digest
          OR NEW.binding_digest IS NOT OLD.binding_digest
          OR NEW.principal IS NOT OLD.principal
          OR NEW.odoo_instance_id IS NOT OLD.odoo_instance_id
          OR NEW.database_name IS NOT OLD.database_name
          OR NEW.database_uuid IS NOT OLD.database_uuid
          OR NEW.user_id IS NOT OLD.user_id
          OR NEW.company_id IS NOT OLD.company_id
          OR NEW.allowed_company_ids_json IS NOT OLD.allowed_company_ids_json
          OR NEW.environment IS NOT OLD.environment
          OR NEW.issued_at IS NOT OLD.issued_at
          OR NEW.expires_at IS NOT OLD.expires_at
          OR NEW.max_uses IS NOT OLD.max_uses
        BEGIN
            SELECT RAISE(ABORT, 'trusted session immutable binding changed');
        END
    """,
    "trusted_sessions_valid_transition": """
        CREATE TRIGGER trusted_sessions_valid_transition
        BEFORE UPDATE OF use_count, revoked_at, revocation_reason, version
        ON trusted_sessions
        WHEN NOT (
            (
                OLD.revoked_at IS NULL
                AND NEW.revoked_at IS NULL
                AND NEW.revocation_reason IS NULL
                AND NEW.use_count = OLD.use_count + 1
                AND NEW.use_count <= OLD.max_uses
                AND NEW.version = OLD.version + 1
            )
            OR
            (
                OLD.revoked_at IS NULL
                AND OLD.revocation_reason IS NULL
                AND NEW.revoked_at IS NOT NULL
                AND length(NEW.revocation_reason) > 0
                AND NEW.use_count = OLD.use_count
                AND NEW.version = OLD.version + 1
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'trusted session transition is invalid');
        END
    """,
    "trusted_session_security_events_no_update": """
        CREATE TRIGGER trusted_session_security_events_no_update
        BEFORE UPDATE ON trusted_session_security_events
        BEGIN
            SELECT RAISE(ABORT, 'trusted session security events are append-only');
        END
    """,
    "trusted_session_security_events_no_delete": """
        CREATE TRIGGER trusted_session_security_events_no_delete
        BEFORE DELETE ON trusted_session_security_events
        BEGIN
            SELECT RAISE(ABORT, 'trusted session security events are append-only');
        END
    """,
}


_EXPECTED_COLUMNS = {
    "trusted_session_schema_meta": ("key", "value"),
    "trusted_sessions": (
        "session_id",
        "handle_digest",
        "binding_digest",
        "principal",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "user_id",
        "company_id",
        "allowed_company_ids_json",
        "environment",
        "issued_at",
        "expires_at",
        "max_uses",
        "use_count",
        "revoked_at",
        "revocation_reason",
        "version",
    ),
    "trusted_session_security_events": (
        "sequence",
        "event_id",
        "event_type",
        "occurred_at",
        "session_id",
        "handle_digest",
        "binding_digest",
        "outcome",
        "details_json",
        "previous_hash",
        "event_hash",
    ),
}


_EVENT_OUTCOMES = {
    "session.issued": frozenset({"accepted"}),
    "session.resolved": frozenset({"accepted"}),
    "session.resolve_rejected": frozenset(
        {"invalid", "unknown", "not_yet_valid", "expired", "revoked", "exhausted"}
    ),
    "session.revoked": frozenset({"accepted"}),
    "session.revoke_rejected": frozenset(
        {"invalid", "unknown", "already_revoked"}
    ),
}


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split()).replace(
        "CREATE TABLE IF NOT EXISTS", "CREATE TABLE"
    )


def _required_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedSessionStoreError(f"{label} is invalid")
    return value


def _uuid_text(value: object, label: str) -> str:
    try:
        normalized = str(uuid.UUID(value))  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrustedSessionStoreError(f"{label} is invalid") from exc
    if value != normalized:
        raise TrustedSessionStoreError(f"{label} is not canonical")
    return normalized


def _sha256_text(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise TrustedSessionStoreError(f"{label} is invalid")
    return value


def _utc_text(value: object, label: str) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise TrustedSessionStoreError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _utc_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise TrustedSessionStoreError(f"stored {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrustedSessionStoreError(f"stored {label} is invalid") from exc
    if _utc_text(parsed, label) != value:
        raise TrustedSessionStoreError(f"stored {label} is not canonical UTC")
    return parsed.astimezone(timezone.utc)


def _canonical_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise TrustedSessionStoreError(f"{label} is invalid")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedSessionStoreError(f"{label} is invalid") from exc
    if (
        not isinstance(parsed, dict)
        or canonical_json(parsed).decode("utf-8") != value
    ):
        raise TrustedSessionStoreError(f"{label} is not canonical")
    return parsed


def _allowed_companies_json(value: frozenset[int]) -> str:
    return canonical_json(sorted(value)).decode("utf-8")


def _allowed_companies(value: object) -> frozenset[int]:
    if not isinstance(value, str):
        raise TrustedSessionStoreError("stored allowed companies are invalid")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedSessionStoreError("stored allowed companies are invalid") from exc
    if (
        not isinstance(parsed, list)
        or not parsed
        or any(type(company_id) is not int or company_id <= 0 for company_id in parsed)
        or parsed != sorted(set(parsed))
        or canonical_json(parsed).decode("utf-8") != value
    ):
        raise TrustedSessionStoreError("stored allowed companies are invalid")
    return frozenset(parsed)


def _binding_payload(session: TrustedSession, max_uses: int) -> dict[str, Any]:
    return {
        "schema": "odoo-accounting-cli-v3/trusted-session-binding/v1",
        "session_id": session.session_id,
        "principal": session.principal,
        "odoo_instance_id": session.odoo_instance_id,
        "database_name": session.database_name,
        "database_uuid": session.database_uuid,
        "user_id": session.user_id,
        "company_id": session.company_id,
        "allowed_company_ids": sorted(session.allowed_company_ids),
        "environment": session.environment,
        "issued_at": _utc_text(session.issued_at, "session issued_at"),
        "expires_at": _utc_text(session.expires_at, "session expires_at"),
        "max_uses": max_uses,
    }


def _binding_digest(session: TrustedSession, max_uses: int) -> str:
    return hashlib.sha256(canonical_json(_binding_payload(session, max_uses))).hexdigest()


def _event_hash(event: TrustedSessionSecurityEvent) -> str:
    details = _canonical_object(event.details_json, "security event details")
    return hashlib.sha256(
        canonical_json(
            {
                "sequence": event.sequence,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "occurred_at": _utc_text(event.occurred_at, "event occurred_at"),
                "session_id": event.session_id,
                "handle_digest": event.handle_digest,
                "binding_digest": event.binding_digest,
                "outcome": event.outcome,
                "details": details,
                "previous_hash": event.previous_hash,
            }
        )
    ).hexdigest()


class SQLiteTrustedSessionStore:
    """Private SQLite issuer/resolver for finite-use opaque session handles."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_ms: int = 5_000,
        max_ttl_seconds: int = 900,
        max_session_uses: int = 64,
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:" or not self.path.is_absolute():
            raise TrustedSessionStoreError(
                "trusted session database path must be absolute"
            )
        if (
            type(busy_timeout_ms) is not int
            or busy_timeout_ms <= 0
            or type(max_ttl_seconds) is not int
            or max_ttl_seconds <= 0
            or type(max_session_uses) is not int
            or max_session_uses <= 0
        ):
            raise TrustedSessionStoreError("trusted session store limits are invalid")
        if clock is not None and not callable(clock):
            raise TrustedSessionStoreError("trusted session clock is invalid")
        self.busy_timeout_ms = busy_timeout_ms
        self.max_ttl_seconds = max_ttl_seconds
        self.max_session_uses = max_session_uses
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._initialize()

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise TrustedSessionStoreError("trusted session clock failed") from exc
        return _utc_datetime(
            _utc_text(value, "trusted session clock"), "trusted session clock"
        )

    def _secure_parent(self) -> None:
        try:
            parent = self.path.parent
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
                raise TrustedSessionStoreError(
                    "trusted session parent directory is invalid"
                )
            if os.name == "posix":
                if not hasattr(os, "O_NOFOLLOW"):
                    raise TrustedSessionStoreError(
                        "trusted session database requires O_NOFOLLOW support"
                    )
                if parent.resolve(strict=True) != parent:
                    raise TrustedSessionStoreError(
                        "trusted session parent directory must not traverse symlinks"
                    )
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                    raise TrustedSessionStoreError(
                        "trusted session parent directory is not private"
                    )
        except TrustedSessionStoreError:
            raise
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session parent directory cannot be secured"
            ) from exc

    def _secure_database_file(self) -> tuple[int, int]:
        self._secure_parent()
        descriptor: int | None = None
        try:
            if not os.path.lexists(self.path):
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(self.path, flags, 0o600)
                except FileExistsError:
                    descriptor = None
                else:
                    if os.name == "posix":
                        os.fchmod(descriptor, 0o600)
                    os.close(descriptor)
                    descriptor = None

            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise TrustedSessionStoreError(
                    "trusted session database must be a regular non-symlink file"
                )
            if opened.st_nlink != 1 or metadata.st_nlink != 1:
                raise TrustedSessionStoreError(
                    "trusted session database must have exactly one hard link"
                )
            if os.name == "posix" and (
                opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise TrustedSessionStoreError(
                    "trusted session database file is not private"
                )
            self._verify_sidecars()
            return opened.st_dev, opened.st_ino
        except TrustedSessionStoreError:
            raise
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session database path cannot be secured"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _verify_database_file(self, expected: tuple[int, int]) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise TrustedSessionStoreError(
                    "trusted session database path changed while open"
                )
            if metadata.st_nlink != 1:
                raise TrustedSessionStoreError(
                    "trusted session database must have exactly one hard link"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise TrustedSessionStoreError(
                    "trusted session database file is not private"
                )
            self._verify_sidecars()
        except TrustedSessionStoreError:
            raise
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session database path cannot be verified"
            ) from exc

    def _verify_sidecars(self) -> None:
        if os.name != "posix":
            return
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if not os.path.lexists(sidecar):
                continue
            descriptor: int | None = None
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
                descriptor = os.open(sidecar, flags)
                opened = os.fstat(descriptor)
                metadata = sidecar.lstat()
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or sidecar.is_symlink()
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != 0o600
                ):
                    raise TrustedSessionStoreError(
                        "trusted session SQLite sidecar is not private"
                    )
            except FileNotFoundError:
                if os.path.lexists(sidecar):
                    raise TrustedSessionStoreError(
                        "trusted session SQLite sidecar changed while checked"
                    )
            except TrustedSessionStoreError:
                raise
            except OSError as exc:
                raise TrustedSessionStoreError(
                    "trusted session SQLite sidecar cannot be secured"
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    @property
    def _writer_lock_path(self) -> Path:
        return Path(f"{self.path}{_WRITER_LOCK_SUFFIX}")

    def _verify_writer_lock_file(
        self, descriptor: int, expected: tuple[int, int]
    ) -> None:
        self._secure_parent()
        try:
            opened = os.fstat(descriptor)
            metadata = self._writer_lock_path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or self._writer_lock_path.is_symlink()
                or (opened.st_dev, opened.st_ino) != expected
                or (metadata.st_dev, metadata.st_ino) != expected
                or opened.st_uid != os.geteuid()
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or opened.st_nlink != 1
                or metadata.st_nlink != 1
            ):
                raise TrustedSessionStoreError(
                    "trusted session writer lock file is invalid"
                )
        except TrustedSessionStoreError:
            raise
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session writer lock file cannot be verified"
            ) from exc

    def _open_writer_lock_file(self) -> tuple[int, tuple[int, int]]:
        self._secure_parent()
        if os.name != "posix" or fcntl is None or not hasattr(os, "O_NOFOLLOW"):
            raise TrustedSessionStoreError(
                "trusted session writer lock requires POSIX flock and O_NOFOLLOW"
        )
        descriptor: int | None = None
        succeeded = False
        try:
            flags = (
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW
            )
            try:
                descriptor = os.open(
                    self._writer_lock_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                descriptor = os.open(self._writer_lock_path, flags)
            else:
                os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            expected = (opened.st_dev, opened.st_ino)
            self._verify_writer_lock_file(descriptor, expected)
            succeeded = True
            return descriptor, expected
        except TrustedSessionStoreError:
            raise
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session writer lock file cannot be secured"
            ) from exc
        finally:
            if descriptor is not None and not succeeded:
                os.close(descriptor)

    def _acquire_writer_lock(
        self, retry_deadline: float
    ) -> tuple[int, tuple[int, int]] | None:
        if os.name != "posix":
            return None
        assert fcntl is not None
        descriptor, expected = self._open_writer_lock_file()
        acquired = False
        retry_delay = _SQLITE_SETUP_RETRY_INITIAL_SECONDS
        try:
            while True:
                if retry_deadline - time.monotonic() <= 0:
                    raise TrustedSessionStoreError(
                        "trusted session writer lock deadline was exceeded"
                    )
                self._verify_writer_lock_file(descriptor, expected)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    self._verify_writer_lock_file(descriptor, expected)
                    return descriptor, expected
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise TrustedSessionStoreError(
                            "trusted session writer lock acquisition failed"
                        ) from exc
                remaining_seconds = retry_deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise TrustedSessionStoreError(
                        "trusted session writer lock deadline was exceeded"
                    )
                sleep_seconds = min(retry_delay, remaining_seconds)
                time.sleep(sleep_seconds)
                retry_delay = min(
                    retry_delay * 2.0,
                    _SQLITE_SETUP_RETRY_MAX_SECONDS,
                )
        except BaseException as exc:
            if acquired:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except BaseException as cleanup_error:
                    exc.add_note(
                        "trusted session writer lock cleanup unlock also failed: "
                        f"{cleanup_error}"
                    )
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                exc.add_note(
                    "trusted session writer lock cleanup close also failed: "
                    f"{cleanup_error}"
                )
            raise

    def _release_writer_lock(
        self, lock: tuple[int, tuple[int, int]] | None
    ) -> None:
        if lock is None:
            return
        assert fcntl is not None
        descriptor, expected = lock
        failure: BaseException | None = None
        try:
            self._verify_writer_lock_file(descriptor, expected)
        except BaseException as exc:
            failure = exc
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as exc:
            unlock_error = TrustedSessionStoreError(
                "trusted session writer lock release failed"
            )
            unlock_error.__cause__ = exc
            if failure is None:
                failure = unlock_error
            else:
                failure.add_note(str(unlock_error))
        try:
            os.close(descriptor)
        except OSError as exc:
            close_error = TrustedSessionStoreError(
                "trusted session writer lock descriptor could not be closed"
            )
            close_error.__cause__ = exc
            if failure is None:
                failure = close_error
            else:
                failure.add_note(str(close_error))
        if failure is not None:
            raise failure

    @contextmanager
    def _writer_lock(
        self, retry_deadline: float
    ) -> Iterator[tuple[int, tuple[int, int]] | None]:
        lock = self._acquire_writer_lock(retry_deadline)
        try:
            yield lock
        except BaseException as body_error:
            try:
                self._release_writer_lock(lock)
            except BaseException as cleanup_error:
                body_error.add_note(
                    "trusted session writer lock cleanup also failed: "
                    f"{cleanup_error}"
                )
            raise
        else:
            self._release_writer_lock(lock)

    def _remaining_transaction_busy_timeout_ms(
        self, retry_deadline: float, *, maximum_ms: int
    ) -> int:
        remaining_seconds = retry_deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise TrustedSessionStoreError(
                "trusted session SQLite transaction deadline was exceeded"
            )
        return min(maximum_ms, max(0, int(remaining_seconds * 1000.0)))

    def _set_transaction_busy_timeout(
        self,
        connection: sqlite3.Connection,
        retry_deadline: float,
        *,
        maximum_ms: int,
    ) -> None:
        busy_timeout_ms = self._remaining_transaction_busy_timeout_ms(
            retry_deadline,
            maximum_ms=maximum_ms,
        )
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")

    def _execute_transaction_setup(
        self,
        connection: sqlite3.Connection,
        statement: str,
        retry_deadline: float,
    ) -> sqlite3.Cursor:
        self._set_transaction_busy_timeout(
            connection,
            retry_deadline,
            maximum_ms=_SQLITE_SETUP_ATTEMPT_MAX_BUSY_MS,
        )
        # Setting the busy handler is itself a SQLite call.  Recheck before the
        # requested setup statement so an expired budget never starts new work.
        self._remaining_transaction_busy_timeout_ms(
            retry_deadline,
            maximum_ms=_SQLITE_SETUP_ATTEMPT_MAX_BUSY_MS,
        )
        return connection.execute(statement)

    def _configure(
        self,
        connection: sqlite3.Connection,
        *,
        write: bool,
        retry_deadline: float | None = None,
    ) -> None:
        if retry_deadline is None:
            busy_timeout_ms = bounded_sqlite_busy_timeout_ms(self.busy_timeout_ms)
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")

            def execute(statement: str) -> sqlite3.Cursor:
                return connection.execute(statement)

        else:

            def execute(statement: str) -> sqlite3.Cursor:
                return self._execute_transaction_setup(
                    connection,
                    statement,
                    retry_deadline,
                )

        # Assigning journal_mode takes a database lock even when the persisted
        # mode is already WAL.  Established stores only need to verify it.
        mode = str(execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if write and mode != "wal":
            mode = execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise TrustedSessionStoreError(
                    "trusted session database requires SQLite WAL mode"
                )
        elif mode != "wal":
            raise TrustedSessionStoreError(
                "trusted session database requires SQLite WAL mode"
            )
        if write:
            execute("PRAGMA synchronous = FULL")
        execute("PRAGMA foreign_keys = ON")
        if execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise TrustedSessionStoreError(
                "trusted session database requires foreign keys"
            )
        execute("PRAGMA trusted_schema = OFF")

    @staticmethod
    def _is_retryable_setup_error(exc: sqlite3.OperationalError) -> bool:
        error_code = getattr(exc, "sqlite_errorcode", None)
        return (
            type(error_code) is int
            and error_code & 0xFF in _RETRYABLE_SQLITE_SETUP_BASE_CODES
        )

    def _write_transaction_attempt(
        self, *, retry_deadline: float
    ) -> tuple[sqlite3.Connection, tuple[int, int]]:
        expected = self._secure_database_file()
        connection: sqlite3.Connection | None = None
        phase = "connect"
        try:
            connect_timeout_ms = self._remaining_transaction_busy_timeout_ms(
                retry_deadline,
                maximum_ms=_SQLITE_SETUP_ATTEMPT_MAX_BUSY_MS,
            )
            connection = sqlite3.connect(
                self.path,
                timeout=connect_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            phase = "configure"
            self._configure(
                connection,
                write=True,
                retry_deadline=retry_deadline,
            )
            phase = "sidecar verification"
            self._verify_sidecars()
            phase = "begin immediate"
            self._execute_transaction_setup(
                connection,
                "BEGIN IMMEDIATE",
                retry_deadline,
            )
            return connection, expected
        except BaseException as exc:
            cleanup_failure: BaseException | None = None
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except BaseException as cleanup_error:
                    cleanup_failure = cleanup_error
                try:
                    connection.close()
                except BaseException as cleanup_error:
                    if cleanup_failure is None:
                        cleanup_failure = cleanup_error
                    else:
                        cleanup_failure.add_note(
                            "trusted session SQLite setup close also failed: "
                            f"{cleanup_error}"
                        )
            try:
                self._verify_database_file(expected)
            except BaseException as cleanup_error:
                if cleanup_failure is None:
                    cleanup_failure = cleanup_error
                else:
                    cleanup_failure.add_note(
                        "trusted session database setup verification also failed: "
                        f"{cleanup_error}"
                    )
            if cleanup_failure is not None:
                cleanup_failure.add_note(
                    "original trusted session SQLite setup failure: " f"{exc}"
                )
                raise TrustedSessionStoreError(
                    "trusted session SQLite setup cleanup failed; retry was rejected"
                ) from cleanup_failure
            if isinstance(exc, sqlite3.OperationalError):
                exc.add_note(f"trusted session write setup phase: {phase}")
            raise

    def _open_write_transaction(
        self, *, retry_deadline: float
    ) -> tuple[sqlite3.Connection, tuple[int, int]]:
        retry_delay = _SQLITE_SETUP_RETRY_INITIAL_SECONDS
        while True:
            self._remaining_transaction_busy_timeout_ms(
                retry_deadline,
                maximum_ms=_SQLITE_SETUP_ATTEMPT_MAX_BUSY_MS,
            )
            try:
                return self._write_transaction_attempt(
                    retry_deadline=retry_deadline
                )
            except sqlite3.OperationalError as exc:
                if not self._is_retryable_setup_error(exc):
                    raise
                remaining_seconds = retry_deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise
                sleep_seconds = min(retry_delay, remaining_seconds)
                time.sleep(sleep_seconds)
                retry_delay = min(
                    retry_delay * 2.0,
                    _SQLITE_SETUP_RETRY_MAX_SECONDS,
                )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        total_budget_ms = bounded_sqlite_busy_timeout_ms(self.busy_timeout_ms)
        retry_deadline = time.monotonic() + total_budget_ms / 1000.0
        committed = False
        try:
            with self._writer_lock(retry_deadline) as writer_lock:
                try:
                    connection, expected = self._open_write_transaction(
                        retry_deadline=retry_deadline
                    )
                except sqlite3.Error as exc:
                    raise TrustedSessionStoreError(
                        "trusted session SQLite transaction failed"
                    ) from exc
                transaction_error: BaseException | None = None
                commit_started = False
                try:
                    yield connection
                    # Both path identities must still be stable while rollback
                    # remains possible.  No integrity check after commit may
                    # turn a known durable success into an ordinary failure.
                    self._verify_database_file(expected)
                    if writer_lock is not None:
                        descriptor, lock_expected = writer_lock
                        self._verify_writer_lock_file(descriptor, lock_expected)
                    self._set_transaction_busy_timeout(
                        connection,
                        retry_deadline,
                        maximum_ms=self.busy_timeout_ms,
                    )
                    self._remaining_transaction_busy_timeout_ms(
                        retry_deadline,
                        maximum_ms=self.busy_timeout_ms,
                    )
                    commit_started = True
                    connection.commit()
                    committed = True
                except BaseException as exc:
                    rollback_confirmed = False
                    if connection.in_transaction:
                        try:
                            connection.rollback()
                        except BaseException as rollback_error:
                            exc.add_note(
                                "trusted session SQLite rollback also failed: "
                                f"{rollback_error}"
                            )
                        else:
                            rollback_confirmed = not connection.in_transaction
                    if commit_started and not rollback_confirmed:
                        error = TrustedSessionCommitOutcomeUnknownError(
                            "trusted session SQLite commit outcome is unknown; "
                            "reconcile durable state and do not replay the request"
                        )
                        transaction_error = error
                        raise error from exc
                    if isinstance(exc, sqlite3.Error):
                        error = TrustedSessionStoreError(
                            "trusted session SQLite transaction failed"
                        )
                        transaction_error = error
                        raise error from exc
                    transaction_error = exc
                    raise
                finally:
                    try:
                        connection.close()
                    except BaseException as close_error:
                        if transaction_error is None:
                            raise
                        transaction_error.add_note(
                            "trusted session SQLite connection close also failed: "
                            f"{close_error}"
                        )
                # Retain the original post-close identity check while the
                # coordinating writer lock is still held.  Any failure here is
                # converted below into a known-committed reconciliation result.
                self._verify_database_file(expected)
        except TrustedSessionReconciliationRequiredError:
            raise
        except BaseException as exc:
            if committed:
                raise TrustedSessionKnownCommittedError(
                    "trusted session SQLite commit completed but cleanup failed; "
                    "reconcile durable state and do not replay the request"
                ) from exc
            raise

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        expected = self._secure_database_file()
        connection = sqlite3.connect(
            self.path,
            timeout=bounded_sqlite_connect_timeout_seconds(self.busy_timeout_ms),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            self._configure(connection, write=False)
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise TrustedSessionStoreError("trusted session SQLite read failed") from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_file(expected)

    def _database_has_content(self) -> bool:
        expected = self._secure_database_file()
        try:
            has_content = self.path.stat().st_size > 0
        except OSError as exc:
            raise TrustedSessionStoreError(
                "trusted session database path cannot be inspected"
            ) from exc
        self._verify_database_file(expected)
        return has_content

    def _initialize(self) -> None:
        if self._database_has_content():
            with self._read_connection() as connection:
                committed_tables = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if committed_tables:
                    self._verify_integrity_connection(connection)
                    return
            # A concurrent first initializer can make the SQLite/WAL header
            # visible before its schema transaction commits.  With no
            # committed user tables, join the serialized initialization path
            # instead of misclassifying that transient state as corruption.
        with self._transaction() as connection:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if not tables:
                for statement in _TABLES.values():
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO trusted_session_schema_meta(key, value) VALUES(?, ?)",
                    ("schema_version", str(TRUSTED_SESSION_STORE_SCHEMA_VERSION)),
                )
                for statement in _TRIGGERS.values():
                    connection.execute(statement)
            self._verify_integrity_connection(connection)

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        tables = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        triggers = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='trigger' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if set(tables) != set(_TABLES) or set(triggers) != set(_TRIGGERS):
            raise TrustedSessionStoreError("trusted session database schema is invalid")
        for name, expected in _TABLES.items():
            if not isinstance(tables[name], str) or _normalize_schema_sql(
                tables[name]
            ) != _normalize_schema_sql(expected):
                raise TrustedSessionStoreError(
                    "trusted session database schema definition changed"
                )
        for name, expected in _TRIGGERS.items():
            if not isinstance(triggers[name], str) or _normalize_schema_sql(
                triggers[name]
            ) != _normalize_schema_sql(expected):
                raise TrustedSessionStoreError(
                    "trusted session database trigger definition changed"
                )
        for table, expected in _EXPECTED_COLUMNS.items():
            columns = tuple(
                row["name"]
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            )
            if columns != expected:
                raise TrustedSessionStoreError(
                    "trusted session database columns changed"
                )
        metadata = tuple(
            connection.execute("SELECT key, value FROM trusted_session_schema_meta")
        )
        if len(metadata) != 1 or tuple(metadata[0]) != (
            "schema_version",
            str(TRUSTED_SESSION_STORE_SCHEMA_VERSION),
        ):
            raise TrustedSessionStoreError(
                "trusted session database schema version is invalid"
            )
        unexpected = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' "
            "AND type NOT IN ('table', 'trigger') LIMIT 1"
        ).fetchone()
        if unexpected is not None:
            raise TrustedSessionStoreError(
                "trusted session database has unexpected schema objects"
            )

    @staticmethod
    def _verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
        if tuple(row[0] for row in connection.execute("PRAGMA quick_check")) != (
            "ok",
        ):
            raise TrustedSessionStoreError(
                "trusted session SQLite integrity check failed"
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise TrustedSessionStoreError(
                "trusted session SQLite foreign key check failed"
            )

    @classmethod
    def _stored_session_from_row(cls, row: sqlite3.Row) -> _StoredSession:
        session_id = _uuid_text(row["session_id"], "stored session ID")
        handle_digest = _sha256_text(
            row["handle_digest"], "stored handle digest"
        )
        binding_digest = _sha256_text(
            row["binding_digest"], "stored binding digest"
        )
        issued_at = _utc_datetime(row["issued_at"], "session issued_at")
        expires_at = _utc_datetime(row["expires_at"], "session expires_at")
        try:
            session = TrustedSession(
                session_id=session_id,
                principal=row["principal"],
                odoo_instance_id=row["odoo_instance_id"],
                database_name=row["database_name"],
                database_uuid=row["database_uuid"],
                user_id=row["user_id"],
                company_id=row["company_id"],
                allowed_company_ids=_allowed_companies(
                    row["allowed_company_ids_json"]
                ),
                environment=row["environment"],
                issued_at=issued_at,
                expires_at=expires_at,
            )
        except (AuthorityError, TypeError, ValueError) as exc:
            raise TrustedSessionStoreError(
                "stored trusted session binding is invalid"
            ) from exc
        max_uses = row["max_uses"]
        use_count = row["use_count"]
        version = row["version"]
        if (
            type(max_uses) is not int
            or max_uses <= 0
            or type(use_count) is not int
            or use_count < 0
            or use_count > max_uses
            or type(version) is not int
            or version < 0
        ):
            raise TrustedSessionStoreError(
                "stored trusted session usage state is invalid"
            )
        if row["revoked_at"] is None:
            revoked_at = None
            if row["revocation_reason"] is not None:
                raise TrustedSessionStoreError(
                    "stored trusted session revocation is invalid"
                )
        else:
            revoked_at = _utc_datetime(row["revoked_at"], "session revoked_at")
            if revoked_at < issued_at:
                raise TrustedSessionStoreError(
                    "stored trusted session revocation is invalid"
                )
            _required_text(row["revocation_reason"], "stored revocation reason")
        if version != use_count + (1 if revoked_at is not None else 0):
            raise TrustedSessionStoreError(
                "stored trusted session version is inconsistent"
            )
        if not hmac.compare_digest(
            binding_digest, _binding_digest(session, max_uses)
        ):
            raise TrustedSessionStoreError(
                "stored trusted session binding digest is invalid"
            )
        return _StoredSession(
            session=session,
            handle_digest=handle_digest,
            binding_digest=binding_digest,
            max_uses=max_uses,
            use_count=use_count,
            revoked_at=revoked_at,
            revocation_reason=row["revocation_reason"],
            version=version,
        )

    @classmethod
    def _load_sessions(
        cls, connection: sqlite3.Connection
    ) -> dict[str, _StoredSession]:
        sessions: dict[str, _StoredSession] = {}
        for row in connection.execute("SELECT * FROM trusted_sessions"):
            stored = cls._stored_session_from_row(row)
            sessions[stored.session.session_id] = stored
        return sessions

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> TrustedSessionSecurityEvent:
        sequence = row["sequence"]
        if type(sequence) is not int or sequence <= 0:
            raise TrustedSessionStoreError("stored security event sequence is invalid")
        event_id = _uuid_text(row["event_id"], "stored security event ID")
        event_type = _required_text(row["event_type"], "stored security event type")
        outcome = _required_text(row["outcome"], "stored security event outcome")
        if event_type not in _EVENT_OUTCOMES or outcome not in _EVENT_OUTCOMES[event_type]:
            raise TrustedSessionStoreError("stored security event decision is invalid")
        session_id = row["session_id"]
        if session_id is not None:
            session_id = _uuid_text(session_id, "stored security event session ID")
        handle_digest = row["handle_digest"]
        if handle_digest is not None:
            handle_digest = _sha256_text(
                handle_digest, "stored security event handle digest"
            )
        binding_digest = row["binding_digest"]
        if binding_digest is not None:
            binding_digest = _sha256_text(
                binding_digest, "stored security event binding digest"
            )
        previous_hash = row["previous_hash"]
        if previous_hash is not None:
            previous_hash = _sha256_text(
                previous_hash, "stored security event previous hash"
            )
        event_hash = _sha256_text(row["event_hash"], "stored security event hash")
        _canonical_object(row["details_json"], "stored security event details")
        return TrustedSessionSecurityEvent(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            occurred_at=_utc_datetime(row["occurred_at"], "security event occurred_at"),
            session_id=session_id,
            handle_digest=handle_digest,
            binding_digest=binding_digest,
            outcome=outcome,
            details_json=row["details_json"],
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    @classmethod
    def _events_from_connection(
        cls, connection: sqlite3.Connection
    ) -> tuple[TrustedSessionSecurityEvent, ...]:
        return tuple(
            cls._event_from_row(row)
            for row in connection.execute(
                "SELECT * FROM trusted_session_security_events ORDER BY sequence"
            )
        )

    @classmethod
    def _verify_audit_chain_only(
        cls, connection: sqlite3.Connection
    ) -> tuple[TrustedSessionSecurityEvent, ...]:
        events = cls._events_from_connection(connection)
        previous_hash: str | None = None
        previous_time: datetime | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous_hash
                or (previous_time is not None and event.occurred_at < previous_time)
                or not hmac.compare_digest(event.event_hash, _event_hash(event))
            ):
                raise TrustedSessionStoreError(
                    "trusted session security event hash chain is invalid"
                )
            previous_hash = event.event_hash
            previous_time = event.occurred_at
        return events

    @classmethod
    def _verify_session_event_bindings(
        cls,
        sessions: dict[str, _StoredSession],
        events: tuple[TrustedSessionSecurityEvent, ...],
    ) -> None:
        by_session: dict[str, list[TrustedSessionSecurityEvent]] = {
            session_id: [] for session_id in sessions
        }
        for event in events:
            if event.session_id is None:
                if event.binding_digest is not None or event.event_type in {
                    "session.issued",
                    "session.resolved",
                    "session.revoked",
                }:
                    raise TrustedSessionStoreError(
                        "trusted session security event binding is invalid"
                    )
                continue
            stored = sessions.get(event.session_id)
            if (
                stored is None
                or event.handle_digest != stored.handle_digest
                or event.binding_digest != stored.binding_digest
            ):
                raise TrustedSessionStoreError(
                    "trusted session security event binding is invalid"
                )
            by_session[event.session_id].append(event)

        for session_id, stored in sessions.items():
            session_events = by_session[session_id]
            issued = [
                event for event in session_events if event.event_type == "session.issued"
            ]
            resolved = [
                event
                for event in session_events
                if event.event_type == "session.resolved"
            ]
            revoked = [
                event for event in session_events if event.event_type == "session.revoked"
            ]
            if (
                len(issued) != 1
                or issued[0].occurred_at != stored.session.issued_at
                or _canonical_object(
                    issued[0].details_json, "session issued event details"
                )
                != {"max_uses": stored.max_uses}
                or len(resolved) != stored.use_count
                or len(revoked) != (1 if stored.revoked_at is not None else 0)
            ):
                raise TrustedSessionStoreError(
                    "trusted session lifecycle evidence is inconsistent"
                )
            for use_number, event in enumerate(resolved, start=1):
                if (
                    _canonical_object(
                        event.details_json, "session resolved event details"
                    )
                    != {"use_number": use_number}
                    or event.occurred_at < stored.session.issued_at
                    or event.occurred_at >= stored.session.expires_at
                ):
                    raise TrustedSessionStoreError(
                        "trusted session resolution evidence is inconsistent"
                    )
            if revoked:
                details = _canonical_object(
                    revoked[0].details_json, "session revoked event details"
                )
                if (
                    revoked[0].occurred_at != stored.revoked_at
                    or details != {"reason": stored.revocation_reason}
                ):
                    raise TrustedSessionStoreError(
                        "trusted session revocation evidence is inconsistent"
                    )

    @classmethod
    def _verify_integrity_connection(cls, connection: sqlite3.Connection) -> None:
        cls._verify_schema(connection)
        cls._verify_sqlite_integrity(connection)
        sessions = cls._load_sessions(connection)
        events = cls._verify_audit_chain_only(connection)
        cls._verify_session_event_bindings(sessions, events)

    @classmethod
    def _append_event(
        cls,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        occurred_at: datetime,
        session: _StoredSession | None,
        handle_digest: str | None,
        outcome: str,
        details: dict[str, Any],
    ) -> TrustedSessionSecurityEvent:
        if event_type not in _EVENT_OUTCOMES or outcome not in _EVENT_OUTCOMES[event_type]:
            raise TrustedSessionStoreError("trusted session security event is invalid")
        details_json = canonical_json(details).decode("utf-8")
        previous = connection.execute(
            "SELECT sequence, occurred_at, event_hash "
            "FROM trusted_session_security_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if previous is None:
            sequence = 1
            previous_hash = None
        else:
            previous_time = _utc_datetime(
                previous["occurred_at"], "security event occurred_at"
            )
            if occurred_at < previous_time:
                raise TrustedSessionStoreError(
                    "trusted session security event clock moved backwards"
                )
            sequence = previous["sequence"] + 1
            previous_hash = previous["event_hash"]
        unsigned = TrustedSessionSecurityEvent(
            sequence=sequence,
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            occurred_at=occurred_at,
            session_id=None if session is None else session.session.session_id,
            handle_digest=(
                session.handle_digest if session is not None else handle_digest
            ),
            binding_digest=None if session is None else session.binding_digest,
            outcome=outcome,
            details_json=details_json,
            previous_hash=previous_hash,
            event_hash="",
        )
        event = replace(unsigned, event_hash=_event_hash(unsigned))
        connection.execute(
            "INSERT INTO trusted_session_security_events("
            "sequence, event_id, event_type, occurred_at, session_id, handle_digest, "
            "binding_digest, outcome, details_json, previous_hash, event_hash"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.sequence,
                event.event_id,
                event.event_type,
                _utc_text(event.occurred_at, "security event occurred_at"),
                event.session_id,
                event.handle_digest,
                event.binding_digest,
                event.outcome,
                event.details_json,
                event.previous_hash,
                event.event_hash,
            ),
        )
        return event

    @staticmethod
    def _candidate_handle_digest(handle: object) -> tuple[str, bool]:
        if isinstance(handle, str) and len(handle) <= 512:
            digest = hashlib.sha256(handle.encode("utf-8")).hexdigest()
            return digest, _HANDLE_PATTERN.fullmatch(handle) is not None
        return hashlib.sha256(b"invalid-non-string-handle").hexdigest(), False

    def issue(
        self,
        identity: TrustedSessionIdentity,
        *,
        ttl_seconds: int,
        max_uses: int = 1,
    ) -> IssuedTrustedSession:
        """Issue a store-generated handle for an already authenticated identity."""

        if type(identity) is not TrustedSessionIdentity:
            raise TrustedSessionStoreError(
                "trusted session identity must be server-established, not request data"
            )
        if (
            type(ttl_seconds) is not int
            or ttl_seconds <= 0
            or ttl_seconds > self.max_ttl_seconds
        ):
            raise TrustedSessionStoreError("trusted session TTL is invalid")
        if (
            type(max_uses) is not int
            or max_uses <= 0
            or max_uses > self.max_session_uses
        ):
            raise TrustedSessionStoreError("trusted session maximum uses is invalid")
        random_value = secrets.token_bytes(_HANDLE_BYTES)
        if type(random_value) is not bytes or len(random_value) != _HANDLE_BYTES:
            raise TrustedSessionStoreError(
                "trusted session random source must return exactly 256 bits"
            )
        handle = base64.urlsafe_b64encode(random_value).rstrip(b"=").decode("ascii")
        if _HANDLE_PATTERN.fullmatch(handle) is None:
            raise TrustedSessionStoreError("generated trusted session handle is invalid")
        handle_digest = hashlib.sha256(handle.encode("ascii")).hexdigest()
        with self._transaction() as connection:
            self._verify_integrity_connection(connection)
            now = self._now()
            try:
                session = TrustedSession(
                    session_id=str(uuid.uuid4()),
                    principal=identity.principal,
                    odoo_instance_id=identity.odoo_instance_id,
                    database_name=identity.database_name,
                    database_uuid=identity.database_uuid,
                    user_id=identity.user_id,
                    company_id=identity.company_id,
                    allowed_company_ids=identity.allowed_company_ids,
                    environment=identity.environment,
                    issued_at=now,
                    expires_at=now + timedelta(seconds=ttl_seconds),
                )
            except AuthorityError as exc:
                raise TrustedSessionStoreError(
                    "trusted session identity is invalid"
                ) from exc
            stored = _StoredSession(
                session=session,
                handle_digest=handle_digest,
                binding_digest=_binding_digest(session, max_uses),
                max_uses=max_uses,
                use_count=0,
                revoked_at=None,
                revocation_reason=None,
                version=0,
            )
            try:
                connection.execute(
                    "INSERT INTO trusted_sessions("
                    "session_id, handle_digest, binding_digest, principal, "
                    "odoo_instance_id, database_name, database_uuid, user_id, "
                    "company_id, allowed_company_ids_json, environment, issued_at, "
                    "expires_at, max_uses, use_count, revoked_at, "
                    "revocation_reason, version"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        session.session_id,
                        handle_digest,
                        stored.binding_digest,
                        session.principal,
                        session.odoo_instance_id,
                        session.database_name,
                        session.database_uuid,
                        session.user_id,
                        session.company_id,
                        _allowed_companies_json(session.allowed_company_ids),
                        session.environment,
                        _utc_text(session.issued_at, "session issued_at"),
                        _utc_text(session.expires_at, "session expires_at"),
                        max_uses,
                        0,
                        None,
                        None,
                        0,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise TrustedSessionStoreError(
                    "trusted session generated identifier collided"
                ) from exc
            self._append_event(
                connection,
                event_type="session.issued",
                occurred_at=now,
                session=stored,
                handle_digest=None,
                outcome="accepted",
                details={"max_uses": max_uses},
            )
            self._verify_integrity_connection(connection)
        return IssuedTrustedSession(handle=handle, session=session, max_uses=max_uses)

    def resolve(self, handle: str) -> TrustedSession | None:
        """Atomically consume one use and return its immutable trusted binding."""

        handle_digest, valid_format = self._candidate_handle_digest(handle)
        with self._transaction() as connection:
            self._verify_integrity_connection(connection)
            now = self._now()
            row = None
            if valid_format:
                row = connection.execute(
                    "SELECT * FROM trusted_sessions WHERE handle_digest=?",
                    (handle_digest,),
                ).fetchone()
            stored = None if row is None else self._stored_session_from_row(row)
            if stored is None:
                outcome = "unknown" if valid_format else "invalid"
            elif now < stored.session.issued_at:
                outcome = "not_yet_valid"
            elif now >= stored.session.expires_at:
                outcome = "expired"
            elif stored.revoked_at is not None:
                outcome = "revoked"
            elif stored.use_count >= stored.max_uses:
                outcome = "exhausted"
            else:
                outcome = "accepted"

            if outcome != "accepted":
                self._append_event(
                    connection,
                    event_type="session.resolve_rejected",
                    occurred_at=now,
                    session=stored,
                    handle_digest=handle_digest,
                    outcome=outcome,
                    details={},
                )
                self._verify_integrity_connection(connection)
                return None

            assert stored is not None
            next_use = stored.use_count + 1
            cursor = connection.execute(
                "UPDATE trusted_sessions SET use_count=?, version=? "
                "WHERE session_id=? AND version=? AND revoked_at IS NULL "
                "AND use_count < max_uses",
                (
                    next_use,
                    stored.version + 1,
                    stored.session.session_id,
                    stored.version,
                ),
            )
            if cursor.rowcount != 1:
                raise TrustedSessionStoreError(
                    "trusted session concurrent resolution was rejected"
                )
            updated = _StoredSession(
                session=stored.session,
                handle_digest=stored.handle_digest,
                binding_digest=stored.binding_digest,
                max_uses=stored.max_uses,
                use_count=next_use,
                revoked_at=None,
                revocation_reason=None,
                version=stored.version + 1,
            )
            self._append_event(
                connection,
                event_type="session.resolved",
                occurred_at=now,
                session=updated,
                handle_digest=None,
                outcome="accepted",
                details={"use_number": next_use},
            )
            self._verify_integrity_connection(connection)
            return stored.session

    def _revoke_stored(
        self,
        connection: sqlite3.Connection,
        *,
        stored: _StoredSession | None,
        handle_digest: str | None,
        now: datetime,
        reason: str,
        invalid: bool = False,
    ) -> bool:
        if stored is None:
            self._append_event(
                connection,
                event_type="session.revoke_rejected",
                occurred_at=now,
                session=None,
                handle_digest=handle_digest,
                outcome="invalid" if invalid else "unknown",
                details={"reason": reason},
            )
            return False
        if stored.revoked_at is not None:
            self._append_event(
                connection,
                event_type="session.revoke_rejected",
                occurred_at=now,
                session=stored,
                handle_digest=None,
                outcome="already_revoked",
                details={"reason": reason},
            )
            return False
        cursor = connection.execute(
            "UPDATE trusted_sessions SET revoked_at=?, revocation_reason=?, version=? "
            "WHERE session_id=? AND version=? AND revoked_at IS NULL",
            (
                _utc_text(now, "session revoked_at"),
                reason,
                stored.version + 1,
                stored.session.session_id,
                stored.version,
            ),
        )
        if cursor.rowcount != 1:
            raise TrustedSessionStoreError(
                "trusted session concurrent revocation was rejected"
            )
        updated = _StoredSession(
            session=stored.session,
            handle_digest=stored.handle_digest,
            binding_digest=stored.binding_digest,
            max_uses=stored.max_uses,
            use_count=stored.use_count,
            revoked_at=now,
            revocation_reason=reason,
            version=stored.version + 1,
        )
        self._append_event(
            connection,
            event_type="session.revoked",
            occurred_at=now,
            session=updated,
            handle_digest=None,
            outcome="accepted",
            details={"reason": reason},
        )
        return True

    def revoke(self, handle: str, *, reason: str) -> bool:
        """Revoke by opaque handle without consuming one of its uses."""

        reason = _required_text(reason, "trusted session revocation reason")
        handle_digest, valid_format = self._candidate_handle_digest(handle)
        with self._transaction() as connection:
            self._verify_integrity_connection(connection)
            now = self._now()
            row = None
            if valid_format:
                row = connection.execute(
                    "SELECT * FROM trusted_sessions WHERE handle_digest=?",
                    (handle_digest,),
                ).fetchone()
            stored = None if row is None else self._stored_session_from_row(row)
            result = self._revoke_stored(
                connection,
                stored=stored,
                handle_digest=handle_digest,
                now=now,
                reason=reason,
                invalid=not valid_format,
            )
            self._verify_integrity_connection(connection)
            return result

    def revoke_session(self, session_id: str, *, reason: str) -> bool:
        """Revoke by the server-generated audit/session identifier."""

        session_id = _uuid_text(session_id, "trusted session ID")
        reason = _required_text(reason, "trusted session revocation reason")
        with self._transaction() as connection:
            self._verify_integrity_connection(connection)
            now = self._now()
            row = connection.execute(
                "SELECT * FROM trusted_sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            stored = None if row is None else self._stored_session_from_row(row)
            result = self._revoke_stored(
                connection,
                stored=stored,
                handle_digest=None,
                now=now,
                reason=reason,
            )
            self._verify_integrity_connection(connection)
            return result

    def security_events(self) -> tuple[TrustedSessionSecurityEvent, ...]:
        with self._read_connection() as connection:
            self._verify_integrity_connection(connection)
            return self._events_from_connection(connection)

    def verify_integrity(self) -> bool:
        with self._read_connection() as connection:
            self._verify_integrity_connection(connection)
        return True


__all__ = [
    "TRUSTED_SESSION_STORE_SCHEMA_VERSION",
    "IssuedTrustedSession",
    "SQLiteTrustedSessionStore",
    "TrustedSessionCommitOutcomeUnknownError",
    "TrustedSessionIdentity",
    "TrustedSessionKnownCommittedError",
    "TrustedSessionReconciliationRequiredError",
    "TrustedSessionSecurityEvent",
    "TrustedSessionStoreError",
]
