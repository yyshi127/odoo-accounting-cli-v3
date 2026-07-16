"""Durable, append-only audit sink for authenticated Broker write attempts.

The sink deliberately accepts a canonical request digest rather than a request
body.  Session handles, signing secrets, and full business parameters therefore
have no persistence path through this API.  Sink failures are never suppressed;
the Broker integration is expected to fail closed when ``append`` raises.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

from .monotonic_deadline import (
    bounded_sqlite_busy_timeout_ms,
    bounded_sqlite_connect_timeout_seconds,
)
from .operations import canonical_json


BROKER_AUDIT_SCHEMA_VERSION = 1

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}\Z")
_ENVIRONMENTS = frozenset({"test", "sandbox", "production"})
_ODOO_EFFECTS = frozenset({"none", "unknown", "verified"})

_TABLES = {
    "broker_audit_schema_meta": """
        CREATE TABLE broker_audit_schema_meta (
            key TEXT PRIMARY KEY CHECK (key = 'schema_version'),
            value TEXT NOT NULL
        ) STRICT
    """,
    "broker_write_attempts": """
        CREATE TABLE broker_write_attempts (
            sequence INTEGER PRIMARY KEY,
            attempt_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            action TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            principal TEXT NOT NULL,
            user_id INTEGER NOT NULL CHECK (user_id > 0),
            company_id INTEGER NOT NULL CHECK (company_id > 0),
            database_name TEXT NOT NULL,
            database_uuid TEXT NOT NULL,
            environment TEXT NOT NULL CHECK (
                environment IN ('test', 'sandbox', 'production')
            ),
            odoo_instance_id TEXT NOT NULL,
            current_release_digest TEXT NOT NULL,
            current_registry_digest TEXT NOT NULL,
            selected_release_digest TEXT,
            selected_registry_digest TEXT,
            operation_id TEXT,
            challenge_id TEXT,
            request_id TEXT,
            outcome_code TEXT NOT NULL,
            odoo_effect TEXT NOT NULL CHECK (
                odoo_effect IN ('none', 'unknown', 'verified')
            ),
            peer_uid INTEGER CHECK (peer_uid IS NULL OR peer_uid >= 0),
            peer_gid INTEGER CHECK (peer_gid IS NULL OR peer_gid >= 0),
            peer_pid INTEGER CHECK (peer_pid IS NULL OR peer_pid > 0),
            payload_json TEXT NOT NULL,
            previous_hash TEXT,
            event_hash TEXT NOT NULL UNIQUE,
            CHECK (
                (selected_release_digest IS NULL
                    AND selected_registry_digest IS NULL)
                OR
                (selected_release_digest IS NOT NULL
                    AND selected_registry_digest IS NOT NULL)
            )
        ) STRICT
    """,
}

_TRIGGERS = {
    "broker_audit_schema_meta_no_update": """
        CREATE TRIGGER broker_audit_schema_meta_no_update
        BEFORE UPDATE ON broker_audit_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'broker audit schema metadata is immutable');
        END
    """,
    "broker_audit_schema_meta_no_delete": """
        CREATE TRIGGER broker_audit_schema_meta_no_delete
        BEFORE DELETE ON broker_audit_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'broker audit schema metadata is immutable');
        END
    """,
    "broker_write_attempts_no_update": """
        CREATE TRIGGER broker_write_attempts_no_update
        BEFORE UPDATE ON broker_write_attempts
        BEGIN
            SELECT RAISE(ABORT, 'broker write attempts are append-only');
        END
    """,
    "broker_write_attempts_no_delete": """
        CREATE TRIGGER broker_write_attempts_no_delete
        BEFORE DELETE ON broker_write_attempts
        BEGIN
            SELECT RAISE(ABORT, 'broker write attempts are append-only');
        END
    """,
}

_EXPECTED_COLUMNS = {
    "broker_audit_schema_meta": ("key", "value"),
    "broker_write_attempts": (
        "sequence",
        "attempt_id",
        "occurred_at",
        "action",
        "request_digest",
        "principal",
        "user_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "current_release_digest",
        "current_registry_digest",
        "selected_release_digest",
        "selected_registry_digest",
        "operation_id",
        "challenge_id",
        "request_id",
        "outcome_code",
        "odoo_effect",
        "peer_uid",
        "peer_gid",
        "peer_pid",
        "payload_json",
        "previous_hash",
        "event_hash",
    ),
}


class BrokerAuditError(RuntimeError):
    """The immutable Broker audit boundary rejected or could not store an event."""


class BrokerAuditConflict(BrokerAuditError):
    """An attempt ID was reused with different immutable content."""


def _required_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise BrokerAuditError(f"{label} is invalid")
    return value


def _required_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerAuditError(f"{label} is invalid")
    return value


def _optional_identifier(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _required_identifier(value, label)


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise BrokerAuditError(f"{label} is invalid")
    return value


def _utc_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BrokerAuditError(f"{label} is invalid")
    try:
        normalized = value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise BrokerAuditError(f"{label} is invalid") from exc
    if normalized.utcoffset() is None:
        raise BrokerAuditError(f"{label} is invalid")
    return normalized


def _utc_text(value: object, label: str) -> str:
    return _utc_datetime(value, label).isoformat()


def _datetime_from_text(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise BrokerAuditError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BrokerAuditError(f"{label} is invalid") from exc
    normalized = _utc_datetime(parsed, label)
    if normalized.isoformat() != value:
        raise BrokerAuditError(f"{label} is not canonical UTC")
    return normalized


def _peer_identifier(value: object, label: str, *, allow_zero: bool) -> int | None:
    if value is None:
        return None
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise BrokerAuditError(f"{label} is invalid")
    return value


def canonical_request_digest(request: Mapping[str, Any]) -> str:
    """Digest one detached canonical request without retaining its contents."""

    if not isinstance(request, Mapping):
        raise BrokerAuditError("broker audit request is invalid")
    try:
        detached = json.loads(canonical_json(dict(request)))
        encoded = canonical_json(detached)
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerAuditError("broker audit request is not canonical JSON") from exc
    if not isinstance(detached, dict):
        raise BrokerAuditError("broker audit request is invalid")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class BrokerWriteAttempt:
    """Safe immutable content accepted by the Broker audit sink."""

    attempt_id: str
    occurred_at: datetime
    action: str
    request_digest: str
    principal: str
    user_id: int
    company_id: int
    database_name: str
    database_uuid: str
    environment: str
    odoo_instance_id: str
    current_release_digest: str
    current_registry_digest: str
    selected_release_digest: str | None
    selected_registry_digest: str | None
    operation_id: str | None
    challenge_id: str | None
    request_id: str | None
    outcome_code: str
    odoo_effect: str
    peer_uid: int | None
    peer_gid: int | None
    peer_pid: int | None

    def __post_init__(self) -> None:
        _required_identifier(self.attempt_id, "broker audit attempt ID")
        object.__setattr__(
            self,
            "occurred_at",
            _utc_datetime(self.occurred_at, "broker audit occurred_at"),
        )
        _required_identifier(self.action, "broker audit action")
        _sha256(self.request_digest, "broker audit request digest")
        _required_text(self.principal, "broker audit principal")
        if type(self.user_id) is not int or self.user_id <= 0:
            raise BrokerAuditError("broker audit user ID is invalid")
        if type(self.company_id) is not int or self.company_id <= 0:
            raise BrokerAuditError("broker audit company ID is invalid")
        _required_text(self.database_name, "broker audit database name")
        try:
            database_uuid = str(uuid.UUID(self.database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise BrokerAuditError("broker audit database UUID is invalid") from exc
        object.__setattr__(self, "database_uuid", database_uuid)
        if self.environment not in _ENVIRONMENTS:
            raise BrokerAuditError("broker audit environment is invalid")
        _required_text(self.odoo_instance_id, "broker audit Odoo instance ID")
        _sha256(self.current_release_digest, "current release digest")
        _sha256(self.current_registry_digest, "current registry digest")
        if (self.selected_release_digest is None) != (
            self.selected_registry_digest is None
        ):
            raise BrokerAuditError("selected release identity is incomplete")
        if self.selected_release_digest is not None:
            _sha256(self.selected_release_digest, "selected release digest")
            _sha256(self.selected_registry_digest, "selected registry digest")
        _optional_identifier(self.operation_id, "broker audit operation ID")
        _optional_identifier(self.challenge_id, "broker audit challenge ID")
        _optional_identifier(self.request_id, "broker audit request ID")
        _required_identifier(self.outcome_code, "broker audit outcome code")
        if self.odoo_effect not in _ODOO_EFFECTS:
            raise BrokerAuditError("broker audit Odoo effect is invalid")
        _peer_identifier(self.peer_uid, "broker audit peer UID", allow_zero=True)
        _peer_identifier(self.peer_gid, "broker audit peer GID", allow_zero=True)
        _peer_identifier(self.peer_pid, "broker audit peer PID", allow_zero=False)


@dataclass(frozen=True, slots=True)
class BrokerWriteAuditEvent(BrokerWriteAttempt):
    """One persisted write-attempt event plus its hash-chain metadata."""

    sequence: int
    previous_hash: str | None
    event_hash: str

    def __post_init__(self) -> None:
        BrokerWriteAttempt.__post_init__(self)
        if type(self.sequence) is not int or self.sequence <= 0:
            raise BrokerAuditError("broker audit sequence is invalid")
        if self.previous_hash is not None:
            _sha256(self.previous_hash, "broker audit previous hash")
        _sha256(self.event_hash, "broker audit event hash")


class BrokerAuditSink(Protocol):
    """Fail-closed persistence contract for an authenticated Broker caller."""

    def append(self, attempt: BrokerWriteAttempt) -> BrokerWriteAuditEvent: ...


def _attempt_payload(attempt: BrokerWriteAttempt) -> dict[str, Any]:
    return {
        "action": attempt.action,
        "attempt_id": attempt.attempt_id,
        "challenge_id": attempt.challenge_id,
        "company_id": attempt.company_id,
        "current_registry_digest": attempt.current_registry_digest,
        "current_release_digest": attempt.current_release_digest,
        "database_name": attempt.database_name,
        "database_uuid": attempt.database_uuid,
        "environment": attempt.environment,
        "occurred_at": _utc_text(attempt.occurred_at, "broker audit occurred_at"),
        "odoo_effect": attempt.odoo_effect,
        "odoo_instance_id": attempt.odoo_instance_id,
        "operation_id": attempt.operation_id,
        "outcome_code": attempt.outcome_code,
        "peer_gid": attempt.peer_gid,
        "peer_pid": attempt.peer_pid,
        "peer_uid": attempt.peer_uid,
        "principal": attempt.principal,
        "request_digest": attempt.request_digest,
        "request_id": attempt.request_id,
        "selected_registry_digest": attempt.selected_registry_digest,
        "selected_release_digest": attempt.selected_release_digest,
        "user_id": attempt.user_id,
    }


def _payload_json(attempt: BrokerWriteAttempt) -> str:
    return canonical_json(_attempt_payload(attempt)).decode("utf-8")


def _event_hash(event: BrokerWriteAuditEvent) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "payload": _attempt_payload(event),
                "previous_hash": event.previous_hash,
                "sequence": event.sequence,
            }
        )
    ).hexdigest()


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split()).replace(
        "CREATE TABLE IF NOT EXISTS", "CREATE TABLE"
    )


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _default_attempt_id() -> str:
    return f"broker-attempt-{uuid.uuid4().hex}"


class SQLiteBrokerAuditSink:
    """Connection-per-call, STRICT SQLite Broker audit implementation."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        clock: Callable[[], datetime] = _default_clock,
        attempt_id_factory: Callable[[], str] = _default_attempt_id,
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:" or not self.path.is_absolute():
            raise BrokerAuditError("broker audit database path must be absolute")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise BrokerAuditError("busy_timeout_ms must be a positive integer")
        if not callable(clock) or not callable(attempt_id_factory):
            raise BrokerAuditError("broker audit factories must be callable")
        self.busy_timeout_ms = busy_timeout_ms
        self._clock = clock
        self._attempt_id_factory = attempt_id_factory
        self._initialize()

    def _secure_database_file(self) -> tuple[int, int]:
        try:
            parent = self.path.parent
            parent_metadata = parent.lstat()
            if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
                raise BrokerAuditError("broker audit parent directory is invalid")
            if os.name == "posix" and (
                parent_metadata.st_uid not in {0, os.geteuid()}
                or parent_metadata.st_mode & 0o022
            ):
                raise BrokerAuditError("broker audit parent directory is not private")
            if not os.path.lexists(self.path):
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(self.path, flags, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
                raise BrokerAuditError(
                    "broker audit database must be a regular non-symlink file"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise BrokerAuditError("broker audit database file is not private")
            self._verify_sidecars()
            return metadata.st_dev, metadata.st_ino
        except BrokerAuditError:
            raise
        except OSError as exc:
            raise BrokerAuditError(
                "broker audit database path cannot be secured"
            ) from exc

    def _verify_database_file(self, expected: tuple[int, int]) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise BrokerAuditError("broker audit database path changed while open")
            self._verify_sidecars()
        except BrokerAuditError:
            raise
        except OSError as exc:
            raise BrokerAuditError(
                "broker audit database path cannot be verified"
            ) from exc

    def _verify_sidecars(self) -> None:
        if os.name != "posix":
            return
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if not os.path.lexists(sidecar):
                continue
            metadata = sidecar.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or sidecar.is_symlink()
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise BrokerAuditError("broker audit SQLite sidecar is not private")

    def _configure(self, connection: sqlite3.Connection, *, write: bool) -> None:
        busy_timeout_ms = bounded_sqlite_busy_timeout_ms(self.busy_timeout_ms)
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if write:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise BrokerAuditError("broker audit requires SQLite WAL mode")
            connection.execute("PRAGMA synchronous = FULL")
        elif str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            raise BrokerAuditError("broker audit requires SQLite WAL mode")
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise BrokerAuditError("broker audit requires SQLite foreign keys")

    @contextmanager
    def _connection(
        self, *, write: bool, verify: bool = True
    ) -> Iterator[sqlite3.Connection]:
        expected = self._secure_database_file()
        connection = sqlite3.connect(
            self.path,
            timeout=bounded_sqlite_connect_timeout_seconds(self.busy_timeout_ms),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            self._configure(connection, write=write)
            if not write:
                connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if verify:
                self._verify_schema(connection)
                self._verify_sqlite_integrity(connection)
                self._events_from_connection(connection, verify_chain=True)
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise BrokerAuditError("broker audit SQLite transaction failed") from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_file(expected)

    def _initialize(self) -> None:
        with self._connection(write=True, verify=False) as connection:
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
                    "INSERT INTO broker_audit_schema_meta(key, value) VALUES(?, ?)",
                    ("schema_version", str(BROKER_AUDIT_SCHEMA_VERSION)),
                )
                for statement in _TRIGGERS.values():
                    connection.execute(statement)
            self._verify_schema(connection)
            self._verify_sqlite_integrity(connection)
            self._events_from_connection(connection, verify_chain=True)

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute(
                "SELECT value FROM broker_audit_schema_meta "
                "WHERE key='schema_version'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise BrokerAuditError("broker audit schema version is missing") from exc
        if (
            version is None
            or version["value"] != str(BROKER_AUDIT_SCHEMA_VERSION)
            or connection.execute(
                "SELECT COUNT(*) FROM broker_audit_schema_meta"
            ).fetchone()[0]
            != 1
        ):
            raise BrokerAuditError("broker audit schema version is unsupported")

        actual_tables = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if set(actual_tables) != set(_TABLES):
            raise BrokerAuditError("broker audit table schema is invalid")
        table_strict = {
            row["name"]: row["strict"]
            for row in connection.execute("PRAGMA table_list")
            if row["name"] in _TABLES
        }
        if table_strict != {name: 1 for name in _TABLES}:
            raise BrokerAuditError("broker audit tables must be STRICT")
        for table, expected_columns in _EXPECTED_COLUMNS.items():
            columns = tuple(
                row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            sql = actual_tables[table]
            if (
                columns != expected_columns
                or not isinstance(sql, str)
                or _normalize_schema_sql(sql)
                != _normalize_schema_sql(_TABLES[table])
            ):
                raise BrokerAuditError("broker audit table schema is invalid")

        actual_triggers = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            )
        }
        if set(actual_triggers) != set(_TRIGGERS) or any(
            not isinstance(actual_triggers[name], str)
            or _normalize_schema_sql(actual_triggers[name])
            != _normalize_schema_sql(statement)
            for name, statement in _TRIGGERS.items()
        ):
            raise BrokerAuditError("broker audit trigger schema is invalid")
        unexpected = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE (type='view' OR (type='index' AND sql IS NOT NULL)) "
            "AND name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        if unexpected is not None:
            raise BrokerAuditError("broker audit schema has unexpected objects")

    @staticmethod
    def _verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
        if tuple(row[0] for row in connection.execute("PRAGMA quick_check")) != ("ok",):
            raise BrokerAuditError("broker audit SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BrokerAuditError("broker audit SQLite foreign key check failed")

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> BrokerWriteAttempt:
        return BrokerWriteAttempt(
            attempt_id=row["attempt_id"],
            occurred_at=_datetime_from_text(row["occurred_at"], "stored occurred_at"),
            action=row["action"],
            request_digest=row["request_digest"],
            principal=row["principal"],
            user_id=row["user_id"],
            company_id=row["company_id"],
            database_name=row["database_name"],
            database_uuid=row["database_uuid"],
            environment=row["environment"],
            odoo_instance_id=row["odoo_instance_id"],
            current_release_digest=row["current_release_digest"],
            current_registry_digest=row["current_registry_digest"],
            selected_release_digest=row["selected_release_digest"],
            selected_registry_digest=row["selected_registry_digest"],
            operation_id=row["operation_id"],
            challenge_id=row["challenge_id"],
            request_id=row["request_id"],
            outcome_code=row["outcome_code"],
            odoo_effect=row["odoo_effect"],
            peer_uid=row["peer_uid"],
            peer_gid=row["peer_gid"],
            peer_pid=row["peer_pid"],
        )

    @classmethod
    def _event_from_row(cls, row: sqlite3.Row) -> BrokerWriteAuditEvent:
        attempt = cls._attempt_from_row(row)
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BrokerAuditError("stored broker audit payload is invalid") from exc
        if (
            not isinstance(payload, dict)
            or canonical_json(payload).decode("utf-8") != row["payload_json"]
            or payload != _attempt_payload(attempt)
        ):
            raise BrokerAuditError("stored broker audit payload is invalid")
        return BrokerWriteAuditEvent(
            **_attempt_payload_for_constructor(attempt),
            sequence=row["sequence"],
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )

    @classmethod
    def _events_from_connection(
        cls, connection: sqlite3.Connection, *, verify_chain: bool
    ) -> tuple[BrokerWriteAuditEvent, ...]:
        events = tuple(
            cls._event_from_row(row)
            for row in connection.execute(
                "SELECT * FROM broker_write_attempts ORDER BY sequence"
            )
        )
        if verify_chain:
            previous_hash: str | None = None
            for expected_sequence, event in enumerate(events, start=1):
                expected_hash = _event_hash(replace(event, event_hash="0" * 64))
                if (
                    event.sequence != expected_sequence
                    or event.previous_hash != previous_hash
                    or not hmac.compare_digest(event.event_hash, expected_hash)
                ):
                    raise BrokerAuditError(
                        "broker audit hash chain verification failed"
                    )
                previous_hash = event.event_hash
        return events

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection, event: BrokerWriteAuditEvent
    ) -> None:
        connection.execute(
            "INSERT INTO broker_write_attempts("
            "sequence, attempt_id, occurred_at, action, request_digest, principal, "
            "user_id, company_id, database_name, database_uuid, environment, "
            "odoo_instance_id, current_release_digest, current_registry_digest, "
            "selected_release_digest, selected_registry_digest, operation_id, "
            "challenge_id, request_id, outcome_code, odoo_effect, peer_uid, "
            "peer_gid, peer_pid, payload_json, previous_hash, event_hash"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.sequence,
                event.attempt_id,
                _utc_text(event.occurred_at, "broker audit occurred_at"),
                event.action,
                event.request_digest,
                event.principal,
                event.user_id,
                event.company_id,
                event.database_name,
                event.database_uuid,
                event.environment,
                event.odoo_instance_id,
                event.current_release_digest,
                event.current_registry_digest,
                event.selected_release_digest,
                event.selected_registry_digest,
                event.operation_id,
                event.challenge_id,
                event.request_id,
                event.outcome_code,
                event.odoo_effect,
                event.peer_uid,
                event.peer_gid,
                event.peer_pid,
                _payload_json(event),
                event.previous_hash,
                event.event_hash,
            ),
        )

    def new_attempt(self, **fields: Any) -> BrokerWriteAttempt:
        """Create a draft using the injected clock and attempt-ID factory."""

        if "attempt_id" in fields or "occurred_at" in fields:
            raise BrokerAuditError(
                "new_attempt owns the broker audit attempt ID and occurred_at"
            )
        return BrokerWriteAttempt(
            attempt_id=self._attempt_id_factory(),
            occurred_at=self._clock(),
            **fields,
        )

    def record(self, **fields: Any) -> BrokerWriteAuditEvent:
        """Create and synchronously append one event; failures propagate."""

        return self.append(self.new_attempt(**fields))

    def append(self, attempt: BrokerWriteAttempt) -> BrokerWriteAuditEvent:
        if not isinstance(attempt, BrokerWriteAttempt) or isinstance(
            attempt, BrokerWriteAuditEvent
        ):
            raise BrokerAuditError("broker write attempt is invalid")
        expected_payload = _payload_json(attempt)
        with self._connection(write=True) as connection:
            duplicate = connection.execute(
                "SELECT * FROM broker_write_attempts WHERE attempt_id=?",
                (attempt.attempt_id,),
            ).fetchone()
            if duplicate is not None:
                existing = self._event_from_row(duplicate)
                if _payload_json(existing) != expected_payload:
                    raise BrokerAuditConflict(
                        "broker audit attempt ID content conflicts"
                    )
                return existing

            tail = connection.execute(
                "SELECT sequence, event_hash "
                "FROM broker_write_attempts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if tail is None:
                sequence = 1
                previous_hash = None
            else:
                sequence = tail["sequence"] + 1
                previous_hash = tail["event_hash"]
            unsigned = BrokerWriteAuditEvent(
                **_attempt_payload_for_constructor(attempt),
                sequence=sequence,
                previous_hash=previous_hash,
                event_hash="0" * 64,
            )
            event = replace(unsigned, event_hash=_event_hash(unsigned))
            self._insert_event(connection, event)
            events = self._events_from_connection(connection, verify_chain=True)
            if not events or events[-1] != event:
                raise BrokerAuditError("broker audit append verification failed")
            return event

    def events(self) -> tuple[BrokerWriteAuditEvent, ...]:
        with self._connection(write=False) as connection:
            return self._events_from_connection(connection, verify_chain=True)

    def verify(self) -> bool:
        with self._connection(write=False) as connection:
            self._events_from_connection(connection, verify_chain=True)
        return True


def _attempt_payload_for_constructor(attempt: BrokerWriteAttempt) -> dict[str, Any]:
    """Return constructor fields without converting ``occurred_at`` to text."""

    payload = _attempt_payload(attempt)
    payload["occurred_at"] = attempt.occurred_at
    return payload


__all__ = [
    "BROKER_AUDIT_SCHEMA_VERSION",
    "BrokerAuditConflict",
    "BrokerAuditError",
    "BrokerAuditSink",
    "BrokerWriteAttempt",
    "BrokerWriteAuditEvent",
    "SQLiteBrokerAuditSink",
    "canonical_request_digest",
]
