"""Durable SQLite primitives for replay, operations, idempotency, and audit.

This module deliberately does not execute Odoo or implement gateway policy.  It
provides the transactional storage invariants those layers need.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .operations import ALLOWED_TRANSITIONS, Operation, State, canonical_json


SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PersistenceError(ValueError):
    pass


class ReplayRejected(PersistenceError):
    pass


class PersistenceIntegrityError(PersistenceError):
    pass


class ConcurrentUpdate(PersistenceError):
    pass


class IdempotencyConflict(PersistenceError):
    pass


class OperationNotFound(PersistenceError):
    pass


@dataclass(frozen=True)
class StoredAuditEvent:
    sequence: int
    event_id: str
    event_type: str
    operation_id: str | None
    occurred_at: datetime
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


_OPERATION_COLUMNS = (
    "operation_id",
    "request_id",
    "capability_id",
    "parameters_json",
    "principal",
    "user_id",
    "company_id",
    "idempotency_key",
    "odoo_instance_id",
    "database_name",
    "database_uuid",
    "environment",
    "registry_digest",
    "release_digest",
    "digest",
    "state",
    "revision",
    "approval_signature",
    "approval_nonce_digest",
    "approval_issued_at",
    "approval_expires_at",
    "approval_revision",
    "approver_user_id",
    "execution_result_digest",
    "verification_result_digest",
)

_IMMUTABLE_OPERATION_FIELDS = _OPERATION_COLUMNS[:15]

_EXPECTED_COLUMNS = {
    "schema_meta": ("key", "value"),
    "consumed_auth_tokens": ("token_id", "request_digest", "expires_at", "consumed_at"),
    "consumed_receipts": ("receipt_id", "request_digest", "observed_at", "consumed_at"),
    "operations": (*_OPERATION_COLUMNS, "record_hash"),
    "idempotency_keys": (
        "odoo_instance_id",
        "database_uuid",
        "environment",
        "company_id",
        "capability_id",
        "scope",
        "idempotency_key",
        "operation_id",
        "operation_digest",
    ),
    "audit_events": (
        "sequence",
        "event_id",
        "event_type",
        "operation_id",
        "occurred_at",
        "payload_json",
        "previous_hash",
        "event_hash",
    ),
}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS consumed_auth_tokens (
        token_id TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
        expires_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS consumed_receipts (
        receipt_id TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
        observed_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        principal TEXT NOT NULL,
        user_id INTEGER NOT NULL CHECK(user_id > 0),
        company_id INTEGER NOT NULL CHECK(company_id > 0),
        idempotency_key TEXT NOT NULL,
        odoo_instance_id TEXT NOT NULL,
        database_name TEXT NOT NULL,
        database_uuid TEXT NOT NULL,
        environment TEXT NOT NULL CHECK(environment IN ('test', 'sandbox', 'production')),
        registry_digest TEXT NOT NULL CHECK(length(registry_digest) = 64),
        release_digest TEXT NOT NULL CHECK(length(release_digest) = 64),
        digest TEXT NOT NULL CHECK(length(digest) = 64),
        state TEXT NOT NULL CHECK(state IN (
            'prepared', 'prechecked', 'awaiting_approval', 'approved', 'executing',
            'verifying', 'completed', 'failed', 'recovering', 'recovered'
        )),
        revision INTEGER NOT NULL CHECK(revision >= 0),
        approval_signature TEXT,
        approval_nonce_digest TEXT,
        approval_issued_at TEXT,
        approval_expires_at TEXT,
        approval_revision INTEGER CHECK(approval_revision IS NULL OR approval_revision >= 0),
        approver_user_id INTEGER CHECK(approver_user_id IS NULL OR approver_user_id > 0),
        execution_result_digest TEXT,
        verification_result_digest TEXT,
        record_hash TEXT NOT NULL CHECK(length(record_hash) = 64)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency_keys (
        odoo_instance_id TEXT NOT NULL,
        database_uuid TEXT NOT NULL,
        environment TEXT NOT NULL,
        company_id INTEGER NOT NULL,
        capability_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation_id TEXT NOT NULL UNIQUE,
        operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
        PRIMARY KEY (
            odoo_instance_id, database_uuid, environment, company_id, capability_id, scope
        ),
        UNIQUE (
            odoo_instance_id, database_uuid, environment, company_id,
            capability_id, idempotency_key
        ),
        FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON DELETE RESTRICT
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        operation_id TEXT,
        occurred_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
        event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash) = 64)
    ) STRICT
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events are append-only');
    END
    """,
)


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise PersistenceError(f"{field} must be a non-empty string of at most 512 characters")
    return value


def _required_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PersistenceError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _utc_text(value: Any, field: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PersistenceError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise PersistenceIntegrityError(f"stored {field} is not a timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PersistenceIntegrityError(f"stored {field} is not a timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise PersistenceIntegrityError(f"stored {field} has no timezone")
    return result


def _optional_datetime_text(value: datetime | None, field: str) -> str | None:
    return None if value is None else _utc_text(value, field)


def _operation_payload(operation: Operation) -> dict[str, Any]:
    try:
        operation.assert_integrity()
        if not isinstance(operation.state, State):
            raise PersistenceError("operation state is invalid")
        if isinstance(operation.revision, bool) or not isinstance(operation.revision, int) or operation.revision < 0:
            raise PersistenceError("operation revision is invalid")
        payload = {
            "operation_id": operation.operation_id,
            "request_id": operation.request_id,
            "capability_id": operation.capability_id,
            "parameters_json": operation.parameters_json,
            "principal": operation.principal,
            "user_id": operation.user_id,
            "company_id": operation.company_id,
            "idempotency_key": operation.idempotency_key,
            "odoo_instance_id": operation.odoo_instance_id,
            "database_name": operation.database_name,
            "database_uuid": operation.database_uuid,
            "environment": operation.environment,
            "registry_digest": operation.registry_digest,
            "release_digest": operation.release_digest,
            "digest": operation.digest,
            "state": operation.state.value,
            "revision": operation.revision,
            "approval_signature": operation.approval_signature,
            "approval_nonce_digest": operation.approval_nonce_digest,
            "approval_issued_at": _optional_datetime_text(
                operation.approval_issued_at, "approval_issued_at"
            ),
            "approval_expires_at": _optional_datetime_text(
                operation.approval_expires_at, "approval_expires_at"
            ),
            "approval_revision": operation.approval_revision,
            "approver_user_id": operation.approver_user_id,
            "execution_result_digest": operation.execution_result_digest,
            "verification_result_digest": operation.verification_result_digest,
        }
    except PersistenceError:
        raise
    except Exception as exc:
        raise PersistenceIntegrityError("operation cannot be serialized safely") from exc

    for field in (
        "approval_signature",
        "approval_nonce_digest",
        "execution_result_digest",
        "verification_result_digest",
    ):
        value = payload[field]
        if value is not None and (
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
        ):
            raise PersistenceIntegrityError(f"operation {field} is invalid")
    for field in ("approval_revision", "approver_user_id"):
        value = payload[field]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < (1 if field == "approver_user_id" else 0)
        ):
            raise PersistenceIntegrityError(f"operation {field} is invalid")
    return payload


def _operation_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _audit_hash(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    operation_id: str | None,
    occurred_at: str,
    payload_json: str,
    previous_hash: str,
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "event_id": event_id,
                "event_type": event_type,
                "occurred_at": occurred_at,
                "operation_id": operation_id,
                "payload_json": payload_json,
                "previous_hash": previous_hash,
                "sequence": sequence,
            }
        )
    ).hexdigest()


def _normalize_schema_sql(value: str) -> str:
    normalized = " ".join(value.split()).lower()
    normalized = normalized.replace("create table if not exists", "create table")
    return normalized.replace("create trigger if not exists", "create trigger")


class SQLitePersistence:
    """One-file SQLite store; every public database call opens a new connection."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise PersistenceError(":memory: cannot be used with connection-per-call persistence")
        if not self.path.is_absolute():
            raise PersistenceError("persistence path must be absolute")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise PersistenceError("busy_timeout_ms must be a positive integer")
        self.busy_timeout_ms = busy_timeout_ms
        self.initialize()

    def _prepare_private_database_file(self) -> tuple[int, int]:
        try:
            parent = self.path.parent
            parent_metadata = parent.lstat()
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent.is_symlink()
                or parent.resolve(strict=True) != parent
            ):
                raise PersistenceError("persistence parent directory is invalid")
            if os.name == "posix" and (
                parent_metadata.st_uid not in {0, os.geteuid()}
                or parent_metadata.st_mode & 0o022
            ):
                raise PersistenceError("persistence parent directory is not private")
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
                raise PersistenceError("persistence database must be a regular non-symlink file")
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise PersistenceError("persistence database file is not private")
            return metadata.st_dev, metadata.st_ino
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceError("persistence database path cannot be secured") from exc

    def _verify_database_and_sidecars(self, expected: tuple[int, int]) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise PersistenceIntegrityError("persistence database path changed while open")
            if os.name == "posix":
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(f"{self.path}{suffix}")
                    if os.path.lexists(sidecar):
                        sidecar_metadata = sidecar.lstat()
                        if (
                            not stat.S_ISREG(sidecar_metadata.st_mode)
                            or sidecar.is_symlink()
                            or sidecar_metadata.st_uid != os.geteuid()
                            or sidecar_metadata.st_mode & 0o077
                        ):
                            raise PersistenceIntegrityError(
                                "persistence SQLite sidecar is not private"
                            )
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceIntegrityError("persistence database path cannot be verified") from exc

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        expected_database = self._prepare_private_database_file()
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise PersistenceError("SQLite WAL mode is required")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise PersistenceError("SQLite foreign keys are required")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_and_sidecars(expected_database)

    def initialize(self) -> None:
        with self._transaction() as connection:
            current_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if current_version not in {0, SCHEMA_VERSION}:
                raise PersistenceIntegrityError("unsupported persistence schema version")
            for statement in _SCHEMA:
                connection.execute(statement)
            connection.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            stored_version = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            if stored_version != str(SCHEMA_VERSION):
                raise PersistenceIntegrityError("persistence schema metadata mismatch")
            for table, expected in _EXPECTED_COLUMNS.items():
                actual = tuple(
                    row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
                )
                if actual != expected:
                    raise PersistenceIntegrityError(f"persistence table schema mismatch: {table}")
            tables = {
                row["name"]: row["sql"]
                for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if set(tables) != set(_EXPECTED_COLUMNS):
                raise PersistenceIntegrityError("persistence table set mismatch")
            expected_table_sql = dict(
                zip(_EXPECTED_COLUMNS, _SCHEMA[: len(_EXPECTED_COLUMNS)], strict=True)
            )
            if any(
                not isinstance(tables[name], str)
                or _normalize_schema_sql(tables[name])
                != _normalize_schema_sql(expected_table_sql[name])
                for name in expected_table_sql
            ):
                raise PersistenceIntegrityError("persistence table schema mismatch")
            expected_triggers = {
                "audit_events_no_update": _SCHEMA[-2],
                "audit_events_no_delete": _SCHEMA[-1],
            }
            actual_triggers = {
                row["name"]: row["sql"]
                for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
                )
            }
            if set(actual_triggers) != set(expected_triggers) or any(
                not isinstance(actual_triggers[name], str)
                or _normalize_schema_sql(actual_triggers[name])
                != _normalize_schema_sql(statement)
                for name, statement in expected_triggers.items()
            ):
                raise PersistenceIntegrityError("persistence trigger schema mismatch")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def consume_auth_token(
        self,
        *,
        token_id: str,
        request_digest: str,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        token_id = _required_text(token_id, "token_id")
        request_digest = _required_digest(request_digest, "request_digest")
        expires_text = _utc_text(expires_at, "expires_at")
        now_text = _utc_text(now, "now")
        if expires_at <= now:
            raise ReplayRejected("authentication token is expired")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT request_digest FROM consumed_auth_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], request_digest):
                    raise ReplayRejected(
                        "authentication token was already consumed for a different request"
                    )
                raise ReplayRejected("authentication token was already consumed")
            connection.execute(
                """
                INSERT INTO consumed_auth_tokens(token_id, request_digest, expires_at, consumed_at)
                VALUES(?, ?, ?, ?)
                """,
                (token_id, request_digest, expires_text, now_text),
            )

    def consume_receipt(
        self,
        *,
        receipt_id: str,
        request_digest: str,
        observed_at: datetime,
        now: datetime,
    ) -> None:
        receipt_id = _required_text(receipt_id, "receipt_id")
        request_digest = _required_digest(request_digest, "request_digest")
        observed_text = _utc_text(observed_at, "observed_at")
        now_text = _utc_text(now, "now")
        if observed_at > now:
            raise ReplayRejected("receipt observation time is in the future")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT request_digest FROM consumed_receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], request_digest):
                    raise ReplayRejected("receipt was already consumed for a different request")
                raise ReplayRejected("receipt was already consumed")
            connection.execute(
                """
                INSERT INTO consumed_receipts(receipt_id, request_digest, observed_at, consumed_at)
                VALUES(?, ?, ?, ?)
                """,
                (receipt_id, request_digest, observed_text, now_text),
            )

    @staticmethod
    def _insert_operation(connection: sqlite3.Connection, operation: Operation) -> None:
        payload = _operation_payload(operation)
        columns = (*_OPERATION_COLUMNS, "record_hash")
        values = tuple(payload[column] for column in _OPERATION_COLUMNS) + (
            _operation_record_hash(payload),
        )
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO operations({', '.join(columns)}) VALUES({placeholders})", values
        )

    @staticmethod
    def _load_operation(connection: sqlite3.Connection, operation_id: str) -> Operation:
        row = connection.execute(
            f"SELECT {', '.join((*_OPERATION_COLUMNS, 'record_hash'))} "
            "FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound("operation does not exist")
        try:
            operation = Operation(
                operation_id=row["operation_id"],
                request_id=row["request_id"],
                capability_id=row["capability_id"],
                parameters_json=row["parameters_json"],
                principal=row["principal"],
                user_id=row["user_id"],
                company_id=row["company_id"],
                idempotency_key=row["idempotency_key"],
                odoo_instance_id=row["odoo_instance_id"],
                database_name=row["database_name"],
                database_uuid=row["database_uuid"],
                environment=row["environment"],
                registry_digest=row["registry_digest"],
                release_digest=row["release_digest"],
                digest=row["digest"],
                state=State(row["state"]),
                revision=row["revision"],
                approval_signature=row["approval_signature"],
                approval_nonce_digest=row["approval_nonce_digest"],
                approval_issued_at=(
                    None
                    if row["approval_issued_at"] is None
                    else _parse_datetime(row["approval_issued_at"], "approval_issued_at")
                ),
                approval_expires_at=(
                    None
                    if row["approval_expires_at"] is None
                    else _parse_datetime(row["approval_expires_at"], "approval_expires_at")
                ),
                approval_revision=row["approval_revision"],
                approver_user_id=row["approver_user_id"],
                execution_result_digest=row["execution_result_digest"],
                verification_result_digest=row["verification_result_digest"],
            )
            payload = _operation_payload(operation)
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceIntegrityError("stored operation is invalid") from exc
        if any(row[column] != payload[column] for column in _OPERATION_COLUMNS):
            raise PersistenceIntegrityError("stored operation representation is not canonical")
        expected_hash = _operation_record_hash(payload)
        if not isinstance(row["record_hash"], str) or not hmac.compare_digest(
            expected_hash, row["record_hash"]
        ):
            raise PersistenceIntegrityError("stored operation record hash mismatch")
        return operation

    def get_operation(self, operation_id: str) -> Operation:
        operation_id = _required_text(operation_id, "operation_id")
        with self._transaction() as connection:
            return self._load_operation(connection, operation_id)

    def get_or_create_operation(
        self, operation: Operation, *, scope: str
    ) -> tuple[Operation, bool]:
        _operation_payload(operation)
        if (
            operation.state != State.PREPARED
            or operation.revision != 0
            or any(
                getattr(operation, field) is not None
                for field in _OPERATION_COLUMNS[17:]
            )
        ):
            raise PersistenceIntegrityError(
                "new operation must be pristine prepared revision zero"
            )
        scope = _required_text(scope, "scope")
        identity = (
            operation.odoo_instance_id,
            operation.database_uuid,
            operation.environment,
            operation.company_id,
            operation.capability_id,
            scope,
        )
        with self._transaction() as connection:
            existing_key = connection.execute(
                """
                SELECT operation_id, operation_digest, idempotency_key
                FROM idempotency_keys
                WHERE odoo_instance_id = ? AND database_uuid = ? AND environment = ?
                  AND company_id = ? AND capability_id = ? AND scope = ?
                """,
                identity,
            ).fetchone()
            if existing_key is not None:
                existing = self._load_operation(connection, existing_key["operation_id"])
                if (
                    not hmac.compare_digest(existing.digest, existing_key["operation_digest"])
                    or not hmac.compare_digest(existing.digest, operation.digest)
                    or existing_key["idempotency_key"] != operation.idempotency_key
                ):
                    raise IdempotencyConflict("idempotency identity has different request content")
                return existing, False
            try:
                self._insert_operation(connection, operation)
                connection.execute(
                    """
                    INSERT INTO idempotency_keys(
                        odoo_instance_id, database_uuid, environment, company_id,
                        capability_id, scope, idempotency_key, operation_id, operation_digest
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *identity,
                        operation.idempotency_key,
                        operation.operation_id,
                        operation.digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IdempotencyConflict("operation or idempotency identity already exists") from exc
            return operation, True

    def cas_update_operation(
        self, operation: Operation, *, expected_revision: int
    ) -> Operation:
        payload = _operation_payload(operation)
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise PersistenceError("expected_revision must be a non-negative integer")
        if operation.revision != expected_revision + 1:
            raise ConcurrentUpdate("operation revision must advance by exactly one")
        if operation.state in {
            State.APPROVED,
            State.EXECUTING,
            State.VERIFYING,
            State.COMPLETED,
            State.RECOVERING,
            State.RECOVERED,
        }:
            raise PersistenceIntegrityError(
                "protected operation transition requires a specialized transactional method"
            )
        with self._transaction() as connection:
            current = self._load_operation(connection, operation.operation_id)
            if current.revision != expected_revision:
                raise ConcurrentUpdate("stored operation revision has changed")
            if any(
                getattr(current, field) != getattr(operation, field)
                for field in _IMMUTABLE_OPERATION_FIELDS
            ):
                raise PersistenceIntegrityError("operation immutable fields changed during CAS")
            if operation.state not in ALLOWED_TRANSITIONS[current.state]:
                raise PersistenceIntegrityError("operation CAS contains an invalid state transition")
            mutable_columns = _OPERATION_COLUMNS[1:]
            assignments = ", ".join(f"{column} = ?" for column in mutable_columns)
            values = tuple(payload[column] for column in mutable_columns) + (
                _operation_record_hash(payload),
                operation.operation_id,
                expected_revision,
            )
            cursor = connection.execute(
                f"UPDATE operations SET {assignments}, record_hash = ? "
                "WHERE operation_id = ? AND revision = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdate("stored operation revision has changed")
            return self._load_operation(connection, operation.operation_id)

    def append_audit_event(
        self,
        *,
        event_id: str,
        event_type: str,
        operation_id: str | None,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> StoredAuditEvent:
        event_id = _required_text(event_id, "event_id")
        event_type = _required_text(event_type, "event_type")
        if operation_id is not None:
            operation_id = _required_text(operation_id, "operation_id")
        if not isinstance(payload, dict):
            raise PersistenceError("audit payload must be an object")
        payload_json = canonical_json(payload).decode("utf-8")
        occurred_text = _utc_text(occurred_at, "occurred_at")
        with self._transaction() as connection:
            last = connection.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if last is None else last["sequence"] + 1
            previous_hash = GENESIS_HASH if last is None else last["event_hash"]
            event_hash = _audit_hash(
                sequence=sequence,
                event_id=event_id,
                event_type=event_type,
                operation_id=operation_id,
                occurred_at=occurred_text,
                payload_json=payload_json,
                previous_hash=previous_hash,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO audit_events(
                        sequence, event_id, event_type, operation_id, occurred_at,
                        payload_json, previous_hash, event_hash
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sequence,
                        event_id,
                        event_type,
                        operation_id,
                        occurred_text,
                        payload_json,
                        previous_hash,
                        event_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise PersistenceError("audit event identity already exists") from exc
            return StoredAuditEvent(
                sequence=sequence,
                event_id=event_id,
                event_type=event_type,
                operation_id=operation_id,
                occurred_at=_parse_datetime(occurred_text, "occurred_at"),
                payload=json.loads(payload_json),
                previous_hash=previous_hash,
                event_hash=event_hash,
            )

    @staticmethod
    def _load_audit_events(connection: sqlite3.Connection) -> tuple[StoredAuditEvent, ...]:
        result = []
        for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            try:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict) or canonical_json(payload).decode("utf-8") != row["payload_json"]:
                    raise PersistenceIntegrityError("audit payload is not canonical")
                result.append(
                    StoredAuditEvent(
                        sequence=row["sequence"],
                        event_id=row["event_id"],
                        event_type=row["event_type"],
                        operation_id=row["operation_id"],
                        occurred_at=_parse_datetime(row["occurred_at"], "occurred_at"),
                        payload=payload,
                        previous_hash=row["previous_hash"],
                        event_hash=row["event_hash"],
                    )
                )
            except PersistenceError:
                raise
            except Exception as exc:
                raise PersistenceIntegrityError("stored audit event is invalid") from exc
        return tuple(result)

    def audit_events(self) -> tuple[StoredAuditEvent, ...]:
        with self._transaction() as connection:
            return self._load_audit_events(connection)

    def verify_chain(self) -> int:
        with self._transaction() as connection:
            events = self._load_audit_events(connection)
        previous_hash = GENESIS_HASH
        for expected_sequence, event in enumerate(events, start=1):
            occurred_text = _utc_text(event.occurred_at, "occurred_at")
            payload_json = canonical_json(event.payload).decode("utf-8")
            expected_hash = _audit_hash(
                sequence=event.sequence,
                event_id=event.event_id,
                event_type=event.event_type,
                operation_id=event.operation_id,
                occurred_at=occurred_text,
                payload_json=payload_json,
                previous_hash=event.previous_hash,
            )
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous_hash
                or not isinstance(event.event_hash, str)
                or not hmac.compare_digest(event.event_hash, expected_hash)
            ):
                raise PersistenceIntegrityError("audit hash chain verification failed")
            previous_hash = event.event_hash
        return len(events)


__all__ = [
    "ConcurrentUpdate",
    "GENESIS_HASH",
    "IdempotencyConflict",
    "OperationNotFound",
    "PersistenceError",
    "PersistenceIntegrityError",
    "ReplayRejected",
    "SCHEMA_VERSION",
    "SQLitePersistence",
    "StoredAuditEvent",
]
