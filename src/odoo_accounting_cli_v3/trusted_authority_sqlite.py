"""Durable SQLite adapter for the trusted approval authority.

The adapter owns no signing or session secrets.  It persists only immutable
operations, approval challenges, signed approval envelopes, nonce digests, and
append-only authority audit events.  Every mutation uses a separate
``BEGIN IMMEDIATE`` transaction so independent authority processes share the
same uniqueness and optimistic-concurrency boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .monotonic_deadline import (
    bounded_sqlite_busy_timeout_ms,
    bounded_sqlite_connect_timeout_seconds,
)
from .operations import (
    APPROVAL_PURPOSE,
    APPROVAL_SIGNATURE_VERSION,
    Approval,
    Operation,
    canonical_json,
)
from .trusted_authority import (
    ApprovalChallenge,
    ApprovalChallengeState,
    AuthorityAuditDraft,
    AuthorityAuditEvent,
    AuthorityConcurrentUpdate,
    AuthorityError,
    _audit_hash,
    _operation_binding_digest,
)
from .write_protocol import (
    approval_from_mapping,
    approval_to_mapping,
    operation_from_mapping,
    operation_to_mapping,
)


AUTHORITY_STORE_SCHEMA_VERSION = 1


_TABLES = {
    "authority_schema_meta": """
        CREATE TABLE authority_schema_meta (
            key TEXT PRIMARY KEY CHECK (key = 'schema_version'),
            value TEXT NOT NULL
        )
    """,
    "approval_challenges": """
        CREATE TABLE approval_challenges (
            challenge_id TEXT PRIMARY KEY,
            binding_digest TEXT NOT NULL UNIQUE,
            operation_id TEXT NOT NULL,
            operation_revision INTEGER NOT NULL,
            operation_json TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds > 0),
            state TEXT NOT NULL CHECK (
                state IN ('pending', 'approved', 'denied', 'expired', 'stale')
            ),
            version INTEGER NOT NULL CHECK (version >= 0),
            decided_at TEXT,
            decider_user_id INTEGER,
            denial_reason TEXT,
            approval_json TEXT,
            approval_nonce_digest TEXT UNIQUE,
            UNIQUE (operation_id, operation_revision),
            CHECK (
                (state = 'pending' AND version = 0 AND decided_at IS NULL
                    AND decider_user_id IS NULL AND denial_reason IS NULL
                    AND approval_json IS NULL AND approval_nonce_digest IS NULL)
                OR
                (state = 'approved' AND version > 0 AND decided_at IS NOT NULL
                    AND decider_user_id > 0 AND denial_reason IS NULL
                    AND approval_json IS NOT NULL
                    AND approval_nonce_digest IS NOT NULL)
                OR
                (state = 'denied' AND version > 0 AND decided_at IS NOT NULL
                    AND decider_user_id > 0 AND length(denial_reason) > 0
                    AND approval_json IS NULL AND approval_nonce_digest IS NULL)
                OR
                (state IN ('expired', 'stale') AND version > 0
                    AND decided_at IS NOT NULL AND decider_user_id IS NULL
                    AND denial_reason IS NULL AND approval_json IS NULL
                    AND approval_nonce_digest IS NULL)
            )
        )
    """,
    "authority_audit_events": """
        CREATE TABLE authority_audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            challenge_id TEXT,
            operation_id TEXT,
            binding_digest TEXT,
            actor_user_id INTEGER NOT NULL CHECK (actor_user_id > 0),
            payload_json TEXT NOT NULL,
            previous_hash TEXT,
            event_hash TEXT NOT NULL,
            FOREIGN KEY (challenge_id) REFERENCES approval_challenges(challenge_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        )
    """,
}


_TRIGGERS = {
    "authority_schema_meta_no_update": """
        CREATE TRIGGER authority_schema_meta_no_update
        BEFORE UPDATE ON authority_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'authority schema metadata is immutable');
        END
    """,
    "authority_schema_meta_no_delete": """
        CREATE TRIGGER authority_schema_meta_no_delete
        BEFORE DELETE ON authority_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'authority schema metadata is immutable');
        END
    """,
    "approval_challenges_no_delete": """
        CREATE TRIGGER approval_challenges_no_delete
        BEFORE DELETE ON approval_challenges
        BEGIN
            SELECT RAISE(ABORT, 'approval challenges cannot be deleted');
        END
    """,
    "approval_challenges_immutable": """
        CREATE TRIGGER approval_challenges_immutable
        BEFORE UPDATE ON approval_challenges
        WHEN NEW.challenge_id IS NOT OLD.challenge_id
          OR NEW.binding_digest IS NOT OLD.binding_digest
          OR NEW.operation_id IS NOT OLD.operation_id
          OR NEW.operation_revision IS NOT OLD.operation_revision
          OR NEW.operation_json IS NOT OLD.operation_json
          OR NEW.issued_at IS NOT OLD.issued_at
          OR NEW.expires_at IS NOT OLD.expires_at
          OR NEW.ttl_seconds IS NOT OLD.ttl_seconds
        BEGIN
            SELECT RAISE(ABORT, 'approval challenge immutable content changed');
        END
    """,
    "approval_challenges_one_transition": """
        CREATE TRIGGER approval_challenges_one_transition
        BEFORE UPDATE ON approval_challenges
        WHEN OLD.state != 'pending'
          OR NEW.state = 'pending'
          OR NEW.version != OLD.version + 1
        BEGIN
            SELECT RAISE(ABORT, 'approval challenge transition is invalid');
        END
    """,
    "authority_audit_events_no_update": """
        CREATE TRIGGER authority_audit_events_no_update
        BEFORE UPDATE ON authority_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'authority audit events are append-only');
        END
    """,
    "authority_audit_events_no_delete": """
        CREATE TRIGGER authority_audit_events_no_delete
        BEFORE DELETE ON authority_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'authority audit events are append-only');
        END
    """,
}


_EXPECTED_COLUMNS = {
    "authority_schema_meta": ("key", "value"),
    "approval_challenges": (
        "challenge_id",
        "binding_digest",
        "operation_id",
        "operation_revision",
        "operation_json",
        "issued_at",
        "expires_at",
        "ttl_seconds",
        "state",
        "version",
        "decided_at",
        "decider_user_id",
        "denial_reason",
        "approval_json",
        "approval_nonce_digest",
    ),
    "authority_audit_events": (
        "sequence",
        "event_id",
        "event_type",
        "occurred_at",
        "challenge_id",
        "operation_id",
        "binding_digest",
        "actor_user_id",
        "payload_json",
        "previous_hash",
        "event_hash",
    ),
}


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split()).replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")


def _required_identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AuthorityError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AuthorityError(f"{label} is invalid")
    return value


def _utc_text(value: object, label: str) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise AuthorityError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _utc_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise AuthorityError(f"stored {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthorityError(f"stored {label} is invalid") from exc
    if _utc_text(parsed, label) != value:
        raise AuthorityError(f"stored {label} is not canonical UTC")
    return parsed.astimezone(timezone.utc)


def _canonical_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise AuthorityError(f"{label} is invalid")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AuthorityError(f"{label} is invalid") from exc
    if (
        not isinstance(parsed, dict)
        or canonical_json(parsed).decode("utf-8") != value
    ):
        raise AuthorityError(f"{label} is not canonical")
    return parsed


def _operation_json(operation: Operation) -> str:
    try:
        mapping = operation_to_mapping(operation)
        return canonical_json(mapping).decode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorityError("approval challenge operation is invalid") from exc


def _operation_from_json(value: object) -> Operation:
    mapping = _canonical_object(value, "stored operation JSON")
    try:
        return operation_from_mapping(mapping)
    except (TypeError, ValueError) as exc:
        raise AuthorityError("stored approval challenge operation is invalid") from exc


def _approval_json(approval: Approval | None) -> str | None:
    if approval is None:
        return None
    try:
        return canonical_json(approval_to_mapping(approval)).decode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorityError("approval challenge approval is invalid") from exc


def _approval_from_json(value: object) -> Approval | None:
    if value is None:
        return None
    mapping = _canonical_object(value, "stored approval JSON")
    try:
        return approval_from_mapping(mapping)
    except (TypeError, ValueError) as exc:
        raise AuthorityError("stored approval challenge approval is invalid") from exc


def _approval_nonce_digest(approval: Approval | None) -> str | None:
    if approval is None:
        return None
    if not isinstance(approval.nonce, str) or not approval.nonce:
        raise AuthorityError("approval nonce is invalid")
    return hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest()


def _validate_approval_binding(challenge: ApprovalChallenge) -> None:
    approval = challenge.approval
    if approval is None:
        return
    operation = challenge.operation
    if (
        approval.operation_id != operation.operation_id
        or approval.request_id != operation.request_id
        or approval.operation_digest != operation.digest
        or approval.precheck_digest != operation.precheck_digest
        or approval.user_id != operation.user_id
        or approval.company_id != operation.company_id
        or approval.operation_revision != operation.revision
        or approval.approver_user_id != challenge.decider_user_id
        or approval.issued_at != challenge.decided_at
        or approval.expires_at != challenge.expires_at
        or not isinstance(approval.key_id, str)
        or not approval.key_id.strip()
        or approval.signature_version != APPROVAL_SIGNATURE_VERSION
        or approval.signature_purpose != APPROVAL_PURPOSE
        or not isinstance(approval.signature, str)
        or len(approval.signature) != 64
        or any(character not in "0123456789abcdef" for character in approval.signature)
    ):
        raise AuthorityError("approval is not bound to its challenge and operation")
    _approval_nonce_digest(approval)


def _immutable_challenge_fields(challenge: ApprovalChallenge) -> tuple[Any, ...]:
    return (
        challenge.challenge_id,
        challenge.binding_digest,
        challenge.operation,
        challenge.issued_at,
        challenge.expires_at,
        challenge.ttl_seconds,
    )


class SQLiteApprovalChallengeStore:
    """Connection-per-call durable implementation of ``ApprovalChallengeStore``."""

    def __init__(
        self, path: str | Path, *, busy_timeout_ms: int = 5_000
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:" or not self.path.is_absolute():
            raise AuthorityError("authority store database path must be absolute")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise AuthorityError("busy_timeout_ms must be a positive integer")
        self.busy_timeout_ms = busy_timeout_ms
        self._initialize()

    def _secure_database_file(self) -> tuple[int, int]:
        try:
            parent = self.path.parent
            parent_metadata = parent.lstat()
            if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
                raise AuthorityError("authority store parent directory is invalid")
            if os.name == "posix" and (
                parent_metadata.st_uid not in {0, os.geteuid()}
                or parent_metadata.st_mode & 0o022
            ):
                raise AuthorityError("authority store parent directory is not private")
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
                raise AuthorityError(
                    "authority store database must be a regular non-symlink file"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise AuthorityError("authority store database file is not private")
            self._verify_sidecars()
            return metadata.st_dev, metadata.st_ino
        except AuthorityError:
            raise
        except OSError as exc:
            raise AuthorityError("authority store database path cannot be secured") from exc

    def _verify_database_file(self, expected: tuple[int, int]) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise AuthorityError("authority store database path changed while open")
            self._verify_sidecars()
        except AuthorityError:
            raise
        except OSError as exc:
            raise AuthorityError("authority store database path cannot be verified") from exc

    def _verify_sidecars(self) -> None:
        if os.name != "posix":
            return
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if not os.path.lexists(sidecar):
                continue
            sidecar_metadata = sidecar.lstat()
            if (
                not stat.S_ISREG(sidecar_metadata.st_mode)
                or sidecar.is_symlink()
                or sidecar_metadata.st_uid != os.geteuid()
                or sidecar_metadata.st_mode & 0o077
            ):
                raise AuthorityError("authority store SQLite sidecar is not private")

    def _configure(self, connection: sqlite3.Connection, *, write: bool) -> None:
        busy_timeout_ms = bounded_sqlite_busy_timeout_ms(self.busy_timeout_ms)
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if write:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise AuthorityError("authority store requires SQLite WAL mode")
            connection.execute("PRAGMA synchronous = FULL")
        elif str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            raise AuthorityError("authority store requires SQLite WAL mode")
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise AuthorityError("authority store requires SQLite foreign keys")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        expected = self._secure_database_file()
        connection = sqlite3.connect(
            self.path,
            timeout=bounded_sqlite_connect_timeout_seconds(self.busy_timeout_ms),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            self._configure(connection, write=True)
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise AuthorityError("authority store SQLite transaction failed") from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_file(expected)

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
            raise AuthorityError("authority store SQLite read failed") from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            self._verify_database_file(expected)

    def _initialize(self) -> None:
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
                    "INSERT INTO authority_schema_meta(key, value) VALUES(?, ?)",
                    ("schema_version", str(AUTHORITY_STORE_SCHEMA_VERSION)),
                )
                for statement in _TRIGGERS.values():
                    connection.execute(statement)
            self._verify_schema(connection)
            self._verify_sqlite_integrity(connection)
            self._verify_challenge_records(connection)
            self._verify_audit_chain_connection(connection)

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute(
                "SELECT value FROM authority_schema_meta "
                "WHERE key='schema_version'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise AuthorityError("authority store schema version is missing") from exc
        if (
            version is None
            or version["value"] != str(AUTHORITY_STORE_SCHEMA_VERSION)
            or connection.execute(
                "SELECT COUNT(*) FROM authority_schema_meta"
            ).fetchone()[0]
            != 1
        ):
            raise AuthorityError("authority store schema version is unsupported")

        actual_tables = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if set(actual_tables) != set(_TABLES):
            raise AuthorityError("authority store table schema is invalid")
        for table, expected_columns in _EXPECTED_COLUMNS.items():
            columns = tuple(
                row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if columns != expected_columns:
                raise AuthorityError("authority store table schema is invalid")
            if (
                not isinstance(actual_tables[table], str)
                or _normalize_schema_sql(actual_tables[table])
                != _normalize_schema_sql(_TABLES[table])
            ):
                raise AuthorityError("authority store table schema is invalid")

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
            raise AuthorityError("authority store trigger schema is invalid")

        unexpected = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE (type='view' OR (type='index' AND sql IS NOT NULL)) "
            "AND name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        if unexpected is not None:
            raise AuthorityError("authority store schema has unexpected objects")

    @staticmethod
    def _verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
        if tuple(row[0] for row in connection.execute("PRAGMA quick_check")) != ("ok",):
            raise AuthorityError("authority store SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise AuthorityError("authority store SQLite foreign key check failed")

    @staticmethod
    def _validate_new_challenge(challenge: ApprovalChallenge) -> str:
        if not isinstance(challenge, ApprovalChallenge):
            raise AuthorityError("new approval challenge is invalid")
        if (
            challenge.state is not ApprovalChallengeState.PENDING
            or challenge.version != 0
            or challenge.binding_digest != _operation_binding_digest(challenge.operation)
        ):
            raise AuthorityError("new approval challenge is invalid")
        _validate_approval_binding(challenge)
        return _operation_json(challenge.operation)

    @staticmethod
    def _validate_event(event: AuthorityAuditDraft) -> None:
        if not isinstance(event, AuthorityAuditDraft):
            raise AuthorityError("authority audit event is invalid")
        _required_identifier(event.event_id, "authority audit event ID")
        _required_identifier(event.event_type, "authority audit event type")
        _utc_text(event.occurred_at, "authority audit occurred_at")
        if type(event.actor_user_id) is not int or event.actor_user_id <= 0:
            raise AuthorityError("authority audit event metadata is invalid")
        if event.challenge_id is not None:
            _required_identifier(event.challenge_id, "authority audit challenge ID")
        if event.operation_id is not None:
            _required_identifier(event.operation_id, "authority audit operation ID")
        if event.binding_digest is not None:
            _sha256(event.binding_digest, "authority audit binding digest")
        _canonical_object(event.payload_json, "authority audit payload")

    @staticmethod
    def _validate_bound_event(
        challenge: ApprovalChallenge, event: AuthorityAuditDraft
    ) -> None:
        if (
            event.challenge_id != challenge.challenge_id
            or event.operation_id != challenge.operation.operation_id
            or event.binding_digest != challenge.binding_digest
        ):
            raise AuthorityError("challenge audit binding is invalid")

    @staticmethod
    def _challenge_from_row(row: sqlite3.Row) -> ApprovalChallenge:
        operation = _operation_from_json(row["operation_json"])
        approval = _approval_from_json(row["approval_json"])
        try:
            state = ApprovalChallengeState(row["state"])
            challenge = ApprovalChallenge(
                challenge_id=row["challenge_id"],
                binding_digest=row["binding_digest"],
                operation=operation,
                issued_at=_utc_datetime(row["issued_at"], "challenge issued_at"),
                expires_at=_utc_datetime(row["expires_at"], "challenge expires_at"),
                ttl_seconds=row["ttl_seconds"],
                state=state,
                version=row["version"],
                decided_at=(
                    None
                    if row["decided_at"] is None
                    else _utc_datetime(row["decided_at"], "challenge decided_at")
                ),
                decider_user_id=row["decider_user_id"],
                denial_reason=row["denial_reason"],
                approval=approval,
            )
        except (TypeError, ValueError) as exc:
            raise AuthorityError("stored approval challenge is invalid") from exc
        if (
            row["operation_id"] != operation.operation_id
            or row["operation_revision"] != operation.revision
            or challenge.binding_digest != _operation_binding_digest(operation)
        ):
            raise AuthorityError("stored approval challenge binding is invalid")
        expected_nonce_digest = _approval_nonce_digest(approval)
        if row["approval_nonce_digest"] != expected_nonce_digest:
            raise AuthorityError("stored approval nonce digest is invalid")
        _validate_approval_binding(challenge)
        return challenge

    @classmethod
    def _load_challenge(
        cls, connection: sqlite3.Connection, challenge_id: str
    ) -> ApprovalChallenge:
        row = connection.execute(
            "SELECT * FROM approval_challenges WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            raise AuthorityError("approval challenge is unknown")
        return cls._challenge_from_row(row)

    @classmethod
    def _events_from_connection(
        cls, connection: sqlite3.Connection
    ) -> tuple[AuthorityAuditEvent, ...]:
        events: list[AuthorityAuditEvent] = []
        for row in connection.execute(
            "SELECT * FROM authority_audit_events ORDER BY sequence"
        ):
            payload = _canonical_object(row["payload_json"], "stored authority audit payload")
            del payload
            event = AuthorityAuditEvent(
                sequence=row["sequence"],
                event_id=_required_identifier(
                    row["event_id"], "stored authority audit event ID"
                ),
                event_type=_required_identifier(
                    row["event_type"], "stored authority audit event type"
                ),
                occurred_at=_utc_datetime(
                    row["occurred_at"], "authority audit occurred_at"
                ),
                challenge_id=row["challenge_id"],
                operation_id=row["operation_id"],
                binding_digest=row["binding_digest"],
                actor_user_id=row["actor_user_id"],
                payload_json=row["payload_json"],
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )
            cls._validate_loaded_event(event)
            events.append(event)
        return tuple(events)

    @staticmethod
    def _validate_loaded_event(event: AuthorityAuditEvent) -> None:
        if type(event.actor_user_id) is not int or event.actor_user_id <= 0:
            raise AuthorityError("stored authority audit event metadata is invalid")
        if event.challenge_id is not None:
            _required_identifier(event.challenge_id, "stored authority audit challenge ID")
        if event.operation_id is not None:
            _required_identifier(event.operation_id, "stored authority audit operation ID")
        if event.binding_digest is not None:
            _sha256(event.binding_digest, "stored authority audit binding digest")
        if event.previous_hash is not None:
            _sha256(event.previous_hash, "stored authority audit previous hash")
        _sha256(event.event_hash, "stored authority audit event hash")

    @classmethod
    def _verify_audit_chain_connection(cls, connection: sqlite3.Connection) -> int:
        previous_hash: str | None = None
        previous_time: datetime | None = None
        events = cls._events_from_connection(connection)
        for expected_sequence, event in enumerate(events, start=1):
            expected_hash = _audit_hash(replace(event, event_hash=""))
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous_hash
                or (previous_time is not None and event.occurred_at < previous_time)
                or not hmac.compare_digest(event.event_hash, expected_hash)
            ):
                raise AuthorityError("authority audit hash chain verification failed")
            previous_hash = event.event_hash
            previous_time = event.occurred_at
        return len(events)

    @classmethod
    def _verify_challenge_records(cls, connection: sqlite3.Connection) -> int:
        rows = tuple(connection.execute("SELECT * FROM approval_challenges"))
        for row in rows:
            cls._challenge_from_row(row)
        return len(rows)

    @classmethod
    def _append_event(
        cls, connection: sqlite3.Connection, draft: AuthorityAuditDraft
    ) -> AuthorityAuditEvent:
        cls._verify_audit_chain_connection(connection)
        cls._verify_schema(connection)
        if connection.execute(
            "SELECT 1 FROM authority_audit_events WHERE event_id=?", (draft.event_id,)
        ).fetchone() is not None:
            raise AuthorityError("authority audit event ID already exists")
        if draft.challenge_id is not None and connection.execute(
            "SELECT 1 FROM approval_challenges WHERE challenge_id=?",
            (draft.challenge_id,),
        ).fetchone() is None:
            raise AuthorityError("authority audit challenge is unknown")
        previous = connection.execute(
            "SELECT sequence, occurred_at, event_hash FROM authority_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        occurred_at = draft.occurred_at.astimezone(timezone.utc)
        if previous is None:
            sequence = 1
            previous_hash = None
        else:
            previous_time = _utc_datetime(
                previous["occurred_at"], "authority audit occurred_at"
            )
            if occurred_at < previous_time:
                raise AuthorityError("authority audit time moved backwards")
            sequence = previous["sequence"] + 1
            previous_hash = previous["event_hash"]
        unsigned = AuthorityAuditEvent(
            sequence=sequence,
            event_id=draft.event_id,
            event_type=draft.event_type,
            occurred_at=occurred_at,
            challenge_id=draft.challenge_id,
            operation_id=draft.operation_id,
            binding_digest=draft.binding_digest,
            actor_user_id=draft.actor_user_id,
            payload_json=draft.payload_json,
            previous_hash=previous_hash,
            event_hash="",
        )
        event = replace(unsigned, event_hash=_audit_hash(unsigned))
        connection.execute(
            "INSERT INTO authority_audit_events("
            "sequence, event_id, event_type, occurred_at, challenge_id, operation_id, "
            "binding_digest, actor_user_id, payload_json, previous_hash, event_hash"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.sequence,
                event.event_id,
                event.event_type,
                _utc_text(event.occurred_at, "authority audit occurred_at"),
                event.challenge_id,
                event.operation_id,
                event.binding_digest,
                event.actor_user_id,
                event.payload_json,
                event.previous_hash,
                event.event_hash,
            ),
        )
        return event

    @staticmethod
    def _insert_challenge(
        connection: sqlite3.Connection,
        challenge: ApprovalChallenge,
        operation_json: str,
    ) -> None:
        connection.execute(
            "INSERT INTO approval_challenges("
            "challenge_id, binding_digest, operation_id, operation_revision, "
            "operation_json, issued_at, expires_at, ttl_seconds, state, version, "
            "decided_at, decider_user_id, denial_reason, approval_json, "
            "approval_nonce_digest"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                challenge.challenge_id,
                challenge.binding_digest,
                challenge.operation.operation_id,
                challenge.operation.revision,
                operation_json,
                _utc_text(challenge.issued_at, "challenge issued_at"),
                _utc_text(challenge.expires_at, "challenge expires_at"),
                challenge.ttl_seconds,
                challenge.state.value,
                challenge.version,
                None,
                None,
                None,
                None,
                None,
            ),
        )

    def get_challenge(self, challenge_id: str) -> ApprovalChallenge:
        _required_identifier(challenge_id, "approval challenge ID")
        with self._read_connection() as connection:
            return self._load_challenge(connection, challenge_id)

    def find_challenge(self, challenge_id: str) -> ApprovalChallenge | None:
        """Resolve an optional challenge without masking store corruption.

        Unknown is the only condition returned as ``None``.  Schema, record,
        SQLite, or audit-chain failures remain exceptions so a route resolver
        can fail closed instead of treating a damaged release store as absent.
        """

        _required_identifier(challenge_id, "approval challenge ID")
        with self._read_connection() as connection:
            self._verify_schema(connection)
            self._verify_sqlite_integrity(connection)
            self._verify_challenge_records(connection)
            self._verify_audit_chain_connection(connection)
            row = connection.execute(
                "SELECT * FROM approval_challenges WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            return None if row is None else self._challenge_from_row(row)

    def find_by_binding(self, binding_digest: str) -> ApprovalChallenge | None:
        _sha256(binding_digest, "approval challenge binding digest")
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM approval_challenges WHERE binding_digest=?",
                (binding_digest,),
            ).fetchone()
            return None if row is None else self._challenge_from_row(row)

    def find_by_operation_revision(
        self, operation_id: str, revision: int
    ) -> ApprovalChallenge | None:
        _required_identifier(operation_id, "operation ID")
        if type(revision) is not int or revision < 0:
            raise AuthorityError("operation revision is invalid")
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM approval_challenges "
                "WHERE operation_id=? AND operation_revision=?",
                (operation_id, revision),
            ).fetchone()
            return None if row is None else self._challenge_from_row(row)

    def challenges(self) -> tuple[ApprovalChallenge, ...]:
        with self._read_connection() as connection:
            return tuple(
                self._challenge_from_row(row)
                for row in connection.execute(
                    "SELECT * FROM approval_challenges ORDER BY rowid"
                )
            )

    def create_challenge(
        self, challenge: ApprovalChallenge, event: AuthorityAuditDraft
    ) -> tuple[ApprovalChallenge, bool]:
        operation_json = self._validate_new_challenge(challenge)
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._verify_schema(connection)
            existing = connection.execute(
                "SELECT * FROM approval_challenges WHERE binding_digest=?",
                (challenge.binding_digest,),
            ).fetchone()
            if existing is not None:
                return self._challenge_from_row(existing), False
            conflict = connection.execute(
                "SELECT 1 FROM approval_challenges "
                "WHERE operation_id=? AND operation_revision=?",
                (challenge.operation.operation_id, challenge.operation.revision),
            ).fetchone()
            if conflict is not None:
                raise AuthorityConcurrentUpdate(
                    "operation revision already has an approval challenge"
                )
            if connection.execute(
                "SELECT 1 FROM approval_challenges WHERE challenge_id=?",
                (challenge.challenge_id,),
            ).fetchone() is not None:
                raise AuthorityError("approval challenge ID already exists")
            self._validate_event(event)
            self._validate_bound_event(challenge, event)
            try:
                self._insert_challenge(connection, challenge, operation_json)
                self._append_event(connection, event)
            except sqlite3.IntegrityError as exc:
                raise AuthorityError("approval challenge uniqueness was violated") from exc
            return challenge, True

    def transition_challenge(
        self,
        challenge: ApprovalChallenge,
        *,
        expected_version: int,
        event: AuthorityAuditDraft,
    ) -> ApprovalChallenge:
        if not isinstance(challenge, ApprovalChallenge):
            raise AuthorityError("approval challenge transition is invalid")
        if type(expected_version) is not int or expected_version < 0:
            raise AuthorityError("approval challenge expected version is invalid")
        with self._transaction() as connection:
            self._verify_audit_chain_connection(connection)
            self._verify_schema(connection)
            current = self._load_challenge(connection, challenge.challenge_id)
            if current.version != expected_version:
                raise AuthorityConcurrentUpdate("approval challenge version changed")
            if (
                _immutable_challenge_fields(current)
                != _immutable_challenge_fields(challenge)
                or challenge.version != current.version + 1
                or current.state is not ApprovalChallengeState.PENDING
                or challenge.state is ApprovalChallengeState.PENDING
            ):
                raise AuthorityError("approval challenge transition is invalid")
            self._validate_event(event)
            self._validate_bound_event(challenge, event)
            _validate_approval_binding(challenge)
            approval_json = _approval_json(challenge.approval)
            nonce_digest = _approval_nonce_digest(challenge.approval)
            if nonce_digest is not None and connection.execute(
                "SELECT 1 FROM approval_challenges WHERE approval_nonce_digest=?",
                (nonce_digest,),
            ).fetchone() is not None:
                raise AuthorityError("approval nonce was already issued")
            try:
                cursor = connection.execute(
                    "UPDATE approval_challenges SET "
                    "state=?, version=?, decided_at=?, decider_user_id=?, "
                    "denial_reason=?, approval_json=?, approval_nonce_digest=? "
                    "WHERE challenge_id=? AND version=? AND state='pending'",
                    (
                        challenge.state.value,
                        challenge.version,
                        _utc_text(challenge.decided_at, "challenge decided_at"),
                        challenge.decider_user_id,
                        challenge.denial_reason,
                        approval_json,
                        nonce_digest,
                        challenge.challenge_id,
                        expected_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AuthorityConcurrentUpdate("approval challenge version changed")
                self._append_event(connection, event)
            except sqlite3.IntegrityError as exc:
                if nonce_digest is not None and connection.execute(
                    "SELECT 1 FROM approval_challenges WHERE approval_nonce_digest=?",
                    (nonce_digest,),
                ).fetchone() is not None:
                    raise AuthorityError("approval nonce was already issued") from exc
                raise AuthorityError("approval challenge transition was rejected") from exc
            return challenge

    def append_audit_event(self, event: AuthorityAuditDraft) -> AuthorityAuditEvent:
        self._validate_event(event)
        with self._transaction() as connection:
            try:
                return self._append_event(connection, event)
            except sqlite3.IntegrityError as exc:
                raise AuthorityError("authority audit event could not be appended") from exc

    def audit_events(self) -> tuple[AuthorityAuditEvent, ...]:
        with self._read_connection() as connection:
            self._verify_audit_chain_connection(connection)
            return self._events_from_connection(connection)

    def verify_audit_chain(self) -> bool:
        with self._read_connection() as connection:
            self._verify_audit_chain_connection(connection)
        return True


__all__ = [
    "AUTHORITY_STORE_SCHEMA_VERSION",
    "SQLiteApprovalChallengeStore",
]
