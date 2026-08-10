"""Durable one-time admission ledger for SSHSIG v3 read evidence.

The ledger is deliberately separate from signing.  It atomically consumes the
authorization, nonce, run, and index replay bindings before returning the
canonical payload that a privileged signer may sign.  A retry of the exact
same request recovers the already committed payload; a request that collides on
any replay binding but changes content fails closed.

No public API accepts signing material or a caller-provided time.  Admission
decisions always use the host UTC clock.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Iterator, Mapping

from .operations import canonical_json


READ_EVIDENCE_ADMISSION_SCHEMA_VERSION = 1
ACTIVE_ADMISSION_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-active-admission.v3"
)
ADMISSION_PAYLOAD_SCHEMA = ACTIVE_ADMISSION_SCHEMA
DEFAULT_READ_EVIDENCE_ADMISSION_PATH = Path(
    "/var/lib/odoo-accounting-cli-v3/read-evidence-v3/admissions.sqlite3"
)
ADMISSION_INDEX_PATH = "index.json"
ADMISSION_INDEX_SIGNATURE_PATH = "index.json.sshsig"
ADMISSION_ARTIFACT_PATH = "active-admission.json"
ADMISSION_ARTIFACT_SIGNATURE_PATH = "active-admission.json.sshsig"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_RELEASE_IDENTITY_FIELDS = frozenset(
    {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
    }
)


class ReadEvidenceAdmissionError(RuntimeError):
    """The admission ledger rejected an unsafe or inconsistent operation."""


class ReadEvidenceAdmissionConflict(ReadEvidenceAdmissionError):
    """A one-time replay binding is already committed to another request."""


class ReadEvidenceAdmissionCommitOutcomeUnknown(ReadEvidenceAdmissionError):
    """A caller must reconcile the ledger and must not sign this attempt."""

    reconciliation_required = True


class AdmissionState(str, Enum):
    CONSUMED = "consumed"
    PUBLISHED = "published"


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ReadEvidenceAdmissionError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ReadEvidenceAdmissionError(f"{label} is invalid")
    return value


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReadEvidenceAdmissionError(f"{label} must be a positive integer")
    return value


def _fixed_relative_path(value: object, *, expected: str, label: str) -> str:
    if not isinstance(value, str) or value != expected:
        raise ReadEvidenceAdmissionError(f"{label} must be {expected!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or len(path.parts) != 1:
        raise ReadEvidenceAdmissionError(f"{label} is invalid")
    return value


def _utc_datetime(value: object, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.microsecond != 0
    ):
        raise ReadEvidenceAdmissionError(
            f"{label} must be a whole-second timezone-aware datetime"
        )
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc_text(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReadEvidenceAdmissionError(f"{label} is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReadEvidenceAdmissionError(f"{label} is invalid") from exc
    if _utc_text(parsed) != value:
        raise ReadEvidenceAdmissionError(f"{label} is invalid")
    return parsed


def _copy_release_identity(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or set(value) != _RELEASE_IDENTITY_FIELDS:
        raise ReadEvidenceAdmissionError("release identity is invalid")
    release_identity: dict[str, str] = {}
    for field in sorted(_RELEASE_IDENTITY_FIELDS):
        field_value = value[field]
        if not isinstance(field_value, str):
            raise ReadEvidenceAdmissionError("release identity is invalid")
        release_identity[field] = field_value
    if _COMMIT.fullmatch(release_identity["commit"]) is None:
        raise ReadEvidenceAdmissionError("release identity is invalid")
    for field in ("manifest_sha256", "package_sha256", "registry_digest"):
        if _SHA256.fullmatch(release_identity[field]) is None:
            raise ReadEvidenceAdmissionError("release identity is invalid")
    if _RELEASE.fullmatch(release_identity["release"]) is None:
        raise ReadEvidenceAdmissionError("release identity is invalid")
    return MappingProxyType(release_identity)


@dataclass(frozen=True)
class ReadEvidenceAdmissionRequest:
    """Fully bound, pre-signing admission input from trusted collector code."""

    release_identity: Mapping[str, str]
    index_path: str
    index_sha256: str
    index_size: int
    index_signature_path: str
    index_signature_sha256: str
    index_signature_size: int
    closure_tree_sha256: str
    closure_file_count: int
    closure_total_bytes: int
    scope_sha256: str
    authorization_id: str
    authorization_sha256: str
    nonce_sha256: str
    run_id: str
    authorization_not_before: datetime
    authorization_expires_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "release_identity", _copy_release_identity(self.release_identity)
        )
        object.__setattr__(
            self,
            "index_path",
            _fixed_relative_path(
                self.index_path,
                expected=ADMISSION_INDEX_PATH,
                label="index_path",
            ),
        )
        object.__setattr__(
            self,
            "index_signature_path",
            _fixed_relative_path(
                self.index_signature_path,
                expected=ADMISSION_INDEX_SIGNATURE_PATH,
                label="index_signature_path",
            ),
        )
        for field in (
            "index_sha256",
            "index_signature_sha256",
            "closure_tree_sha256",
            "scope_sha256",
            "authorization_sha256",
            "nonce_sha256",
        ):
            object.__setattr__(self, field, _sha256(getattr(self, field), field))
        for field in (
            "index_size",
            "index_signature_size",
            "closure_file_count",
            "closure_total_bytes",
        ):
            object.__setattr__(
                self, field, _positive_integer(getattr(self, field), field)
            )
        object.__setattr__(
            self,
            "authorization_id",
            _identifier(self.authorization_id, "authorization_id"),
        )
        object.__setattr__(self, "run_id", _identifier(self.run_id, "run_id"))
        not_before = _utc_datetime(
            self.authorization_not_before, "authorization_not_before"
        )
        expires_at = _utc_datetime(
            self.authorization_expires_at, "authorization_expires_at"
        )
        if expires_at <= not_before:
            raise ReadEvidenceAdmissionError(
                "authorization expiry must be after not_before"
            )
        object.__setattr__(self, "authorization_not_before", not_before)
        object.__setattr__(self, "authorization_expires_at", expires_at)


@dataclass(frozen=True)
class ReadEvidenceAdmission:
    """A committed canonical admission payload, ready for detached signing."""

    sequence: int
    state: AdmissionState
    payload_json: str
    payload_sha256: str
    recovered: bool
    admission_signature_path: str | None = None
    admission_signature_sha256: str | None = None
    admission_signature_size: int | None = None
    published_at: datetime | None = None

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.payload_json)

    @property
    def payload_bytes(self) -> bytes:
        return self.payload_json.encode("utf-8")


_TABLES = {
    "read_evidence_admission_schema_meta": """
        CREATE TABLE read_evidence_admission_schema_meta (
            key TEXT PRIMARY KEY CHECK (key = 'schema_version'),
            value TEXT NOT NULL
        ) STRICT
    """,
    "read_evidence_admissions": """
        CREATE TABLE read_evidence_admissions (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            authorization_id TEXT NOT NULL UNIQUE,
            authorization_sha256 TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL UNIQUE,
            release_identity_json TEXT NOT NULL,
            index_path TEXT NOT NULL,
            index_sha256 TEXT NOT NULL UNIQUE,
            index_size INTEGER NOT NULL CHECK (index_size > 0),
            index_signature_path TEXT NOT NULL,
            index_signature_sha256 TEXT NOT NULL,
            index_signature_size INTEGER NOT NULL CHECK (index_signature_size > 0),
            closure_tree_sha256 TEXT NOT NULL,
            closure_file_count INTEGER NOT NULL CHECK (closure_file_count > 0),
            closure_total_bytes INTEGER NOT NULL CHECK (closure_total_bytes > 0),
            scope_sha256 TEXT NOT NULL,
            not_before TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            admitted_at TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'published')),
            payload_json TEXT UNIQUE,
            payload_sha256 TEXT UNIQUE,
            admission_signature_path TEXT CHECK (
                admission_signature_path IS NULL
                OR admission_signature_path = 'active-admission.json.sshsig'
            ),
            admission_signature_sha256 TEXT UNIQUE,
            admission_signature_size INTEGER CHECK (admission_signature_size > 0),
            published_at TEXT,
            CHECK (
                (state = 'pending' AND payload_json IS NULL
                    AND payload_sha256 IS NULL
                    AND admission_signature_path IS NULL
                    AND admission_signature_sha256 IS NULL
                    AND admission_signature_size IS NULL
                    AND published_at IS NULL)
                OR
                (state = 'consumed' AND payload_json IS NOT NULL
                    AND payload_sha256 IS NOT NULL
                    AND admission_signature_path IS NULL
                    AND admission_signature_sha256 IS NULL
                    AND admission_signature_size IS NULL
                    AND published_at IS NULL)
                OR
                (state = 'published' AND payload_json IS NOT NULL
                    AND payload_sha256 IS NOT NULL
                    AND admission_signature_path IS NOT NULL
                    AND admission_signature_sha256 IS NOT NULL
                    AND admission_signature_size IS NOT NULL
                    AND published_at IS NOT NULL)
            )
        ) STRICT
    """,
}

_TRIGGERS = {
    "read_evidence_admission_schema_meta_no_update": """
        CREATE TRIGGER read_evidence_admission_schema_meta_no_update
        BEFORE UPDATE ON read_evidence_admission_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'read evidence admission schema metadata is immutable');
        END
    """,
    "read_evidence_admission_schema_meta_no_delete": """
        CREATE TRIGGER read_evidence_admission_schema_meta_no_delete
        BEFORE DELETE ON read_evidence_admission_schema_meta
        BEGIN
            SELECT RAISE(ABORT, 'read evidence admission schema metadata is immutable');
        END
    """,
    "read_evidence_admissions_no_delete": """
        CREATE TRIGGER read_evidence_admissions_no_delete
        BEFORE DELETE ON read_evidence_admissions
        BEGIN
            SELECT RAISE(ABORT, 'read evidence admissions cannot be deleted');
        END
    """,
    "read_evidence_admissions_valid_transition": """
        CREATE TRIGGER read_evidence_admissions_valid_transition
        BEFORE UPDATE ON read_evidence_admissions
        WHEN NOT (
            OLD.state = 'pending'
            AND NEW.state = 'consumed'
            AND NEW.sequence IS OLD.sequence
            AND NEW.authorization_id IS OLD.authorization_id
            AND NEW.authorization_sha256 IS OLD.authorization_sha256
            AND NEW.nonce_sha256 IS OLD.nonce_sha256
            AND NEW.run_id IS OLD.run_id
            AND NEW.release_identity_json IS OLD.release_identity_json
            AND NEW.index_path IS OLD.index_path
            AND NEW.index_sha256 IS OLD.index_sha256
            AND NEW.index_size IS OLD.index_size
            AND NEW.index_signature_path IS OLD.index_signature_path
            AND NEW.index_signature_sha256 IS OLD.index_signature_sha256
            AND NEW.index_signature_size IS OLD.index_signature_size
            AND NEW.closure_tree_sha256 IS OLD.closure_tree_sha256
            AND NEW.closure_file_count IS OLD.closure_file_count
            AND NEW.closure_total_bytes IS OLD.closure_total_bytes
            AND NEW.scope_sha256 IS OLD.scope_sha256
            AND NEW.not_before IS OLD.not_before
            AND NEW.expires_at IS OLD.expires_at
            AND NEW.admitted_at IS OLD.admitted_at
            AND NEW.payload_json IS NOT NULL
            AND NEW.payload_sha256 IS NOT NULL
            AND NEW.admission_signature_path IS NULL
            AND NEW.admission_signature_sha256 IS NULL
            AND NEW.admission_signature_size IS NULL
            AND NEW.published_at IS NULL
        ) AND NOT (
            OLD.state = 'consumed'
            AND NEW.state = 'published'
            AND NEW.sequence IS OLD.sequence
            AND NEW.authorization_id IS OLD.authorization_id
            AND NEW.authorization_sha256 IS OLD.authorization_sha256
            AND NEW.nonce_sha256 IS OLD.nonce_sha256
            AND NEW.run_id IS OLD.run_id
            AND NEW.release_identity_json IS OLD.release_identity_json
            AND NEW.index_path IS OLD.index_path
            AND NEW.index_sha256 IS OLD.index_sha256
            AND NEW.index_size IS OLD.index_size
            AND NEW.index_signature_path IS OLD.index_signature_path
            AND NEW.index_signature_sha256 IS OLD.index_signature_sha256
            AND NEW.index_signature_size IS OLD.index_signature_size
            AND NEW.closure_tree_sha256 IS OLD.closure_tree_sha256
            AND NEW.closure_file_count IS OLD.closure_file_count
            AND NEW.closure_total_bytes IS OLD.closure_total_bytes
            AND NEW.scope_sha256 IS OLD.scope_sha256
            AND NEW.not_before IS OLD.not_before
            AND NEW.expires_at IS OLD.expires_at
            AND NEW.admitted_at IS OLD.admitted_at
            AND NEW.payload_json IS OLD.payload_json
            AND NEW.payload_sha256 IS OLD.payload_sha256
            AND NEW.admission_signature_path = 'active-admission.json.sshsig'
            AND NEW.admission_signature_sha256 IS NOT NULL
            AND NEW.admission_signature_size > 0
            AND NEW.published_at IS NOT NULL
        )
        BEGIN
            SELECT RAISE(ABORT, 'read evidence admission transition is invalid');
        END
    """,
}

_EXPECTED_COLUMNS = {
    "read_evidence_admission_schema_meta": ("key", "value"),
    "read_evidence_admissions": (
        "sequence",
        "authorization_id",
        "authorization_sha256",
        "nonce_sha256",
        "run_id",
        "release_identity_json",
        "index_path",
        "index_sha256",
        "index_size",
        "index_signature_path",
        "index_signature_sha256",
        "index_signature_size",
        "closure_tree_sha256",
        "closure_file_count",
        "closure_total_bytes",
        "scope_sha256",
        "not_before",
        "expires_at",
        "admitted_at",
        "state",
        "payload_json",
        "payload_sha256",
        "admission_signature_path",
        "admission_signature_sha256",
        "admission_signature_size",
        "published_at",
    ),
}


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split()).replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")


def _system_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json_line(value: Any) -> str:
    return (canonical_json(value) + b"\n").decode("utf-8")


def _commit_connection(connection: sqlite3.Connection) -> None:
    connection.commit()


def _after_consume_commit() -> None:
    """Crash-injection seam used only after durable consumption is confirmed."""


class SQLiteReadEvidenceAdmissionStore:
    """Connection-per-call SQLite one-time admission ledger."""

    def __init__(
        self,
        path: str | Path = DEFAULT_READ_EVIDENCE_ADMISSION_PATH,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self._configure_instance(
            path=path,
            busy_timeout_ms=busy_timeout_ms,
            allow_create=True,
        )
        self._prepare_parent(create_missing=True)
        self._initialize()

    @classmethod
    def open_existing(
        cls,
        path: str | Path = DEFAULT_READ_EVIDENCE_ADMISSION_PATH,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> "SQLiteReadEvidenceAdmissionStore":
        """Open and verify an existing ledger without creating any state."""

        instance = cls.__new__(cls)
        instance._configure_instance(
            path=path,
            busy_timeout_ms=busy_timeout_ms,
            allow_create=False,
        )
        instance._prepare_parent(create_missing=False)
        instance._initialize()
        return instance

    def _configure_instance(
        self,
        *,
        path: str | Path,
        busy_timeout_ms: int,
        allow_create: bool,
    ) -> None:
        self.path = Path(path)
        if str(path) == ":memory:" or not self.path.is_absolute():
            raise ReadEvidenceAdmissionError(
                "read evidence admission database path must be absolute"
            )
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms <= 0
        ):
            raise ReadEvidenceAdmissionError(
                "busy_timeout_ms must be a positive integer"
            )
        self.busy_timeout_ms = busy_timeout_ms
        self._allow_create = allow_create
        self._bootstrap_initialization_allowed = False
        self._bootstrap_sidecar_observed = False
        self._zero_length_database_observed = False

    @staticmethod
    def _verify_ancestor_chain(directory: Path) -> None:
        current = directory
        while True:
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission ancestor does not exist"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode) or current.is_symlink():
                raise ReadEvidenceAdmissionError(
                    "read evidence admission ancestor is invalid or symlinked"
                )
            if os.name == "posix":
                if metadata.st_uid not in {0, os.geteuid()}:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission ancestor owner is unsafe"
                    )
                writable = metadata.st_mode & 0o022
                root_sticky_shared = (
                    metadata.st_uid == 0
                    and bool(metadata.st_mode & stat.S_ISVTX)
                )
                if writable and not root_sticky_shared:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission ancestor is writable by other users"
                    )
            parent = current.parent
            if parent == current:
                break
            current = parent

    def _prepare_parent(self, *, create_missing: bool) -> None:
        parent = self.path.parent
        try:
            if not os.path.lexists(parent):
                if not create_missing:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission database does not exist"
                    )
                grandparent = parent.parent
                self._verify_ancestor_chain(grandparent)
                os.mkdir(parent, 0o700)
                if os.name == "posix":
                    os.chmod(parent, 0o700)
                    self._fsync_directory(grandparent)
            self._verify_ancestor_chain(parent)
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
                raise ReadEvidenceAdmissionError(
                    "read evidence admission parent directory is invalid"
                )
            if os.name == "posix" and (
                metadata.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission parent directory is not private"
                )
        except ReadEvidenceAdmissionError:
            raise
        except OSError as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission parent directory cannot be secured"
            ) from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _secure_database_file(
        self, *, allow_create: bool | None = None
    ) -> tuple[int, int]:
        descriptor: int | None = None
        try:
            if allow_create is None:
                allow_create = self._allow_create
            if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database requires O_NOFOLLOW"
                )
            if not os.path.lexists(self.path):
                if not allow_create:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission database does not exist"
                    )
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(self.path, flags, 0o600)
                except FileExistsError:
                    descriptor = None
                else:
                    if os.name == "posix":
                        os.fchmod(descriptor, 0o600)
                    os.fsync(descriptor)
                    os.close(descriptor)
                    descriptor = None
                    self._fsync_directory(self.path.parent)
            if any(
                os.path.lexists(Path(f"{self.path}{suffix}"))
                for suffix in ("-journal", "-wal", "-shm")
            ):
                self._bootstrap_sidecar_observed = True
            initial = self.path.lstat()
            if not stat.S_ISREG(initial.st_mode) or self.path.is_symlink():
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must be a regular non-symlink file"
                )
            if initial.st_nlink != 1:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must have exactly one hard link"
                )
            if os.name == "posix" and (
                initial.st_uid != os.geteuid()
                or stat.S_IMODE(initial.st_mode) != 0o600
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database file is not private"
                )
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (opened.st_dev, opened.st_ino)
                != (metadata.st_dev, metadata.st_ino)
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database path changed while open"
                )
            if opened.st_nlink != 1 or metadata.st_nlink != 1:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must have exactly one hard link"
                )
            if os.name == "posix" and (
                opened.st_uid != os.geteuid()
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database file is not private"
                )
            if opened.st_size == 0 and metadata.st_size == 0:
                self._zero_length_database_observed = True
            self._verify_sidecars()
            if (
                self._zero_length_database_observed
                and not self._bootstrap_sidecar_observed
            ):
                self._bootstrap_initialization_allowed = True
            return opened.st_dev, opened.st_ino
        except ReadEvidenceAdmissionError:
            raise
        except OSError as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database path cannot be secured"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _secure_existing_database_readonly(self) -> tuple[int, int]:
        """Verify an existing ledger using only a read descriptor."""

        descriptor: int | None = None
        try:
            self._verify_ancestor_chain(self.path.parent)
            if not os.path.lexists(self.path):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database does not exist"
                )
            if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database requires O_NOFOLLOW"
                )
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must be a regular non-symlink file"
                )
            if metadata.st_nlink != 1:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must have exactly one hard link"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database file is not private"
                )
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
            current = self.path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or self.path.is_symlink()
                or (opened.st_dev, opened.st_ino)
                != (current.st_dev, current.st_ino)
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database path changed while read"
                )
            if opened.st_nlink != 1 or current.st_nlink != 1:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must have exactly one hard link"
                )
            if os.name == "posix" and (
                opened.st_uid != os.geteuid()
                or current.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}
                or stat.S_IMODE(current.st_mode) not in {0o400, 0o600}
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database file is not private"
                )
            self._verify_sidecars(
                read_only=True,
                reject_rollback_journal=True,
            )
            return opened.st_dev, opened.st_ino
        except ReadEvidenceAdmissionError:
            raise
        except OSError as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database cannot be opened read-only"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _verify_database_file(self, expected: tuple[int, int]) -> None:
        self._verify_database_file_access(expected, read_only=False)

    def _verify_database_file_access(
        self, expected: tuple[int, int], *, read_only: bool
    ) -> None:
        try:
            metadata = self.path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.path.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != expected
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database path changed while open"
                )
            if metadata.st_nlink != 1:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database must have exactly one hard link"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode)
                not in ({0o400, 0o600} if read_only else {0o600})
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database file is not private"
                )
            self._verify_sidecars(
                read_only=read_only,
                reject_rollback_journal=read_only,
            )
        except ReadEvidenceAdmissionError:
            raise
        except OSError as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database path cannot be verified"
            ) from exc

    def _verify_sidecars(
        self,
        *,
        read_only: bool = False,
        reject_rollback_journal: bool = False,
    ) -> None:
        for suffix in ("-wal", "-shm"):
            if os.path.lexists(Path(f"{self.path}{suffix}")):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission has an unexpected legacy WAL sidecar"
                )
        sidecar = Path(f"{self.path}-journal")
        if not os.path.lexists(sidecar):
            return
        if reject_rollback_journal:
            raise ReadEvidenceAdmissionError(
                "read evidence admission rollback journal requires writer recovery"
            )
        initial = sidecar.lstat()
        if (
            not stat.S_ISREG(initial.st_mode)
            or sidecar.is_symlink()
            or initial.st_nlink != 1
            or (
                os.name == "posix"
                and (
                    initial.st_uid != os.geteuid()
                    or stat.S_IMODE(initial.st_mode)
                    not in ({0o400, 0o600} if read_only else {0o600})
                )
            )
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission SQLite sidecar is not private"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(sidecar, flags)
        try:
            opened = os.fstat(descriptor)
            metadata = sidecar.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or sidecar.is_symlink()
                or opened.st_nlink != 1
                or metadata.st_nlink != 1
                or (opened.st_dev, opened.st_ino)
                != (metadata.st_dev, metadata.st_ino)
                or (opened.st_dev, opened.st_ino)
                != (initial.st_dev, initial.st_ino)
                or (
                    os.name == "posix"
                    and (
                        opened.st_uid != os.geteuid()
                        or metadata.st_uid != os.geteuid()
                        or stat.S_IMODE(opened.st_mode)
                        not in ({0o400, 0o600} if read_only else {0o600})
                        or stat.S_IMODE(metadata.st_mode)
                        not in ({0o400, 0o600} if read_only else {0o600})
                    )
                )
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission SQLite sidecar is not private"
                )
        finally:
            os.close(descriptor)

    def _verify_no_bootstrap_sidecars(self) -> None:
        if any(
            os.path.lexists(Path(f"{self.path}{suffix}"))
            for suffix in ("-journal", "-wal", "-shm")
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission bootstrap has an unexpected sidecar"
            )

    def _recover_writer_rollback_journal(
        self, expected: tuple[int, int]
    ) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            self._configure(connection)
            connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            self._verify_integrity(connection)
            self._verify_database_file(expected)
        except ReadEvidenceAdmissionError:
            raise
        except sqlite3.Error as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission writer recovery failed"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        self._verify_database_file(expected)
        self._verify_no_bootstrap_sidecars()
        self._fsync_database()

    def _configure(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise ReadEvidenceAdmissionError(
                "read evidence admission database requires SQLite DELETE journal mode"
            )
        connection.execute("PRAGMA synchronous = FULL")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database requires FULL synchronization"
            )
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database requires foreign keys"
            )

    def _configure_read_only(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ReadEvidenceAdmissionError(
                "read evidence admission lookup requires query-only SQLite"
            )

    def _verify_rollback_header(self, expected: tuple[int, int]) -> None:
        """Verify rollback journaling from the database header without a PRAGMA."""

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != expected:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database path changed while read"
                )
            header = os.read(descriptor, 20)
        finally:
            os.close(descriptor)
        if (
            len(header) != 20
            or header[:16] != b"SQLite format 3\x00"
            or header[18:20] != b"\x01\x01"
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission schema is invalid or not rollback-journal mode"
            )

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        """Open one existing-only, query-only SQLite snapshot."""

        expected = self._secure_existing_database_readonly()
        self._verify_rollback_header(expected)
        connection: sqlite3.Connection | None = None
        try:
            uri = f"{self.path.as_uri()}?mode=ro"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            self._configure_read_only(connection)
            self._verify_database_file_access(expected, read_only=True)
            connection.execute("BEGIN")
            try:
                yield connection
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            self._verify_database_file_access(expected, read_only=True)
            connection.rollback()
        except ReadEvidenceAdmissionError:
            raise
        except sqlite3.Error as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission read-only lookup failed"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
            self._verify_database_file_access(expected, read_only=True)

    @contextmanager
    def _transaction(
        self, *, expected_identity: tuple[int, int] | None = None
    ) -> Iterator[sqlite3.Connection]:
        expected = self._secure_database_file()
        if expected_identity is not None and expected != expected_identity:
            raise ReadEvidenceAdmissionError(
                "read evidence admission database changed before transaction"
            )
        connection: sqlite3.Connection | None = None
        committed = False
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            self._configure(connection)
            self._verify_database_file(expected)
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            self._verify_database_file(expected)
            try:
                _commit_connection(connection)
                committed = True
            except BaseException as exc:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except BaseException as rollback_error:
                    exc.add_note(f"admission rollback also failed: {rollback_error}")
                raise ReadEvidenceAdmissionCommitOutcomeUnknown(
                    "read evidence admission commit outcome is unknown; "
                    "reconcile durable state and do not sign this attempt"
                ) from exc
        except (ReadEvidenceAdmissionError, ReadEvidenceAdmissionConflict):
            raise
        except sqlite3.IntegrityError as exc:
            raise ReadEvidenceAdmissionConflict(
                "read evidence admission replay binding conflicts"
            ) from exc
        except sqlite3.Error as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission SQLite transaction failed"
            ) from exc
        finally:
            close_error: BaseException | None = None
            if connection is not None:
                try:
                    connection.close()
                except BaseException as exc:
                    close_error = exc
            try:
                self._verify_database_file(expected)
                self._fsync_database()
            except BaseException as verification_error:
                if close_error is not None:
                    verification_error.add_note(
                        f"SQLite close also failed: {close_error}"
                    )
                if committed:
                    raise ReadEvidenceAdmissionCommitOutcomeUnknown(
                        "read evidence admission was committed but durable cleanup "
                        "could not be confirmed; reconcile before signing"
                    ) from verification_error
                raise
            if close_error is not None:
                if committed:
                    raise ReadEvidenceAdmissionCommitOutcomeUnknown(
                        "read evidence admission was committed but connection close "
                        "could not be confirmed; reconcile before signing"
                    ) from close_error
                raise close_error

    def _fsync_database(self) -> None:
        # Windows rejects fsync on a descriptor opened read-only.  These are
        # ledger-owned SQLite file, so an O_RDWR durability descriptor is the
        # portable choice; O_NOFOLLOW still protects POSIX path resolution.
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory(self.path.parent)

    @staticmethod
    def _schema_objects(connection: sqlite3.Connection) -> tuple[sqlite3.Row, ...]:
        return tuple(
            connection.execute(
                "SELECT type, name, tbl_name, rootpage, sql "
                "FROM sqlite_master ORDER BY type, name"
            )
        )

    @classmethod
    def _verify_empty_bootstrap(cls, connection: sqlite3.Connection) -> None:
        if cls._schema_objects(connection):
            raise ReadEvidenceAdmissionError(
                "read evidence admission bootstrap schema is not empty"
            )
        cls._verify_integrity(connection)
        metadata = {
            "application_id": connection.execute(
                "PRAGMA application_id"
            ).fetchone()[0],
            "auto_vacuum": connection.execute("PRAGMA auto_vacuum").fetchone()[0],
            "encoding": connection.execute("PRAGMA encoding").fetchone()[0],
            "freelist_count": connection.execute(
                "PRAGMA freelist_count"
            ).fetchone()[0],
            "page_count": connection.execute("PRAGMA page_count").fetchone()[0],
            "schema_version": connection.execute(
                "PRAGMA schema_version"
            ).fetchone()[0],
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
        }
        if (
            metadata["application_id"] != 0
            or metadata["auto_vacuum"] != 0
            or metadata["encoding"] != "UTF-8"
            or metadata["freelist_count"] != 0
            or metadata["page_count"] not in {0, 1}
            or metadata["schema_version"] not in {0, 1}
            or metadata["user_version"] != 0
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission bootstrap metadata is not empty"
            )

    def _preflight_writer_initialization(self) -> tuple[int, int]:
        expected = self._secure_database_file()
        if self._bootstrap_sidecar_observed:
            self._recover_writer_rollback_journal(expected)
            self._bootstrap_sidecar_observed = False
            recovered = self._secure_database_file()
            if recovered != expected or self._bootstrap_sidecar_observed:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission database changed during writer recovery"
                )
        if self._zero_length_database_observed:
            self._verify_no_bootstrap_sidecars()
            self._bootstrap_initialization_allowed = True
            return expected
        with self._read_connection() as connection:
            if not self._schema_objects(connection):
                self._verify_empty_bootstrap(connection)
                self._bootstrap_initialization_allowed = True
            else:
                self._verify_schema(connection)
                self._verify_integrity(connection)
                self._verify_rows(connection)
        return expected

    def _initialize(self) -> None:
        if not self._allow_create:
            with self._read_connection() as connection:
                self._verify_schema(connection)
                self._verify_integrity(connection)
                self._verify_rows(connection)
            return
        expected = self._preflight_writer_initialization()
        with self._transaction(expected_identity=expected) as connection:
            if not self._schema_objects(connection):
                if not self._bootstrap_initialization_allowed:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission schema is missing"
                    )
                self._verify_empty_bootstrap(connection)
                for statement in _TABLES.values():
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO read_evidence_admission_schema_meta(key, value) "
                    "VALUES('schema_version', ?)",
                    (str(READ_EVIDENCE_ADMISSION_SCHEMA_VERSION),),
                )
                for statement in _TRIGGERS.values():
                    connection.execute(statement)
            self._verify_schema(connection)
            self._verify_integrity(connection)
            self._verify_rows(connection)
        self._bootstrap_initialization_allowed = False
        self._bootstrap_sidecar_observed = False
        self._zero_length_database_observed = False

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        try:
            version_rows = connection.execute(
                "SELECT key, value FROM read_evidence_admission_schema_meta"
            ).fetchall()
        except sqlite3.Error as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission schema version is missing"
            ) from exc
        if (
            len(version_rows) != 1
            or version_rows[0]["key"] != "schema_version"
            or version_rows[0]["value"]
            != str(READ_EVIDENCE_ADMISSION_SCHEMA_VERSION)
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission schema version is unsupported"
            )
        actual_tables = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if set(actual_tables) != set(_TABLES):
            raise ReadEvidenceAdmissionError(
                "read evidence admission table schema is invalid"
            )
        for table, expected_columns in _EXPECTED_COLUMNS.items():
            columns = tuple(
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if (
                columns != expected_columns
                or not isinstance(actual_tables[table], str)
                or _normalize_schema_sql(actual_tables[table])
                != _normalize_schema_sql(_TABLES[table])
            ):
                raise ReadEvidenceAdmissionError(
                    "read evidence admission table schema is invalid"
                )
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
            raise ReadEvidenceAdmissionError(
                "read evidence admission trigger schema is invalid"
            )
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE (type='view' OR (type='index' AND sql IS NOT NULL)) "
                "AND name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            is not None
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission schema has unexpected objects"
            )

    @staticmethod
    def _verify_integrity(connection: sqlite3.Connection) -> None:
        if tuple(row[0] for row in connection.execute("PRAGMA quick_check")) != (
            "ok",
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission SQLite integrity check failed"
            )

    @classmethod
    def _verify_rows(cls, connection: sqlite3.Connection) -> None:
        for row in connection.execute(
            "SELECT * FROM read_evidence_admissions ORDER BY sequence"
        ):
            cls._decision_from_row(row, recovered=True)

    @staticmethod
    def _request_values(request: ReadEvidenceAdmissionRequest) -> tuple[Any, ...]:
        return (
            request.authorization_id,
            request.authorization_sha256,
            request.nonce_sha256,
            request.run_id,
            canonical_json(dict(request.release_identity)).decode("utf-8"),
            request.index_path,
            request.index_sha256,
            request.index_size,
            request.index_signature_path,
            request.index_signature_sha256,
            request.index_signature_size,
            request.closure_tree_sha256,
            request.closure_file_count,
            request.closure_total_bytes,
            request.scope_sha256,
            _utc_text(request.authorization_not_before),
            _utc_text(request.authorization_expires_at),
        )

    @classmethod
    def _row_matches_request(
        cls, row: sqlite3.Row, request: ReadEvidenceAdmissionRequest
    ) -> bool:
        columns = (
            "authorization_id",
            "authorization_sha256",
            "nonce_sha256",
            "run_id",
            "release_identity_json",
            "index_path",
            "index_sha256",
            "index_size",
            "index_signature_path",
            "index_signature_sha256",
            "index_signature_size",
            "closure_tree_sha256",
            "closure_file_count",
            "closure_total_bytes",
            "scope_sha256",
            "not_before",
            "expires_at",
        )
        return tuple(row[column] for column in columns) == cls._request_values(request)

    @classmethod
    def _payload_for_row(cls, row: sqlite3.Row) -> dict[str, Any]:
        try:
            release_identity = json.loads(row["release_identity_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission release identity is corrupt"
            ) from exc
        validated_identity = dict(_copy_release_identity(release_identity))
        if canonical_json(validated_identity).decode("utf-8") != row["release_identity_json"]:
            raise ReadEvidenceAdmissionError(
                "read evidence admission release identity is not canonical"
            )
        return {
            "admitted_at": row["admitted_at"],
            "authorization_id": row["authorization_id"],
            "authorization_sha256": row["authorization_sha256"],
            "closure_file_count": row["closure_file_count"],
            "closure_total_bytes": row["closure_total_bytes"],
            "closure_tree_sha256": row["closure_tree_sha256"],
            "index_path": row["index_path"],
            "index_sha256": row["index_sha256"],
            "index_signature_path": row["index_signature_path"],
            "index_signature_sha256": row["index_signature_sha256"],
            "index_signature_size": row["index_signature_size"],
            "index_size": row["index_size"],
            "nonce_sha256": row["nonce_sha256"],
            "release_identity": validated_identity,
            "run_id": row["run_id"],
            "schema_version": ADMISSION_PAYLOAD_SCHEMA,
            "sequence": row["sequence"],
            "scope_sha256": row["scope_sha256"],
        }

    @classmethod
    def _decision_from_row(
        cls, row: sqlite3.Row, *, recovered: bool
    ) -> ReadEvidenceAdmission:
        if row["state"] == "pending":
            raise ReadEvidenceAdmissionError(
                "read evidence admission contains an unresolved pending row"
            )
        try:
            state = AdmissionState(row["state"])
        except ValueError as exc:
            raise ReadEvidenceAdmissionError(
                "read evidence admission state is invalid"
            ) from exc
        for field in (
            "authorization_sha256",
            "nonce_sha256",
            "index_sha256",
            "index_signature_sha256",
            "closure_tree_sha256",
            "scope_sha256",
        ):
            _sha256(row[field], field)
        _identifier(row["authorization_id"], "authorization_id")
        _identifier(row["run_id"], "run_id")
        _fixed_relative_path(
            row["index_path"],
            expected=ADMISSION_INDEX_PATH,
            label="index_path",
        )
        _fixed_relative_path(
            row["index_signature_path"],
            expected=ADMISSION_INDEX_SIGNATURE_PATH,
            label="index_signature_path",
        )
        for field in (
            "sequence",
            "index_size",
            "index_signature_size",
            "closure_file_count",
            "closure_total_bytes",
        ):
            _positive_integer(row[field], field)
        not_before = _parse_utc_text(row["not_before"], "not_before")
        expires_at = _parse_utc_text(row["expires_at"], "expires_at")
        if not_before >= expires_at:
            raise ReadEvidenceAdmissionError(
                "read evidence authorization time window is invalid"
            )
        admitted_at = _parse_utc_text(row["admitted_at"], "admitted_at")
        if not (not_before <= admitted_at < expires_at):
            raise ReadEvidenceAdmissionError(
                "read evidence admitted_at is outside the authorization window"
            )
        signature_path: str | None = None
        signature_sha256: str | None = None
        signature_size: int | None = None
        published_at: datetime | None = None
        if state is AdmissionState.PUBLISHED:
            signature_path = _fixed_relative_path(
                row["admission_signature_path"],
                expected=ADMISSION_ARTIFACT_SIGNATURE_PATH,
                label="admission_signature_path",
            )
            signature_sha256 = _sha256(
                row["admission_signature_sha256"],
                "admission_signature_sha256",
            )
            signature_size = _positive_integer(
                row["admission_signature_size"],
                "admission_signature_size",
            )
            published_at = _parse_utc_text(row["published_at"], "published_at")
            if published_at < admitted_at:
                raise ReadEvidenceAdmissionError(
                    "read evidence publication is before admitted_at"
                )
            if published_at >= expires_at:
                raise ReadEvidenceAdmissionError(
                    "read evidence publication is outside the authorization window"
                )
        expected_payload_json = _canonical_json_line(cls._payload_for_row(row))
        expected_digest = hashlib.sha256(expected_payload_json.encode("utf-8")).hexdigest()
        if (
            row["payload_json"] != expected_payload_json
            or row["payload_sha256"] != expected_digest
        ):
            raise ReadEvidenceAdmissionError(
                "read evidence admission payload binding is corrupt"
            )
        return ReadEvidenceAdmission(
            sequence=row["sequence"],
            state=state,
            payload_json=expected_payload_json,
            payload_sha256=expected_digest,
            recovered=recovered,
            admission_signature_path=signature_path,
            admission_signature_sha256=signature_sha256,
            admission_signature_size=signature_size,
            published_at=published_at,
        )

    def consume(
        self, request: ReadEvidenceAdmissionRequest
    ) -> ReadEvidenceAdmission:
        """Atomically consume replay bindings and return a committed payload."""

        if not isinstance(request, ReadEvidenceAdmissionRequest):
            raise ReadEvidenceAdmissionError(
                "read evidence admission request type is invalid"
            )
        decision: ReadEvidenceAdmission | None = None
        with self._transaction() as connection:
            self._verify_schema(connection)
            self._verify_integrity(connection)
            self._verify_rows(connection)
            rows = connection.execute(
                "SELECT * FROM read_evidence_admissions "
                "WHERE authorization_id=? OR nonce_sha256=? OR run_id=? "
                "OR index_sha256=? ORDER BY sequence",
                (
                    request.authorization_id,
                    request.nonce_sha256,
                    request.run_id,
                    request.index_sha256,
                ),
            ).fetchall()
            if rows:
                if len(rows) == 1 and self._row_matches_request(rows[0], request):
                    decision = self._decision_from_row(rows[0], recovered=True)
                else:
                    duplicate_fields = [
                        field
                        for field in (
                            "authorization_id",
                            "nonce_sha256",
                            "run_id",
                            "index_sha256",
                        )
                        if any(row[field] == getattr(request, field) for row in rows)
                    ]
                    raise ReadEvidenceAdmissionConflict(
                        "read evidence admission replay binding conflicts: "
                        + ", ".join(duplicate_fields)
                    )
            else:
                now = _system_utc_now()
                if now.tzinfo is None or now.utcoffset() is None:
                    raise ReadEvidenceAdmissionError(
                        "system UTC clock returned an invalid time"
                    )
                now = now.astimezone(timezone.utc)
                if now < request.authorization_not_before:
                    raise ReadEvidenceAdmissionError(
                        "read evidence authorization is not active"
                    )
                if now >= request.authorization_expires_at:
                    raise ReadEvidenceAdmissionError(
                        "read evidence authorization is expired"
                    )
                admitted_at = now.replace(microsecond=0)
                cursor = connection.execute(
                    """
                    INSERT INTO read_evidence_admissions(
                        authorization_id, authorization_sha256, nonce_sha256,
                        run_id, release_identity_json, index_path, index_sha256,
                        index_size, index_signature_path,
                        index_signature_sha256, index_signature_size,
                        closure_tree_sha256, closure_file_count,
                        closure_total_bytes, scope_sha256, not_before,
                        expires_at, admitted_at, state, payload_json,
                        payload_sha256, admission_signature_path,
                        admission_signature_sha256, admission_signature_size,
                        published_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'pending', NULL, NULL, NULL, NULL, NULL, NULL)
                    """,
                    self._request_values(request) + (_utc_text(admitted_at),),
                )
                sequence = cursor.lastrowid
                if type(sequence) is not int or sequence <= 0:
                    raise ReadEvidenceAdmissionError(
                        "read evidence admission sequence allocation failed"
                    )
                pending = connection.execute(
                    "SELECT * FROM read_evidence_admissions WHERE sequence=?",
                    (sequence,),
                ).fetchone()
                if pending is None:
                    raise ReadEvidenceAdmissionError(
                        "read evidence pending admission is missing"
                    )
                payload_json = _canonical_json_line(self._payload_for_row(pending))
                payload_sha256 = hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                connection.execute(
                    "UPDATE read_evidence_admissions SET state='consumed', "
                    "payload_json=?, payload_sha256=? WHERE sequence=? AND state='pending'",
                    (payload_json, payload_sha256, sequence),
                )
                consumed = connection.execute(
                    "SELECT * FROM read_evidence_admissions WHERE sequence=?",
                    (sequence,),
                ).fetchone()
                if consumed is None:
                    raise ReadEvidenceAdmissionError(
                        "read evidence consumed admission is missing"
                    )
                decision = self._decision_from_row(consumed, recovered=False)
        if decision is None:  # pragma: no cover - defensive invariant
            raise ReadEvidenceAdmissionError(
                "read evidence admission did not produce a decision"
            )
        _after_consume_commit()
        return decision

    def mark_published(
        self,
        *,
        authorization_id: str,
        payload_sha256: str,
        admission_signature_path: str,
        admission_signature_sha256: str,
        admission_signature_size: int,
    ) -> ReadEvidenceAdmission:
        """Irreversibly mark an already consumed payload as published."""

        authorization_id = _identifier(authorization_id, "authorization_id")
        payload_sha256 = _sha256(payload_sha256, "payload_sha256")
        admission_signature_path = _fixed_relative_path(
            admission_signature_path,
            expected=ADMISSION_ARTIFACT_SIGNATURE_PATH,
            label="admission_signature_path",
        )
        admission_signature_sha256 = _sha256(
            admission_signature_sha256,
            "admission_signature_sha256",
        )
        admission_signature_size = _positive_integer(
            admission_signature_size,
            "admission_signature_size",
        )
        decision: ReadEvidenceAdmission | None = None
        with self._transaction() as connection:
            self._verify_schema(connection)
            self._verify_integrity(connection)
            self._verify_rows(connection)
            row = connection.execute(
                "SELECT * FROM read_evidence_admissions WHERE authorization_id=?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                raise ReadEvidenceAdmissionConflict(
                    "read evidence admission authorization_id is unknown"
                )
            if row["payload_sha256"] != payload_sha256:
                raise ReadEvidenceAdmissionConflict(
                    "read evidence admission payload_sha256 conflicts"
                )
            if row["state"] == AdmissionState.PUBLISHED.value:
                if (
                    row["admission_signature_path"] != admission_signature_path
                    or row["admission_signature_sha256"]
                    != admission_signature_sha256
                    or row["admission_signature_size"] != admission_signature_size
                ):
                    raise ReadEvidenceAdmissionConflict(
                        "read evidence admission signature binding conflicts"
                    )
                decision = self._decision_from_row(row, recovered=True)
            elif row["state"] == AdmissionState.CONSUMED.value:
                published_at = _system_utc_now()
                if published_at.tzinfo is None or published_at.utcoffset() is None:
                    raise ReadEvidenceAdmissionError(
                        "system UTC clock returned an invalid time"
                    )
                published_at = published_at.astimezone(timezone.utc)
                expires_at = _parse_utc_text(row["expires_at"], "expires_at")
                if published_at >= expires_at:
                    raise ReadEvidenceAdmissionError(
                        "read evidence authorization is expired for publication"
                    )
                published_at = published_at.replace(microsecond=0)
                admitted_at = _parse_utc_text(row["admitted_at"], "admitted_at")
                if published_at < admitted_at:
                    raise ReadEvidenceAdmissionError(
                        "read evidence publication is before admitted_at"
                    )
                connection.execute(
                    "UPDATE read_evidence_admissions SET state='published', "
                    "admission_signature_path=?, admission_signature_sha256=?, "
                    "admission_signature_size=?, published_at=? "
                    "WHERE sequence=? AND state='consumed'",
                    (
                        admission_signature_path,
                        admission_signature_sha256,
                        admission_signature_size,
                        _utc_text(published_at),
                        row["sequence"],
                    ),
                )
                published = connection.execute(
                    "SELECT * FROM read_evidence_admissions WHERE sequence=?",
                    (row["sequence"],),
                ).fetchone()
                if published is None:
                    raise ReadEvidenceAdmissionError(
                        "published read evidence admission is missing"
                    )
                decision = self._decision_from_row(published, recovered=False)
            else:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission is not consumable"
                )
        if decision is None:  # pragma: no cover - defensive invariant
            raise ReadEvidenceAdmissionError(
                "read evidence publication did not produce a decision"
            )
        return decision

    def require_published(
        self,
        *,
        authorization_id: str,
        payload_sha256: str,
        sequence: int,
        admission_signature_sha256: str,
    ) -> ReadEvidenceAdmission:
        """Return one exact published row through an existing-only snapshot.

        This verifier-facing lookup neither creates the database nor changes
        SQLite journal settings, starts a writer transaction, or accepts a
        caller-selected time or artifact path.
        """

        authorization_id = _identifier(authorization_id, "authorization_id")
        payload_sha256 = _sha256(payload_sha256, "payload_sha256")
        sequence = _positive_integer(sequence, "sequence")
        admission_signature_sha256 = _sha256(
            admission_signature_sha256,
            "admission_signature_sha256",
        )
        with self._read_connection() as connection:
            self._verify_schema(connection)
            self._verify_integrity(connection)
            self._verify_rows(connection)
            row = connection.execute(
                "SELECT * FROM read_evidence_admissions WHERE sequence=?",
                (sequence,),
            ).fetchone()
            if row is None:
                raise ReadEvidenceAdmissionError(
                    "published read evidence admission does not exist"
                )
            if row["state"] != AdmissionState.PUBLISHED.value:
                raise ReadEvidenceAdmissionError(
                    "read evidence admission is not published"
                )
            if (
                row["authorization_id"] != authorization_id
                or row["payload_sha256"] != payload_sha256
                or row["admission_signature_sha256"]
                != admission_signature_sha256
            ):
                raise ReadEvidenceAdmissionConflict(
                    "published read evidence admission binding conflicts"
                )
            return self._decision_from_row(row, recovered=True)


__all__ = [
    "ACTIVE_ADMISSION_SCHEMA",
    "ADMISSION_ARTIFACT_PATH",
    "ADMISSION_ARTIFACT_SIGNATURE_PATH",
    "ADMISSION_INDEX_PATH",
    "ADMISSION_INDEX_SIGNATURE_PATH",
    "ADMISSION_PAYLOAD_SCHEMA",
    "DEFAULT_READ_EVIDENCE_ADMISSION_PATH",
    "READ_EVIDENCE_ADMISSION_SCHEMA_VERSION",
    "AdmissionState",
    "ReadEvidenceAdmission",
    "ReadEvidenceAdmissionCommitOutcomeUnknown",
    "ReadEvidenceAdmissionConflict",
    "ReadEvidenceAdmissionError",
    "ReadEvidenceAdmissionRequest",
    "SQLiteReadEvidenceAdmissionStore",
]
