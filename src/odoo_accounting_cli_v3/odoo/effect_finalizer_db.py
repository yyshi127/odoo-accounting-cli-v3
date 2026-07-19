"""Direct-LOGIN PostgreSQL adapter for the isolated effect finalizer service."""

from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..effect_finalizer import (
    EffectFinalizationAttestation,
    EffectFinalizationError,
    EffectFinalizationIdentity,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
)
from ..effect_finalizer_service import EffectFinalizationAttemptExpired


class EffectFinalizerDatabaseError(RuntimeError):
    """The direct finalizer connection or immutable DB receipt was rejected."""


_APPLICATION_NAME = "odoo-accounting-cli-v3-effect-finalizer"
_FINALIZE_EXPIRED_MESSAGE = "operation effect finalization request is invalid"
_TRUSTED_LOCAL_SOCKET_HOSTS = frozenset(
    {"/run/postgresql", "/var/run/postgresql"}
)
_LIBPQ_ENVIRONMENT_LOCK = threading.Lock()
_STATE_FIELDS = (
    "protocol_version",
    "schema_version",
    "guard_installation_id",
    "database_oid",
    "database_uuid",
    "epoch",
    "module_guard_open",
    "opened_epoch",
    "unresolved_effect_count",
    "ledger_unresolved_effect_count",
    "runtime_role",
    "maintenance_role",
    "finalizer_role",
    "maintenance_id",
    "maintenance_expires_at",
    "maintenance_holder_pid",
    "maintenance_holder_backend_start",
    "last_module_change_at",
    "last_module_change_txid",
)
_RECEIPT_FIELDS = (
    "receipt_attestation_id",
    "receipt_guard_installation_id",
    "receipt_database_oid",
    "receipt_database_uuid",
    "resolved_operation_id",
    "receipt_resolution_operation_id",
    "applied_resolution_kind",
    "resolved_anchor_count",
    "remaining_unresolved_count",
    "guard_epoch",
    "receipt_attestation_digest",
    "finalized_at",
    "finalized_txid",
    "replayed",
)
_IDENTITY_SQL = (
    "SELECT pg_catalog.current_database(), session_user::text, "
    "current_user::text, pg_catalog.current_setting('role', true)"
)
_STATE_SQL = (
    "SELECT * FROM odoo_accounting_cli_v3_guard.read_module_guard_state()"
)
_FINALIZE_SQL = (
    "SELECT * FROM odoo_accounting_cli_v3_guard.finalize_operation_effect("
    "%s::uuid, %s::oid, %s::uuid, %s::uuid, %s::text, %s::text, "
    "%s::timestamp with time zone, %s::timestamp with time zone, "
    "%s::text, %s::text, %s::text, %s::text, %s::text, %s::text, "
    "%s::text, %s::text)"
)


def _strict_text(value: Any, label: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EffectFinalizerDatabaseError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class EffectFinalizerDatabaseConfig:
    database_name: str
    database_uuid: str
    database_user: str
    expected_guard_installation_id: str
    expected_database_oid: int
    host: str
    port: int
    passfile_path: Path
    connect_timeout_seconds: int
    statement_timeout_ms: int
    require_posix_owner: bool = True

    def __post_init__(self) -> None:
        try:
            import uuid

            normalized_uuid = str(uuid.UUID(self.database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise EffectFinalizerDatabaseError(
                "effect finalizer database UUID is invalid"
            ) from exc
        try:
            identity = EffectFinalizationIdentity(
                attestation_key_id="runtime-validation-key",
                guard_installation_id=self.expected_guard_installation_id,
                database_oid=self.expected_database_oid,
            )
        except EffectFinalizationError as exc:
            raise EffectFinalizerDatabaseError(
                "effect finalizer database identity is invalid"
            ) from exc
        if (
            _strict_text(self.database_name, "database_name") != self.database_name
            or _strict_text(self.database_user, "database_user")
            != self.database_user
            or _strict_text(self.host, "database host", 255) != self.host
            or self.host not in _TRUSTED_LOCAL_SOCKET_HOSTS
            or normalized_uuid != self.database_uuid
            or "*" in {self.database_name, self.database_user, self.host}
            or ":" in self.database_name
            or ":" in self.database_user
            or isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
            or not isinstance(self.passfile_path, Path)
            or not self.passfile_path.is_absolute()
            or isinstance(self.connect_timeout_seconds, bool)
            or not isinstance(self.connect_timeout_seconds, int)
            # libpq rounds a one-second connect timeout up to two seconds.
            or not 2 <= self.connect_timeout_seconds <= 30
            or isinstance(self.statement_timeout_ms, bool)
            or not isinstance(self.statement_timeout_ms, int)
            or not 100 <= self.statement_timeout_ms <= 30_000
            or type(self.require_posix_owner) is not bool
        ):
            raise EffectFinalizerDatabaseError(
                "effect finalizer database configuration is invalid"
            )
        object.__setattr__(
            self,
            "expected_guard_installation_id",
            identity.guard_installation_id,
        )


def _read_exact_passfile(config: EffectFinalizerDatabaseConfig) -> str:
    path = config.passfile_path
    try:
        current = path.parent
        while True:
            ancestor = current.lstat()
            if (
                not stat.S_ISDIR(ancestor.st_mode)
                or current.is_symlink()
                or current.resolve(strict=True) != current
                or (
                    os.name == "posix"
                    and config.require_posix_owner
                    and (
                        ancestor.st_uid != 0
                        or stat.S_IMODE(ancestor.st_mode) & 0o022
                    )
                )
            ):
                raise EffectFinalizerDatabaseError(
                    "effect finalizer pgpass ancestors are unsafe"
                )
            if current.parent == current:
                break
            current = current.parent
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise EffectFinalizerDatabaseError("effect finalizer pgpass is unsafe")
        if os.name == "posix":
            if (
                stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
                or (
                    config.require_posix_owner
                    and metadata.st_uid not in {0, os.geteuid()}
                )
            ):
                raise EffectFinalizerDatabaseError(
                    "effect finalizer pgpass is unsafe"
                )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise EffectFinalizerDatabaseError(
                    "effect finalizer pgpass changed while opened"
                )
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not raw or len(raw) > 4096 or not raw.endswith(b"\n") or b"\r" in raw:
            raise EffectFinalizerDatabaseError("effect finalizer pgpass is invalid")
        text = raw[:-1].decode("utf-8")
    except EffectFinalizerDatabaseError:
        raise
    except (OSError, UnicodeError) as exc:
        raise EffectFinalizerDatabaseError(
            "effect finalizer pgpass is unavailable"
        ) from exc

    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise EffectFinalizerDatabaseError("effect finalizer pgpass is invalid")
    fields.append("".join(current))
    expected = [
        config.host,
        str(config.port),
        config.database_name,
        config.database_user,
    ]
    if (
        len(fields) != 5
        or fields[:4] != expected
        or any(not field or "*" in field for field in fields[:4])
        or not fields[4]
        or "\n" in fields[4]
        or "\x00" in fields[4]
    ):
        raise EffectFinalizerDatabaseError(
            "effect finalizer pgpass is not one exact database binding"
        )
    return fields[4]


def preflight_effect_finalizer_database_config(
    config: EffectFinalizerDatabaseConfig,
) -> None:
    """Fail startup unless the direct LOGIN credential has one exact binding."""

    if not isinstance(config, EffectFinalizerDatabaseConfig):
        raise EffectFinalizerDatabaseError(
            "effect finalizer database configuration is invalid"
        )
    _read_exact_passfile(config)


@contextmanager
def _without_libpq_environment():
    """Prevent libpq environment defaults from changing the pinned session."""

    with _LIBPQ_ENVIRONMENT_LOCK:
        saved = {
            key: value
            for key, value in os.environ.items()
            if key.upper().startswith("PG")
        }
        for key in saved:
            os.environ.pop(key, None)
        try:
            yield
        finally:
            for key in tuple(os.environ):
                if key.upper().startswith("PG"):
                    os.environ.pop(key, None)
            os.environ.update(saved)


def sanitized_direct_connection_info(
    config: EffectFinalizerDatabaseConfig,
) -> dict[str, Any]:
    """Bind a direct LOGIN to one local socket and one securely read password."""

    if not isinstance(config, EffectFinalizerDatabaseConfig):
        raise EffectFinalizerDatabaseError(
            "effect finalizer database configuration is invalid"
        )
    password = _read_exact_passfile(config)
    return {
        "dbname": config.database_name,
        "host": config.host,
        "port": config.port,
        "user": config.database_user,
        "password": password,
        "connect_timeout": config.connect_timeout_seconds,
        "application_name": _APPLICATION_NAME,
    }


def open_direct_finalizer_connection(
    *,
    config: EffectFinalizerDatabaseConfig,
    connect: Callable[..., Any],
) -> Any:
    """Open the finalizer role as session_user; SET ROLE is never supported."""

    if not callable(connect):
        raise EffectFinalizerDatabaseError("database connector is invalid")
    parameters = sanitized_direct_connection_info(config)
    try:
        with _without_libpq_environment():
            return connect(**parameters)
    except Exception as exc:
        raise EffectFinalizerDatabaseError(
            "direct effect finalizer database connection failed"
        ) from exc
    finally:
        # Do not retain the credential in this adapter after libpq consumed it.
        parameters["password"] = ""

def _one_row(cursor: Any, sql: str, parameters: Any = None) -> tuple[Any, ...]:
    cursor.execute(sql, parameters)
    rows = cursor.fetchall()
    if (
        not isinstance(rows, (list, tuple))
        or len(rows) != 1
        or not isinstance(rows[0], (list, tuple))
    ):
        raise EffectFinalizerDatabaseError(
            "effect finalizer database did not return exactly one row"
        )
    return tuple(rows[0])


def _columns(cursor: Any, expected: tuple[str, ...]) -> None:
    try:
        observed = tuple(item[0] for item in cursor.description)
    except (TypeError, IndexError) as exc:
        raise EffectFinalizerDatabaseError(
            "effect finalizer database columns are invalid"
        ) from exc
    if observed != expected:
        raise EffectFinalizerDatabaseError(
            "effect finalizer database columns are invalid"
        )


def _expired_uncommitted(exc: BaseException, request: EffectFinalizationRequest, now: datetime) -> bool:
    sqlstate = getattr(exc, "pgcode", None) or getattr(exc, "sqlstate", None)
    diagnostic = getattr(exc, "diag", None)
    primary = getattr(diagnostic, "message_primary", None)
    return (
        sqlstate == "22000"
        and primary == _FINALIZE_EXPIRED_MESSAGE
        and now >= request.expires_at
    )


def finalize_effect_attempt(
    connection: Any,
    *,
    config: EffectFinalizerDatabaseConfig,
    request: EffectFinalizationRequest,
    attestation: EffectFinalizationAttestation,
    now: Callable[[], datetime],
) -> EffectFinalizationReceipt:
    """Commit one parameterized finalizer call before returning its typed receipt."""

    if (
        not isinstance(config, EffectFinalizerDatabaseConfig)
        or not isinstance(request, EffectFinalizationRequest)
        or not isinstance(attestation, EffectFinalizationAttestation)
        or not callable(now)
        or request.database_name != config.database_name
        or request.database_uuid != config.database_uuid
        or request.request_digest != attestation.request_digest
    ):
        raise EffectFinalizerDatabaseError(
            "effect finalizer database request is invalid"
        )
    cursor = None
    try:
        connection.autocommit = False
        cursor = connection.cursor()
        configured = _one_row(
            cursor,
            "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
            (f"{config.statement_timeout_ms}ms",),
        )
        if configured != (f"{config.statement_timeout_ms}ms",):
            raise EffectFinalizerDatabaseError(
                "effect finalizer statement timeout was not applied"
            )
        identity = _one_row(cursor, _IDENTITY_SQL)
        if identity != (
            config.database_name,
            config.database_user,
            config.database_user,
            "none",
        ):
            raise EffectFinalizerDatabaseError(
                "effect finalizer is not a direct database LOGIN"
            )
        state_row = _one_row(cursor, _STATE_SQL)
        _columns(cursor, _STATE_FIELDS)
        state = dict(zip(_STATE_FIELDS, state_row, strict=True))
        if (
            type(state["protocol_version"]) is not int
            or state["protocol_version"] != 1
            or type(state["schema_version"]) is not int
            or state["schema_version"] != 2
            or str(state["database_uuid"]) != config.database_uuid
            or state["finalizer_role"] != config.database_user
            or str(state["guard_installation_id"])
            != config.expected_guard_installation_id
            or state["database_oid"] != config.expected_database_oid
            or type(state["module_guard_open"]) is not bool
            or state["module_guard_open"] is not False
            or isinstance(state["database_oid"], bool)
            or not isinstance(state["database_oid"], int)
            or state["database_oid"] <= 0
            or isinstance(state["unresolved_effect_count"], bool)
            or not isinstance(state["unresolved_effect_count"], int)
            or state["unresolved_effect_count"] < 0
            or isinstance(state["ledger_unresolved_effect_count"], bool)
            or not isinstance(state["ledger_unresolved_effect_count"], int)
            or state["ledger_unresolved_effect_count"] < 0
            or state["unresolved_effect_count"]
            != state["ledger_unresolved_effect_count"]
        ):
            raise EffectFinalizerDatabaseError(
                "effect finalizer module-guard state is invalid"
            )
        parameters = (
            config.expected_guard_installation_id,
            config.expected_database_oid,
            config.database_uuid,
            attestation.attestation_id,
            attestation.attestation_digest,
            attestation.key_id,
            request.verified_at,
            request.expires_at,
            request.operation_id,
            request.operation_digest,
            request.execution_result_digest,
            request.resolution_operation_id,
            request.resolution_operation_digest,
            request.resolution_execution_result_digest,
            request.resolution_kind,
            request.resolution_result_digest,
        )
        try:
            receipt_row = _one_row(cursor, _FINALIZE_SQL, parameters)
        except Exception as exc:
            observed_now = now()
            if (
                isinstance(observed_now, datetime)
                and observed_now.tzinfo is not None
                and _expired_uncommitted(
                    exc, request, observed_now.astimezone(timezone.utc)
                )
            ):
                raise EffectFinalizationAttemptExpired(
                    "exact finalization attempt is absent and expired"
                ) from exc
            raise
        _columns(cursor, _RECEIPT_FIELDS)
        mapping = {
            key: (str(value) if key.endswith("_id") and value is not None else value)
            for key, value in zip(_RECEIPT_FIELDS, receipt_row, strict=True)
        }
        mapping["receipt_database_uuid"] = str(mapping["receipt_database_uuid"])
        mapping["receipt_guard_installation_id"] = str(
            mapping["receipt_guard_installation_id"]
        )
        mapping["receipt_attestation_id"] = str(mapping["receipt_attestation_id"])
        receipt = EffectFinalizationReceipt.from_database_mapping(
            mapping,
            request=request,
            attestation=attestation,
        )
        connection.commit()
        return receipt
    except EffectFinalizationAttemptExpired:
        try:
            connection.rollback()
        finally:
            if cursor is not None:
                cursor.close()
        raise
    except Exception as exc:
        try:
            connection.rollback()
        finally:
            if cursor is not None:
                cursor.close()
        if isinstance(exc, EffectFinalizerDatabaseError):
            raise
        raise EffectFinalizerDatabaseError(
            "effect finalizer database transaction failed"
        ) from exc
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass


__all__ = [
    "EffectFinalizerDatabaseConfig",
    "EffectFinalizerDatabaseError",
    "finalize_effect_attempt",
    "open_direct_finalizer_connection",
    "preflight_effect_finalizer_database_config",
    "sanitized_direct_connection_info",
]
