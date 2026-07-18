"""Cross-transaction guard against concurrent Odoo module mutations.

The parent starts this one-shot helper before Odoo builds a Registry.  The
helper owns an independent PostgreSQL connection and holds both the V3 shared
module-maintenance advisory lock and a table ``SHARE`` lock until the parent
has completed its final probe and explicitly releases the guard.
"""

from __future__ import annotations

import math
import socket
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping

from ..operations import canonical_json
from .module_graph import (
    OdooModuleGraphError,
    TrustedModuleGraph,
    build_trusted_module_graph,
    validate_module_graph_evidence,
)
from .runner import (
    DATABASE_NAME,
    MAX_TIMEOUT_SECONDS,
    OdooRunnerError,
    RuntimeConfig,
    _kill_child_process_group,
    _linux_supervisor_argv,
    _load_json_object,
    _safe_environment,
    _validate_child_environment,
    _validate_runtime_paths,
)


class ModuleGuardError(OdooRunnerError):
    """The module-mutation guard could not be acquired or proved live."""


MODULE_GUARD_PROTOCOL_VERSION = 1
ADVISORY_NAMESPACE = 0x4F414356
ADVISORY_KEY = 0x4D4F4431
MAX_MODULE_GUARD_FRAME_BYTES = 2 * 1024 * 1024
MAX_MODULE_GUARD_LOCK_TIMEOUT_MS = 10_000

_LOCK_TIMEOUT_SQL = (
    "SELECT pg_catalog.set_config('lock_timeout', %s, true)"
)
_ADVISORY_LOCK_STATUS_SQL = (
    "SELECT pg_catalog.pg_try_advisory_lock_shared(%s, %s)"
)
_TABLE_LOCK_SQL = (
    "LOCK TABLE ONLY public.ir_module_module IN SHARE MODE"
)
_DATABASE_IDENTITY_SQL = (
    "SELECT pg_catalog.current_database(), pg_catalog.pg_backend_pid(), "
    "backend_start FROM pg_catalog.pg_stat_activity "
    "WHERE pid = pg_catalog.pg_backend_pid()"
)
_DATABASE_UUID_SQL = (
    "SELECT value FROM ONLY public.ir_config_parameter "
    "WHERE key = 'database.uuid' ORDER BY id"
)
_PENDING_MODULES_SQL = (
    "SELECT EXISTS (SELECT 1 FROM ONLY public.ir_module_module "
    "WHERE state IN ('to install', 'to remove', 'to upgrade'))"
)
_INSTALLED_MODULES_SQL = (
    "SELECT name, latest_version FROM ONLY public.ir_module_module "
    "WHERE state = 'installed' ORDER BY name, id"
)
_ADVISORY_HELD_SQL = (
    "SELECT count(*) = 1 FROM pg_catalog.pg_locks "
    "WHERE locktype = 'advisory' AND pid = pg_catalog.pg_backend_pid() "
    "AND database = (SELECT oid FROM pg_catalog.pg_database "
    "WHERE datname = pg_catalog.current_database()) "
    "AND classid = %s::pg_catalog.oid AND objid = %s::pg_catalog.oid "
    "AND objsubid = 2 "
    "AND mode = 'ShareLock' AND granted"
)
_TABLE_LOCK_STATUS_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks "
    "WHERE locktype = 'relation' AND pid = pg_catalog.pg_backend_pid() "
    "AND relation = 'public.ir_module_module'::pg_catalog.regclass "
    "AND mode = 'ShareLock' AND granted)"
)
_ADVISORY_UNLOCK_SQL = (
    "SELECT pg_catalog.pg_advisory_unlock_shared(%s, %s)"
)
_RESIDUAL_ADVISORY_LOCK_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_locks "
    "WHERE locktype = 'advisory' AND pid = pg_catalog.pg_backend_pid() "
    "AND database = (SELECT oid FROM pg_catalog.pg_database "
    "WHERE datname = pg_catalog.current_database()) "
    "AND classid = %s::pg_catalog.oid AND objid = %s::pg_catalog.oid "
    "AND objsubid = 2 "
    "AND mode = 'ShareLock' AND granted"
)

_EVIDENCE_FIELDS = frozenset(
    {
        "guard_protocol_version",
        "database_name",
        "database_uuid",
        "backend_pid",
        "backend_start",
        "advisory_lock",
        "table_lock",
        "module_graph",
    }
)
_ADVISORY_EVIDENCE = {
    "namespace": ADVISORY_NAMESPACE,
    "key": ADVISORY_KEY,
    "mode": "shared",
}
_TABLE_EVIDENCE = {
    "relation": "public.ir_module_module",
    "mode": "SHARE",
}
_HELPER_ERROR_CODES = frozenset(
    {
        "database_identity_mismatch",
        "module_guard_failed",
        "module_maintenance_active",
        "pending_module_operation",
    }
)


def _normalized_uuid(value: Any, label: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ModuleGuardError(f"{label} is invalid") from exc
    if not isinstance(value, str) or value != normalized:
        raise ModuleGuardError(f"{label} is invalid")
    return normalized


def _canonical_backend_start(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ModuleGuardError("module guard backend start is invalid")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _validate_backend_start(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ModuleGuardError("module guard backend start is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ModuleGuardError("module guard backend start is invalid") from exc
    if _canonical_backend_start(parsed) != value:
        raise ModuleGuardError("module guard backend start is not canonical")
    return value


class ModuleGuardEvidence:
    """Strict, canonical identity of the backend and locks held by the helper."""

    __slots__ = (
        "database_name",
        "database_uuid",
        "backend_pid",
        "backend_start",
        "module_graph",
    )

    def __init__(
        self,
        *,
        database_name: str,
        database_uuid: str,
        backend_pid: int,
        backend_start: str,
        module_graph: TrustedModuleGraph,
    ) -> None:
        if not isinstance(database_name, str) or DATABASE_NAME.fullmatch(
            database_name
        ) is None:
            raise ModuleGuardError("module guard database name is invalid")
        if isinstance(backend_pid, bool) or not isinstance(backend_pid, int) or backend_pid <= 1:
            raise ModuleGuardError("module guard backend PID is invalid")
        if not isinstance(module_graph, TrustedModuleGraph):
            raise ModuleGuardError("module guard module graph is invalid")
        self.database_name = database_name
        self.database_uuid = _normalized_uuid(
            database_uuid, "module guard database UUID"
        )
        self.backend_pid = backend_pid
        self.backend_start = _validate_backend_start(backend_start)
        self.module_graph = module_graph

    @classmethod
    def from_mapping(cls, value: Any) -> "ModuleGuardEvidence":
        if not isinstance(value, Mapping) or set(value) != _EVIDENCE_FIELDS:
            raise ModuleGuardError("module guard evidence fields are invalid")
        if (
            type(value["guard_protocol_version"]) is not int
            or value["guard_protocol_version"] != MODULE_GUARD_PROTOCOL_VERSION
            or value["advisory_lock"] != _ADVISORY_EVIDENCE
            or value["table_lock"] != _TABLE_EVIDENCE
        ):
            raise ModuleGuardError("module guard lock evidence is invalid")
        try:
            graph = validate_module_graph_evidence(value["module_graph"])
        except OdooModuleGraphError as exc:
            raise ModuleGuardError("module guard module graph is invalid") from exc
        return cls(
            database_name=value["database_name"],
            database_uuid=value["database_uuid"],
            backend_pid=value["backend_pid"],
            backend_start=value["backend_start"],
            module_graph=graph,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "guard_protocol_version": MODULE_GUARD_PROTOCOL_VERSION,
            "database_name": self.database_name,
            "database_uuid": self.database_uuid,
            "backend_pid": self.backend_pid,
            "backend_start": self.backend_start,
            "advisory_lock": dict(_ADVISORY_EVIDENCE),
            "table_lock": dict(_TABLE_EVIDENCE),
            "module_graph": self.module_graph.evidence,
        }


def _single_row(cursor: Any, statement: str, parameters=None) -> tuple[Any, ...]:
    cursor.execute(statement, parameters)
    row = cursor.fetchone()
    if not isinstance(row, (tuple, list)):
        raise ModuleGuardError("module guard database readback is invalid")
    return tuple(row)


def _strict_boolean_row(
    cursor: Any, statement: str, parameters=None
) -> bool:
    row = _single_row(cursor, statement, parameters)
    if len(row) != 1 or type(row[0]) is not bool:
        raise ModuleGuardError("module guard database readback is invalid")
    return row[0]


def _read_database_evidence(
    cursor: Any,
    *,
    expected_database_name: str,
    expected_database_uuid: str,
) -> ModuleGuardEvidence:
    identity = _single_row(cursor, _DATABASE_IDENTITY_SQL)
    if (
        len(identity) != 3
        or identity[0] != expected_database_name
        or isinstance(identity[1], bool)
        or not isinstance(identity[1], int)
        or identity[1] <= 1
    ):
        raise ModuleGuardError("module guard database identity does not match")
    cursor.execute(_DATABASE_UUID_SQL)
    observed_uuid_rows = cursor.fetchall()
    if (
        not isinstance(observed_uuid_rows, (list, tuple))
        or len(observed_uuid_rows) != 1
        or not isinstance(observed_uuid_rows[0], (list, tuple))
        or len(observed_uuid_rows[0]) != 1
    ):
        raise ModuleGuardError("module guard database identity does not match")
    observed_uuid = observed_uuid_rows[0][0]
    if observed_uuid != expected_database_uuid:
        raise ModuleGuardError("module guard database identity does not match")
    if _strict_boolean_row(cursor, _PENDING_MODULES_SQL):
        raise ModuleGuardError("pending module operation prevents the write guard")

    cursor.execute(_INSTALLED_MODULES_SQL)
    raw_graph = cursor.fetchall()
    if not isinstance(raw_graph, (list, tuple)) or any(
        not isinstance(row, (tuple, list)) or len(row) != 2
        for row in raw_graph
    ):
        raise ModuleGuardError("module guard module graph is invalid")
    try:
        graph = build_trusted_module_graph(
            {"name": row[0], "latest_version": row[1]}
            for row in raw_graph
        )
    except (OdooModuleGraphError, TypeError) as exc:
        raise ModuleGuardError("module guard module graph is invalid") from exc
    if len(raw_graph) != len(graph.modules):
        raise ModuleGuardError("module guard module graph is invalid")
    if not _strict_boolean_row(
        cursor,
        _ADVISORY_HELD_SQL,
        (ADVISORY_NAMESPACE, ADVISORY_KEY),
    ) or not _strict_boolean_row(cursor, _TABLE_LOCK_STATUS_SQL):
        raise ModuleGuardError("module guard locks are not held")
    return ModuleGuardEvidence(
        database_name=expected_database_name,
        database_uuid=expected_database_uuid,
        backend_pid=identity[1],
        backend_start=_canonical_backend_start(identity[2]),
        module_graph=graph,
    )


def _unlock_and_close_database_guard(
    connection: Any,
    cursor: Any,
    *,
    advisory_acquired: bool,
    exact: bool,
) -> None:
    error: ModuleGuardError | None = None
    try:
        connection.rollback()
        if advisory_acquired:
            unlocked = _strict_boolean_row(
                cursor,
                _ADVISORY_UNLOCK_SQL,
                (ADVISORY_NAMESPACE, ADVISORY_KEY),
            )
            residual = _single_row(
                cursor,
                _RESIDUAL_ADVISORY_LOCK_SQL,
                (ADVISORY_NAMESPACE, ADVISORY_KEY),
            )
            if (
                unlocked is not True
                or len(residual) != 1
                or isinstance(residual[0], bool)
                or not isinstance(residual[0], int)
                or residual[0] != 0
            ):
                error = ModuleGuardError(
                    "module guard advisory lock was not exactly released"
                )
            connection.rollback()
    except Exception as exc:
        if exact:
            error = ModuleGuardError(
                "module guard advisory lock could not be exactly released"
            )
            error.__cause__ = exc
    finally:
        try:
            cursor.close()
        except Exception:
            if exact and error is None:
                error = ModuleGuardError("module guard cursor could not be closed")
        try:
            connection.close()
        except Exception:
            if exact and error is None:
                error = ModuleGuardError("module guard connection could not be closed")
    if exact and error is not None:
        raise error


class _DatabaseGuardSession:
    def __init__(
        self,
        connection: Any,
        cursor: Any,
        evidence: ModuleGuardEvidence,
    ) -> None:
        self.connection = connection
        self.cursor = cursor
        self.evidence = evidence
        self.closed = False

    def probe(self) -> ModuleGuardEvidence:
        if self.closed:
            raise ModuleGuardError("module guard database session is closed")
        observed = _read_database_evidence(
            self.cursor,
            expected_database_name=self.evidence.database_name,
            expected_database_uuid=self.evidence.database_uuid,
        )
        if observed.as_dict() != self.evidence.as_dict():
            raise ModuleGuardError("module guard evidence changed")
        return observed

    def release(self) -> None:
        if self.closed:
            raise ModuleGuardError("module guard database session is closed")
        self.closed = True
        _unlock_and_close_database_guard(
            self.connection,
            self.cursor,
            advisory_acquired=True,
            exact=True,
        )

    def abort(self) -> None:
        if self.closed:
            return
        self.closed = True
        _unlock_and_close_database_guard(
            self.connection,
            self.cursor,
            advisory_acquired=True,
            exact=False,
        )


def _establish_database_guard(
    connection: Any,
    *,
    expected_database_name: str,
    expected_database_uuid: str,
    lock_timeout_ms: int,
) -> _DatabaseGuardSession:
    cursor = None
    advisory_acquired = False
    try:
        cursor = connection.cursor()
        configured = _single_row(
            cursor, _LOCK_TIMEOUT_SQL, (f"{lock_timeout_ms}ms",)
        )
        if configured != (f"{lock_timeout_ms}ms",):
            raise ModuleGuardError("module guard lock timeout was not applied")
        advisory_acquired = _strict_boolean_row(
            cursor,
            _ADVISORY_LOCK_STATUS_SQL,
            (ADVISORY_NAMESPACE, ADVISORY_KEY),
        )
        if not advisory_acquired:
            raise ModuleGuardError("module maintenance lock is already exclusive")
        cursor.execute(_TABLE_LOCK_SQL)
        evidence = _read_database_evidence(
            cursor,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
        )
        return _DatabaseGuardSession(connection, cursor, evidence)
    except ModuleGuardError:
        if cursor is not None:
            _unlock_and_close_database_guard(
                connection,
                cursor,
                advisory_acquired=advisory_acquired,
                exact=False,
            )
        else:
            try:
                connection.close()
            except Exception:
                pass
        raise
    except Exception as exc:
        if cursor is not None:
            _unlock_and_close_database_guard(
                connection,
                cursor,
                advisory_acquired=advisory_acquired,
                exact=False,
            )
        else:
            try:
                connection.close()
            except Exception:
                pass
        raise ModuleGuardError("module guard database operation failed") from exc


def _open_guard_database(config_path: str, database_name: str):
    """Open a dedicated psycopg2 connection using Odoo config, without Registry."""

    from odoo import sql_db
    from odoo.tools import config as odoo_config
    import psycopg2

    odoo_config.parse_config(["--config", config_path])
    observed_database, connection_info = sql_db.connection_info_for(database_name)
    if observed_database != database_name or not isinstance(connection_info, dict):
        raise ModuleGuardError("module guard database connection identity is invalid")
    return psycopg2.connect(**connection_info)


def _send_frame(control: Any, value: Mapping[str, Any]) -> None:
    try:
        payload = canonical_json(dict(value)) + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ModuleGuardError("module guard control message is invalid") from exc
    if len(payload) > MAX_MODULE_GUARD_FRAME_BYTES:
        raise ModuleGuardError("module guard control message is too large")
    try:
        control.sendall(payload)
    except (OSError, socket.timeout) as exc:
        raise ModuleGuardError("module guard private control socket failed") from exc


def _receive_frame(control: Any) -> dict[str, Any]:
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = control.recv(min(65_536, MAX_MODULE_GUARD_FRAME_BYTES + 1 - total))
            if not chunk:
                raise ModuleGuardError(
                    "module guard helper closed its private control socket"
                )
            newline = chunk.find(b"\n")
            if newline >= 0:
                if (
                    newline != len(chunk) - 1
                    or total + newline >= MAX_MODULE_GUARD_FRAME_BYTES
                ):
                    raise ModuleGuardError(
                        "module guard private control framing is invalid"
                    )
                chunks.append(chunk[:newline])
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_MODULE_GUARD_FRAME_BYTES:
                raise ModuleGuardError("module guard control message is too large")
    except ModuleGuardError:
        raise
    except (OSError, socket.timeout) as exc:
        raise ModuleGuardError("module guard private control socket failed") from exc
    try:
        raw = b"".join(chunks).decode("utf-8")
    except UnicodeError as exc:
        raise ModuleGuardError("module guard control message is not UTF-8") from exc
    try:
        return _load_json_object(raw, "module guard control message")
    except OdooRunnerError as exc:
        raise ModuleGuardError("module guard control message is not valid JSON") from exc


def _validate_command(value: Any, command: str) -> dict[str, Any]:
    common = {"protocol", "status", "command"}
    expected = common
    if command == "acquire":
        expected = common | {
            "config_path",
            "database_name",
            "database_uuid",
            "lock_timeout_ms",
        }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or type(value.get("protocol")) is not int
        or value.get("protocol") != MODULE_GUARD_PROTOCOL_VERSION
        or value.get("status") != "request"
        or value.get("command") != command
    ):
        raise ModuleGuardError("module guard control command is invalid")
    return value


def _validate_acquire_command(value: Any) -> dict[str, Any]:
    command = _validate_command(value, "acquire")
    config_path = command["config_path"]
    database_name = command["database_name"]
    lock_timeout_ms = command["lock_timeout_ms"]
    if (
        not isinstance(config_path, str)
        or not config_path
        or len(config_path) > 4096
        or "\x00" in config_path
        or not PurePosixPath(config_path).is_absolute()
        or not isinstance(database_name, str)
        or DATABASE_NAME.fullmatch(database_name) is None
        or isinstance(lock_timeout_ms, bool)
        or not isinstance(lock_timeout_ms, int)
        or not 1 <= lock_timeout_ms <= MAX_MODULE_GUARD_LOCK_TIMEOUT_MS
    ):
        raise ModuleGuardError("module guard acquire command is invalid")
    _normalized_uuid(command["database_uuid"], "module guard database UUID")
    return command


def _safe_helper_error(exc: BaseException) -> str:
    if isinstance(exc, ModuleGuardError):
        message = str(exc)
        if "pending module operation" in message:
            return "pending_module_operation"
        if "database identity" in message:
            return "database_identity_mismatch"
        if "maintenance lock" in message:
            return "module_maintenance_active"
    return "module_guard_failed"


def _module_guard_helper_main(control_fd: int) -> None:
    """Run the fixed one-shot database guard protocol in the helper process."""

    if isinstance(control_fd, bool) or not isinstance(control_fd, int) or control_fd <= 2:
        raise ModuleGuardError("module guard control descriptor is invalid")
    control = socket.socket(fileno=control_fd)
    session: _DatabaseGuardSession | None = None
    try:
        try:
            command = _validate_acquire_command(_receive_frame(control))
            connection = _open_guard_database(
                command["config_path"], command["database_name"]
            )
            session = _establish_database_guard(
                connection,
                expected_database_name=command["database_name"],
                expected_database_uuid=command["database_uuid"],
                lock_timeout_ms=command["lock_timeout_ms"],
            )
            _send_frame(
                control,
                {
                    "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                    "status": "ready",
                    "evidence": session.evidence.as_dict(),
                },
            )
            while True:
                request = _receive_frame(control)
                requested_command = request.get("command")
                if requested_command == "probe":
                    _validate_command(request, "probe")
                    observed = session.probe()
                    _send_frame(
                        control,
                        {
                            "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                            "status": "probed",
                            "evidence": observed.as_dict(),
                        },
                    )
                elif requested_command == "release":
                    _validate_command(request, "release")
                    session.release()
                    session = None
                    _send_frame(
                        control,
                        {
                            "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                            "status": "released",
                        },
                    )
                    return
                else:
                    raise ModuleGuardError("module guard control command is invalid")
        except BaseException as exc:
            try:
                _send_frame(
                    control,
                    {
                        "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                        "status": "error",
                        "code": _safe_helper_error(exc),
                    },
                )
            except BaseException:
                pass
            raise
    finally:
        if session is not None:
            session.abort()
        control.close()


class ModuleGuard:
    """Parent-side handle for a live one-shot module guard helper."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        control: Any,
        ready_evidence: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> None:
        self._process = process
        self._control = control
        self._ready = ModuleGuardEvidence.from_mapping(ready_evidence)
        self._timeout_seconds = float(timeout_seconds)
        self._state = "acquired"
        self._mutex = threading.Lock()

    @property
    def evidence(self) -> dict[str, Any]:
        return self._ready.as_dict()

    def _fail_closed(self) -> None:
        if self._state in {"released", "aborted", "failed"}:
            return
        self._state = "failed"
        try:
            self._control.close()
        finally:
            if self._process.poll() is None:
                _kill_child_process_group(self._process)

    def _exchange(
        self,
        command: str,
        expected_status: str,
        *,
        timeout_seconds: float | None,
        allow_exit: bool = False,
    ) -> dict[str, Any]:
        timeout = self._timeout_seconds if timeout_seconds is None else timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > MAX_TIMEOUT_SECONDS
        ):
            raise ModuleGuardError("module guard timeout_seconds is invalid")
        try:
            if self._process.poll() is not None:
                raise ModuleGuardError("module guard helper is not alive")
            self._control.settimeout(float(timeout))
            _send_frame(
                self._control,
                {
                    "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                    "status": "request",
                    "command": command,
                },
            )
            response = _receive_frame(self._control)
            if (
                not allow_exit
                and self._process.poll() is not None
            ):
                raise ModuleGuardError("module guard helper died after its response")
            if response.get("status") == "error":
                if (
                    set(response) != {"protocol", "status", "code"}
                    or response.get("protocol") != MODULE_GUARD_PROTOCOL_VERSION
                    or response.get("code") not in _HELPER_ERROR_CODES
                ):
                    raise ModuleGuardError("module guard error response is invalid")
                raise ModuleGuardError(
                    f"module guard helper rejected the command: {response['code']}"
                )
            if (
                response.get("protocol") != MODULE_GUARD_PROTOCOL_VERSION
                or response.get("status") != expected_status
            ):
                raise ModuleGuardError("module guard response is invalid")
            return response
        except ModuleGuardError:
            self._fail_closed()
            raise
        except BaseException as exc:
            self._fail_closed()
            raise ModuleGuardError("module guard command failed") from exc

    def final_probe(
        self, *, timeout_seconds: float | None = None
    ) -> dict[str, Any]:
        with self._mutex:
            if self._state not in {"acquired", "probed"}:
                raise ModuleGuardError("module guard is not available for final probe")
            response = self._exchange(
                "probe", "probed", timeout_seconds=timeout_seconds
            )
            if set(response) != {"protocol", "status", "evidence"}:
                self._fail_closed()
                raise ModuleGuardError("module guard probe response is invalid")
            try:
                observed = ModuleGuardEvidence.from_mapping(response["evidence"])
            except ModuleGuardError:
                self._fail_closed()
                raise
            if observed.as_dict() != self._ready.as_dict():
                self._fail_closed()
                raise ModuleGuardError("module guard evidence changed")
            self._state = "probed"
            return observed.as_dict()

    def release(self, *, timeout_seconds: float | None = None) -> None:
        with self._mutex:
            if self._state != "probed":
                raise ModuleGuardError(
                    "module guard release requires a successful final probe"
                )
            response = self._exchange(
                "release",
                "released",
                timeout_seconds=timeout_seconds,
                allow_exit=True,
            )
            if set(response) != {"protocol", "status"}:
                self._fail_closed()
                raise ModuleGuardError("module guard release response is invalid")
            try:
                returncode = self._process.wait(
                    timeout=(
                        self._timeout_seconds
                        if timeout_seconds is None
                        else float(timeout_seconds)
                    )
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                self._fail_closed()
                raise ModuleGuardError("module guard helper did not exit") from exc
            if returncode != 0:
                self._fail_closed()
                raise ModuleGuardError("module guard helper exited unsuccessfully")
            self._control.close()
            self._state = "released"

    def abort(self) -> None:
        with self._mutex:
            if self._state in {"released", "aborted"}:
                return
            try:
                self._control.close()
            finally:
                if self._process.poll() is None:
                    _kill_child_process_group(self._process)
                self._state = "aborted"

    def __enter__(self) -> "ModuleGuard":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        if self._state != "released":
            self.abort()


def _helper_argv(config: RuntimeConfig, control_fd: int) -> list[str]:
    source_root = config.release_root / "src"
    odoo_root = config.odoo_bin.parent
    bootstrap = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        f"sys.path.insert(0, {str(odoo_root)!r})\n"
        "from odoo_accounting_cli_v3.odoo.module_guard import "
        "_module_guard_helper_main\n"
        "_module_guard_helper_main(int(sys.argv[1]))\n"
    )
    return [
        str(config.odoo_python),
        "-I",
        "-c",
        bootstrap,
        str(control_fd),
    ]


def _cleanup_failed_spawn(process: Any, control: Any) -> None:
    try:
        control.close()
    finally:
        if process is not None and process.poll() is None:
            _kill_child_process_group(process)


def acquire_module_guard(
    config: RuntimeConfig,
    *,
    timeout_seconds: float = 10.0,
    lock_timeout_ms: int = 3000,
) -> ModuleGuard:
    """Acquire the pre-Registry guard and return a fail-closed live handle."""

    if not isinstance(config, RuntimeConfig):
        raise ModuleGuardError("a validated Odoo runtime configuration is required")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise ModuleGuardError("module guard timeout_seconds is invalid")
    if (
        isinstance(lock_timeout_ms, bool)
        or not isinstance(lock_timeout_ms, int)
        or not 1 <= lock_timeout_ms <= MAX_MODULE_GUARD_LOCK_TIMEOUT_MS
    ):
        raise ModuleGuardError("module guard lock_timeout_ms is invalid")
    if sys.platform != "linux":
        raise ModuleGuardError("the module guard helper requires Linux")

    _validate_runtime_paths(config)
    environment = _safe_environment()
    _validate_child_environment(environment)
    parent_control = None
    child_control = None
    process = None
    try:
        # On Linux, the default socketpair family is AF_UNIX.  Leaving the
        # defaults also lets non-POSIX unit tests mock this trusted boundary.
        parent_control, child_control = socket.socketpair()
        child_fd = child_control.fileno()
        process = subprocess.Popen(
            _linux_supervisor_argv(_helper_argv(config, child_fd), child_fd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=(child_fd,),
            start_new_session=True,
            cwd=str(config.release_root),
            env=environment,
        )
        child_control.close()
        child_control = None
        parent_control.settimeout(float(timeout_seconds))
        _send_frame(
            parent_control,
            {
                "protocol": MODULE_GUARD_PROTOCOL_VERSION,
                "status": "request",
                "command": "acquire",
                "config_path": str(config.odoo_config),
                "database_name": config.database_name,
                "database_uuid": config.database_uuid,
                "lock_timeout_ms": lock_timeout_ms,
            },
        )
        response = _receive_frame(parent_control)
        if process.poll() is not None:
            raise ModuleGuardError("module guard helper exited during acquisition")
        if response.get("status") == "error":
            if (
                set(response) != {"protocol", "status", "code"}
                or response.get("protocol") != MODULE_GUARD_PROTOCOL_VERSION
                or response.get("code") not in _HELPER_ERROR_CODES
            ):
                raise ModuleGuardError("module guard error response is invalid")
            raise ModuleGuardError(
                f"module guard helper rejected acquisition: {response['code']}"
            )
        if set(response) != {"protocol", "status", "evidence"} or (
            response.get("protocol") != MODULE_GUARD_PROTOCOL_VERSION
            or response.get("status") != "ready"
        ):
            raise ModuleGuardError("module guard ready response is invalid")
        evidence = ModuleGuardEvidence.from_mapping(response["evidence"])
        if (
            evidence.database_name != config.database_name
            or evidence.database_uuid != config.database_uuid
        ):
            raise ModuleGuardError("module guard runtime identity does not match")
        return ModuleGuard(
            process,
            parent_control,
            evidence.as_dict(),
            timeout_seconds=float(timeout_seconds),
        )
    except ModuleGuardError:
        if child_control is not None:
            child_control.close()
        if parent_control is not None:
            _cleanup_failed_spawn(process, parent_control)
        raise
    except BaseException as exc:
        if child_control is not None:
            child_control.close()
        if parent_control is not None:
            _cleanup_failed_spawn(process, parent_control)
        raise ModuleGuardError("module guard helper could not be started") from exc


__all__ = [
    "ADVISORY_KEY",
    "ADVISORY_NAMESPACE",
    "MODULE_GUARD_PROTOCOL_VERSION",
    "ModuleGuard",
    "ModuleGuardError",
    "ModuleGuardEvidence",
    "acquire_module_guard",
]
