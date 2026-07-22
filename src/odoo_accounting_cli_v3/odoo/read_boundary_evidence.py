"""Strict evidence collector for the Odoo PostgreSQL read boundary."""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from types import SimpleNamespace
from typing import Any

from .read_transaction import (
    OdooReadTransactionError,
    run_readonly_odoo_transaction,
)


class ReadBoundaryEvidenceError(RuntimeError):
    """The runtime did not prove the complete rollback-only read boundary."""


SCHEMA_VERSION = "odoo-accounting-cli-v3.read-boundary-evidence.v1"
_TRANSACTION_STATUS_IDLE = 0
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DATABASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SNAPSHOT_SQL = (
    "SELECT current_setting('transaction_read_only'), "
    "current_setting('transaction_isolation'), "
    "current_setting('odoo_accounting_cli_v3.read_transaction_marker', true), "
    "current_database(), pg_backend_pid()::bigint, "
    "(SELECT value FROM ONLY public.ir_config_parameter "
    "WHERE key = 'database.uuid'), "
    "relation.oid::bigint, pg_relation_filenode(relation.oid)::bigint, "
    "(SELECT count(*)::bigint FROM ONLY public.ir_config_parameter) "
    "FROM pg_catalog.pg_class AS relation "
    "JOIN pg_catalog.pg_namespace AS namespace "
    "ON namespace.oid = relation.relnamespace "
    "WHERE namespace.nspname = 'public' "
    "AND relation.relname = 'ir_config_parameter' "
    "AND relation.relkind IN ('r', 'p')"
)
_WRITE_PROBE_SQL = (
    "UPDATE ONLY public.ir_config_parameter SET value = value WHERE FALSE"
)
_ROLLBACK_REOPEN_SQL = "SELECT 1::integer"
_ATTESTATION_FAILED = "Odoo read-only transaction attestation failed"
_ROLLBACK_REOPENED = "Odoo read transaction did not return to idle"
_COLLECTION_FAILED = "Odoo read-boundary evidence collection failed"
_WRITE_NOT_PROVEN = "Odoo read-boundary write rejection was not proven"
_DRIFT_NOT_PROVEN = "Odoo read-boundary drift rejection was not proven"
_INVARIANTS_CHANGED = "Odoo read-boundary invariants changed"
_INVALID_EVIDENCE = "Odoo read-boundary evidence is invalid"


def _root_cursor(root_env: Any) -> tuple[Any, Any]:
    try:
        cursor = root_env.cr
        connection = cursor.connection
    except Exception:
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED) from None
    try:
        for owner, method in (
            (connection, "commit"),
            (connection, "get_transaction_status"),
            (cursor, "execute"),
            (cursor, "fetchone"),
            (cursor, "rollback"),
        ):
            if not callable(getattr(owner, method, None)):
                raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    except ReadBoundaryEvidenceError:
        raise
    except Exception:
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED) from None
    return cursor, connection


def _is_idle(connection: Any) -> bool:
    try:
        observed = connection.get_transaction_status()
    except Exception:
        return False
    return not isinstance(observed, bool) and observed == _TRANSACTION_STATUS_IDLE


def _cleanup_to_idle(cursor: Any, connection: Any, message: str) -> None:
    try:
        cursor.rollback()
    except Exception:
        raise ReadBoundaryEvidenceError(message) from None
    if not _is_idle(connection):
        raise ReadBoundaryEvidenceError(message)


def _strict_positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _strict_nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    try:
        normalized = str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError):
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED) from None
    if value != normalized:
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    return normalized


def _snapshot(cursor: Any, connection: Any) -> dict[str, Any]:
    def observe() -> Any:
        cursor.execute(_SNAPSHOT_SQL)
        return cursor.fetchone()

    try:
        row = run_readonly_odoo_transaction(
            SimpleNamespace(cr=cursor),
            observe,
        )
    except Exception:
        if not _is_idle(connection):
            _cleanup_to_idle(cursor, connection, _COLLECTION_FAILED)
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED) from None
    if not _is_idle(connection):
        _cleanup_to_idle(cursor, connection, _COLLECTION_FAILED)
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    if (
        not isinstance(row, (tuple, list))
        or len(row) != 9
        or row[0] != "on"
        or row[1] != "repeatable read"
        or not isinstance(row[2], str)
        or _SHA256.fullmatch(row[2]) is None
        or not isinstance(row[3], str)
        or _DATABASE_NAME.fullmatch(row[3]) is None
        or not _strict_positive_integer(row[4])
        or not _strict_positive_integer(row[6])
        or not _strict_positive_integer(row[7])
        or not _strict_nonnegative_integer(row[8])
    ):
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    return {
        "database": {
            "backend_pid": row[4],
            "name": row[3],
            "uuid": _canonical_uuid(row[5]),
        },
        "relation": {
            "filenode": row[7],
            "oid": row[6],
            "row_count": row[8],
        },
        "transaction": {
            "idle_after_rollback": True,
            "isolation": "repeatable read",
            "marker_sha256": hashlib.sha256(row[2].encode("ascii")).hexdigest(),
            "read_only": True,
        },
    }


def _sqlstate(error: Exception) -> str | None:
    try:
        value = getattr(error, "pgcode", None)
        if value is None:
            value = getattr(error, "sqlstate", None)
    except Exception:
        return None
    return value if isinstance(value, str) else None


def _write_rejection_probe(root_env: Any, cursor: Any, connection: Any) -> dict[str, Any]:
    failure: Exception | None = None

    def attempt_write() -> None:
        cursor.execute(_WRITE_PROBE_SQL)

    try:
        run_readonly_odoo_transaction(root_env, attempt_write)
    except Exception as exc:
        failure = exc
    finally:
        _cleanup_to_idle(cursor, connection, _WRITE_NOT_PROVEN)
    if failure is None or _sqlstate(failure) != "25006":
        raise ReadBoundaryEvidenceError(_WRITE_NOT_PROVEN)
    return {
        "idle_after_rollback": True,
        "rejected": True,
        "sqlstate": "25006",
        "statement_id": "ir-config-parameter-noop-update-v1",
    }


class _RollbackReopenCursor:
    """Probe-only cursor facade whose rollback hook starts a new transaction."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor
        self.connection = cursor.connection

    @property
    def readonly(self) -> Any:
        return self._cursor.readonly

    def execute(self, statement: str, parameters: Any = None) -> None:
        self._cursor.execute(statement, parameters)

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def rollback(self) -> None:
        self._cursor.rollback()
        self._cursor.execute(_ROLLBACK_REOPEN_SQL)


def _new_canaries() -> dict[str, bytes]:
    names = ("hidden_commit", "hidden_rollback", "rollback_hook_reopen")
    values: dict[str, bytes] = {}
    for name in names:
        try:
            value = secrets.token_bytes(32)
        except Exception:
            raise ReadBoundaryEvidenceError(_DRIFT_NOT_PROVEN) from None
        if not isinstance(value, bytes) or len(value) != 32 or value in values.values():
            raise ReadBoundaryEvidenceError(_DRIFT_NOT_PROVEN)
        values[name] = value
    return values


def _drift_probe(
    name: str,
    canary: bytes,
    root_env: Any,
    cursor: Any,
    connection: Any,
) -> dict[str, Any]:
    if name == "hidden_commit":
        def callback() -> bytes:
            connection.commit()
            cursor.execute(_ROLLBACK_REOPEN_SQL)
            return canary

        probe_env = root_env
        expected = _ATTESTATION_FAILED
    elif name == "hidden_rollback":
        def callback() -> bytes:
            cursor.rollback()
            cursor.execute(_ROLLBACK_REOPEN_SQL)
            return canary

        probe_env = root_env
        expected = _ATTESTATION_FAILED
    elif name == "rollback_hook_reopen":
        def callback() -> bytes:
            return canary

        probe_env = SimpleNamespace(cr=_RollbackReopenCursor(cursor))
        expected = _ROLLBACK_REOPENED
    else:  # pragma: no cover - names are fixed at the only call site.
        raise ReadBoundaryEvidenceError(_DRIFT_NOT_PROVEN)

    rejected = False
    try:
        run_readonly_odoo_transaction(probe_env, callback)
    except OdooReadTransactionError as exc:
        rejected = str(exc) == expected
    except Exception:
        rejected = False
    finally:
        _cleanup_to_idle(cursor, connection, _DRIFT_NOT_PROVEN)
    if not rejected:
        raise ReadBoundaryEvidenceError(_DRIFT_NOT_PROVEN)
    return {
        "canary_sha256": hashlib.sha256(canary).hexdigest(),
        "idle_after_cleanup": True,
        "rejected": True,
        "result_released": False,
    }


def collect_read_boundary_evidence(root_env: Any) -> dict[str, Any]:
    """Collect one strict, secret-free proof on a single Odoo shell connection."""

    cursor, connection = _root_cursor(root_env)
    if not _is_idle(connection):
        raise ReadBoundaryEvidenceError(_COLLECTION_FAILED)
    before = _snapshot(cursor, connection)
    write_probe = _write_rejection_probe(root_env, cursor, connection)
    canaries = _new_canaries()
    drift_probes = {
        name: _drift_probe(name, canary, root_env, cursor, connection)
        for name, canary in canaries.items()
    }
    after = _snapshot(cursor, connection)

    checks = {
        "backend_pid_unchanged": before["database"]["backend_pid"]
        == after["database"]["backend_pid"],
        "database_name_unchanged": before["database"]["name"]
        == after["database"]["name"],
        "database_uuid_unchanged": before["database"]["uuid"]
        == after["database"]["uuid"],
        "relation_filenode_unchanged": before["relation"]["filenode"]
        == after["relation"]["filenode"],
        "relation_oid_unchanged": before["relation"]["oid"]
        == after["relation"]["oid"],
        "relation_row_count_unchanged": before["relation"]["row_count"]
        == after["relation"]["row_count"],
    }
    if not all(checks.values()) or (
        before["transaction"]["marker_sha256"]
        == after["transaction"]["marker_sha256"]
    ):
        raise ReadBoundaryEvidenceError(_INVARIANTS_CHANGED)
    evidence = {
        "checks": checks,
        "database": {
            "after": after["database"],
            "before": before["database"],
        },
        "drift_probes": drift_probes,
        "relation": {
            "after": after["relation"],
            "before": before["relation"],
            "name": "ir_config_parameter",
            "schema": "public",
        },
        "schema_version": SCHEMA_VERSION,
        "successful_transactions": {
            "after": after["transaction"],
            "before": before["transaction"],
        },
        "write_probe": write_probe,
    }
    return validate_read_boundary_evidence(evidence)


def _plain_dict(value: Any, fields: set[str]) -> bool:
    return type(value) is dict and set(value) == fields


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def validate_read_boundary_evidence(
    value: Any,
    *,
    expected_database_name: str | None = None,
    expected_database_uuid: str | None = None,
) -> dict[str, Any]:
    """Validate the exact evidence schema and optional runtime binding."""

    try:
        if not _plain_dict(
            value,
            {
                "checks",
                "database",
                "drift_probes",
                "relation",
                "schema_version",
                "successful_transactions",
                "write_probe",
            },
        ) or value["schema_version"] != SCHEMA_VERSION:
            raise ValueError
        database = value["database"]
        if not _plain_dict(database, {"after", "before"}):
            raise ValueError
        for snapshot in (database["before"], database["after"]):
            if (
                not _plain_dict(snapshot, {"backend_pid", "name", "uuid"})
                or not _strict_positive_integer(snapshot["backend_pid"])
                or not isinstance(snapshot["name"], str)
                or _DATABASE_NAME.fullmatch(snapshot["name"]) is None
                or str(uuid.UUID(snapshot["uuid"])) != snapshot["uuid"]
                or (
                    expected_database_name is not None
                    and snapshot["name"] != expected_database_name
                )
                or (
                    expected_database_uuid is not None
                    and snapshot["uuid"] != str(uuid.UUID(expected_database_uuid))
                )
            ):
                raise ValueError
        if (
            database["before"] != database["after"]
        ):
            raise ValueError

        checks = value["checks"]
        check_fields = {
            "backend_pid_unchanged",
            "database_name_unchanged",
            "database_uuid_unchanged",
            "relation_filenode_unchanged",
            "relation_oid_unchanged",
            "relation_row_count_unchanged",
        }
        if not _plain_dict(checks, check_fields) or any(
            checks[field] is not True for field in check_fields
        ):
            raise ValueError

        relation = value["relation"]
        if (
            not _plain_dict(relation, {"after", "before", "name", "schema"})
            or relation["schema"] != "public"
            or relation["name"] != "ir_config_parameter"
        ):
            raise ValueError
        relation_fields = {"filenode", "oid", "row_count"}
        for snapshot in (relation["before"], relation["after"]):
            if (
                not _plain_dict(snapshot, relation_fields)
                or not _strict_positive_integer(snapshot["filenode"])
                or not _strict_positive_integer(snapshot["oid"])
                or not _strict_nonnegative_integer(snapshot["row_count"])
            ):
                raise ValueError
        if relation["before"] != relation["after"]:
            raise ValueError

        transactions = value["successful_transactions"]
        if not _plain_dict(transactions, {"after", "before"}):
            raise ValueError
        transaction_fields = {
            "idle_after_rollback",
            "isolation",
            "marker_sha256",
            "read_only",
        }
        marker_hashes = set()
        for transaction in (transactions["before"], transactions["after"]):
            if (
                not _plain_dict(transaction, transaction_fields)
                or transaction["idle_after_rollback"] is not True
                or transaction["isolation"] != "repeatable read"
                or transaction["read_only"] is not True
                or not _valid_digest(transaction["marker_sha256"])
            ):
                raise ValueError
            marker_hashes.add(transaction["marker_sha256"])
        if len(marker_hashes) != 2:
            raise ValueError

        write_probe = value["write_probe"]
        if (
            not _plain_dict(
                write_probe,
                {"idle_after_rollback", "rejected", "sqlstate", "statement_id"},
            )
            or write_probe["idle_after_rollback"] is not True
            or write_probe["rejected"] is not True
            or write_probe["sqlstate"] != "25006"
            or write_probe["statement_id"]
            != "ir-config-parameter-noop-update-v1"
        ):
            raise ValueError

        drift_probes = value["drift_probes"]
        drift_names = {"hidden_commit", "hidden_rollback", "rollback_hook_reopen"}
        drift_fields = {
            "canary_sha256",
            "idle_after_cleanup",
            "rejected",
            "result_released",
        }
        if not _plain_dict(drift_probes, drift_names):
            raise ValueError
        canary_hashes = set()
        for name in drift_names:
            probe = drift_probes[name]
            if (
                not _plain_dict(probe, drift_fields)
                or not _valid_digest(probe["canary_sha256"])
                or probe["idle_after_cleanup"] is not True
                or probe["rejected"] is not True
                or probe["result_released"] is not False
            ):
                raise ValueError
            canary_hashes.add(probe["canary_sha256"])
        if len(canary_hashes) != 3:
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ReadBoundaryEvidenceError(_INVALID_EVIDENCE) from None
    return value


__all__ = [
    "ReadBoundaryEvidenceError",
    "collect_read_boundary_evidence",
    "validate_read_boundary_evidence",
]
