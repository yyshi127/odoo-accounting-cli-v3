"""Fail-closed PostgreSQL read-only boundary for Odoo shell reads."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from typing import Any, TypeVar


class OdooReadTransactionError(RuntimeError):
    """The Odoo cursor could not prove a rollback-only read transaction."""


_Result = TypeVar("_Result")
_MARKER_SETTING = "odoo_accounting_cli_v3.read_transaction_marker"
_BEGIN_ATTESTATION_SQL = (
    "SELECT current_setting('transaction_read_only'), "
    "current_setting('transaction_isolation'), set_config(%s, %s, true)"
)
_VERIFY_ATTESTATION_SQL = (
    "SELECT current_setting('transaction_read_only'), "
    "current_setting('transaction_isolation'), current_setting(%s, true)"
)
_EXPECTED_TRANSACTION_STATE = ("on", "repeatable read")
_TRANSACTION_STATUS_IDLE = 0
_TRANSACTION_STATUS_INTRANS = 2


def _require_cursor(root_env: Any) -> tuple[Any, Any]:
    try:
        cursor = root_env.cr
        connection = cursor.connection
    except (AttributeError, TypeError) as exc:
        raise OdooReadTransactionError("Odoo read transaction API is unavailable") from exc
    for owner, method_name in (
        (connection, "set_session"),
        (connection, "get_transaction_status"),
        (cursor, "execute"),
        (cursor, "fetchone"),
        (cursor, "rollback"),
    ):
        if not callable(getattr(owner, method_name, None)):
            raise OdooReadTransactionError("Odoo read transaction API is unavailable")
    if getattr(connection, "autocommit", None) is not False:
        raise OdooReadTransactionError("Odoo read transaction must disable autocommit")
    return cursor, connection


def _require_transaction_status(connection: Any, expected: int, message: str) -> None:
    try:
        observed = connection.get_transaction_status()
    except Exception as exc:
        raise OdooReadTransactionError("Odoo transaction status is unavailable") from exc
    if isinstance(observed, bool) or observed != expected:
        raise OdooReadTransactionError(message)


def _require_readonly_session(cursor: Any, connection: Any) -> None:
    if (
        getattr(cursor, "readonly", None) is not True
        or getattr(connection, "readonly", None) is not True
    ):
        raise OdooReadTransactionError("Odoo read-only session was not established")


def _require_attestation(row: Any, marker: str) -> None:
    if (
        not isinstance(row, Sequence)
        or isinstance(row, (str, bytes, bytearray))
        or len(row) != 3
        or tuple(row[:2]) != _EXPECTED_TRANSACTION_STATE
        or row[2] != marker
    ):
        raise OdooReadTransactionError("Odoo read-only transaction attestation failed")


def _begin_attested_transaction(cursor: Any, marker: str) -> None:
    cursor.execute(_BEGIN_ATTESTATION_SQL, (_MARKER_SETTING, marker))
    _require_attestation(cursor.fetchone(), marker)


def _verify_attested_transaction(cursor: Any, marker: str) -> None:
    cursor.execute(_VERIFY_ATTESTATION_SQL, (_MARKER_SETTING,))
    _require_attestation(cursor.fetchone(), marker)


def run_readonly_odoo_transaction(
    root_env: Any,
    callback: Callable[[], _Result],
) -> _Result:
    """Run ``callback`` in one proven read-only transaction and roll it back.

    Odoo 19's ``registry.cursor(readonly=True)`` may fall back to a writable
    primary cursor.  This boundary instead hardens the existing shell
    connection before any V3 ORM access, proves the server-side state, binds a
    transaction-local marker so a hidden commit/rollback cannot swap the
    snapshot, and only releases the detached result after rollback succeeds.
    """

    if not callable(callback):
        raise OdooReadTransactionError("Odoo read transaction callback is invalid")
    cursor, connection = _require_cursor(root_env)
    _require_transaction_status(
        connection,
        _TRANSACTION_STATUS_IDLE,
        "Odoo read transaction must start from an idle connection",
    )
    marker = secrets.token_hex(32)
    result: _Result
    session_hardened = False
    try:
        try:
            connection.set_session(
                readonly=True,
                isolation_level="REPEATABLE READ",
            )
        except Exception as exc:
            raise OdooReadTransactionError(
                "Odoo read-only session could not be established"
            ) from exc
        _require_transaction_status(
            connection,
            _TRANSACTION_STATUS_IDLE,
            "Odoo read-only session unexpectedly opened a transaction",
        )
        _require_readonly_session(cursor, connection)
        session_hardened = True
        _begin_attested_transaction(cursor, marker)
        _require_transaction_status(
            connection,
            _TRANSACTION_STATUS_INTRANS,
            "Odoo read-only transaction did not start",
        )
        result = callback()
        _require_readonly_session(cursor, connection)
        _require_transaction_status(
            connection,
            _TRANSACTION_STATUS_INTRANS,
            "Odoo read transaction boundary changed during execution",
        )
        _verify_attested_transaction(cursor, marker)
        _require_transaction_status(
            connection,
            _TRANSACTION_STATUS_INTRANS,
            "Odoo read transaction boundary changed during verification",
        )
    finally:
        try:
            cursor.rollback()
        except Exception as exc:
            raise OdooReadTransactionError("Odoo read transaction rollback failed") from exc
        _require_transaction_status(
            connection,
            _TRANSACTION_STATUS_IDLE,
            "Odoo read transaction did not return to idle",
        )
        if session_hardened:
            _require_readonly_session(cursor, connection)
    return result
