from __future__ import annotations

from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.read_transaction import (
    OdooReadTransactionError,
    run_readonly_odoo_transaction,
)


class ReadOnlySqlTransaction(RuntimeError):
    pass


class FakeConnection:
    def __init__(
        self,
        events,
        *,
        keep_writable=False,
        autocommit=False,
        set_session_fails=False,
    ):
        self.events = events
        self.autocommit = autocommit
        self.readonly = False
        self.keep_writable = keep_writable
        self.set_session_fails = set_session_fails
        self.transaction_status = 0

    def set_session(self, *, readonly, isolation_level):
        self.events.append(("set_session", readonly, isolation_level))
        if self.set_session_fails:
            raise RuntimeError("driver refused session settings")
        if not self.keep_writable:
            self.readonly = readonly

    def get_transaction_status(self):
        self.events.append(("transaction_status", self.transaction_status))
        return self.transaction_status


class FakeCursor:
    dbname = "odoo_test"

    def __init__(
        self,
        *,
        isolation="repeatable read",
        keep_writable=False,
        autocommit=False,
        rollback_fails=False,
        rollback_leaves_transaction=False,
        initial_transaction_status=0,
        set_session_fails=False,
    ):
        self.events = []
        self.connection = FakeConnection(
            self.events,
            keep_writable=keep_writable,
            autocommit=autocommit,
            set_session_fails=set_session_fails,
        )
        self.isolation = isolation
        self.marker = None
        self._row = None
        self.rollback_fails = rollback_fails
        self.rollback_leaves_transaction = rollback_leaves_transaction
        self.persisted_rows = []
        self.connection.transaction_status = initial_transaction_status

    @property
    def readonly(self):
        return self.connection.readonly

    def execute(self, sql, parameters=None):
        self.events.append(("execute", sql, parameters))
        self.connection.transaction_status = 2
        if "set_config" in sql:
            self.marker = parameters[1]
            self._row = (
                "on" if self.readonly else "off",
                self.isolation,
                self.marker,
            )
        elif "current_setting(%s, true)" in sql:
            self._row = (
                "on" if self.readonly else "off",
                self.isolation,
                self.marker,
            )
        elif sql.startswith("INSERT"):
            if self.readonly:
                self.connection.transaction_status = 3
                raise ReadOnlySqlTransaction("cannot execute INSERT in a read-only transaction")
            self.persisted_rows.append(parameters)
        else:  # pragma: no cover - catches unexpected helper SQL during development.
            raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self):
        self.events.append(("fetchone",))
        return self._row

    def rollback(self):
        self.events.append(("rollback",))
        if self.rollback_fails:
            raise RuntimeError("rollback failed")
        self.marker = None
        self.connection.transaction_status = (
            2 if self.rollback_leaves_transaction else 0
        )

    def commit(self):
        self.events.append(("commit",))
        self.marker = None
        self.connection.transaction_status = 0


def environment(cursor=None):
    return SimpleNamespace(cr=cursor or FakeCursor())


def test_success_hardens_before_sql_and_releases_only_after_rollback():
    cursor = FakeCursor()

    result = run_readonly_odoo_transaction(
        environment(cursor),
        lambda: cursor.events.append(("callback",)) or {"ok": True},
    )

    assert result == {"ok": True}
    assert ("set_session", True, "REPEATABLE READ") in cursor.events
    begin = next(item for item in cursor.events if item[0] == "execute")
    assert "set_config" in begin[1]
    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]
    assert cursor.readonly is True
    assert cursor.connection.readonly is True
    assert cursor.marker is None


@pytest.mark.parametrize(
    ("cursor", "message"),
    [
        (FakeCursor(keep_writable=True), "session was not established"),
        (FakeCursor(isolation="read committed"), "attestation failed"),
    ],
)
def test_writable_or_wrong_isolation_session_is_rejected(cursor, message):
    with pytest.raises(OdooReadTransactionError, match=message):
        run_readonly_odoo_transaction(environment(cursor), lambda: "unreachable")

    assert ("rollback",) in cursor.events


@pytest.mark.parametrize(
    "root_env",
    [
        object(),
        SimpleNamespace(cr=object()),
        SimpleNamespace(
            cr=SimpleNamespace(
                connection=SimpleNamespace(autocommit=False),
                execute=lambda *_: None,
                fetchone=lambda: None,
                rollback=lambda: None,
            )
        ),
    ],
)
def test_missing_transaction_api_fails_closed(root_env):
    with pytest.raises(OdooReadTransactionError, match="API is unavailable"):
        run_readonly_odoo_transaction(root_env, lambda: None)


def test_autocommit_is_rejected_before_session_hardening():
    cursor = FakeCursor(autocommit=True)

    with pytest.raises(OdooReadTransactionError, match="disable autocommit"):
        run_readonly_odoo_transaction(environment(cursor), lambda: None)

    assert cursor.events == []


def test_existing_transaction_is_rejected_without_rolling_it_back():
    cursor = FakeCursor(initial_transaction_status=2)

    with pytest.raises(OdooReadTransactionError, match="start from an idle"):
        run_readonly_odoo_transaction(environment(cursor), lambda: None)

    assert ("set_session", True, "REPEATABLE READ") not in cursor.events
    assert ("rollback",) not in cursor.events
    assert cursor.connection.transaction_status == 2


def test_driver_session_failure_is_wrapped_and_idle_connection_is_rolled_back():
    cursor = FakeCursor(set_session_fails=True)

    with pytest.raises(OdooReadTransactionError, match="could not be established"):
        run_readonly_odoo_transaction(environment(cursor), lambda: None)

    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]


def test_callback_failure_is_preserved_and_transaction_is_rolled_back():
    cursor = FakeCursor()

    def fail():
        raise ValueError("business read failed")

    with pytest.raises(ValueError, match="business read failed"):
        run_readonly_odoo_transaction(environment(cursor), fail)

    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]
    assert cursor.marker is None


def test_rollback_failure_discards_a_successful_result():
    cursor = FakeCursor(rollback_fails=True)

    with pytest.raises(OdooReadTransactionError, match="rollback failed"):
        run_readonly_odoo_transaction(environment(cursor), lambda: {"must": "discard"})


def test_rollback_hook_reopening_a_transaction_discards_the_result():
    cursor = FakeCursor(rollback_leaves_transaction=True)

    with pytest.raises(OdooReadTransactionError, match="return to idle"):
        run_readonly_odoo_transaction(environment(cursor), lambda: {"must": "discard"})


def test_database_rejects_dml_and_no_row_is_persisted():
    cursor = FakeCursor()

    def attempt_write():
        cursor.execute("INSERT INTO account_move(id) VALUES (%s)", (99,))

    with pytest.raises(ReadOnlySqlTransaction, match="read-only transaction"):
        run_readonly_odoo_transaction(environment(cursor), attempt_write)

    assert cursor.persisted_rows == []
    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]


@pytest.mark.parametrize("boundary_method", ["commit", "rollback"])
def test_hidden_transaction_boundary_discards_the_result(boundary_method):
    cursor = FakeCursor()

    def cross_boundary():
        getattr(cursor, boundary_method)()
        return {"must": "discard"}

    with pytest.raises(OdooReadTransactionError, match="boundary changed"):
        run_readonly_odoo_transaction(environment(cursor), cross_boundary)

    assert cursor.readonly is True
    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]


def test_readonly_state_tampering_discards_the_result():
    cursor = FakeCursor()

    def tamper():
        cursor.connection.readonly = False
        return {"must": "discard"}

    with pytest.raises(OdooReadTransactionError, match="session was not established"):
        run_readonly_odoo_transaction(environment(cursor), tamper)

    assert cursor.events[-2:] == [("rollback",), ("transaction_status", 0)]
