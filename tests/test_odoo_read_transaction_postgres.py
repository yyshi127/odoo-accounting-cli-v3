from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo import read_transaction
from odoo_accounting_cli_v3.odoo.read_transaction import (
    OdooReadTransactionError,
    run_readonly_odoo_transaction,
)


RUN_INTEGRATION = os.environ.get("READ_TRANSACTION_POSTGRES_INTEGRATION") == "1"
pytestmark = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="set READ_TRANSACTION_POSTGRES_INTEGRATION=1 for the isolated PostgreSQL gate",
)

if RUN_INTEGRATION:
    import psycopg2
    from psycopg2 import extensions, sql


class OdooCursorAdapter:
    def __init__(self, connection, *, reopen_after_rollback=False):
        self.connection = connection
        self._cursor = connection.cursor()
        self.reopen_after_rollback = reopen_after_rollback

    @property
    def readonly(self):
        return bool(self.connection.readonly)

    def execute(self, statement, parameters=None):
        self._cursor.execute(statement, parameters)

    def fetchone(self):
        return self._cursor.fetchone()

    def rollback(self):
        self.connection.rollback()
        if self.reopen_after_rollback:
            self._cursor.execute("SELECT 1")

    def close(self):
        self._cursor.close()


def _connect(database):
    return psycopg2.connect(
        dbname=database,
        user=os.environ["READ_TRANSACTION_PGUSER"],
        host=os.environ["READ_TRANSACTION_PGHOST"],
        port=int(os.environ["READ_TRANSACTION_PGPORT"]),
        connect_timeout=5,
        application_name="odoo-cli-v3-read-transaction-ci",
    )


@pytest.fixture(scope="module")
def probe_database():
    database = f"odoo_read_tx_{uuid.uuid4().hex[:16]}"
    control = _connect("postgres")
    control.autocommit = True
    created = False
    try:
        with control.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        created = True
        setup = _connect(database)
        try:
            with setup.cursor() as cursor:
                cursor.execute(
                    "CREATE TABLE public.read_transaction_probe "
                    "(id integer PRIMARY KEY, value text NOT NULL)"
                )
                cursor.execute(
                    "INSERT INTO public.read_transaction_probe(id, value) "
                    "VALUES (1, 'unchanged')"
                )
            setup.commit()
        finally:
            setup.close()
        yield database
    finally:
        try:
            if created:
                with control.cursor() as cursor:
                    cursor.execute(
                        sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                            sql.Identifier(database)
                        )
                    )
        finally:
            control.close()


@pytest.fixture
def live_cursor(probe_database):
    connection = _connect(probe_database)
    cursor = OdooCursorAdapter(connection)
    try:
        yield cursor
    finally:
        cursor.close()
        connection.close()


def test_real_postgresql_success_is_rr_readonly_and_clears_marker(
    live_cursor, monkeypatch
):
    marker = "a" * 64
    monkeypatch.setattr(read_transaction.secrets, "token_hex", lambda _size: marker)

    def read_state():
        live_cursor.execute(
            "SELECT current_setting('transaction_read_only'), "
            "current_setting('transaction_isolation'), "
            "current_setting(%s, true), "
            "(SELECT count(*) FROM public.read_transaction_probe)",
            ("odoo_accounting_cli_v3.read_transaction_marker",),
        )
        return live_cursor.fetchone()

    result = run_readonly_odoo_transaction(
        SimpleNamespace(cr=live_cursor),
        read_state,
    )

    assert result == ("on", "repeatable read", marker, 1)
    assert live_cursor.connection.get_transaction_status() == extensions.TRANSACTION_STATUS_IDLE
    assert live_cursor.connection.readonly is True
    assert live_cursor.connection.isolation_level == extensions.ISOLATION_LEVEL_REPEATABLE_READ
    live_cursor.execute(
        "SELECT current_setting(%s, true)",
        ("odoo_accounting_cli_v3.read_transaction_marker",),
    )
    assert live_cursor.fetchone()[0] != marker
    live_cursor.rollback()


def test_real_postgresql_rejects_dml_with_25006_and_preserves_row(
    probe_database, live_cursor
):
    def attempt_write():
        live_cursor.execute(
            "UPDATE public.read_transaction_probe SET value = 'changed' WHERE id = 1"
        )

    with pytest.raises(psycopg2.errors.ReadOnlySqlTransaction) as error:
        run_readonly_odoo_transaction(
            SimpleNamespace(cr=live_cursor),
            attempt_write,
        )

    assert error.value.pgcode == "25006"
    assert live_cursor.connection.get_transaction_status() == extensions.TRANSACTION_STATUS_IDLE
    witness = _connect(probe_database)
    try:
        witness.set_session(readonly=True, isolation_level="REPEATABLE READ")
        with witness.cursor() as cursor:
            cursor.execute(
                "SELECT id, value FROM public.read_transaction_probe ORDER BY id"
            )
            assert cursor.fetchall() == [(1, "unchanged")]
        witness.rollback()
        assert witness.get_transaction_status() == extensions.TRANSACTION_STATUS_IDLE
    finally:
        witness.close()


def test_real_postgresql_hidden_rollback_discards_result(live_cursor):
    def cross_boundary():
        live_cursor.rollback()
        live_cursor.execute("SELECT 1")
        return {"must": "discard"}

    with pytest.raises(OdooReadTransactionError, match="attestation failed"):
        run_readonly_odoo_transaction(
            SimpleNamespace(cr=live_cursor),
            cross_boundary,
        )

    assert live_cursor.connection.get_transaction_status() == extensions.TRANSACTION_STATUS_IDLE


def test_real_postgresql_hidden_commit_discards_result(live_cursor):
    def cross_boundary():
        live_cursor.connection.commit()
        live_cursor.execute("SELECT 1")
        return {"must": "discard"}

    with pytest.raises(OdooReadTransactionError, match="attestation failed"):
        run_readonly_odoo_transaction(
            SimpleNamespace(cr=live_cursor),
            cross_boundary,
        )

    assert live_cursor.connection.get_transaction_status() == extensions.TRANSACTION_STATUS_IDLE


def test_real_postgresql_rollback_hook_must_leave_connection_idle(probe_database):
    connection = _connect(probe_database)
    cursor = OdooCursorAdapter(connection, reopen_after_rollback=True)
    try:
        with pytest.raises(OdooReadTransactionError, match="return to idle"):
            run_readonly_odoo_transaction(
                SimpleNamespace(cr=cursor),
                lambda: {"must": "discard"},
            )
    finally:
        connection.rollback()
        cursor.close()
        connection.close()
