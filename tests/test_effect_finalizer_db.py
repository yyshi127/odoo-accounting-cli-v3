from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationRequest,
    create_effect_attestation,
)
from odoo_accounting_cli_v3.odoo.effect_finalizer_db import (
    EffectFinalizerDatabaseConfig,
    EffectFinalizerDatabaseError,
    finalize_effect_attempt,
    open_direct_finalizer_connection,
    sanitized_direct_connection_info,
)


NOW = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
SECRET = b"effect-finalizer-secret-material-32-bytes"


def _request() -> EffectFinalizationRequest:
    return EffectFinalizationRequest(
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        operation_id="op-finalize-1",
        operation_digest="0" * 64,
        execution_result_digest="1" * 64,
        resolution_operation_id="op-finalize-1",
        resolution_operation_digest="0" * 64,
        resolution_execution_result_digest="1" * 64,
        resolution_result_digest="3" * 64,
        resolution_kind="verified",
        verified_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )


def _config(tmp_path) -> EffectFinalizerDatabaseConfig:
    pgpass = tmp_path / "pgpass"
    pgpass.write_text(
        "/var/run/postgresql:5432:odoo_sandbox:odoo_v3_finalizer:secret-value\n",
        encoding="utf-8",
    )
    pgpass.chmod(0o600)
    return EffectFinalizerDatabaseConfig(
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        database_user="odoo_v3_finalizer",
        expected_guard_installation_id=INSTALLATION_ID,
        expected_database_oid=16384,
        host="/var/run/postgresql",
        port=5432,
        passfile_path=pgpass,
        connect_timeout_seconds=2,
        statement_timeout_ms=5000,
        require_posix_owner=False,
    )


def test_connection_info_replaces_runtime_credentials_with_one_read_password(
    tmp_path,
) -> None:
    config = _config(tmp_path)

    result = sanitized_direct_connection_info(
        {
            "dbname": "odoo_sandbox",
            "host": "/var/run/postgresql",
            "port": 5432,
            "user": "odoo_runtime",
            "password": "runtime-secret",
            "options": "-c role=owner",
            "sslmode": "verify-full",
        },
        config,
    )

    assert result == {
        "dbname": "odoo_sandbox",
        "host": "/var/run/postgresql",
        "port": 5432,
        "user": "odoo_v3_finalizer",
        "password": "secret-value",
        "connect_timeout": 2,
        "application_name": "odoo-accounting-cli-v3-effect-finalizer",
    }
    assert "passfile" not in result
    assert "options" not in result


def test_pgpass_rejects_wildcard_or_more_than_one_entry(tmp_path) -> None:
    config = _config(tmp_path)
    config.passfile_path.write_text(
        "*:5432:odoo_sandbox:odoo_v3_finalizer:secret\n", encoding="utf-8"
    )
    with pytest.raises(EffectFinalizerDatabaseError, match="pgpass"):
        sanitized_direct_connection_info(
            {
                "dbname": "odoo_sandbox",
                "host": "/var/run/postgresql",
                "port": 5432,
            },
            config,
        )


def test_database_config_rejects_remote_tcp_endpoint(tmp_path) -> None:
    config = _config(tmp_path)

    with pytest.raises(EffectFinalizerDatabaseError, match="configuration"):
        EffectFinalizerDatabaseConfig(
            **{
                **config.__dict__,
                "host": "db.internal",
            }
        )


def test_direct_connect_clears_pg_environment_and_never_reopens_passfile(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    monkeypatch.setenv("PGOPTIONS", "-c role=odoo_owner")
    monkeypatch.setenv("PGPASSWORD", "environment-secret")
    observed = {}
    connection = object()

    def connect(**parameters):
        assert not any(name.upper().startswith("PG") for name in os.environ)
        # A replacement after the secure read cannot affect the in-memory password.
        config.passfile_path.write_text(
            "/var/run/postgresql:5432:odoo_sandbox:odoo_v3_finalizer:changed\n",
            encoding="utf-8",
        )
        observed.update(parameters)
        return connection

    result = open_direct_finalizer_connection(
        odoo_connection_info={
            "dbname": "odoo_sandbox",
            "host": "/var/run/postgresql",
            "port": 5432,
            "password": "odoo-runtime-secret",
            "options": "-c role=odoo_owner",
        },
        config=config,
        connect=connect,
    )

    assert result is connection
    assert observed["password"] == "secret-value"
    assert observed["connect_timeout"] == 2
    assert "passfile" not in observed
    assert os.environ["PGOPTIONS"] == "-c role=odoo_owner"
    assert os.environ["PGPASSWORD"] == "environment-secret"


def test_direct_connect_restores_pg_environment_when_connector_fails(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    monkeypatch.setenv("PGOPTIONS", "-c role=odoo_owner")

    def connect(**_parameters):
        assert "PGOPTIONS" not in os.environ
        raise RuntimeError("connect failed")

    with pytest.raises(EffectFinalizerDatabaseError, match="connection failed"):
        open_direct_finalizer_connection(
            odoo_connection_info={
                "dbname": "odoo_sandbox",
                "host": "/var/run/postgresql",
                "port": 5432,
            },
            config=config,
            connect=connect,
        )

    assert os.environ["PGOPTIONS"] == "-c role=odoo_owner"


class _Cursor:
    def __init__(self, request, attestation):
        self.request = request
        self.attestation = attestation
        self.calls = []
        self._row = None
        self.description = None
        self.duplicate_finalizer_row = False
        self.state_installation_id = INSTALLATION_ID
        self.state_database_oid = 16384
        self._last_sql = ""

    def execute(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        self._last_sql = sql
        if "set_config" in sql:
            self._row = (parameters[0],)
        elif "session_user" in sql:
            self._row = (
                "odoo_sandbox",
                "odoo_v3_finalizer",
                "odoo_v3_finalizer",
                "none",
            )
        elif "read_module_guard_state" in sql:
            self.description = [(name,) for name in (
                "protocol_version", "schema_version", "guard_installation_id",
                "database_oid", "database_uuid", "epoch", "module_guard_open",
                "opened_epoch", "unresolved_effect_count",
                "ledger_unresolved_effect_count", "runtime_role",
                "maintenance_role", "finalizer_role", "maintenance_id",
                "maintenance_expires_at", "maintenance_holder_pid",
                "maintenance_holder_backend_start", "last_module_change_at",
                "last_module_change_txid",
            )]
            self._row = (
                1, 2, self.state_installation_id, self.state_database_oid,
                DATABASE_UUID, 0, False, None,
                1, 1, "odoo_runtime", "odoo_maintenance", "odoo_v3_finalizer",
                None, None, None, None, None, None,
            )
        elif "finalize_operation_effect" in sql:
            self.description = [(name,) for name in (
                "receipt_attestation_id", "receipt_guard_installation_id",
                "receipt_database_oid", "receipt_database_uuid",
                "resolved_operation_id", "receipt_resolution_operation_id",
                "applied_resolution_kind", "resolved_anchor_count",
                "remaining_unresolved_count", "guard_epoch",
                "receipt_attestation_digest", "finalized_at", "finalized_txid",
                "replayed",
            )]
            self._row = (
                self.attestation.attestation_id, INSTALLATION_ID, 16384,
                DATABASE_UUID, self.request.operation_id,
                self.request.resolution_operation_id, "verified", 1, 0, 0,
                self.attestation.attestation_digest,
                NOW + timedelta(seconds=1), "9123", False,
            )

    def fetchone(self):
        return self._row

    def fetchall(self):
        if self.duplicate_finalizer_row and "finalize_operation_effect" in self._last_sql:
            return [self._row, self._row]
        return [self._row]

    def close(self):
        pass


class _Connection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.autocommit = True
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_database_finalizer_uses_direct_identity_parameterized_function_and_commit(
    tmp_path,
) -> None:
    request = _request()
    attestation = create_effect_attestation(
        request, key_id="effect-finalizer-v1", secret=SECRET
    )
    cursor = _Cursor(request, attestation)
    connection = _Connection(cursor)

    receipt = finalize_effect_attempt(
        connection,
        config=_config(tmp_path),
        request=request,
        attestation=attestation,
        now=lambda: NOW,
    )

    assert receipt.operation_id == request.operation_id
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.autocommit is False
    finalizer_calls = [call for call in cursor.calls if "finalize_operation_effect" in call[0]]
    assert len(finalizer_calls) == 1
    assert finalizer_calls[0][0].count("%s") == 16
    assert len(finalizer_calls[0][1]) == 16
    assert request.operation_id not in finalizer_calls[0][0]


def test_database_finalizer_rolls_back_on_nonunique_receipt(tmp_path) -> None:
    request = _request()
    attestation = create_effect_attestation(
        request, key_id="effect-finalizer-v1", secret=SECRET
    )
    cursor = _Cursor(request, attestation)
    cursor.duplicate_finalizer_row = True
    connection = _Connection(cursor)

    with pytest.raises(EffectFinalizerDatabaseError):
        finalize_effect_attempt(
            connection,
            config=_config(tmp_path),
            request=request,
            attestation=attestation,
            now=lambda: NOW,
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("state_installation_id", "33333333-3333-4333-8333-333333333333"),
        ("state_database_oid", 16385),
    ],
)
def test_database_finalizer_rejects_pinned_identity_drift_before_effect_sql(
    tmp_path, attribute, value
) -> None:
    request = _request()
    attestation = create_effect_attestation(
        request, key_id="effect-finalizer-v1", secret=SECRET
    )
    cursor = _Cursor(request, attestation)
    setattr(cursor, attribute, value)
    connection = _Connection(cursor)

    with pytest.raises(EffectFinalizerDatabaseError, match="guard state"):
        finalize_effect_attempt(
            connection,
            config=_config(tmp_path),
            request=request,
            attestation=attestation,
            now=lambda: NOW,
        )

    assert not any(
        "finalize_operation_effect" in sql for sql, _parameters in cursor.calls
    )
    assert connection.commits == 0
    assert connection.rollbacks == 1
