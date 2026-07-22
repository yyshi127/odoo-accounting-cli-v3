from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo import read_boundary_evidence
from odoo_accounting_cli_v3.odoo.read_boundary_evidence import (
    ReadBoundaryEvidenceError,
    collect_read_boundary_evidence,
    validate_read_boundary_evidence,
)


DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"


class ProbeSqlError(RuntimeError):
    def __init__(self, sqlstate: str, detail: str = "driver detail must stay private"):
        super().__init__(detail)
        self.pgcode = sqlstate


class FakeConnection:
    def __init__(self, cursor: "FakeCursor") -> None:
        self.cursor = cursor
        self.autocommit = False
        self.readonly = False
        self.transaction_status = 0

    def set_session(self, *, readonly: bool, isolation_level: str) -> None:
        assert isolation_level == "REPEATABLE READ"
        self.readonly = readonly

    def get_transaction_status(self) -> int:
        return self.transaction_status

    def commit(self) -> None:
        self.cursor.marker = None
        self.transaction_status = 0


class FakeCursor:
    def __init__(
        self,
        *,
        dml_sqlstate: str = "25006",
        dml_succeeds: bool = False,
        relation_drift: bool = False,
        rollback_leaves_transaction: bool = False,
    ) -> None:
        self.connection = FakeConnection(self)
        self.marker: str | None = None
        self.row = None
        self.snapshot_count = 0
        self.dml_sqlstate = dml_sqlstate
        self.dml_succeeds = dml_succeeds
        self.relation_drift = relation_drift
        self.rollback_leaves_transaction = rollback_leaves_transaction
        self.executed_sql: list[str] = []

    @property
    def readonly(self) -> bool:
        return self.connection.readonly

    def execute(self, statement: str, parameters=None) -> None:
        self.executed_sql.append(statement)
        self.connection.transaction_status = 2
        if "set_config" in statement:
            self.marker = parameters[1]
            self.row = ("on", "repeatable read", self.marker)
        elif statement == read_boundary_evidence._SNAPSHOT_SQL:
            self.snapshot_count += 1
            filenode = 8181 + (1 if self.relation_drift and self.snapshot_count == 2 else 0)
            self.row = (
                "on",
                "repeatable read",
                self.marker,
                "odoo_test",
                9911,
                DATABASE_UUID,
                4242,
                filenode,
                7,
            )
        elif statement == read_boundary_evidence._WRITE_PROBE_SQL:
            if self.dml_succeeds:
                self.row = None
            else:
                self.connection.transaction_status = 3
                raise ProbeSqlError(self.dml_sqlstate)
        elif statement == read_boundary_evidence._ROLLBACK_REOPEN_SQL:
            self.row = (1,)
        elif "current_setting(%s, true)" in statement:
            self.row = ("on", "repeatable read", self.marker)
        else:  # pragma: no cover - catches unreviewed SQL in development.
            raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        return self.row

    def rollback(self) -> None:
        self.marker = None
        self.connection.transaction_status = (
            2 if self.rollback_leaves_transaction else 0
        )


def _token_hex_factory():
    values = iter(f"{index:064x}" for index in range(1, 20))
    return lambda _size: next(values)


def _token_bytes_factory():
    values = iter(bytes([index]) * 32 for index in range(1, 10))
    return lambda _size: next(values)


@pytest.fixture
def deterministic_tokens(monkeypatch):
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.read_transaction.secrets.token_hex",
        _token_hex_factory(),
    )
    monkeypatch.setattr(
        read_boundary_evidence.secrets,
        "token_bytes",
        _token_bytes_factory(),
    )


def test_collector_proves_success_rejection_drift_cleanup_and_no_canary_leak(
    deterministic_tokens,
):
    cursor = FakeCursor()

    evidence = collect_read_boundary_evidence(SimpleNamespace(cr=cursor))

    assert evidence == validate_read_boundary_evidence(
        evidence,
        expected_database_name="odoo_test",
        expected_database_uuid=DATABASE_UUID,
    )
    assert set(evidence) == {
        "checks",
        "database",
        "drift_probes",
        "relation",
        "schema_version",
        "successful_transactions",
        "write_probe",
    }
    assert evidence["schema_version"] == (
        "odoo-accounting-cli-v3.read-boundary-evidence.v1"
    )
    assert evidence["database"] == {
        "after": {
            "backend_pid": 9911,
            "name": "odoo_test",
            "uuid": DATABASE_UUID,
        },
        "before": {
            "backend_pid": 9911,
            "name": "odoo_test",
            "uuid": DATABASE_UUID,
        },
    }
    assert evidence["checks"] == {
        "backend_pid_unchanged": True,
        "database_name_unchanged": True,
        "database_uuid_unchanged": True,
        "relation_filenode_unchanged": True,
        "relation_oid_unchanged": True,
        "relation_row_count_unchanged": True,
    }
    assert evidence["write_probe"] == {
        "idle_after_rollback": True,
        "rejected": True,
        "sqlstate": "25006",
        "statement_id": "ir-config-parameter-noop-update-v1",
    }
    observed_hashes = set()
    for name in ("hidden_commit", "hidden_rollback", "rollback_hook_reopen"):
        probe = evidence["drift_probes"][name]
        assert probe["rejected"] is True
        assert probe["result_released"] is False
        assert probe["idle_after_cleanup"] is True
        assert len(probe["canary_sha256"]) == 64
        observed_hashes.add(probe["canary_sha256"])
    assert len(observed_hashes) == 3

    serialized = repr(evidence)
    for index in range(1, 4):
        canary = bytes([index]) * 32
        assert canary.hex() not in serialized
        assert repr(canary) not in serialized
        assert hashlib.sha256(canary).hexdigest() in serialized
    assert cursor.connection.get_transaction_status() == 0
    assert read_boundary_evidence._WRITE_PROBE_SQL in cursor.executed_sql
    assert cursor.executed_sql.count(read_boundary_evidence._ROLLBACK_REOPEN_SQL) == 3


def test_missing_api_fails_closed_without_leaking_underlying_detail():
    with pytest.raises(ReadBoundaryEvidenceError) as error:
        collect_read_boundary_evidence(object())

    assert str(error.value) == "Odoo read-boundary evidence collection failed"


@pytest.mark.parametrize(
    "cursor",
    [
        FakeCursor(dml_sqlstate="42501"),
        FakeCursor(dml_succeeds=True),
    ],
)
def test_wrong_sqlstate_or_unexpected_dml_success_fails_closed(
    cursor, deterministic_tokens
):
    with pytest.raises(ReadBoundaryEvidenceError) as error:
        collect_read_boundary_evidence(SimpleNamespace(cr=cursor))

    assert str(error.value) == "Odoo read-boundary write rejection was not proven"
    assert "driver detail" not in str(error.value)
    assert cursor.connection.get_transaction_status() == 0


def test_relation_drift_fails_closed(deterministic_tokens):
    cursor = FakeCursor(relation_drift=True)

    with pytest.raises(ReadBoundaryEvidenceError) as error:
        collect_read_boundary_evidence(SimpleNamespace(cr=cursor))

    assert str(error.value) == "Odoo read-boundary invariants changed"
    assert cursor.connection.get_transaction_status() == 0


def test_duplicate_success_markers_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.read_transaction.secrets.token_hex",
        lambda _size: "a" * 64,
    )
    monkeypatch.setattr(
        read_boundary_evidence.secrets,
        "token_bytes",
        _token_bytes_factory(),
    )
    cursor = FakeCursor()

    with pytest.raises(ReadBoundaryEvidenceError) as error:
        collect_read_boundary_evidence(SimpleNamespace(cr=cursor))

    assert str(error.value) == "Odoo read-boundary invariants changed"
    assert cursor.connection.get_transaction_status() == 0


def test_rollback_non_idle_fails_closed(deterministic_tokens):
    cursor = FakeCursor(rollback_leaves_transaction=True)

    with pytest.raises(ReadBoundaryEvidenceError) as error:
        collect_read_boundary_evidence(SimpleNamespace(cr=cursor))

    assert str(error.value) == "Odoo read-boundary evidence collection failed"


def test_validator_rejects_unknown_fields_marker_drift_and_relation_drift(
    deterministic_tokens,
):
    evidence = collect_read_boundary_evidence(SimpleNamespace(cr=FakeCursor()))
    mutations = []

    unknown = copy.deepcopy(evidence)
    unknown["unexpected"] = True
    mutations.append(unknown)

    duplicate_marker = copy.deepcopy(evidence)
    duplicate_marker["successful_transactions"]["after"]["marker_sha256"] = (
        duplicate_marker["successful_transactions"]["before"]["marker_sha256"]
    )
    mutations.append(duplicate_marker)

    relation_drift = copy.deepcopy(evidence)
    relation_drift["relation"]["after"]["filenode"] += 1
    mutations.append(relation_drift)

    database_drift = copy.deepcopy(evidence)
    database_drift["database"]["after"]["uuid"] = (
        "29b09656-d10f-11f0-9065-00163e54a5ad"
    )
    mutations.append(database_drift)

    for mutation in mutations:
        with pytest.raises(ReadBoundaryEvidenceError) as error:
            validate_read_boundary_evidence(
                mutation,
                expected_database_name="odoo_test",
                expected_database_uuid=DATABASE_UUID,
            )
        assert str(error.value) == "Odoo read-boundary evidence is invalid"
