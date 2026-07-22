from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEV29 = ROOT / "deployment" / "dev29"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "dev29_read_oracles", DEV29 / "read_oracles.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def request_for(plan: dict, case: dict) -> dict:
    return {
        "capability_id": case["capability_id"],
        "context": {
            "allowed_company_ids": case["allowed_company_ids"],
            "company_id": case["company_id"],
            "database_name": plan["database"]["name"],
            "database_uuid": plan["database"]["uuid"],
            "environment": plan["target"]["environment"],
            "odoo_instance_id": plan["target"]["instance_id"],
            "principal": case["principal"],
            "user_id": case["user_id"],
            "auth_token_id": "00000000-0000-4000-8000-000000000001",
            "auth_expires_at": "2026-07-20T01:00:00Z",
        },
        "parameters": case["parameters"],
    }


def test_fixed_plan_binds_target_cases_negative_matrix_and_schema_identities():
    oracle = load_module()
    plan = oracle.read_plan(DEV29 / "read_plan.json")

    assert plan["database"] == {
        "name": "odoo_test",
        "uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        "current_user": "postgres",
        "unix_socket_directory": "/var/run/postgresql",
        "unix_socket_path": "/var/run/postgresql/.s.PGSQL.5432",
        "port": 5432,
        "server_version_num": 160014,
        "system_identifier": "7616327373742442245",
    }
    cases = {item["name"]: item for item in plan["cases"]}
    assert list(cases) == [
        "registry",
        "trial_balance",
        "ar_open_items",
        "ap_open_items",
        "multicurrency",
    ]
    assert cases["trial_balance"]["parameters"]["date_from"] == "2026-01-01"
    assert cases["trial_balance"]["parameters"]["date_to"] == "2026-12-31"
    assert cases["ar_open_items"]["parameters"]["as_of_date"] == "2026-07-14"
    assert cases["ap_open_items"]["parameters"]["as_of_date"] == "2026-07-14"
    assert cases["multicurrency"]["allowed_company_ids"] == [9]
    assert cases["multicurrency"]["parameters"]["currency_ids"] == [6, 1]
    assert [item["name"] for item in plan["negative_cases"]] == [
        "acl_deny",
        "cross_company",
        "mixed_company",
        "wrong_database_uuid",
        "expired",
        "tamper_parameters",
        "replay",
    ]
    relations = {item["name"]: item for item in plan["witness"]["relations"]}
    assert relations["account_move_line"]["oid"] == 53705
    assert relations["res_partner"]["oid"] == 56121
    assert relations["ir_model_data"]["witness_scope"] == "required_group_xmlids_only"
    assert set(relations) == set(oracle.WITNESS_PROJECTIONS)


def test_plan_mutations_and_duplicate_json_keys_fail_closed(tmp_path: Path):
    oracle = load_module()
    original = json.loads((DEV29 / "read_plan.json").read_text("utf-8"))
    mutations = []
    wrong_oid = copy.deepcopy(original)
    wrong_oid["witness"]["relations"][0]["oid"] += 1
    mutations.append(wrong_oid)
    extra_key = copy.deepcopy(original)
    extra_key["unexpected"] = True
    mutations.append(extra_key)
    wrong_parameter = copy.deepcopy(original)
    wrong_parameter["cases"][1]["parameters"]["date_to"] = "2026-12-30"
    mutations.append(wrong_parameter)
    missing_negative = copy.deepcopy(original)
    missing_negative["negative_cases"].pop()
    mutations.append(missing_negative)
    boolean_schema = copy.deepcopy(original)
    boolean_schema["schema_version"] = True
    mutations.append(boolean_schema)

    for index, value in enumerate(mutations):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(oracle.OracleInputError):
            oracle.read_plan(path)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(oracle.OracleInputError, match="duplicate JSON key"):
        oracle.read_plan(duplicate)


def test_request_is_bound_to_frozen_case_not_response_filters():
    oracle = load_module()
    plan = oracle.read_plan(DEV29 / "read_plan.json")
    case = oracle.case_by_name(plan, "ar_open_items")
    request = request_for(plan, case)
    oracle.validate_request(plan, case, request)

    for mutate in (
        lambda value: value["parameters"].__setitem__("as_of_date", "2026-07-13"),
        lambda value: value["context"].__setitem__("company_id", 2),
        lambda value: value.__setitem__("capability_id", "acct.ap.open_items.v1"),
    ):
        changed = copy.deepcopy(request)
        mutate(changed)
        with pytest.raises(oracle.OracleInputError):
            oracle.validate_request(plan, case, changed)


def test_trial_balance_builder_recomputes_full_page_and_golden_projection():
    oracle = load_module()
    parameters = {
        "account_id": None,
        "company_id": 1,
        "currency_id": None,
        "date_from": "2026-01-01",
        "date_to": "2026-12-31",
        "include_off_balance": False,
        "include_zero": False,
        "limit": 500,
        "offset": 0,
        "opening_basis": "ledger_cumulative",
    }
    rows = [
        {
            "account_id": 10,
            "code": "1000",
            "name": "Cash",
            "account_type": "asset_cash",
            "opening_balance": Decimal("2"),
            "period_debit": Decimal("8"),
            "period_credit": Decimal("3"),
            "move_line_count": 4,
        },
        {
            "account_id": 20,
            "code": "2000",
            "name": "Payable",
            "account_type": "liability_payable",
            "opening_balance": Decimal("-2"),
            "period_debit": Decimal("3"),
            "period_credit": Decimal("8"),
            "move_line_count": 5,
        },
    ]
    currency = {"id": 6, "name": "CNY", "symbol": "¥", "rounding": Decimal("0.01")}
    result, metrics = oracle.build_trial_balance(rows, currency, parameters)
    assert result["page"] == {"limit": 500, "offset": 0, "count": 2, "total_count": 2}
    assert result["ledger_summary"] == {
        "opening_balance": "0.00",
        "period_debit": "11.00",
        "period_credit": "11.00",
        "period_balance": "0.00",
        "closing_balance": "0.00",
        "debit_credit_difference": "0.00",
        "is_balanced": True,
    }
    assert metrics["account_count"] == 2
    assert metrics["move_line_count"] == 9
    assert metrics["ledger_summary"] == result["ledger_summary"]


def test_open_item_builder_checks_names_pagination_aging_currency_and_old_hash():
    oracle = load_module()
    parameters = {
        "as_of_date": "2026-07-14",
        "company_id": 1,
        "currency_id": None,
        "limit": 1,
        "offset": 0,
        "partner_id": None,
    }
    source = {
        "move_line_id": 7,
        "move_id": 8,
        "move_name": "INV/7",
        "move_type": "out_invoice",
        "payment_id": None,
        "line_date": "2026-06-01",
        "due_date": "2026-06-13",
        "partner_id": 9,
        "partner_name": "Fixture partner",
        "account_id": 10,
        "account_code": "1122",
        "account_name": "Receivable",
        "journal_id": 11,
        "journal_code": "INV",
        "currency_id": 6,
        "currency_name": "CNY",
        "currency_rounding": Decimal("0.01"),
        "balance": Decimal("100"),
        "amount_currency": Decimal("100"),
        "current_reconciled": False,
        "debit_company": Decimal("40"),
        "credit_company": Decimal("0"),
        "debit_currency": Decimal("40"),
        "credit_currency": Decimal("0"),
        "matched_count": 1,
    }
    company = {"id": 6, "name": "CNY", "symbol": "¥", "rounding": Decimal("0.01")}
    result, metrics = oracle.build_open_items([source], company, parameters, "ar")
    assert result["filters"] == {
        "company_id": 1,
        "as_of_date": "2026-07-14",
        "partner_id": None,
        "currency_id": None,
    }
    assert result["items"][0]["partner_name"] == "Fixture partner"
    assert result["items"][0]["residual_company_amount"] == "60.00"
    assert result["items"][0]["aging_bucket"] == "days_31_60"
    assert result["page"]["count"] == 1
    assert metrics["source_line_count"] == 1
    assert metrics["open_item_count"] == 1
    assert len(metrics["historical_projection_sha256"]) == 64

    changed = copy.deepcopy(result)
    changed["items"][0]["partner_name"] = "tampered"
    checks = oracle.result_checks(changed, result)
    assert checks["business_result"] is False


def test_historical_golden_mutation_is_not_accepted():
    oracle = load_module()
    plan = oracle.read_plan(DEV29 / "read_plan.json")
    case = oracle.case_by_name(plan, "ap_open_items")
    metrics = copy.deepcopy(case["expected"])
    assert all(oracle.golden_checks(case, metrics).values())
    metrics["open_item_count"] -= 1
    assert oracle.golden_checks(case, metrics)["golden_open_item_count"] is False


class FakeCursor:
    def __init__(self):
        self.executed = []
        self._one = ("repeatable read", "on")

    def execute(self, statement, parameters=None):
        self.executed.append((statement, parameters))

    def fetchone(self):
        return self._one

    def close(self):
        pass


class FakeConnection:
    def __init__(self, *, rollback_error=None, final_status=0):
        self.cursor_value = FakeCursor()
        self.rollback_error = rollback_error
        self.final_status = final_status
        self.rollback_calls = 0
        self.closed = False
        self.session = None

    def set_session(self, **kwargs):
        self.session = kwargs

    def cursor(self):
        return self.cursor_value

    def rollback(self):
        self.rollback_calls += 1
        if self.rollback_error:
            raise self.rollback_error

    def get_transaction_status(self):
        return self.final_status

    def close(self):
        self.closed = True


def test_transaction_boundary_is_repeatable_read_read_only_rolled_back_and_idle():
    oracle = load_module()
    connection = FakeConnection()
    value, transaction = oracle.run_read_only_transaction(
        connection, lambda cursor: {"seen": len(cursor.executed)}
    )
    assert value == {"seen": 1}
    assert connection.session == {
        "isolation_level": "REPEATABLE READ",
        "readonly": True,
        "autocommit": False,
    }
    assert connection.rollback_calls == 1
    assert connection.closed is True
    assert transaction == {
        "isolation": "repeatable read",
        "read_only": "on",
        "rollback_completed": True,
        "final_status": "IDLE",
    }

    failed = FakeConnection(rollback_error=RuntimeError("rollback failed"))
    with pytest.raises(oracle.OracleInputError, match="rollback failed"):
        oracle.run_read_only_transaction(failed, lambda _cursor: None)
    assert failed.closed is True


class SchemaCursor:
    def __init__(self, oracle, planned, postmaster_started_at):
        self.oracle = oracle
        self.planned = planned
        self.postmaster_started_at = postmaster_started_at
        self.statement = None

    def execute(self, statement, parameters=None):
        self.statement = statement

    def fetchone(self):
        database = self.planned["database"]
        if self.statement != self.oracle.IDENTITY_SQL:
            raise AssertionError("unexpected fetchone")
        return (
            database["name"],
            database["current_user"],
            database["uuid"],
            database["server_version_num"],
            database["system_identifier"],
            self.postmaster_started_at,
            None,
            None,
            database["unix_socket_directory"],
            "repeatable read",
            "on",
        )

    def fetchall(self):
        if self.statement == self.oracle.RELATIONS_SQL:
            return [
                (name, identity[0], identity[1], identity[2])
                for name, identity in self.oracle.RELATION_IDENTITIES.items()
            ]
        if self.statement == self.oracle.PRIMARY_KEYS_SQL:
            return [
                (name, list(identity[3]))
                for name, identity in self.oracle.RELATION_IDENTITIES.items()
            ]
        if self.statement == self.oracle.COLUMNS_SQL:
            rows = []
            for relation in self.planned["witness"]["relations"]:
                for ordinal, column in enumerate(relation["required_columns"], 1):
                    rows.append(
                        (
                            relation["name"],
                            column["name"],
                            column["type"],
                            column["name"] == "id",
                            ordinal,
                        )
                    )
            return rows
        raise AssertionError("unexpected fetchall")


def test_database_schema_binds_aware_postmaster_start_for_restart_continuity():
    oracle = load_module()
    planned = oracle.read_plan(DEV29 / "read_plan.json")
    started = datetime(2026, 7, 20, tzinfo=timezone.utc)
    before = oracle.verify_database_schema(
        SchemaCursor(oracle, planned, started), planned
    )
    after = oracle.verify_database_schema(
        SchemaCursor(oracle, planned, started + timedelta(seconds=1)), planned
    )
    assert before["database"]["postmaster_started_at"] == started.isoformat()
    assert after != before

    with pytest.raises(oracle.OracleInputError, match="postmaster start"):
        oracle.verify_database_schema(
            SchemaCursor(oracle, planned, started.replace(tzinfo=None)), planned
        )


def test_witness_digest_is_canonical_ordered_and_never_emits_rows():
    oracle = load_module()
    rows = [{"id": 1, "balance": "1.00"}, {"id": 2, "balance": "-1.00"}]
    expected_stream = b'{"balance":"1.00","id":1}\n{"balance":"-1.00","id":2}\n'
    evidence = oracle.witness_digest(rows)
    assert evidence == {
        "row_count": 2,
        "row_stream_sha256": hashlib.sha256(expected_stream).hexdigest(),
    }
    assert "rows" not in evidence


def test_oracle_runtime_is_bound_to_isolated_odoo_python_without_odoo_imports():
    oracle = load_module()
    plan = oracle.read_plan(DEV29 / "read_plan.json")
    expected = plan["runtime"]
    assert oracle.verify_runtime_python(
        plan,
        executable=expected["odoo_python"],
        isolated=1,
        module_names={"sys", "psycopg2"},
        executable_sha256=expected["odoo_python_sha256"],
    ) == {
        "path": expected["odoo_python"],
        "sha256": expected["odoo_python_sha256"],
        "isolated": True,
    }
    with pytest.raises(oracle.OracleInputError):
        oracle.verify_runtime_python(
            plan,
            executable="/usr/bin/python3.12",
            isolated=1,
            module_names=set(),
            executable_sha256=expected["odoo_python_sha256"],
        )


def test_source_declares_fixed_socket_schema_and_privacy_boundaries():
    source = (DEV29 / "read_oracles.py").read_text("utf-8")
    plan_source = (DEV29 / "read_plan.json").read_text("utf-8")
    assert "SET LOCAL search_path TO pg_catalog" in source
    assert "REPEATABLE READ" in source
    assert "READ ONLY" in source
    assert "public.account_move_line" in source
    assert "public.account_partial_reconcile" in source
    assert "pg_catalog.pg_control_system" in source
    assert "get_transaction_status" in source
    assert "response[\"filters\"]" not in source
    for selector in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE", "PGPASSWORD", "PGOPTIONS"):
        assert selector in source
    combined = (source + plan_source).lower()
    assert "totp_secret" not in combined
    assert '"password"' not in combined
