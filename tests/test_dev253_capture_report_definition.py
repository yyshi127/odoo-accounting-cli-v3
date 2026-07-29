from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

from odoo_accounting_cli_v3.report_definition_projection import (
    build_root_definition_projection,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev253" / "capture_report_definition.py"
SPEC = importlib.util.spec_from_file_location(
    "dev253_report_definition_capture_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)

DATABASE_NAME = "odoo_test"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
SYSTEM_IDENTIFIER = "7616327373742442245"
COMPANY_ID = 7
CAPTURED_AT = datetime(2026, 7, 29, 6, 7, 8, 9012, timezone.utc)
WRITE_TIME = datetime(
    2026,
    7,
    28,
    23,
    59,
    58,
    123456,
    timezone(timedelta(hours=8)),
)


def report_row(
    record_id: int,
    xmlid: str,
    *,
    root_record_id: int | None = None,
    name: str | None = None,
    use_sections: bool = False,
    custom_handler_model: str | None = None,
) -> dict[str, object]:
    return {
        "active": True,
        "availability_condition": "always",
        "chart_template": None,
        "country_code": None,
        "custom_handler_model": custom_handler_model,
        "filter_allow_foreign_vat": False,
        "filter_currency_translation": "cta",
        "filter_date_range": True,
        "filter_default_opening_date": "previous_month",
        "filter_growth_comparison": True,
        "filter_hide_0_lines": "optional",
        "filter_journals": True,
        "filter_multi_company": "selector",
        "filter_period_comparison": True,
        "filter_show_draft": True,
        "filter_unfold_all": False,
        "filter_unreconciled": False,
        "integer_rounding": "HALF-UP",
        "load_more_limit": 80,
        "name": name or xmlid,
        "only_tax_exigible": False,
        "prefix_groups_threshold": 4000,
        "record_id": record_id,
        "root_record_id": root_record_id,
        "search_bar": False,
        "sequence": record_id,
        "use_sections": use_sections,
        "write_date": WRITE_TIME,
        "xmlid": xmlid,
        "xmlid_count": 1,
    }


def line_row(
    record_id: int,
    report_id: int,
    *,
    parent_id: int | None = None,
    code: str | None = None,
    name: str = "Line",
    sequence: int = 10,
) -> dict[str, object]:
    return {
        "action_id": None,
        "action_xmlid": None,
        "action_xmlid_count": 0,
        "code": code,
        "foldable": False,
        "groupby": None,
        "hide_if_zero": False,
        "hierarchy_level": 1 if parent_id is None else 3,
        "horizontal_split_side": None,
        "name": name,
        "parent_id": parent_id,
        "print_on_new_page": False,
        "record_id": record_id,
        "report_id": report_id,
        "sequence": sequence,
        "user_groupby": None,
        "write_date": WRITE_TIME,
    }


def expression_row(
    record_id: int,
    line_id: int,
    *,
    engine: str,
    formula: str,
    label: str = "balance",
) -> dict[str, object]:
    return {
        "auditable": True,
        "blank_if_zero": False,
        "carryover_target": None,
        "date_scope": "strict_range",
        "engine": engine,
        "figure_type": "monetary",
        "formula": formula,
        "green_on_positive": True,
        "label": label,
        "line_id": line_id,
        "record_id": record_id,
        "subformula": "sum" if engine == "domain" else None,
        "write_date": WRITE_TIME,
    }


def rows() -> dict[str, list[dict[str, object]]]:
    boundary = {
        "database_name": DATABASE_NAME,
        "search_path": "pg_catalog",
        "system_identifier": SYSTEM_IDENTIFIER,
        "transaction_isolation": "repeatable read",
        "transaction_read_only": "on",
    }
    identity = {
        "database_name": DATABASE_NAME,
        "database_uuid": DATABASE_UUID,
        "system_identifier": SYSTEM_IDENTIFIER,
    }
    reports = [
        report_row(
            31,
            "account_reports.balance_sheet_variant",
            root_record_id=30,
            name="Balance Sheet SG",
        ),
        report_row(
            11,
            "account.generic_tax_report",
            name="Tax Report",
            custom_handler_model="account.tax.report.handler",
        ),
        report_row(
            32,
            "account_reports.balance_sheet_section",
            name="Balance Sheet Section",
        ),
        report_row(50, "account_reports.profit_and_loss", name="Profit and Loss"),
        report_row(40, "account_reports.cash_flow_report", name="Cash Flow"),
        report_row(
            30,
            "account_reports.balance_sheet",
            name="Balance Sheet",
            use_sections=True,
        ),
    ]
    lines = [
        line_row(140, 40, code="CF", name="Cash Flow"),
        line_row(111, 11, parent_id=110, name="测试", sequence=20),
        line_row(150, 50, code="PL", name="Profit and Loss"),
        line_row(130, 30, code="BS", name="Balance Sheet"),
        line_row(110, 11, code="TAX", name="Tax"),
    ]
    expressions = [
        expression_row(250, 150, engine="aggregation", formula="INC.balance"),
        expression_row(210, 110, engine="domain", formula="[('tax_line_id','!=',False)]"),
        expression_row(240, 140, engine="aggregation", formula="CASH.balance"),
        expression_row(230, 130, engine="aggregation", formula="ASSET.balance"),
    ]
    return {
        "boundary_after": [deepcopy(boundary)],
        "boundary_before": [deepcopy(boundary)],
        "columns": [
            {
                "blank_if_zero": False,
                "custom_audit_action_id": None,
                "custom_audit_action_xmlid": None,
                "custom_audit_action_xmlid_count": 0,
                "expression_label": "balance",
                "figure_type": "monetary",
                "name": "Balance",
                "record_id": 501,
                "report_id": 11,
                "sequence": 10,
                "sortable": False,
                "write_date": WRITE_TIME,
            }
        ],
        "company": [
            {
                "account_fiscal_country_code": "SG",
                "chart_template": "sg",
                "company_id": COMPANY_ID,
                "company_name": "Sandbox SG",
                "country_code": "SG",
                "currency_decimal_places": 2,
                "currency_name": "SGD",
                "currency_rounding": "0.01",
                "currency_symbol": "$",
                "fiscalyear_last_day": 31,
                "fiscalyear_last_month": "12",
                "fiscalyear_lock_date": "2025-12-31",
                "hard_lock_date": None,
                "tax_lock_date": "2026-03-31",
                "write_date": WRITE_TIME,
            }
        ],
        "expressions": expressions,
        "identity_after": [deepcopy(identity)],
        "identity_before": [deepcopy(identity)],
        "lines": lines,
        "module_dependencies": [
            {
                "auto_install_required": False,
                "dependency_name": "account",
                "module_id": 3,
            },
            {
                "auto_install_required": False,
                "dependency_name": "base",
                "module_id": 2,
            },
        ],
        "modules": [
            {
                "latest_version": "19.0.1.0",
                "module_id": 3,
                "name": "account_reports",
                "write_date": WRITE_TIME,
            },
            {
                "latest_version": "19.0.1.0",
                "module_id": 1,
                "name": "base",
                "write_date": WRITE_TIME,
            },
            {
                "latest_version": "19.0.1.0",
                "module_id": 2,
                "name": "account",
                "write_date": WRITE_TIME,
            },
        ],
        "reports": reports,
        "sections": [{"main_report_id": 30, "sub_report_id": 32}],
    }


class FakeAdapter:
    def __init__(
        self,
        fixtures: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
        *,
        initial_status: str = "IDLE",
        drift_after: str | None = None,
        rollback_status: str = "IDLE",
    ) -> None:
        self.rows = deepcopy(dict(fixtures or rows()))
        self.status = initial_status
        self.drift_after = drift_after
        self.rollback_status = rollback_status
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fetched: list[tuple[str, tuple[object, ...]]] = []
        self.rollback_count = 0

    def transaction_status(self) -> str:
        return self.status

    def execute(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> None:
        self.executed.append((statement, tuple(parameters)))
        if statement == capture.BEGIN_READ_ONLY:
            self.status = "INTRANS"

    def fetch(
        self,
        query_id: str,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        assert statement
        self.fetched.append((query_id, tuple(parameters)))
        result = deepcopy(self.rows[query_id])
        if self.drift_after == query_id:
            self.status = "INERROR"
        return result

    def rollback(self) -> None:
        self.rollback_count += 1
        self.status = self.rollback_status


def collect(adapter: FakeAdapter | None = None) -> dict[str, object]:
    return capture.capture_report_definition(
        adapter or FakeAdapter(),
        expected_database_name=DATABASE_NAME,
        expected_database_uuid=DATABASE_UUID,
        expected_postgresql_system_identifier=SYSTEM_IDENTIFIER,
        company_id=COMPANY_ID,
        clock=lambda: CAPTURED_AT,
    )


def primitive_leaves(value: object) -> bool:
    if value is None or type(value) in {str, int, bool, float}:
        return True
    if isinstance(value, list):
        return all(primitive_leaves(item) for item in value)
    if isinstance(value, dict):
        return all(
            type(key) is str and primitive_leaves(item)
            for key, item in value.items()
        )
    return False


def test_capture_builds_canonical_unapproved_candidate_and_rolls_back() -> None:
    adapter = FakeAdapter()
    document = collect(adapter)

    assert set(document) == set(capture.TOP_LEVEL_FIELDS)
    assert document["candidate_is_approval"] is False
    assert document["production_promotion_allowed"] is False
    assert document["captured_at"] == "2026-07-29T06:07:08.009012Z"
    assert document["database"] == {
        "name": DATABASE_NAME,
        "postgresql_system_identifier": SYSTEM_IDENTIFIER,
        "uuid": DATABASE_UUID,
    }
    assert document["company"]["company_id"] == COMPANY_ID
    assert document["company"]["write_date"] == "2026-07-28T15:59:58.123456Z"
    assert primitive_leaves(document)
    assert adapter.executed == [
        (capture.BEGIN_READ_ONLY, ()),
        (capture.SET_SEARCH_PATH, ()),
    ]
    assert [item[0] for item in adapter.fetched] == [
        "boundary_before",
        "identity_before",
        "company",
        "reports",
        "sections",
        "columns",
        "lines",
        "expressions",
        "modules",
        "module_dependencies",
        "identity_after",
        "boundary_after",
    ]
    assert dict(adapter.fetched)["company"] == (COMPANY_ID,)
    assert adapter.rollback_count == 1
    assert adapter.status == "IDLE"

    encoded = capture.canonical_document_bytes(document)
    assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
    assert encoded[:-1] == capture.canonical_json(document)
    assert json.loads(encoded) == document
    assert b"record_id" not in encoded
    assert b"module_id" not in encoded
    assert document["definition_sha256"] == hashlib.sha256(
        capture.canonical_json(capture.definition_payload(document))
    ).hexdigest()


def test_fixed_root_identities_and_per_root_projection_are_bound() -> None:
    document = collect()
    roots = document["report_roots"]

    assert [item["report_key"] for item in roots] == [
        "generic_tax",
        "balance_sheet",
        "cash_flow",
        "profit_and_loss",
    ]
    assert roots[0]["baseline_identity"] == {
        "company_id": COMPANY_ID,
        "database_uuid": DATABASE_UUID,
        "family": "tax",
        "kind": "generic_tax",
        "root_xmlid": "account.generic_tax_report",
    }
    for root in roots:
        identity = root["baseline_identity"]
        projection = build_root_definition_projection(
            **identity,
            company_profile=document["company"],
            module_graph=document["module_graph"],
            reports=document["reports"],
        )
        assert root["definition_sha256"] == hashlib.sha256(
            capture.canonical_json(projection)
        ).hexdigest()
    assert roots[1]["variant_report_keys"] == [
        "account_reports.balance_sheet_variant"
    ]
    assert roots[1]["section_report_keys"] == [
        "account_reports.balance_sheet_section"
    ]
    assert all("id" not in item for item in document["reports"])


def test_report_content_captures_columns_hierarchy_expressions_and_domains() -> None:
    document = collect()
    reports = {item["key"]: item for item in document["reports"]}
    tax = reports["account.generic_tax_report"]

    assert tax["custom_handler_model"] == "account.tax.report.handler"
    assert len(tax["columns"]) == 1
    assert tax["columns"][0]["expression_label"] == "balance"
    assert [line["code"] for line in tax["lines"]] == [None, "TAX"]
    by_code = {line["code"]: line for line in tax["lines"]}
    assert by_code[None]["parent_key"] == by_code["TAX"]["key"]
    assert by_code[None]["name"] == "测试"
    assert by_code[None]["key"].startswith(
        "account.generic_tax_report/line/"
    )
    expression = by_code["TAX"]["expressions"][0]
    assert expression["engine"] == "domain"
    assert expression["domain"] == expression["formula"]
    financial = reports["account_reports.cash_flow_report"]
    assert financial["lines"][0]["expressions"][0]["domain"] is None


def test_module_graph_and_source_projection_are_semantic_and_deterministic() -> None:
    first = collect()
    shuffled = rows()
    shuffled["modules"].reverse()
    shuffled["module_dependencies"].reverse()
    shuffled["reports"].reverse()
    shuffled["lines"].reverse()
    shuffled["expressions"].reverse()
    second = collect(FakeAdapter(shuffled))

    assert first["module_graph"] == second["module_graph"]
    assert first["source_projection"] == second["source_projection"]
    assert first["definition_sha256"] == second["definition_sha256"]
    assert [item["name"] for item in first["module_graph"]["modules"]] == [
        "account",
        "account_reports",
        "base",
    ]
    capture.validate_candidate_document(first)


def test_each_root_digest_binds_company_and_installed_module_meaning() -> None:
    original = collect()
    company_changed_rows = rows()
    company_changed_rows["company"][0]["currency_rounding"] = "0.001"
    company_changed = collect(FakeAdapter(company_changed_rows))
    assert [
        item["definition_sha256"] for item in company_changed["report_roots"]
    ] != [
        item["definition_sha256"] for item in original["report_roots"]
    ]

    module_changed_rows = rows()
    module_changed_rows["modules"][0]["latest_version"] = "19.0.2.0"
    module_changed = collect(FakeAdapter(module_changed_rows))
    assert [
        item["definition_sha256"] for item in module_changed["report_roots"]
    ] != [
        item["definition_sha256"] for item in original["report_roots"]
    ]


@pytest.mark.parametrize(
    ("query_id", "mutation"),
    [
        ("company", lambda value: value[0].__setitem__("extra", True)),
        ("company", lambda value: value[0].pop("country_code")),
        (
            "identity_before",
            lambda value: value.append(deepcopy(value[0])),
        ),
        (
            "reports",
            lambda value: value.__setitem__(
                slice(None),
                [
                    row
                    for row in value
                    if row["xmlid"] != "account.generic_tax_report"
                ],
            ),
        ),
        (
            "sections",
            lambda value: value.append(deepcopy(value[0])),
        ),
        (
            "modules",
            lambda value: value.append(
                {
                    **deepcopy(value[0]),
                    "module_id": 99,
                }
            ),
        ),
        (
            "expressions",
            lambda value: value.append(
                {
                    **deepcopy(value[0]),
                    "record_id": 999,
                }
            ),
        ),
    ],
)
def test_extra_missing_and_duplicate_database_projection_fails_closed(
    query_id: str, mutation: Any
) -> None:
    fixtures = rows()
    mutation(fixtures[query_id])
    adapter = FakeAdapter(fixtures)

    with pytest.raises(capture.CaptureError):
        collect(adapter)
    assert adapter.rollback_count == 1
    assert adapter.status == "IDLE"


def test_identity_drift_and_transaction_boundary_drift_fail_closed() -> None:
    fixtures = rows()
    fixtures["identity_after"][0]["database_uuid"] = (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    adapter = FakeAdapter(fixtures)
    with pytest.raises(capture.CaptureError, match="identity changed"):
        collect(adapter)
    assert adapter.rollback_count == 1

    adapter = FakeAdapter(drift_after="reports")
    with pytest.raises(capture.CaptureError, match="transaction state"):
        collect(adapter)
    assert adapter.rollback_count == 1

    adapter = FakeAdapter(initial_status="INTRANS")
    with pytest.raises(capture.CaptureError, match="not idle"):
        collect(adapter)
    assert adapter.rollback_count == 1

    adapter = FakeAdapter(rollback_status="INTRANS")
    with pytest.raises(capture.CaptureError, match="rollback boundary"):
        collect(adapter)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_database_name", "other"),
        (
            "expected_database_uuid",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        ("expected_postgresql_system_identifier", "7000000000000000000"),
        ("company_id", 8),
    ],
)
def test_expected_binding_mismatch_is_rejected(field: str, value: object) -> None:
    arguments = {
        "expected_database_name": DATABASE_NAME,
        "expected_database_uuid": DATABASE_UUID,
        "expected_postgresql_system_identifier": SYSTEM_IDENTIFIER,
        "company_id": COMPANY_ID,
        "clock": lambda: CAPTURED_AT,
    }
    arguments[field] = value
    adapter = FakeAdapter()
    with pytest.raises(capture.CaptureError, match="differs|row count"):
        capture.capture_report_definition(adapter, **arguments)
    assert adapter.rollback_count == 1


def test_candidate_validation_rejects_tampering_and_extra_fields() -> None:
    document = collect()
    document["candidate_is_approval"] = True
    with pytest.raises(capture.CaptureError, match="safety"):
        capture.validate_candidate_document(document)

    document = collect()
    document["report_roots"][0]["baseline_identity"]["kind"] = "tax"
    with pytest.raises(capture.CaptureError):
        capture.validate_candidate_document(document)

    document = collect()
    document["reports"][0]["extra"] = True
    with pytest.raises(capture.CaptureError, match="fields"):
        capture.validate_candidate_document(document)

    document = collect()
    document["definition_sha256"] = "0" * 64
    with pytest.raises(capture.CaptureError, match="digest differs"):
        capture.validate_candidate_document(document)


def test_sql_contract_is_read_only_catalog_qualified_and_has_no_credentials() -> None:
    assert capture.BEGIN_READ_ONLY == (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    )
    assert capture.SET_SEARCH_PATH == "SET LOCAL search_path = pg_catalog"
    query_texts = (
        capture.BOUNDARY_SQL,
        capture.IDENTITY_SQL,
        capture.COMPANY_SQL,
        capture.REPORT_SQL,
        capture.SECTION_SQL,
        capture.COLUMN_SQL,
        capture.LINE_SQL,
        capture.EXPRESSION_SQL,
        capture.MODULE_SQL,
        capture.DEPENDENCY_SQL,
    )
    forbidden = re.compile(
        r"\b(?:INSERT|UPDATE|DELETE|MERGE|TRUNCATE|ALTER|DROP|CREATE|COMMIT)\b",
        re.IGNORECASE,
    )
    for query in query_texts:
        assert forbidden.search(query) is None
        assert "public." in query or "pg_catalog." in query
    source = SCRIPT.read_text(encoding="utf-8")
    assert "psycopg2" not in sys.modules or "import psycopg2" in source
    assert "password=" not in source.lower()
    assert "postgres://" not in source.lower()


def test_output_is_new_canonical_file_and_cli_does_not_echo_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "candidate.json"
    payload = capture.canonical_document_bytes(collect())
    capture._write_new(output, payload)
    assert output.read_bytes() == payload
    with pytest.raises(capture.CaptureError, match="could not be created"):
        capture._write_new(output, payload)
    assert output.read_bytes() == payload

    secret = "host=example password=DO_NOT_ECHO"
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_REPORT_DEFINITION_DSN", secret
    )

    def fail_connect(_dsn: str) -> object:
        raise capture.CaptureError("database connection failed")

    monkeypatch.setattr(capture.PsycopgAdapter, "connect", fail_connect)
    result = capture.main(
        [
            "--database-name",
            DATABASE_NAME,
            "--database-uuid",
            DATABASE_UUID,
            "--postgresql-system-identifier",
            SYSTEM_IDENTIFIER,
            "--company-id",
            str(COMPANY_ID),
            "--environment",
            "development",
            "--allow-development-dsn-env",
        ]
    )
    output_streams = capsys.readouterr()
    assert result == 1
    assert secret not in output_streams.err
    assert "DO_NOT_ECHO" not in output_streams.err


def test_private_dsn_descriptor_is_consumed_without_environment_exposure() -> None:
    read_descriptor, write_descriptor = os.pipe()
    os.write(write_descriptor, b"host=127.0.0.1 dbname=odoo_test\n")
    os.close(write_descriptor)

    assert capture._read_dsn_fd(read_descriptor) == (
        "host=127.0.0.1 dbname=odoo_test"
    )
    with pytest.raises(OSError):
        os.fstat(read_descriptor)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\n",
        b" host=localhost",
        b"host=localhost ",
        b"host=localhost\r\n",
        b"host=localhost\n\n",
        b"host=\x00localhost",
    ],
)
def test_private_dsn_material_rejects_ambiguous_encodings(payload: bytes) -> None:
    with pytest.raises(capture.CaptureError):
        capture._dsn_text(payload)


def test_production_rejects_environment_dsn_even_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_REPORT_DEFINITION_DSN",
        "host=example password=DO_NOT_ECHO",
    )
    result = capture.main(
        [
            "--database-name",
            DATABASE_NAME,
            "--database-uuid",
            DATABASE_UUID,
            "--postgresql-system-identifier",
            SYSTEM_IDENTIFIER,
            "--company-id",
            str(COMPANY_ID),
            "--environment",
            "production",
            "--allow-development-dsn-env",
        ]
    )
    output_streams = capsys.readouterr()
    assert result == 1
    assert "limited to explicit development" in output_streams.err
    assert "DO_NOT_ECHO" not in output_streams.err
