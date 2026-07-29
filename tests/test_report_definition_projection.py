from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from odoo_accounting_cli_v3 import report_definition_projection as projection


DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"


def report(
    key: str,
    *,
    root: str | None = None,
    sections: list[str] | None = None,
) -> dict[str, object]:
    return {
        "active": True,
        "availability_condition": "always",
        "chart_template": None,
        "columns": [],
        "country_code": None,
        "custom_handler_model": None,
        "key": key,
        "lines": [],
        "name": key,
        "options": {
            "allow_foreign_vat": False,
            "currency_translation": "cta",
            "default_opening_date_filter": "previous_month",
            "filter_date_range": True,
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
            "only_tax_exigible": False,
            "prefix_groups_threshold": 4000,
            "search_bar": False,
        },
        "root_report_key": root,
        "section_report_keys": sections or [],
        "sequence": 10,
        "use_sections": bool(sections),
        "write_date": None,
        "xmlid": key,
    }


def reports() -> list[dict[str, object]]:
    return sorted(
        [
            report("account.generic_tax_report"),
            report(
                "account_reports.balance_sheet",
                sections=["account_reports.balance_sheet_section"],
            ),
            report(
                "account_reports.balance_sheet_section",
            ),
            report(
                "account_reports.balance_sheet_variant",
                root="account_reports.balance_sheet",
                sections=["account_reports.balance_sheet_variant_section"],
            ),
            report("account_reports.balance_sheet_variant_section"),
            report("account_reports.cash_flow_report"),
            report("account_reports.profit_and_loss"),
        ],
        key=lambda item: str(item["key"]),
    )


def build(**overrides: object) -> dict[str, object]:
    module_payload = {
        "modules": [
            {
                "dependencies": [],
                "latest_version": "19.0.1.0",
                "name": "account",
                "write_date": None,
            }
        ],
        "schema_version": 1,
    }
    values: dict[str, object] = {
        "database_uuid": DATABASE_UUID,
        "company_id": 7,
        "family": "tax",
        "kind": "generic_tax",
        "root_xmlid": "account.generic_tax_report",
        "company_profile": {
            "account_fiscal_country_code": "SG",
            "chart_template": "sg",
            "company_id": 7,
            "country_code": "SG",
            "currency": {
                "decimal_places": 2,
                "name": "SGD",
                "rounding": "0.01",
                "symbol": "$",
            },
            "fiscal": {
                "fiscalyear_last_day": 31,
                "fiscalyear_last_month": "12",
                "fiscalyear_lock_date": None,
                "hard_lock_date": None,
                "tax_lock_date": None,
            },
            "name": "Sandbox SG",
            "write_date": None,
        },
        "module_graph": {
            **module_payload,
            "digest": hashlib.sha256(
                projection.canonical_projection_json(module_payload)
            ).hexdigest(),
        },
        "reports": reports(),
    }
    values.update(overrides)
    return projection.build_root_definition_projection(**values)


def test_generic_tax_identity_and_projection_are_canonical_and_pure() -> None:
    source = reports()
    before = deepcopy(source)
    result = build(reports=source)

    assert source == before
    assert result["baseline_identity"] == {
        "company_id": 7,
        "database_uuid": DATABASE_UUID,
        "family": "tax",
        "kind": "generic_tax",
        "root_xmlid": "account.generic_tax_report",
    }
    assert result["reports"] == [report("account.generic_tax_report")]
    assert result["company_profile"]["currency"]["name"] == "SGD"
    assert result["module_graph"]["modules"][0]["name"] == "account"
    assert result["source_projection"]["digest"]
    projection.validate_root_definition_projection(result)
    assert build(reports=deepcopy(source)) == result


def test_financial_projection_follows_variants_and_sections_recursively() -> None:
    result = build(
        family="financial",
        kind="balance_sheet",
        root_xmlid="account_reports.balance_sheet",
    )

    assert [item["key"] for item in result["reports"]] == [
        "account_reports.balance_sheet",
        "account_reports.balance_sheet_section",
        "account_reports.balance_sheet_variant",
        "account_reports.balance_sheet_variant_section",
    ]
    projection.validate_root_definition_projection(result)


def test_company_module_and_source_projection_are_digest_bound() -> None:
    original = build()
    company = deepcopy(original["company_profile"])
    company["currency"]["rounding"] = "0.001"
    changed_company = build(company_profile=company)
    assert (
        changed_company["source_projection"]["digest"]
        != original["source_projection"]["digest"]
    )
    assert (
        projection.canonical_projection_json(changed_company)
        != projection.canonical_projection_json(original)
    )

    module_graph = deepcopy(original["module_graph"])
    module_graph["modules"][0]["latest_version"] = "19.0.2.0"
    module_payload = {
        "modules": module_graph["modules"],
        "schema_version": 1,
    }
    module_graph["digest"] = hashlib.sha256(
        projection.canonical_projection_json(module_payload)
    ).hexdigest()
    changed_module = build(module_graph=module_graph)
    assert (
        changed_module["source_projection"]["digest"]
        != original["source_projection"]["digest"]
    )

    tampered = deepcopy(original)
    tampered["source_projection"]["digest"] = "0" * 64
    with pytest.raises(projection.ReportDefinitionProjectionError):
        projection.validate_root_definition_projection(tampered)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("database_uuid", "not-a-uuid"),
        ("database_uuid", DATABASE_UUID.upper()),
        ("company_id", True),
        ("company_id", 0),
        ("family", "tax"),
        ("kind", "tax"),
        ("root_xmlid", "account.tax_report"),
    ],
)
def test_identity_drift_is_rejected(field: str, value: object) -> None:
    values: dict[str, object] = {}
    if field == "family":
        values.update(
            family=value,
            kind="balance_sheet",
            root_xmlid="account_reports.balance_sheet",
        )
    else:
        values[field] = value
    with pytest.raises(
        projection.ReportDefinitionProjectionError,
        match="invalid|canonical|fixed",
    ):
        build(**values)


def test_report_shape_ambiguities_fail_closed() -> None:
    cases = []
    duplicated = reports()
    duplicated.append(deepcopy(duplicated[0]))
    cases.append(duplicated)

    unsorted = reports()
    unsorted.reverse()
    cases.append(unsorted)

    missing_section = reports()
    missing_section[1]["section_report_keys"] = ["account_reports.absent"]
    cases.append(missing_section)

    unsorted_sections = reports()
    unsorted_sections[1]["section_report_keys"] = [
        "account_reports.balance_sheet_variant_section",
        "account_reports.balance_sheet_section",
    ]
    cases.append(unsorted_sections)

    missing_root = [
        item
        for item in reports()
        if item["key"] != "account.generic_tax_report"
    ]
    cases.append(missing_root)

    for candidate in cases:
        with pytest.raises(projection.ReportDefinitionProjectionError):
            build(reports=candidate)


def test_non_json_values_and_noncanonical_projection_fail_closed() -> None:
    invalid = reports()
    invalid[0]["name"] = object()
    with pytest.raises(
        projection.ReportDefinitionProjectionError, match="non-JSON"
    ):
        build(reports=invalid)

    result = build()
    result["baseline_identity"]["kind"] = "tax"
    with pytest.raises(projection.ReportDefinitionProjectionError):
        projection.validate_root_definition_projection(result)

    result = build()
    result["extra"] = True
    with pytest.raises(
        projection.ReportDefinitionProjectionError, match="fields"
    ):
        projection.validate_root_definition_projection(result)
