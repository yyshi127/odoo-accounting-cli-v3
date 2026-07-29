"""Unit tests for deterministic native-report domain normalization."""

import copy
import re
import unittest
from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path
from unittest import mock

from odoo_accounting_cli_v3.contracts import ContractError, validate_value
from odoo_accounting_cli_v3.domain.report_read import (
    CurrencyInfo,
    NativeReportColumn,
    NativeReportFilters,
    NativeReportLine,
    NativeReportPeriod,
    NativeReportSnapshot,
    ReportReadError,
    canonical_period_key,
    read_financial_report,
    read_tax_report,
)
from odoo_accounting_cli_v3.registry import load_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
MAIN_DATE_FROM = date(2026, 1, 1)
MAIN_DATE_TO = date(2026, 6, 30)
MAIN_PERIOD_KEY = canonical_period_key("range", MAIN_DATE_FROM, MAIN_DATE_TO)
COMPARISON_DATE_FROM = date(2025, 1, 1)
COMPARISON_DATE_TO = date(2025, 6, 30)
COMPARISON_PERIOD_KEY = canonical_period_key(
    "range",
    COMPARISON_DATE_FROM,
    COMPARISON_DATE_TO,
)


def financial_report_request(**overrides):
    values = {
        "kind": "balance_sheet",
        "comparison": None,
    }
    values.update(overrides)
    return values


def financial_parameters(**overrides):
    values = {
        "company_id": 9,
        "report_request": financial_report_request(),
        "date_from": "2026-01-01",
        "date_to": "2026-06-30",
        "move_state": "posted",
        "journal_scope": "all_report_eligible",
        "tax_unit_id": None,
        "unreconciled_only": False,
        "hide_zero_lines": False,
        "line_expansion_request": "none",
        "currency_id": None,
        "limit": 100,
        "offset": 0,
    }
    values.update(overrides)
    return values


def tax_parameters(**overrides):
    values = financial_parameters()
    values.pop("report_request")
    values.update(overrides)
    return values


def effective_filters(**overrides):
    values = {
        "move_state": "posted",
        "journal_scope": "all_report_eligible",
        "journal_ids": (11, 12),
        "tax_unit_id": None,
        "unreconciled_only": False,
        "hide_zero_lines": False,
        "line_expansion_request": "none",
        "custom_aml_filter_count": 0,
        "analytic_groupby": False,
        "consolidation": False,
        "multi_currency_display": False,
    }
    values.update(overrides)
    return NativeReportFilters(**values)


def native_column(
    value=Decimal("10"),
    figure_type="monetary",
    *,
    label="Current",
    expression_label="balance",
    period_key=MAIN_PERIOD_KEY,
    period_label="Current period",
    period_mode="range",
    period_date_from=MAIN_DATE_FROM,
    period_date_to=MAIN_DATE_TO,
    currency_id=6,
    is_blank=False,
    auditable=True,
):
    return NativeReportColumn(
        label=label,
        expression_label=expression_label,
        value=value,
        figure_type=figure_type,
        period_key=period_key,
        period_label=period_label,
        period_mode=period_mode,
        period_date_from=period_date_from,
        period_date_to=period_date_to,
        currency_id=currency_id,
        is_blank=is_blank,
        auditable=auditable,
    )


def native_line(raw_id="root", **overrides):
    values = {
        "raw_id": raw_id,
        "code": None,
        "name": "Assets",
        "level": 0,
        "columns": (native_column(),),
        "unfoldable": False,
        "unfolded": False,
    }
    values.update(overrides)
    return NativeReportLine(**values)


def comparison_column(**overrides):
    values = {
        "label": "Same period last year",
        "period_key": COMPARISON_PERIOD_KEY,
        "period_label": "Same period last year",
        "period_date_from": COMPARISON_DATE_FROM,
        "period_date_to": COMPARISON_DATE_TO,
    }
    values.update(overrides)
    return native_column(**values)


def native_snapshot(**overrides):
    values = {
        "company_id": 9,
        "requested_report_id": 20,
        "requested_report_name": "Balance Sheet",
        "resolved_report_id": 21,
        "resolved_report_name": "Balance Sheet (Country)",
        "report_family": "financial",
        "report_kind": "balance_sheet",
        "currency_id": 6,
        "period_key": MAIN_PERIOD_KEY,
        "date_mode": "range",
        "date_from": MAIN_DATE_FROM,
        "date_to": MAIN_DATE_TO,
        "comparison_mode": None,
        "comparison_periods": None,
        "resolved_comparison_periods": (),
        "effective_filters": effective_filters(),
        "warnings": ("odoo:report_variant_resolved",),
        "lines": (native_line(),),
    }
    values.update(overrides)
    return NativeReportSnapshot(**values)


def registry_output_schema(capability_id):
    capability = next(
        item for item in load_registry(REGISTRY_PATH) if item.id == capability_id
    )
    return capability.data["output_schema"]


def read_receipt_v2(capability_id, record_count):
    return {
        "id": f"receipt-{capability_id}",
        "odoo_instance_id": "odoo19@test",
        "database_name": "odoo_test",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "company_id": 9,
        "user_id": 42,
        "capability_id": capability_id,
        "environment": "test",
        "capability_channel": "staged",
        "request_digest": "a" * 64,
        "result_digest": "b" * 64,
        "registry_digest": "c" * 64,
        "release_digest": "d" * 64,
        "record_count": record_count,
        "observed_at": "2026-07-28T00:00:00Z",
        "signature_version": 2,
        "signature_purpose": "read_receipt_v2",
        "signature_key_id": "test-read-receipt-key",
        "signature": "e" * 64,
    }


class FakeBackend:
    def __init__(self, snapshot=None):
        self.currency = CurrencyInfo(6, "CNY", "¥", Decimal("0.01"))
        self.snapshot = snapshot or native_snapshot()
        self.calls = []

    def assert_read_access(self, *, company_id):
        self.calls.append(("access", company_id))

    def company_currency(self, *, company_id):
        self.calls.append(("currency", company_id))
        return self.currency

    def fetch_native_report(self, **kwargs):
        self.calls.append(("fetch", kwargs))
        return self.snapshot


class ReportReadTests(unittest.TestCase):
    def test_invalid_identity_dates_comparison_and_pagination_fail_closed(self):
        invalid_cases = (
            ({"company_id": True}, "company_id"),
            (
                {
                    "report_request": financial_report_request(
                        report_id=20,
                    )
                },
                "financial report contract",
            ),
            (
                {
                    "report_request": financial_report_request(
                        kind="aged_receivable",
                    )
                },
                "report kind",
            ),
            ({"date_from": "2026-02-30"}, "date_from"),
            ({"date_from": "2026-07-01"}, "date_from"),
            (
                {
                    "report_request": financial_report_request(
                        comparison={"mode": "quarter", "periods": 1},
                    )
                },
                "mode",
            ),
            (
                {
                    "report_request": financial_report_request(
                        comparison={"mode": "previous_year", "periods": 13},
                    )
                },
                "only one comparison",
            ),
            ({"limit": 0}, "limit"),
            ({"offset": -1}, "offset"),
        )
        for overrides, message in invalid_cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ReportReadError, message):
                    read_financial_report(
                        FakeBackend(), financial_parameters(**overrides)
                    )

    def test_parameter_shape_and_fixed_accounting_filters_are_exact(self):
        missing = financial_parameters()
        del missing["move_state"]
        extra = financial_parameters(unexpected=True)
        bad_request_missing = financial_parameters(
            report_request={
                "kind": "balance_sheet",
            }
        )
        bad_request_extra = financial_parameters(
            report_request={
                **financial_report_request(),
                "name": "Balance Sheet",
            }
        )
        for parameters in (
            missing,
            extra,
            bad_request_missing,
            bad_request_extra,
        ):
            with self.subTest(parameters=parameters):
                with self.assertRaisesRegex(ReportReadError, "contract"):
                    read_financial_report(FakeBackend(), parameters)

        invalid_filters = (
            {"move_state": "all"},
            {"journal_scope": "selected"},
            {"tax_unit_id": 1},
            {"unreconciled_only": True},
            {"hide_zero_lines": True},
            {"line_expansion_request": "unfolded"},
        )
        for overrides in invalid_filters:
            with self.subTest(overrides=overrides):
                backend = FakeBackend()
                with self.assertRaisesRegex(ReportReadError, "fixed filters"):
                    read_financial_report(
                        backend,
                        financial_parameters(**overrides),
                    )
                self.assertFalse(
                    any(call[0] == "fetch" for call in backend.calls)
                )

    def test_cash_flow_requires_null_comparison(self):
        request = financial_report_request(kind="cash_flow", comparison=None)
        result = read_financial_report(
            FakeBackend(
                native_snapshot(
                    report_kind="cash_flow",
                    comparison_mode=None,
                    comparison_periods=None,
                    resolved_comparison_periods=(),
                )
            ),
            financial_parameters(report_request=request),
        )
        self.assertEqual(result["report"]["kind"], "cash_flow")
        self.assertIsNone(result["period"]["comparison"])

        request["comparison"] = {"mode": "previous_period", "periods": 1}
        with self.assertRaisesRegex(ReportReadError, "not supported"):
            read_financial_report(
                FakeBackend(),
                financial_parameters(report_request=request),
            )

    def test_previous_year_maps_to_same_last_year_and_context_keeps_both(self):
        snapshot = native_snapshot(
            comparison_mode="same_last_year",
            comparison_periods=1,
            resolved_comparison_periods=(
                NativeReportPeriod(
                    key=COMPARISON_PERIOD_KEY,
                    label="Same period last year",
                    mode="range",
                    date_from=COMPARISON_DATE_FROM,
                    date_to=COMPARISON_DATE_TO,
                ),
            ),
            lines=(
                native_line(
                    columns=(native_column(), comparison_column()),
                ),
            ),
        )
        backend = FakeBackend(snapshot)
        parameters = financial_parameters(
            report_request=financial_report_request(
                comparison={"mode": "previous_year", "periods": 1},
            )
        )

        result = read_financial_report(backend, parameters)

        fetch = next(call[1] for call in backend.calls if call[0] == "fetch")
        self.assertEqual(fetch["comparison_mode"], "same_last_year")
        self.assertEqual(fetch["comparison_periods"], 1)
        self.assertEqual(
            result["period"]["comparison"],
            {
                "requested_mode": "previous_year",
                "resolved_mode": "same_last_year",
                "periods": 1,
                "resolved_periods": [
                    {
                        "key": COMPARISON_PERIOD_KEY,
                        "label": "Same period last year",
                        "mode": "range",
                        "date_from": "2025-01-01",
                        "date_to": "2025-06-30",
                    }
                ],
            },
        )
        self.assertEqual(fetch["move_state"], "posted")
        self.assertEqual(fetch["journal_scope"], "all_report_eligible")
        self.assertIsNone(fetch["tax_unit_id"])
        self.assertFalse(fetch["unreconciled_only"])
        self.assertFalse(fetch["hide_zero_lines"])
        self.assertEqual(fetch["line_expansion_request"], "none")
        self.assertEqual(fetch["report_kind"], "balance_sheet")
        self.assertEqual(result["report"]["kind"], "balance_sheet")
        self.assertEqual(result["period"]["resolved"]["key"], MAIN_PERIOD_KEY)

    def test_non_company_request_and_native_column_currency_are_rejected(self):
        backend = FakeBackend()
        with self.assertRaisesRegex(ReportReadError, "company currency"):
            read_financial_report(
                backend, financial_parameters(currency_id=1)
            )
        self.assertFalse(any(call[0] == "fetch" for call in backend.calls))

        foreign_column = native_column(currency_id=1)
        snapshot = native_snapshot(
            lines=(native_line(columns=(foreign_column,)),)
        )
        with self.assertRaisesRegex(ReportReadError, "column currency"):
            read_financial_report(FakeBackend(snapshot), financial_parameters())

    def test_ids_are_stable_safe_and_preserve_nullable_code_and_hierarchy(self):
        lines = (
            native_line("unsafe id/one", unfoldable=True, unfolded=True),
            native_line(
                7,
                code="1000",
                name="Cash",
                level=1,
                parent_raw_id="unsafe id/one",
            ),
        )
        backend = FakeBackend(native_snapshot(lines=lines))

        first = read_financial_report(backend, financial_parameters())
        second = read_financial_report(
            FakeBackend(native_snapshot(lines=lines)), financial_parameters()
        )

        root, child = first["lines"]
        self.assertRegex(root["line_id"], re.compile(r"^line-[0-9a-f]{64}$"))
        self.assertEqual(root["line_id"], second["lines"][0]["line_id"])
        self.assertNotEqual(root["line_id"], child["line_id"])
        self.assertIsNone(root["code"])
        self.assertEqual(
            child["parent"],
            {"line_id": root["line_id"], "relation_source": "explicit"},
        )
        self.assertEqual(
            root["parent"],
            {"line_id": None, "relation_source": "none"},
        )

    def test_missing_parent_is_not_inferred_from_display_indentation(self):
        lines = (
            native_line("heading"),
            native_line("indented", level=1, parent_raw_id=None),
        )
        result = read_financial_report(
            FakeBackend(native_snapshot(lines=lines)),
            financial_parameters(),
        )

        self.assertEqual(
            result["lines"][1]["parent"],
            {"line_id": None, "relation_source": "none"},
        )

    def test_all_native_figure_types_normalize_deterministically(self):
        columns = (
            native_column(Decimal("123.4500"), "monetary"),
            native_column(
                Decimal("-0.000"), "percentage", label="Percent", currency_id=None
            ),
            native_column(
                Decimal("7.0"), "integer", label="Count", currency_id=None
            ),
            native_column("1E+3", "float", label="Ratio", currency_id=None),
            native_column(
                date(2026, 6, 30), "date", label="Date", currency_id=None
            ),
            native_column(
                "2026-06-30T12:30:00Z",
                "datetime",
                label="Timestamp",
                currency_id=None,
            ),
            native_column(True, "boolean", label="Flag", currency_id=None),
            native_column("", "string", label="Memo", currency_id=None),
        )
        result = read_financial_report(
            FakeBackend(native_snapshot(lines=(native_line(columns=columns),))),
            financial_parameters(),
        )

        self.assertEqual(
            [
                column["cell"]["value"]
                for column in result["lines"][0]["columns"]
            ],
            [
                "123.45",
                "0",
                "7",
                "1000",
                "2026-06-30",
                "2026-06-30T12:30:00+00:00",
                "true",
                "",
            ],
        )
        self.assertEqual(
            result["lines"][0]["columns"][0]["expression_label"], "balance"
        )
        self.assertEqual(
            result["lines"][0]["columns"][0]["period"],
            {
                "key": MAIN_PERIOD_KEY,
                "label": "Current period",
                "mode": "range",
                "date_from": "2026-01-01",
                "date_to": "2026-06-30",
            },
        )

    def test_non_finite_and_unknown_figure_types_fail_closed(self):
        for column, message in (
            (native_column(Decimal("NaN")), "finite"),
            (native_column(1, "duration"), "unsupported figure_type"),
        ):
            with self.subTest(column=column):
                snapshot = native_snapshot(
                    lines=(native_line(columns=(column,)),)
                )
                with self.assertRaisesRegex(ReportReadError, message):
                    read_financial_report(
                        FakeBackend(snapshot), financial_parameters()
                    )

    def test_period_warning_and_resolved_comparison_context_fail_closed(self):
        other_from = date(2024, 1, 1)
        other_to = date(2024, 6, 30)
        undeclared_period = canonical_period_key(
            "range",
            other_from,
            other_to,
        )
        cases = (
            (
                native_snapshot(
                    lines=(
                        native_line(
                            columns=(
                                native_column(period_key="unsafe-period"),
                            )
                        ),
                    )
                ),
                "safe period key",
            ),
            (
                native_snapshot(period_key=f"period-{'0' * 64}"),
                "not canonical",
            ),
            (
                native_snapshot(
                    lines=(
                        native_line(
                            columns=(
                                native_column(
                                    period_key=undeclared_period,
                                    period_date_from=other_from,
                                    period_date_to=other_to,
                                ),
                            )
                        ),
                    )
                ),
                "undeclared period",
            ),
            (
                native_snapshot(report_kind="profit_and_loss"),
                "kind",
            ),
            (
                native_snapshot(warnings=("odoo:unknown_warning",)),
                "allowlisted",
            ),
            (
                native_snapshot(date_from=None),
                "date_from",
            ),
        )
        for snapshot, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ReportReadError, message):
                    read_financial_report(
                        FakeBackend(snapshot),
                        financial_parameters(),
                    )

        with self.assertRaisesRegex(
            ReportReadError,
            "resolved comparison periods",
        ):
            read_financial_report(
                FakeBackend(
                    native_snapshot(
                        comparison_mode="same_last_year",
                        comparison_periods=1,
                    )
                ),
                financial_parameters(
                    report_request=financial_report_request(
                        comparison={
                            "mode": "previous_year",
                            "periods": 1,
                        }
                    )
                ),
            )

    def test_effective_journal_candidates_are_sorted_unique_and_nonempty(self):
        result = read_financial_report(FakeBackend(), financial_parameters())
        self.assertEqual(result["effective_filters"]["journal_ids"], [11, 12])
        for journal_ids in ((), (12, 11), (11, 11)):
            with self.subTest(journal_ids=journal_ids):
                snapshot = native_snapshot(
                    effective_filters=effective_filters(
                        journal_ids=journal_ids,
                    )
                )
                with self.assertRaisesRegex(
                    ReportReadError,
                    "journal scope",
                ):
                    read_financial_report(
                        FakeBackend(snapshot),
                        financial_parameters(),
                    )

    def test_report_cell_budget_is_checked_before_page_normalization(self):
        lines = (
            native_line("one"),
            native_line("two"),
        )
        with mock.patch(
            "odoo_accounting_cli_v3.domain.report_read.MAX_REPORT_CELLS",
            1,
        ):
            with self.assertRaisesRegex(ReportReadError, "cell count"):
                read_financial_report(
                    FakeBackend(native_snapshot(lines=lines)),
                    financial_parameters(limit=1),
                )

    def test_only_requested_page_values_are_materialized(self):
        unsafe_outside_page = native_column(
            value=object(),
            figure_type="string",
            currency_id=None,
        )
        result = read_financial_report(
            FakeBackend(
                native_snapshot(
                    lines=(
                        native_line("visible"),
                        native_line(
                            "outside-page",
                            columns=(unsafe_outside_page,),
                        ),
                    )
                )
            ),
            financial_parameters(limit=1),
        )

        self.assertEqual(result["page"]["total_count"], 2)
        self.assertEqual(len(result["lines"]), 1)

    def test_pagination_preserves_requested_resolved_context_and_warnings(self):
        normalized_date_from = date(2025, 12, 29)
        normalized_date_to = date(2026, 6, 28)
        normalized_period_key = canonical_period_key(
            "range",
            normalized_date_from,
            normalized_date_to,
        )
        lines = tuple(
            native_line(
                f"line/{index}",
                name=f"Line {index}",
                columns=(
                    native_column(
                        index,
                        "integer",
                        label="Count",
                        currency_id=None,
                        period_key=normalized_period_key,
                        period_date_from=normalized_date_from,
                        period_date_to=normalized_date_to,
                    ),
                ),
            )
            for index in range(3)
        )
        snapshot = native_snapshot(
            period_key=normalized_period_key,
            date_from=normalized_date_from,
            date_to=normalized_date_to,
            warnings=(
                "odoo:date_range_normalized",
                "odoo:report_variant_resolved",
            ),
            lines=lines,
        )

        result = read_financial_report(
            FakeBackend(snapshot),
            financial_parameters(limit=1, offset=1),
        )

        self.assertEqual(
            result["page"],
            {"limit": 1, "offset": 1, "count": 1, "total_count": 3},
        )
        self.assertEqual(result["lines"][0]["name"], "Line 1")
        self.assertEqual(result["report"]["requested"]["id"], 20)
        self.assertEqual(result["report"]["resolved"]["id"], 21)
        self.assertEqual(result["report"]["kind"], "balance_sheet")
        self.assertEqual(
            result["period"]["requested"],
            {
                "mode": "range",
                "date_from": "2026-01-01",
                "date_to": "2026-06-30",
            },
        )
        self.assertEqual(
            result["period"]["resolved"],
            {
                "key": normalized_period_key,
                "mode": "range",
                "date_from": "2025-12-29",
                "date_to": "2026-06-28",
            },
        )
        self.assertEqual(
            result["warnings"],
            [
                "odoo:date_range_normalized",
                "odoo:report_variant_resolved",
            ],
        )

    def test_blank_cell_and_single_date_mode_are_not_coerced_to_zero(self):
        single_date_from = date(2026, 6, 1)
        single_date_to = date(2026, 6, 30)
        single_period_key = canonical_period_key(
            "single",
            single_date_from,
            single_date_to,
        )
        blank = native_column(
            value=None,
            is_blank=True,
            auditable=False,
            period_key=single_period_key,
            period_mode="single",
            period_date_from=single_date_from,
            period_date_to=single_date_to,
        )
        snapshot = native_snapshot(
            period_key=single_period_key,
            date_mode="single",
            date_from=single_date_from,
            date_to=single_date_to,
            lines=(native_line(columns=(blank,)),),
        )

        result = read_financial_report(
            FakeBackend(snapshot),
            financial_parameters(),
        )

        column = result["lines"][0]["columns"][0]
        self.assertIsNone(column["cell"]["value"])
        self.assertIs(column["cell"]["is_blank"], True)
        self.assertIs(column["auditable"], False)
        self.assertEqual(column["period"]["mode"], "single")
        self.assertEqual(
            result["period"]["resolved"],
            {
                "key": single_period_key,
                "mode": "single",
                "date_from": "2026-06-01",
                "date_to": "2026-06-30",
            },
        )

    def test_financial_result_with_blank_cell_matches_live_registry_contract(self):
        blank = native_column(
            value=None,
            is_blank=True,
            auditable=False,
        )
        snapshot = native_snapshot(
            warnings=(
                "odoo:date_range_normalized",
                "odoo:report_variant_resolved",
            ),
            lines=(native_line(columns=(blank,)),),
        )
        result = read_financial_report(
            FakeBackend(snapshot),
            financial_parameters(),
        )
        result["receipt"] = read_receipt_v2(
            "acct.report.financial_read.v1", result["page"]["total_count"]
        )

        self.assertIsNone(
            result["lines"][0]["columns"][0]["cell"]["value"]
        )
        self.assertEqual(
            set(result["period"]),
            {"requested", "resolved", "comparison"},
        )
        validate_value(
            result,
            registry_output_schema("acct.report.financial_read.v1"),
        )
        schema = registry_output_schema("acct.report.financial_read.v1")
        bad_cell = copy.deepcopy(result)
        bad_cell["lines"][0]["columns"][0]["cell"] = {
            "value": "0",
            "is_blank": True,
        }
        with self.assertRaises(ContractError):
            validate_value(bad_cell, schema)
        bad_measure = copy.deepcopy(result)
        bad_measure["lines"][0]["columns"][0]["measure"] = {
            "figure_type": "monetary",
            "currency_id": None,
        }
        with self.assertRaises(ContractError):
            validate_value(bad_measure, schema)
        bad_receipt = copy.deepcopy(result)
        bad_receipt["receipt"]["capability_id"] = "acct.tax.report_read.v1"
        with self.assertRaises(ContractError):
            validate_value(bad_receipt, schema)

    def test_tax_result_matches_contract_and_rejects_unapproved_context(self):
        blank = native_column(
            value=None,
            is_blank=True,
            auditable=False,
        )
        snapshot = native_snapshot(
            requested_report_name="Tax Report",
            resolved_report_name="Tax Report",
            report_family="tax",
            report_kind="generic_tax",
            comparison_mode=None,
            comparison_periods=None,
            resolved_comparison_periods=(),
            warnings=("odoo:tax_source_move_line_count_unavailable",),
            lines=(native_line(columns=(blank,)),),
        )
        result = read_tax_report(
            FakeBackend(snapshot),
            tax_parameters(),
        )
        result["receipt"] = read_receipt_v2(
            "acct.tax.report_read.v1", result["page"]["total_count"]
        )
        schema = registry_output_schema("acct.tax.report_read.v1")

        self.assertIsNone(result["period"]["comparison"])
        self.assertEqual(
            result["lines"][0]["source_move_line_count"],
            {"available": False, "count": None},
        )
        validate_value(result, schema)

        bad_warning = copy.deepcopy(result)
        bad_warning["warnings"] = ["odoo:unapproved_warning"]
        with self.assertRaises(ContractError):
            validate_value(bad_warning, schema)

        bad_comparison = copy.deepcopy(result)
        bad_comparison["period"]["comparison"] = {
            "requested_mode": "previous_year",
            "resolved_mode": "same_last_year",
            "periods": 1,
            "resolved_periods": [],
        }
        with self.assertRaises(ContractError):
            validate_value(bad_comparison, schema)
        bad_count = copy.deepcopy(result)
        bad_count["lines"][0]["source_move_line_count"] = {
            "available": False,
            "count": 1,
        }
        with self.assertRaises(ContractError):
            validate_value(bad_count, schema)

    def test_tax_source_counts_are_null_until_explicitly_proven(self):
        lines = (
            native_line("unavailable"),
            native_line(
                "proven-zero",
                source_move_line_count=0,
                source_move_line_count_proven=True,
            ),
        )
        snapshot = native_snapshot(
            requested_report_name="Tax Report",
            resolved_report_name="Tax Report",
            report_family="tax",
            report_kind="generic_tax",
            comparison_mode=None,
            comparison_periods=None,
            resolved_comparison_periods=(),
            lines=lines,
        )
        parameters = tax_parameters(limit=10)

        result = read_tax_report(FakeBackend(snapshot), parameters)

        self.assertEqual(
            result["lines"][0]["source_move_line_count"],
            {"available": False, "count": None},
        )
        self.assertEqual(
            result["lines"][1]["source_move_line_count"],
            {"available": True, "count": 0},
        )

        unproven = replace(
            lines[0],
            source_move_line_count=4,
            source_move_line_count_proven=False,
        )
        with self.assertRaisesRegex(ReportReadError, "unproven"):
            read_tax_report(
                FakeBackend(replace(snapshot, lines=(unproven,))),
                parameters,
            )

    def test_entry_point_rejects_the_wrong_native_report_family(self):
        with self.assertRaisesRegex(ReportReadError, "family"):
            read_tax_report(
                FakeBackend(native_snapshot()),
                tax_parameters(),
            )


if __name__ == "__main__":
    unittest.main()
