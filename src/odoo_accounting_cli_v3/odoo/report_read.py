"""Odoo 19 adapter for trusted native tax and financial report reads."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any, Mapping

from ..domain.report_read import (
    MAX_LINE_COLUMNS,
    MAX_REPORT_CELLS,
    MAX_REPORT_LINES,
    CurrencyInfo,
    NativeReportColumn,
    NativeReportFilters,
    NativeReportLine,
    NativeReportPeriod,
    NativeReportSnapshot,
    ReportReadError,
    canonical_period_key,
)


@dataclass(frozen=True)
class _Period:
    raw_key: str
    safe_key: str
    label: str
    mode: str
    date_from: date
    date_to: date


@dataclass(frozen=True)
class _ColumnSpec:
    label: str
    expression_label: str | None
    figure_type: str
    raw_group_key: str
    period: _Period
    currency_id: int | None


_FIGURE_TYPES = frozenset(
    {
        "monetary",
        "percentage",
        "integer",
        "float",
        "date",
        "datetime",
        "boolean",
        "string",
    }
)
_REPORT_KIND_XMLIDS = {
    ("financial", "balance_sheet"): "account_reports.balance_sheet",
    ("financial", "cash_flow"): "account_reports.cash_flow_report",
    ("financial", "profit_and_loss"): "account_reports.profit_and_loss",
    ("tax", "generic_tax"): "account.generic_tax_report",
}
_ALLOWED_EXPAND_FUNCTIONS = frozenset(
    {None, "_report_expand_unfoldable_line_with_groupby"}
)
_ALLOWED_EXPRESSION_ENGINES = frozenset({"aggregation", "domain"})
_WARNING_CODES = {
    "account_reports.common_warning_draft_in_period": "odoo:draft_entries_excluded"
}
_REQUIRED_READ_MODELS = (
    "account.account",
    "account.journal",
    "account.move",
    "account.move.line",
    "account.report",
    "account.report.expression",
    "account.report.line",
    "account.tax",
    "account.tax.group",
    "account.tax.repartition.line",
    "res.currency",
)
_MAX_OPTIONS_BYTES = 1_048_576
_MAX_TEXT_LENGTH = 4_096


def _record_id(value: Any) -> int | None:
    if value is False or value is None:
        return None
    raw = getattr(value, "id", value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return None
    return raw


def _optional_record_id(value: Any, field: str) -> int | None:
    if value is False or value is None:
        return None
    raw = getattr(value, "id", value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        raise ReportReadError(f"{field} is invalid")
    return raw


def _read_acl(record: Any) -> None:
    record.check_access_rights("read")
    record.check_access_rule("read")


def _date(value: Any, field: str, *, nullable: bool = False) -> date | None:
    if nullable and (value is False or value is None):
        return None
    if type(value) is date:
        return value
    if not isinstance(value, str):
        raise ReportReadError(f"{field} is not an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ReportReadError(f"{field} is not an ISO date") from exc
    if parsed.isoformat() != value:
        raise ReportReadError(f"{field} is not an ISO date")
    return parsed


def _text(
    value: Any,
    field: str,
    *,
    nullable: bool = False,
    max_length: int = _MAX_TEXT_LENGTH,
) -> str | None:
    if nullable and (value is False or value is None):
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > max_length
    ):
        raise ReportReadError(f"{field} must be a non-empty string")
    return value


def _canonical_options(options: Any) -> bytes:
    try:
        payload = json.dumps(
            options,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise ReportReadError(
            "native report options are not canonical JSON"
        ) from exc
    if len(payload) > _MAX_OPTIONS_BYTES:
        raise ReportReadError("native report options exceed the safety limit")
    return payload


def _period(value: Any, raw_key: str, field: str) -> _Period:
    if not isinstance(value, Mapping):
        raise ReportReadError(f"{field} is invalid")
    mode = value.get("mode")
    if mode not in {"range", "single"}:
        raise ReportReadError(f"{field}.mode is unsupported")
    date_from = _date(value.get("date_from"), f"{field}.date_from")
    date_to = _date(value.get("date_to"), f"{field}.date_to")
    if date_from is None or date_to is None:
        raise ReportReadError(f"{field} dates are required")
    if date_from > date_to:
        raise ReportReadError(f"{field} dates are reversed")
    label = _text(
        value.get("string"),
        f"{field}.string",
        max_length=128,
    )
    return _Period(
        raw_key=raw_key,
        safe_key=canonical_period_key(mode, date_from, date_to),
        label=label,
        mode=mode,
        date_from=date_from,
        date_to=date_to,
    )


def _root_id(report: Any) -> int | None:
    root = getattr(report, "root_report_id", None)
    return _record_id(root) or _record_id(report)


class OdooReportReadBackend:
    """Bind Odoo's native report API to one signed user and company."""

    def __init__(
        self,
        env: Any,
        *,
        user_id: int,
        allowed_company_ids: frozenset[int],
        allowed_root_xmlids_by_family: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._env = env
        self._user_id = user_id
        self._allowed_company_ids = allowed_company_ids
        source = allowed_root_xmlids_by_family or {}
        self._allowed_root_xmlids_by_family = {
            family: frozenset(xmlids)
            for family, xmlids in source.items()
        }

    def _bound(self, model_name: str, company: Any) -> Any:
        return self._env[model_name].with_context(
            allowed_company_ids=[company.id],
            company_id=company.id,
        ).with_company(company)

    def _company(self, company_id: int) -> Any:
        if (
            getattr(self._env, "su", False)
            or getattr(self._env, "uid", None) != self._user_id
        ):
            raise ReportReadError(
                "Odoo environment is not bound to the authenticated non-superuser"
            )
        if company_id not in self._allowed_company_ids:
            raise ReportReadError(
                "company is outside the authenticated allowed companies"
            )
        company = self._env["res.company"].with_context(
            allowed_company_ids=[company_id],
            company_id=company_id,
        ).browse(company_id).exists()
        if not company or len(company) != 1:
            raise ReportReadError("company does not exist or is not visible")
        _read_acl(company)
        return company

    def _assert_clean_transaction_state(self, stage: str) -> None:
        transaction = getattr(self._env, "transaction", None)
        if transaction is None:
            raise ReportReadError("Odoo transaction state is unavailable")
        transaction_state = (
            ("field_dirty", getattr(transaction, "field_dirty", None)),
            ("tocompute", getattr(transaction, "tocompute", None)),
            (
                "field_data_patches",
                getattr(transaction, "field_data_patches", None),
            ),
        )
        for _field, value in transaction_state:
            if value is None:
                raise ReportReadError("Odoo transaction state is unavailable")
            if value:
                raise ReportReadError(
                    f"Odoo transaction became dirty {stage}"
                )

    def assert_read_access(self, *, company_id: int) -> None:
        company = self._company(company_id)
        for model_name in _REQUIRED_READ_MODELS:
            self._bound(model_name, company).check_access_rights("read")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        company = self._company(company_id)
        currency = company.currency_id
        _read_acl(currency)
        return CurrencyInfo(
            id=currency.id,
            name=str(currency.name),
            symbol=str(currency.symbol or currency.name),
            rounding=Decimal(str(currency.rounding)),
        )

    @staticmethod
    def _trusted_root_id(*, xmlid: str, report_model: Any, env: Any) -> int:
        referenced = env.ref(xmlid, raise_if_not_found=False)
        if getattr(referenced, "_name", None) != "account.report":
            raise ReportReadError("trusted native report root is invalid")
        referenced_id = _record_id(referenced)
        if referenced_id is None:
            raise ReportReadError("trusted native report root is unavailable")
        report = report_model.browse(referenced_id).exists()
        if (
            not report
            or len(report) != 1
            or getattr(report, "_name", None) != "account.report"
            or _root_id(report) != referenced_id
        ):
            raise ReportReadError("trusted native report root is invalid")
        _read_acl(report)
        return referenced_id

    def _allowed_root_id(
        self,
        *,
        family: str,
        report_kind: str,
        company: Any,
    ) -> int:
        xmlids = self._allowed_root_xmlids_by_family.get(family, frozenset())
        if not xmlids:
            raise ReportReadError("native report family has no trusted root allowlist")
        expected_xmlid = _REPORT_KIND_XMLIDS.get((family, report_kind))
        if expected_xmlid is None or expected_xmlid not in xmlids:
            raise ReportReadError("native report kind has no trusted root")
        configured_roots = tuple(
            (configured_family, xmlid)
            for configured_family, configured_xmlids in sorted(
                self._allowed_root_xmlids_by_family.items()
            )
            for xmlid in sorted(configured_xmlids)
        )
        known_roots = frozenset(
            (candidate_family, xmlid)
            for (candidate_family, _candidate_kind), xmlid in (
                _REPORT_KIND_XMLIDS.items()
            )
        )
        if any(root not in known_roots for root in configured_roots):
            raise ReportReadError("native report root allowlist is invalid")
        report_model = self._bound("account.report", company)
        resolved_roots = tuple(
            (
                configured_family,
                xmlid,
                self._trusted_root_id(
                    xmlid=xmlid,
                    report_model=report_model,
                    env=self._env,
                ),
            )
            for configured_family, xmlid in configured_roots
        )
        root_ids = tuple(
            root_id
            for _configured_family, _xmlid, root_id in resolved_roots
        )
        if len(set(root_ids)) != len(root_ids):
            raise ReportReadError("trusted native report roots collide")
        for configured_family, xmlid, root_id in resolved_roots:
            if configured_family == family and xmlid == expected_xmlid:
                return root_id
        raise ReportReadError("native report kind has no trusted root")

    @staticmethod
    def _report_definition_line_ids(report: Any) -> frozenset[int]:
        line_ids = getattr(report, "line_ids", None)
        expressions = getattr(line_ids, "expression_ids", None)
        if expressions is None:
            raise ReportReadError("native report expressions are unavailable")
        if (
            len(line_ids) > MAX_REPORT_LINES
            or len(expressions) > MAX_REPORT_CELLS
        ):
            raise ReportReadError(
                "native report definition exceeds the safety limit"
            )
        _read_acl(line_ids)
        _read_acl(expressions)
        engines = set(expressions.mapped("engine"))
        if any(
            not isinstance(engine, str)
            or engine not in _ALLOWED_EXPRESSION_ENGINES
            for engine in engines
        ):
            raise ReportReadError(
                "native report expression engine is not allowlisted"
            )
        raw_line_ids = tuple(line_ids.ids)
        if (
            any(
                isinstance(line_id, bool)
                or not isinstance(line_id, int)
                or line_id <= 0
                for line_id in raw_line_ids
            )
            or len(set(raw_line_ids)) != len(raw_line_ids)
        ):
            raise ReportReadError("native report definition line IDs are invalid")
        return frozenset(raw_line_ids)

    def _report(
        self,
        *,
        company: Any,
        report_id: int,
        allowed_root_id: int,
    ) -> Any:
        report = self._bound("account.report", company).browse(report_id).exists()
        if not report or len(report) != 1:
            raise ReportReadError("native report does not exist or is not visible")
        _read_acl(report)
        if _root_id(report) != allowed_root_id:
            raise ReportReadError("native report is outside the trusted family")
        if (
            bool(getattr(report, "use_sections", False))
            or bool(getattr(report, "section_report_ids", False))
        ):
            raise ReportReadError("composite section reports are not supported")
        return report

    @staticmethod
    def _previous_options(
        *,
        company_id: int,
        date_from: date,
        date_to: date,
        comparison_mode: str | None,
        comparison_periods: int | None,
        move_state: str,
        unreconciled_only: bool,
        hide_zero_lines: bool,
    ) -> dict[str, Any]:
        if comparison_mode is None:
            if comparison_periods is not None:
                raise ReportReadError("comparison period count is inconsistent")
            comparison = {"filter": "no_comparison", "number_period": 1}
        else:
            if (
                comparison_mode not in {"previous_period", "same_last_year"}
                or isinstance(comparison_periods, bool)
                or not isinstance(comparison_periods, int)
                or not 1 <= comparison_periods <= 12
            ):
                raise ReportReadError("comparison context is unsupported")
            comparison = {
                "filter": comparison_mode,
                "number_period": comparison_periods,
            }
        return {
            "forced_companies": [company_id],
            "date": {
                "filter": "custom",
                "mode": "range",
                "date_from": date_from.isoformat(),
                "date_to": date_to.isoformat(),
            },
            "comparison": comparison,
            "export_mode": "file",
            "unfold_all": False,
            "unfolded_lines": [],
            "all_entries": move_state != "posted",
            "unreconciled": unreconciled_only,
            "hide_0_lines": hide_zero_lines,
            "hierarchy": False,
            "readonly_query": True,
        }

    @staticmethod
    def _comparison_periods(
        options: Mapping[str, Any],
        *,
        requested_mode: str | None,
        requested_count: int | None,
    ) -> tuple[_Period, ...]:
        comparison = options.get("comparison")
        if comparison is None and requested_mode is None:
            return ()
        if not isinstance(comparison, Mapping):
            raise ReportReadError("native report comparison options are invalid")
        observed_filter = comparison.get("filter")
        observed_count = comparison.get("number_period")
        raw_periods = comparison.get("periods")
        if not isinstance(raw_periods, list):
            raise ReportReadError("native report comparison periods are invalid")
        if requested_mode is None:
            if (
                observed_filter != "no_comparison"
                or observed_count != 1
                or raw_periods
            ):
                raise ReportReadError("native report added an unrequested comparison")
            return ()
        if (
            observed_filter != requested_mode
            or requested_count is None
            or observed_count != requested_count
            or len(raw_periods) != requested_count
        ):
            raise ReportReadError("native report comparison context changed")
        if any(
            not isinstance(item, Mapping)
            or "filter" in item
            for item in raw_periods
        ):
            raise ReportReadError("native report comparison period is invalid")
        return tuple(
            _period(
                item,
                f"comparison:{index}:{item.get('currency_table_period_key', '')}",
                f"comparison.periods[{index}]",
            )
            for index, item in enumerate(raw_periods)
        )

    @staticmethod
    def _column_specs(
        options: Mapping[str, Any],
        *,
        main_period: _Period,
        comparison_periods: tuple[_Period, ...],
        company_currency_id: int,
    ) -> tuple[_ColumnSpec, ...]:
        raw_groups = options.get("column_groups")
        if (
            not isinstance(raw_groups, Mapping)
            or not raw_groups
            or len(raw_groups) > MAX_LINE_COLUMNS
        ):
            raise ReportReadError("native report column groups are invalid")
        group_pairs: list[tuple[str, _Period]] = []
        for raw_key, raw_group in raw_groups.items():
            if (
                not isinstance(raw_key, str)
                or not raw_key
                or len(raw_key) > 4_096
            ):
                raise ReportReadError("native report column group key is invalid")
            if (
                not isinstance(raw_group, Mapping)
                or set(raw_group) != {"forced_options", "forced_domain"}
                or raw_group.get("forced_domain") != []
            ):
                raise ReportReadError("native report column group is invalid")
            forced_options = raw_group.get("forced_options")
            if (
                not isinstance(forced_options, Mapping)
                or set(forced_options) != {"date"}
            ):
                raise ReportReadError("native report column group options are invalid")
            group_pairs.append(
                (
                    raw_key,
                    _period(
                        forced_options.get("date"),
                        raw_key,
                        f"column_groups[{raw_key!r}].date",
                    ),
                )
            )
        periods_by_group = dict(group_pairs)
        if len(periods_by_group) != len(group_pairs):
            raise ReportReadError("native report column groups are duplicated")

        def signature(period: _Period) -> tuple[str, date | None, date]:
            return period.mode, period.date_from, period.date_to

        expected = {signature(main_period)} | {
            signature(period) for period in comparison_periods
        }
        observed = {signature(period) for period in periods_by_group.values()}
        if observed != expected or len(periods_by_group) != len(expected):
            raise ReportReadError("native report column periods changed")

        raw_columns = options.get("columns")
        if (
            not isinstance(raw_columns, list)
            or not raw_columns
            or len(raw_columns) > 48
        ):
            raise ReportReadError("native report columns are invalid")
        specs: list[_ColumnSpec] = []
        referenced_group_keys: set[str] = set()
        for index, raw_column in enumerate(raw_columns):
            if not isinstance(raw_column, Mapping):
                raise ReportReadError(f"native report column {index} is invalid")
            group_key = raw_column.get("column_group_key")
            if group_key not in periods_by_group:
                raise ReportReadError(
                    "native report column references an unknown period"
                )
            referenced_group_keys.add(group_key)
            figure_type = raw_column.get("figure_type", "string")
            if figure_type not in _FIGURE_TYPES:
                raise ReportReadError("native report column figure type is unsupported")
            referenced_currency_id = _optional_record_id(
                raw_column.get("currency_id"),
                f"options.columns[{index}].currency_id",
            )
            if (
                referenced_currency_id is not None
                and referenced_currency_id != company_currency_id
            ):
                raise ReportReadError("native report column currency changed")
            if figure_type != "monetary" and referenced_currency_id is not None:
                raise ReportReadError(
                    "native non-monetary report column declared a currency"
                )
            specs.append(
                _ColumnSpec(
                    label=_text(
                        raw_column.get("name"),
                        f"options.columns[{index}].name",
                        max_length=128,
                    ),
                    expression_label=_text(
                        raw_column.get("expression_label"),
                        f"options.columns[{index}].expression_label",
                        max_length=128,
                    ),
                    figure_type=figure_type,
                    raw_group_key=group_key,
                    period=periods_by_group[group_key],
                    currency_id=(
                        company_currency_id
                        if figure_type == "monetary"
                        else None
                    ),
                )
            )
        if referenced_group_keys != set(periods_by_group):
            raise ReportReadError("native report column groups are not fully referenced")
        return tuple(specs)

    def _effective_filters(
        self,
        options: Mapping[str, Any],
        *,
        company: Any,
        report_kind: str,
    ) -> NativeReportFilters:
        aml_filters = options.get("aml_ir_filters")
        if (
            options.get("all_entries") is not False
            or options.get("unreconciled") is not False
            or options.get("hide_0_lines") is not False
            or options.get("unfold_all") is not False
            or options.get("unfolded_lines") != []
            or options.get("hierarchy") is not False
            or options.get("consolidation") is not False
            or options.get("multi_currency") is not False
            or options.get("selected_horizontal_group_id") not in (None, False)
            or options.get("available_horizontal_groups") != []
            or options.get("show_horizontal_group_total") not in (None, False)
            or options.get("horizontal_split") not in (None, False)
            or options.get("integer_rounding_enabled") not in (None, False)
            or options.get("rounding_unit") != "decimals"
            or not isinstance(options.get("rounding_unit_names"), Mapping)
            or aml_filters != []
        ):
            raise ReportReadError("native report effective filters changed")
        selected_journal_groups = options.get("selected_journal_groups", {})
        if (
            not isinstance(selected_journal_groups, Mapping)
            or selected_journal_groups
        ):
            raise ReportReadError("native report journal groups changed")
        journals = options.get("journals")
        if journals is None:
            if report_kind != "generic_tax":
                raise ReportReadError(
                    "native report journal options are unavailable"
                )
            records = self._bound("account.journal", company).with_context(
                active_test=False
            ).search(
                [("company_id", "=", company.id)],
                order="id",
                limit=10_001,
            )
            if len(records) > 10_000:
                raise ReportReadError(
                    "native report journal scope exceeds the safety limit"
                )
            _read_acl(records)
            ordered_journal_ids = tuple(sorted(records.ids))
        else:
            if not isinstance(journals, list) or len(journals) > 10_000:
                raise ReportReadError("native report journal options are invalid")
            eligible_journal_ids: set[int] = set()
            for index, journal in enumerate(journals):
                if not isinstance(journal, Mapping):
                    raise ReportReadError(
                        f"native report journal option {index} is invalid"
                    )
                model_name = journal.get("model")
                raw_id = journal.get("id")
                if raw_id == "divider":
                    if (
                        model_name not in {"account.journal.group", "res.company"}
                        or journal.get("selected") not in (None, False)
                    ):
                        raise ReportReadError(
                            "native report journal divider is invalid"
                        )
                    continue
                if model_name == "account.journal.group":
                    if (
                        _optional_record_id(
                            raw_id,
                            f"journals[{index}].id",
                        )
                        is None
                        or journal.get("selected") is not False
                    ):
                        raise ReportReadError(
                            "native report journal group changed"
                        )
                    continue
                if model_name != "account.journal":
                    raise ReportReadError(
                        "native report journal model is invalid"
                    )
                journal_id = _optional_record_id(
                    raw_id,
                    f"journals[{index}].id",
                )
                if (
                    journal_id is None
                    or journal_id in eligible_journal_ids
                    or journal.get("selected") is not False
                ):
                    raise ReportReadError(
                        "native report journal option is invalid"
                    )
                eligible_journal_ids.add(journal_id)
            ordered_journal_ids = tuple(sorted(eligible_journal_ids))
            records = self._bound("account.journal", company).browse(
                list(ordered_journal_ids)
            ).exists()
            if (
                len(records) != len(ordered_journal_ids)
                or tuple(sorted(records.ids)) != ordered_journal_ids
            ):
                raise ReportReadError(
                    "native report journal ACL scope is invalid"
                )
            _read_acl(records)
        if not ordered_journal_ids:
            raise ReportReadError(
                "native report journal scope has no eligible candidates"
            )
        if any(
            _record_id(record.company_id) != company.id
            for record in records
        ):
            raise ReportReadError(
                "native report journal company scope changed"
            )
        if options.get("tax_unit") not in (None, False):
            raise ReportReadError("native report tax-unit scope changed")
        analytic_values = (
            options.get("analytic_accounts", []),
            options.get("analytic_accounts_groupby", []),
            options.get("analytic_plans_groupby", []),
            options.get("selected_analytic_account_groupby_names", []),
            options.get("selected_analytic_plan_groupby_names", []),
        )
        if any(value != [] for value in analytic_values) or options.get(
            "include_analytic_without_aml", False
        ) is not False:
            raise ReportReadError("native report analytic grouping changed")
        budgets = options.get("budgets", [])
        if budgets != []:
            raise ReportReadError("native report budget scope changed")
        return NativeReportFilters(
            move_state="posted",
            journal_scope="all_report_eligible",
            journal_ids=ordered_journal_ids,
            tax_unit_id=None,
            unreconciled_only=False,
            hide_zero_lines=False,
            line_expansion_request="none",
            custom_aml_filter_count=0,
            analytic_groupby=False,
            consolidation=False,
            multi_currency_display=False,
        )

    @staticmethod
    def _native_columns(
        raw_columns: Any,
        *,
        specs: tuple[_ColumnSpec, ...],
        company_currency_id: int,
        definition_line_ids: frozenset[int],
    ) -> tuple[NativeReportColumn, ...]:
        if not isinstance(raw_columns, list) or len(raw_columns) != len(specs):
            raise ReportReadError("native report line column count changed")
        columns: list[NativeReportColumn] = []
        observed_report_line_ids: set[int | None] = set()
        for column_index, (raw_column, spec) in enumerate(
            zip(raw_columns, specs, strict=True)
        ):
            if not isinstance(raw_column, Mapping):
                raise ReportReadError("native report line column is invalid")
            if raw_column.get("column_group_key") != spec.raw_group_key:
                raise ReportReadError(
                    "native report line column period identity changed"
                )
            if raw_column.get("expression_label") != spec.expression_label:
                raise ReportReadError(
                    "native report line column expression identity changed"
                )
            observed_figure_type = raw_column.get("figure_type")
            if observed_figure_type != spec.figure_type:
                raise ReportReadError("native report line figure type changed")
            if "report_line_id" not in raw_column:
                raise ReportReadError(
                    "native report line definition identity is unavailable"
                )
            report_line_id = raw_column.get("report_line_id")
            if definition_line_ids:
                if (
                    isinstance(report_line_id, bool)
                    or not isinstance(report_line_id, int)
                    or report_line_id not in definition_line_ids
                ):
                    raise ReportReadError(
                        "native report line definition identity changed"
                    )
            elif report_line_id is not None:
                raise ReportReadError(
                    "native dynamic report line identity changed"
                )
            observed_report_line_ids.add(report_line_id)
            if "no_format" not in raw_column:
                raise ReportReadError("native report line value is unavailable")
            raw_value = raw_column.get("no_format")
            is_blank = raw_value is None or raw_value == ""
            if (
                "currency" not in raw_column
                or raw_column.get("currency") is not False
                or "currency_id" in raw_column
            ):
                raise ReportReadError(
                    "native report line monocurrency shape changed"
                )
            auditable = raw_column.get("auditable")
            if not isinstance(auditable, bool):
                raise ReportReadError("native report auditable flag is invalid")
            columns.append(
                NativeReportColumn(
                    label=spec.label,
                    expression_label=spec.expression_label,
                    value=None if is_blank else raw_value,
                    figure_type=spec.figure_type,
                    period_key=spec.period.safe_key,
                    period_label=spec.period.label,
                    period_mode=spec.period.mode,
                    period_date_from=spec.period.date_from,
                    period_date_to=spec.period.date_to,
                    currency_id=spec.currency_id,
                    is_blank=is_blank,
                    auditable=auditable,
                )
            )
        if len(observed_report_line_ids) != 1:
            raise ReportReadError(
                "native report row spans multiple report definitions"
            )
        return tuple(columns)

    @classmethod
    def _native_lines(
        cls,
        raw_lines: Any,
        *,
        report: Any,
        specs: tuple[_ColumnSpec, ...],
        company_currency_id: int,
        definition_line_ids: frozenset[int],
    ) -> tuple[NativeReportLine, ...]:
        if not isinstance(raw_lines, list) or len(raw_lines) > MAX_REPORT_LINES:
            raise ReportReadError("native report lines are invalid")
        total_cells = 0
        for index, raw_line in enumerate(raw_lines):
            if not isinstance(raw_line, Mapping):
                raise ReportReadError(f"native report line {index} is invalid")
            raw_columns = raw_line.get("columns")
            if (
                not isinstance(raw_columns, list)
                or not raw_columns
                or len(raw_columns) > MAX_LINE_COLUMNS
            ):
                raise ReportReadError(
                    "native report line columns exceed the safety limit"
                )
            total_cells += len(raw_columns)
            if total_cells > MAX_REPORT_CELLS:
                raise ReportReadError(
                    "native report cells exceed the safety limit"
                )
        markup_method = getattr(report, "_get_markup", None)
        if not callable(markup_method):
            raise ReportReadError("native report line markup API is unavailable")
        lines: list[NativeReportLine] = []
        for index, raw_line in enumerate(raw_lines):
            expand_function = raw_line.get("expand_function")
            if expand_function not in _ALLOWED_EXPAND_FUNCTIONS:
                raise ReportReadError(
                    "native report line expansion function is not allowlisted"
                )
            if "offset" in raw_line or "progress" in raw_line:
                raise ReportReadError("native report returned a truncated load-more line")
            raw_id = raw_line.get("id")
            if (
                not isinstance(raw_id, str)
                or not raw_id
                or len(raw_id) > 4_096
            ):
                raise ReportReadError("native report line ID is invalid")
            try:
                markup = markup_method(raw_id)
            except Exception as exc:
                raise ReportReadError(
                    "native report line ID could not be parsed"
                ) from exc
            if markup == "load_more":
                raise ReportReadError(
                    "native report returned a truncated load-more line"
                )
            parent_id = raw_line.get("parent_id")
            if parent_id is False or parent_id is None:
                parent_id = None
            elif (
                not isinstance(parent_id, str)
                or not parent_id
                or len(parent_id) > 4_096
            ):
                raise ReportReadError("native report parent line ID is invalid")
            level = raw_line.get("level", 0)
            if (
                isinstance(level, bool)
                or not isinstance(level, int)
                or not 0 <= level <= 64
            ):
                raise ReportReadError("native report line level is invalid")
            unfoldable = raw_line.get("unfoldable", False)
            unfolded = raw_line.get("unfolded", False)
            if not isinstance(unfoldable, bool) or not isinstance(unfolded, bool):
                raise ReportReadError("native report unfold flags are invalid")
            code = _text(
                raw_line.get("code"),
                f"lines[{index}].code",
                nullable=True,
                max_length=128,
            )
            lines.append(
                NativeReportLine(
                    raw_id=raw_id,
                    parent_raw_id=parent_id,
                    code=code,
                    name=_text(
                        raw_line.get("name"),
                        f"lines[{index}].name",
                        max_length=256,
                    ),
                    level=level,
                    columns=cls._native_columns(
                        raw_line.get("columns"),
                        specs=specs,
                        company_currency_id=company_currency_id,
                        definition_line_ids=definition_line_ids,
                    ),
                    unfoldable=unfoldable,
                    unfolded=unfolded,
                    source_move_line_count=None,
                    source_move_line_count_proven=False,
                )
            )
        return tuple(lines)

    def fetch_native_report(
        self,
        *,
        company_id: int,
        report_family: str,
        report_kind: str,
        date_from: date,
        date_to: date,
        comparison_mode: str | None,
        comparison_periods: int | None,
        currency_id: int,
        move_state: str,
        journal_scope: str,
        tax_unit_id: int | None,
        unreconciled_only: bool,
        hide_zero_lines: bool,
        line_expansion_request: str,
    ) -> NativeReportSnapshot:
        if report_family not in {"financial", "tax"}:
            raise ReportReadError("native report family is unsupported")
        if (
            move_state != "posted"
            or journal_scope != "all_report_eligible"
            or tax_unit_id is not None
            or unreconciled_only is not False
            or hide_zero_lines is not False
            or line_expansion_request != "none"
        ):
            raise ReportReadError("native report fixed filters are unsupported")
        if (report_family, report_kind) not in _REPORT_KIND_XMLIDS:
            raise ReportReadError("native report kind is unsupported")
        if report_kind == "cash_flow" and comparison_mode is not None:
            raise ReportReadError("cash-flow comparison is not supported")
        self._assert_clean_transaction_state("before native report preparation")
        company = self._company(company_id)
        company_currency_id = _record_id(company.currency_id)
        if company_currency_id is None or currency_id != company_currency_id:
            raise ReportReadError("native report currency is not the company currency")
        allowed_root_id = self._allowed_root_id(
            family=report_family,
            report_kind=report_kind,
            company=company,
        )
        requested = self._report(
            company=company,
            report_id=allowed_root_id,
            allowed_root_id=allowed_root_id,
        )
        requested_definition_line_ids = self._report_definition_line_ids(
            requested
        )
        if (
            comparison_mode is not None
            and getattr(requested, "filter_period_comparison", False) is not True
        ):
            raise ReportReadError(
                "native report does not support the requested comparison"
            )
        previous_options = self._previous_options(
            company_id=company_id,
            date_from=date_from,
            date_to=date_to,
            comparison_mode=comparison_mode,
            comparison_periods=comparison_periods,
            move_state=move_state,
            unreconciled_only=unreconciled_only,
            hide_zero_lines=hide_zero_lines,
        )
        options = requested.get_options(previous_options)
        self._assert_clean_transaction_state("after native report options")
        if not isinstance(options, Mapping):
            raise ReportReadError("native report options are invalid")
        currency_table = options.get("currency_table")
        if (
            options.get("readonly_query") is not True
            or options.get("unfold_all") is not False
            or not isinstance(currency_table, Mapping)
            or set(currency_table) != {"periods", "type"}
            or currency_table.get("type") != "monocurrency"
            or currency_table.get("periods") != {}
        ):
            raise ReportReadError("native report did not preserve read-only options")
        effective_filters = self._effective_filters(
            options,
            company=company,
            report_kind=report_kind,
        )
        resolved_id = options.get("report_id")
        if (
            isinstance(resolved_id, bool)
            or not isinstance(resolved_id, int)
            or resolved_id <= 0
        ):
            raise ReportReadError("native report resolved ID is invalid")
        resolved = self._report(
            company=company,
            report_id=resolved_id,
            allowed_root_id=allowed_root_id,
        )
        resolved_definition_line_ids = self._report_definition_line_ids(
            resolved
        )
        definition_line_ids = (
            requested_definition_line_ids | resolved_definition_line_ids
        )
        if getattr(resolved, "active", None) is not True:
            raise ReportReadError("native report resolved to an inactive variant")
        if _root_id(resolved) != _root_id(requested):
            raise ReportReadError("native report resolved outside the requested root")
        if (
            options.get("variants_source_id") != allowed_root_id
            or options.get("selected_variant_id") != resolved_id
            or options.get("sections_source_id") != resolved_id
            or options.get("sections") != []
        ):
            raise ReportReadError("native report variant identity changed")
        available_variants = options.get("available_variants")
        if (
            not isinstance(available_variants, list)
            or not available_variants
            or len(available_variants) > 10_000
        ):
            raise ReportReadError("native report variants are invalid")
        available_variant_ids = tuple(
            item.get("id")
            for item in available_variants
            if isinstance(item, Mapping)
        )
        if (
            len(available_variant_ids) != len(available_variants)
            or any(
                isinstance(variant_id, bool)
                or not isinstance(variant_id, int)
                or variant_id <= 0
                for variant_id in available_variant_ids
            )
            or len(set(available_variant_ids)) != len(available_variant_ids)
            or resolved_id not in available_variant_ids
        ):
            raise ReportReadError("native report variants are invalid")
        observed_company_ids = resolved.get_report_company_ids(options)
        if (
            not isinstance(observed_company_ids, list)
            or observed_company_ids != [company_id]
        ):
            raise ReportReadError("native report company scope changed")

        raw_main_period = options.get("date")
        main_period = _period(
            raw_main_period,
            (
                "main:"
                + str(
                    raw_main_period.get("currency_table_period_key", "")
                    if isinstance(raw_main_period, Mapping)
                    else ""
                )
            ),
            "options.date",
        )
        observed_comparison_periods = self._comparison_periods(
            options,
            requested_mode=comparison_mode,
            requested_count=comparison_periods,
        )
        specs = self._column_specs(
            options,
            main_period=main_period,
            comparison_periods=observed_comparison_periods,
            company_currency_id=company_currency_id,
        )
        options_snapshot = _canonical_options(options)
        readonly_method = getattr(
            resolved, "get_report_information_readonly", None
        )
        if not callable(readonly_method):
            raise ReportReadError("native report read-only API is unavailable")
        information = readonly_method(options)
        self._assert_clean_transaction_state("after native report execution")
        if _canonical_options(options) != options_snapshot:
            raise ReportReadError(
                "native report options changed during execution"
            )
        if not isinstance(information, Mapping):
            raise ReportReadError("native report information is invalid")
        report_information = information.get("report")
        expected_information_root_id = (
            None if resolved_id == allowed_root_id else allowed_root_id
        )
        if (
            not isinstance(report_information, Mapping)
            or report_information.get("name") != resolved.name
            or _record_id(report_information.get("root_report_id"))
            != expected_information_root_id
            or report_information.get("company_name") != company.name
            or report_information.get("company_currency_symbol")
            != company.currency_id.symbol
        ):
            raise ReportReadError("native report information identity changed")
        upstream_warnings = information.get("warnings")
        if not isinstance(upstream_warnings, Mapping):
            raise ReportReadError("native report returned an unreviewed warning")
        mapped_warnings: list[str] = []
        for warning_code, warning_payload in upstream_warnings.items():
            mapped = _WARNING_CODES.get(warning_code)
            if mapped is None or warning_payload != {}:
                raise ReportReadError(
                    "native report returned an unreviewed warning"
                )
            mapped_warnings.append(mapped)

        warnings = mapped_warnings
        if resolved_id != allowed_root_id:
            warnings.append("odoo:report_variant_resolved")
        if (
            main_period.mode != "range"
            or main_period.date_from != date_from
            or main_period.date_to != date_to
        ):
            warnings.append("odoo:date_range_normalized")
        if report_family == "tax":
            warnings.append("odoo:tax_source_move_line_count_unavailable")

        return NativeReportSnapshot(
            company_id=company_id,
            requested_report_id=allowed_root_id,
            requested_report_name=_text(
                requested.name,
                "requested report name",
                max_length=256,
            ),
            resolved_report_id=resolved_id,
            resolved_report_name=_text(
                resolved.name,
                "resolved report name",
                max_length=256,
            ),
            report_family=report_family,
            report_kind=report_kind,
            currency_id=company_currency_id,
            period_key=main_period.safe_key,
            date_mode=main_period.mode,
            date_from=main_period.date_from,
            date_to=main_period.date_to,
            comparison_mode=comparison_mode,
            comparison_periods=comparison_periods,
            resolved_comparison_periods=tuple(
                NativeReportPeriod(
                    key=period.safe_key,
                    label=period.label,
                    mode=period.mode,
                    date_from=period.date_from,
                    date_to=period.date_to,
                )
                for period in observed_comparison_periods
            ),
            effective_filters=effective_filters,
            warnings=tuple(sorted(set(warnings))),
            lines=self._native_lines(
                information.get("lines"),
                report=resolved,
                specs=specs,
                company_currency_id=company_currency_id,
                definition_line_ids=definition_line_ids,
            ),
        )
