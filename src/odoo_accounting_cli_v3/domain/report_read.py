"""Deterministic normalization for native Odoo accounting reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Any, Protocol


class ReportReadError(ValueError):
    pass


MAX_PAGE_SIZE = 5_000
MAX_PAGE_OFFSET = 1_000_000
MAX_REPORT_LINES = 50_000
MAX_REPORT_CELLS = 500_000
MAX_LINE_COLUMNS = 48
MAX_CELL_TEXT_LENGTH = 4_096
MAX_PAGE_TEXT_BYTES = 8 * 1_024 * 1_024
_FINANCIAL_WARNINGS = frozenset(
    {
        "odoo:date_range_normalized",
        "odoo:draft_entries_excluded",
        "odoo:report_variant_resolved",
    }
)
_TAX_WARNINGS = _FINANCIAL_WARNINGS | {
    "odoo:tax_source_move_line_count_unavailable"
}
_FIGURE_TYPES = {
    "monetary",
    "percentage",
    "integer",
    "float",
    "date",
    "datetime",
    "boolean",
    "string",
}
_REPORT_KINDS = {
    "financial": frozenset(
        {"balance_sheet", "cash_flow", "profit_and_loss"}
    ),
    "tax": frozenset({"generic_tax"}),
}


@dataclass(frozen=True)
class CurrencyInfo:
    id: int
    name: str
    symbol: str
    rounding: Decimal


@dataclass(frozen=True)
class NativeReportColumn:
    label: str
    expression_label: str | None
    value: Any
    figure_type: str
    period_key: str
    period_label: str
    period_mode: str
    period_date_from: date
    period_date_to: date
    currency_id: int | None = None
    is_blank: bool = False
    auditable: bool = False


@dataclass(frozen=True)
class NativeReportLine:
    raw_id: str | int
    code: str | None
    name: str
    level: int
    columns: tuple[NativeReportColumn, ...]
    unfoldable: bool
    unfolded: bool
    parent_raw_id: str | int | None = None
    source_move_line_count: int | None = None
    source_move_line_count_proven: bool = False


@dataclass(frozen=True)
class NativeReportPeriod:
    key: str
    label: str
    mode: str
    date_from: date
    date_to: date


@dataclass(frozen=True)
class NativeReportFilters:
    move_state: str
    journal_scope: str
    journal_ids: tuple[int, ...]
    tax_unit_id: int | None
    unreconciled_only: bool
    hide_zero_lines: bool
    line_expansion_request: str
    custom_aml_filter_count: int
    analytic_groupby: bool
    consolidation: bool
    multi_currency_display: bool


@dataclass(frozen=True)
class NativeReportDefinitionBinding:
    schema_version: int
    definition_sha256: str
    baseline_catalog_sha256: str
    baseline_entry_sha256: str
    source_candidate_sha256: str
    approval_set_sha256: str
    allowed_signers_sha256: str
    revocations_sha256: str
    oracle_contract_sha256: str
    trust_envelope_sha256: str
    binding_sha256: str
    approvals_verified: bool
    revocations_checked: bool
    artifact_digests_verified: bool
    pre_matches_approved: bool
    post_matches_approved: bool
    same_transaction_snapshot_definition_equal: bool


@dataclass(frozen=True)
class NativeReportSnapshot:
    company_id: int
    requested_report_id: int
    requested_report_name: str
    resolved_report_id: int
    resolved_report_name: str
    report_family: str
    report_kind: str
    definition_binding: NativeReportDefinitionBinding
    currency_id: int
    period_key: str
    date_mode: str
    date_from: date
    date_to: date
    comparison_mode: str | None
    comparison_periods: int | None
    resolved_comparison_periods: tuple[NativeReportPeriod, ...]
    effective_filters: NativeReportFilters
    warnings: tuple[str, ...]
    lines: tuple[NativeReportLine, ...]


class ReportReadBackend(Protocol):
    def assert_read_access(self, *, company_id: int) -> None: ...

    def company_currency(self, *, company_id: int) -> CurrencyInfo: ...

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
    ) -> NativeReportSnapshot: ...


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReportReadError(f"{field} must be a positive integer")
    return value


def _non_negative_integer(value: Any, field: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportReadError(f"{field} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ReportReadError(f"{field} exceeds the supported maximum")
    return value


def _iso_date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise ReportReadError(f"{field} must be an ISO date")
    try:
        result = date.fromisoformat(value)
    except ValueError as exc:
        raise ReportReadError(f"{field} must be an ISO date") from exc
    if result.isoformat() != value:
        raise ReportReadError(f"{field} must be an ISO date")
    return result


def _text(
    value: Any,
    field: str,
    *,
    nullable: bool = False,
    max_length: int = MAX_CELL_TEXT_LENGTH,
) -> str | None:
    if nullable and value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > max_length
    ):
        raise ReportReadError(f"{field} must be a non-empty string")
    return value


def _safe_period_key(value: Any, field: str) -> str:
    text = _text(value, field)
    if (
        len(text) != 71
        or not text.startswith("period-")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ReportReadError(f"{field} is not a safe period key")
    return text


def canonical_period_key(mode: str, date_from: date, date_to: date) -> str:
    if mode not in {"range", "single"}:
        raise ReportReadError("canonical period mode is unsupported")
    if type(date_from) is not date or type(date_to) is not date:
        raise ReportReadError("canonical period dates are invalid")
    if date_from > date_to:
        raise ReportReadError("canonical period dates are reversed")
    material = "\0".join(
        (mode, date_from.isoformat(), date_to.isoformat())
    ).encode("utf-8")
    return f"period-{sha256(material).hexdigest()}"


def _decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool):
        raise ReportReadError(f"{field} must be numeric")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ReportReadError(f"{field} must be numeric") from exc
    if not result.is_finite():
        raise ReportReadError(f"{field} must be finite")
    return result


def _decimal_text(
    value: Any,
    field: str,
    *,
    max_length: int = MAX_CELL_TEXT_LENGTH,
) -> str:
    result = _decimal(value, field)
    if result == 0:
        return "0"
    sign, digits, exponent = result.as_tuple()
    digit_count = len(digits)
    if exponent >= 0:
        maximum_rendered_length = sign + digit_count + exponent
    else:
        integer_digits = digit_count + exponent
        maximum_rendered_length = (
            sign + digit_count + 1
            if integer_digits > 0
            else sign + 2 + (-integer_digits) + digit_count
        )
    if maximum_rendered_length > max_length:
        raise ReportReadError(f"{field} exceeds the supported numeric size")
    rendered = format(result, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if len(rendered) > max_length:
        raise ReportReadError(f"{field} exceeds the supported numeric size")
    return rendered


def _date_text(value: Any, field: str) -> str:
    if type(value) is date:
        return value.isoformat()
    return _iso_date(value, field).isoformat()


def _datetime_text(value: Any, field: str) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if not isinstance(value, str):
        raise ReportReadError(f"{field} must be an ISO datetime")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(candidate).isoformat()
    except ValueError as exc:
        raise ReportReadError(f"{field} must be an ISO datetime") from exc


def _figure_value(value: Any, figure_type: str, field: str) -> str:
    if figure_type in {"monetary", "percentage", "float"}:
        return _decimal_text(value, field)
    if figure_type == "integer":
        result = _decimal(value, field)
        if result != result.to_integral_value():
            raise ReportReadError(f"{field} must be an integer")
        return _decimal_text(result, field)
    if figure_type == "date":
        return _date_text(value, field)
    if figure_type == "datetime":
        return _datetime_text(value, field)
    if figure_type == "boolean":
        if not isinstance(value, bool):
            raise ReportReadError(f"{field} must be a boolean")
        return "true" if value else "false"
    if figure_type == "string":
        if not isinstance(value, str) or len(value) > MAX_CELL_TEXT_LENGTH:
            raise ReportReadError(f"{field} must be a string")
        return value
    raise ReportReadError(f"unsupported figure_type: {figure_type!r}")


def _raw_key(value: Any, field: str) -> str:
    if isinstance(value, bool):
        raise ReportReadError(f"{field} is invalid")
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, str) and value:
        return f"str:{value}"
    raise ReportReadError(f"{field} must be a non-empty string or integer")


def _safe_line_id(family: str, report_id: int, raw_key: str) -> str:
    material = "\0".join((family, str(report_id), raw_key)).encode("utf-8")
    return f"line-{sha256(material).hexdigest()}"


def _comparison(
    value: Any, *, allowed: bool
) -> tuple[str | None, str | None, int | None]:
    if value is None:
        return None, None, None
    if not allowed:
        raise ReportReadError("comparison is not supported for tax reports")
    if not isinstance(value, dict) or set(value) != {"mode", "periods"}:
        raise ReportReadError("comparison must contain only mode and periods")
    requested_mode = value["mode"]
    if requested_mode not in {"previous_period", "previous_year"}:
        raise ReportReadError("comparison mode is unsupported")
    periods = _positive_integer(value["periods"], "comparison.periods")
    if periods != 1:
        raise ReportReadError("only one comparison period is supported")
    resolved_mode = {
        "previous_period": "previous_period",
        "previous_year": "same_last_year",
    }[requested_mode]
    return requested_mode, resolved_mode, periods


def _currency(value: Any) -> CurrencyInfo:
    if not isinstance(value, CurrencyInfo):
        raise ReportReadError("company currency is invalid")
    _positive_integer(value.id, "company currency id")
    _text(value.name, "company currency name", max_length=64)
    _text(value.symbol, "company currency symbol", max_length=16)
    rounding = _decimal(value.rounding, "company currency rounding")
    if rounding <= 0:
        raise ReportReadError("company currency rounding must be positive")
    return value


def _pagination(parameters: dict[str, Any]) -> tuple[int, int]:
    limit = parameters.get("limit", MAX_PAGE_SIZE)
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or limit > MAX_PAGE_SIZE
    ):
        raise ReportReadError("limit is outside the supported range")
    offset = _non_negative_integer(
        parameters.get("offset", 0), "offset", MAX_PAGE_OFFSET
    )
    return limit, offset


def _normalize_column(
    column: NativeReportColumn,
    *,
    company_currency_id: int,
    declared_periods: dict[str, tuple[str, date, date]],
    line_index: int,
    column_index: int,
) -> dict[str, Any]:
    field = f"lines[{line_index}].columns[{column_index}]"
    if not isinstance(column, NativeReportColumn):
        raise ReportReadError(f"{field} is invalid")
    figure_type = column.figure_type
    if not isinstance(figure_type, str) or figure_type not in _FIGURE_TYPES:
        raise ReportReadError(f"unsupported figure_type: {figure_type!r}")
    currency_id = column.currency_id
    if currency_id is not None:
        _positive_integer(currency_id, f"{field}.currency_id")
    if figure_type == "monetary":
        if currency_id != company_currency_id:
            raise ReportReadError(
                "native monetary report column currency differs from company currency"
            )
    elif currency_id is not None:
        raise ReportReadError(
            "native non-monetary report column must not declare a currency"
        )
    if column.period_mode not in {"range", "single"}:
        raise ReportReadError(f"{field}.period_mode is unsupported")
    if type(column.period_date_from) is not date:
        raise ReportReadError(f"{field}.period_date_from is invalid")
    if type(column.period_date_to) is not date:
        raise ReportReadError(f"{field}.period_date_to is invalid")
    if column.period_date_from > column.period_date_to:
        raise ReportReadError(f"{field} period dates are reversed")
    period_key = _safe_period_key(column.period_key, f"{field}.period_key")
    if declared_periods.get(period_key) != (
        column.period_mode,
        column.period_date_from,
        column.period_date_to,
    ):
        raise ReportReadError(f"{field} references an undeclared period")
    if not isinstance(column.is_blank, bool) or not isinstance(column.auditable, bool):
        raise ReportReadError(f"{field} flags are invalid")
    if column.is_blank:
        if column.value is not None:
            raise ReportReadError(f"{field}.value must be null for a blank column")
        normalized_value = None
    else:
        normalized_value = _figure_value(column.value, figure_type, f"{field}.value")
    return {
        "label": _text(
            column.label,
            f"{field}.label",
            max_length=128,
        ),
        "expression_label": _text(
            column.expression_label,
            f"{field}.expression_label",
            nullable=True,
            max_length=128,
        ),
        "period": {
            "key": period_key,
            "label": _text(
                column.period_label,
                f"{field}.period_label",
                max_length=128,
            ),
            "mode": column.period_mode,
            "date_from": column.period_date_from.isoformat(),
            "date_to": column.period_date_to.isoformat(),
        },
        "cell": {
            "value": normalized_value,
            "is_blank": column.is_blank,
        },
        "measure": {
            "figure_type": figure_type,
            "currency_id": currency_id,
        },
        "auditable": column.auditable,
    }


def _normalize_period(period: Any, field: str) -> dict[str, str]:
    if not isinstance(period, NativeReportPeriod):
        raise ReportReadError(f"{field} is invalid")
    if period.mode not in {"range", "single"}:
        raise ReportReadError(f"{field}.mode is unsupported")
    if type(period.date_from) is not date or type(period.date_to) is not date:
        raise ReportReadError(f"{field} dates are invalid")
    if period.date_from > period.date_to:
        raise ReportReadError(f"{field} dates are reversed")
    key = _safe_period_key(period.key, f"{field}.key")
    if key != canonical_period_key(period.mode, period.date_from, period.date_to):
        raise ReportReadError(f"{field}.key is not canonical")
    return {
        "key": key,
        "label": _text(
            period.label,
            f"{field}.label",
            max_length=128,
        ),
        "mode": period.mode,
        "date_from": period.date_from.isoformat(),
        "date_to": period.date_to.isoformat(),
    }


def _normalize_filters(filters: Any) -> dict[str, Any]:
    if not isinstance(filters, NativeReportFilters):
        raise ReportReadError("native report effective filters are invalid")
    if (
        filters.move_state != "posted"
        or filters.journal_scope != "all_report_eligible"
        or filters.tax_unit_id is not None
        or filters.unreconciled_only is not False
        or filters.hide_zero_lines is not False
        or filters.line_expansion_request != "none"
        or filters.custom_aml_filter_count != 0
        or filters.analytic_groupby is not False
        or filters.consolidation is not False
        or filters.multi_currency_display is not False
    ):
        raise ReportReadError("native report effective filters changed")
    if (
        not isinstance(filters.journal_ids, tuple)
        or not filters.journal_ids
        or len(filters.journal_ids) > 10_000
        or any(
            isinstance(journal_id, bool)
            or not isinstance(journal_id, int)
            or journal_id <= 0
            for journal_id in filters.journal_ids
        )
        or tuple(sorted(set(filters.journal_ids))) != filters.journal_ids
    ):
        raise ReportReadError("native report journal scope changed")
    return {
        "move_state": filters.move_state,
        "journal_scope": filters.journal_scope,
        "journal_ids": list(filters.journal_ids),
        "tax_unit_id": filters.tax_unit_id,
        "unreconciled_only": filters.unreconciled_only,
        "hide_zero_lines": filters.hide_zero_lines,
        "line_expansion_request": filters.line_expansion_request,
        "custom_aml_filter_count": filters.custom_aml_filter_count,
        "analytic_groupby": filters.analytic_groupby,
        "consolidation": filters.consolidation,
        "multi_currency_display": filters.multi_currency_display,
    }


def _sha256_text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReportReadError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _normalize_definition_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, NativeReportDefinitionBinding):
        raise ReportReadError("native report definition binding is invalid")
    if value.schema_version != 1:
        raise ReportReadError(
            "native report definition binding schema is unsupported"
        )
    checks = (
        value.approvals_verified,
        value.revocations_checked,
        value.artifact_digests_verified,
        value.pre_matches_approved,
        value.post_matches_approved,
        value.same_transaction_snapshot_definition_equal,
    )
    if any(type(check) is not bool or check is not True for check in checks):
        raise ReportReadError(
            "native report definition was not verified before and after execution"
        )
    return {
        "schema_version": value.schema_version,
        "definition_sha256": _sha256_text(
            value.definition_sha256,
            "native report definition digest",
        ),
        "baseline_catalog_sha256": _sha256_text(
            value.baseline_catalog_sha256,
            "native report baseline catalog digest",
        ),
        "baseline_entry_sha256": _sha256_text(
            value.baseline_entry_sha256,
            "native report baseline entry digest",
        ),
        "source_candidate_sha256": _sha256_text(
            value.source_candidate_sha256,
            "native report source candidate digest",
        ),
        "approval_set_sha256": _sha256_text(
            value.approval_set_sha256,
            "native report approval set digest",
        ),
        "allowed_signers_sha256": _sha256_text(
            value.allowed_signers_sha256,
            "native report allowed signers digest",
        ),
        "revocations_sha256": _sha256_text(
            value.revocations_sha256,
            "native report revocations digest",
        ),
        "oracle_contract_sha256": _sha256_text(
            value.oracle_contract_sha256,
            "native report oracle contract digest",
        ),
        "trust_envelope_sha256": _sha256_text(
            value.trust_envelope_sha256,
            "native report trust envelope digest",
        ),
        "binding_sha256": _sha256_text(
            value.binding_sha256,
            "native report baseline binding digest",
        ),
        "approvals_verified": value.approvals_verified,
        "revocations_checked": value.revocations_checked,
        "artifact_digests_verified": value.artifact_digests_verified,
        "pre_matches_approved": value.pre_matches_approved,
        "post_matches_approved": value.post_matches_approved,
        "same_transaction_snapshot_definition_equal": (
            value.same_transaction_snapshot_definition_equal
        ),
    }


def _validate_snapshot(
    snapshot: Any,
    *,
    company_id: int,
    family: str,
    report_kind: str,
    company_currency_id: int,
    comparison_mode: str | None,
    comparison_periods: int | None,
) -> NativeReportSnapshot:
    if not isinstance(snapshot, NativeReportSnapshot):
        raise ReportReadError("native report snapshot is invalid")
    if snapshot.company_id != company_id:
        raise ReportReadError("native report company binding mismatch")
    _positive_integer(snapshot.requested_report_id, "requested report id")
    _text(
        snapshot.requested_report_name,
        "requested report name",
        max_length=256,
    )
    _positive_integer(snapshot.resolved_report_id, "resolved report id")
    _text(
        snapshot.resolved_report_name,
        "resolved report name",
        max_length=256,
    )
    if snapshot.report_family != family:
        raise ReportReadError("native report family does not match the entry point")
    if snapshot.report_kind != report_kind:
        raise ReportReadError("native report kind does not match the request")
    _normalize_definition_binding(snapshot.definition_binding)
    if snapshot.currency_id != company_currency_id:
        raise ReportReadError("native report currency differs from company currency")
    main_period_key = _safe_period_key(
        snapshot.period_key, "native report period key"
    )
    if snapshot.date_mode not in {"range", "single"}:
        raise ReportReadError("native report effective date mode is unsupported")
    if type(snapshot.date_from) is not date:
        raise ReportReadError("native report effective date_from is invalid")
    if type(snapshot.date_to) is not date:
        raise ReportReadError("native report effective dates are invalid")
    if snapshot.date_from > snapshot.date_to:
        raise ReportReadError("native report effective date_from is after date_to")
    if main_period_key != canonical_period_key(
        snapshot.date_mode,
        snapshot.date_from,
        snapshot.date_to,
    ):
        raise ReportReadError("native report period key is not canonical")
    if (
        snapshot.comparison_mode != comparison_mode
        or snapshot.comparison_periods != comparison_periods
    ):
        raise ReportReadError("native report comparison context mismatch")
    if not isinstance(snapshot.resolved_comparison_periods, (tuple, list)):
        raise ReportReadError("native report resolved comparison periods are invalid")
    resolved_periods = tuple(
        _normalize_period(period, f"resolved comparison periods[{index}]")
        for index, period in enumerate(snapshot.resolved_comparison_periods)
    )
    if comparison_mode is None:
        if comparison_periods is not None or resolved_periods:
            raise ReportReadError("native report added an unrequested comparison")
    elif (
        comparison_periods is None
        or len(resolved_periods) != comparison_periods
        or len({period["key"] for period in resolved_periods})
        != len(resolved_periods)
    ):
        raise ReportReadError("native report resolved comparison periods changed")
    period_keys = [main_period_key, *(period["key"] for period in resolved_periods)]
    if len(period_keys) != len(set(period_keys)):
        raise ReportReadError("native report period keys are duplicated")
    _normalize_filters(snapshot.effective_filters)
    if not isinstance(snapshot.warnings, (tuple, list)):
        raise ReportReadError("native report warnings are invalid")
    warnings = list(snapshot.warnings)
    allowed_warnings = (
        _FINANCIAL_WARNINGS if family == "financial" else _TAX_WARNINGS
    )
    if (
        len(warnings) != len(set(warnings))
        or warnings != sorted(warnings)
        or any(warning not in allowed_warnings for warning in warnings)
    ):
        raise ReportReadError("native report warnings are not allowlisted and ordered")
    if not isinstance(snapshot.lines, (tuple, list)):
        raise ReportReadError("native report lines are invalid")
    if len(snapshot.lines) > MAX_REPORT_LINES:
        raise ReportReadError("native report line count exceeds the safety limit")
    return snapshot


def _normalize_lines(
    snapshot: NativeReportSnapshot,
    *,
    family: str,
    company_currency_id: int,
    offset: int,
    limit: int,
) -> list[dict[str, Any]]:
    raw_keys: list[str] = []
    line_ids: dict[str, str] = {}
    line_levels: dict[str, int] = {}
    line_positions: dict[str, int] = {}
    total_cells = 0
    for index, line in enumerate(snapshot.lines):
        if not isinstance(line, NativeReportLine):
            raise ReportReadError(f"lines[{index}] is invalid")
        raw_key = _raw_key(line.raw_id, f"lines[{index}].raw_id")
        if raw_key in line_ids:
            raise ReportReadError("native report line IDs are duplicated")
        level = _non_negative_integer(line.level, f"lines[{index}].level", 64)
        columns = line.columns
        if (
            not isinstance(columns, (tuple, list))
            or not columns
            or len(columns) > MAX_LINE_COLUMNS
        ):
            raise ReportReadError(
                f"lines[{index}].columns are outside the safety limit"
            )
        total_cells += len(columns)
        if total_cells > MAX_REPORT_CELLS:
            raise ReportReadError(
                "native report cell count exceeds the safety limit"
            )
        raw_keys.append(raw_key)
        line_ids[raw_key] = _safe_line_id(
            family, snapshot.resolved_report_id, raw_key
        )
        line_levels[raw_key] = level
        line_positions[raw_key] = index

    for index, line in enumerate(snapshot.lines):
        if line.parent_raw_id is None:
            continue
        parent_key = _raw_key(
            line.parent_raw_id, f"lines[{index}].parent_raw_id"
        )
        raw_key = raw_keys[index]
        if parent_key not in line_ids:
            raise ReportReadError("native report parent line does not exist")
        if line_levels[parent_key] >= line_levels[raw_key]:
            raise ReportReadError("native report parent hierarchy is invalid")
        if line_positions[parent_key] >= index:
            raise ReportReadError(
                "native report parent line must precede its child"
            )

    rows: list[dict[str, Any]] = []
    declared_period_items = (
        (
            _safe_period_key(
                snapshot.period_key,
                "native report period key",
            ),
            (
                snapshot.date_mode,
                snapshot.date_from,
                snapshot.date_to,
            ),
        ),
    ) + tuple(
        (
            _safe_period_key(
                period.key,
                f"resolved comparison periods[{index}].key",
            ),
            (
                period.mode,
                period.date_from,
                period.date_to,
            ),
        )
        for index, period in enumerate(snapshot.resolved_comparison_periods)
    )
    declared_period_keys = tuple(
        key for key, _period_identity in declared_period_items
    )
    if len(set(declared_period_keys)) != len(declared_period_keys):
        raise ReportReadError("native report period keys are duplicated")
    declared_periods = dict(declared_period_items)
    declared_period_key_set = set(declared_period_keys)
    for line_index, line in enumerate(snapshot.lines):
        observed_period_keys: set[str] = set()
        for column_index, column in enumerate(line.columns):
            if not isinstance(column, NativeReportColumn):
                raise ReportReadError(
                    f"lines[{line_index}].columns[{column_index}] is invalid"
                )
            column_key = _safe_period_key(
                column.period_key,
                f"lines[{line_index}].columns[{column_index}].period_key",
            )
            if declared_periods.get(column_key) != (
                column.period_mode,
                column.period_date_from,
                column.period_date_to,
            ):
                raise ReportReadError(
                    f"lines[{line_index}].columns[{column_index}] "
                    "references an undeclared period"
                )
            observed_period_keys.add(column_key)
        if observed_period_keys != declared_period_key_set:
            raise ReportReadError(
                f"lines[{line_index}] does not cover every declared period"
            )
    stop = min(len(snapshot.lines), offset + limit)
    page_text_bytes = 0
    for index in range(offset, stop):
        line = snapshot.lines[index]
        columns = line.columns
        raw_key = raw_keys[index]
        level = line_levels[raw_key]
        parent_key: str | None = None
        if line.parent_raw_id is not None:
            parent_key = _raw_key(
                line.parent_raw_id, f"lines[{index}].parent_raw_id"
            )
        code = _text(
            line.code,
            f"lines[{index}].code",
            nullable=True,
            max_length=128,
        )
        name = _text(
            line.name,
            f"lines[{index}].name",
            max_length=256,
        )
        normalized_columns = [
            _normalize_column(
                column,
                company_currency_id=company_currency_id,
                declared_periods=declared_periods,
                line_index=index,
                column_index=column_index,
            )
            for column_index, column in enumerate(columns)
        ]
        text_values = [code, name]
        for normalized_column in normalized_columns:
            text_values.extend(
                (
                    normalized_column["label"],
                    normalized_column["expression_label"],
                    normalized_column["period"]["label"],
                    normalized_column["cell"]["value"],
                )
            )
        page_text_bytes += sum(
            len(value.encode("utf-8"))
            for value in text_values
            if isinstance(value, str)
        )
        if page_text_bytes > MAX_PAGE_TEXT_BYTES:
            raise ReportReadError(
                "native report page text exceeds the safety limit"
            )
        row = {
            "line_id": line_ids[raw_key],
            "parent": {
                "line_id": line_ids[parent_key] if parent_key else None,
                "relation_source": "explicit" if parent_key else "none",
            },
            "code": code,
            "name": name,
            "level": level,
            "columns": normalized_columns,
            "unfoldable": line.unfoldable,
            "unfolded": line.unfolded,
        }
        if not isinstance(line.unfoldable, bool) or not isinstance(line.unfolded, bool):
            raise ReportReadError(f"lines[{index}] unfold flags are invalid")
        if family == "tax":
            if not isinstance(line.source_move_line_count_proven, bool):
                raise ReportReadError("tax source audit proof flag is invalid")
            if line.source_move_line_count_proven:
                count = _non_negative_integer(
                    line.source_move_line_count,
                    f"lines[{index}].source_move_line_count",
                )
            else:
                if line.source_move_line_count is not None:
                    raise ReportReadError(
                        "unproven tax source move-line count must be null"
                    )
                count = None
            row["source_move_line_count"] = {
                "available": line.source_move_line_count_proven,
                "count": count,
            }
        rows.append(row)
    return rows


def _read_report(
    backend: ReportReadBackend,
    parameters: dict[str, Any],
    *,
    family: str,
) -> dict[str, Any]:
    if not isinstance(parameters, dict):
        raise ReportReadError("parameters must be an object")
    expected_parameters = {
        "company_id",
        "date_from",
        "date_to",
        "move_state",
        "journal_scope",
        "tax_unit_id",
        "unreconciled_only",
        "hide_zero_lines",
        "line_expansion_request",
        "currency_id",
        "limit",
        "offset",
    }
    if family == "financial":
        expected_parameters.add("report_request")
    if set(parameters) != expected_parameters:
        raise ReportReadError("parameters do not match the native report contract")
    company_id = _positive_integer(parameters.get("company_id"), "company_id")
    if family == "financial":
        report_request = parameters.get("report_request")
        if (
            not isinstance(report_request, dict)
            or set(report_request) != {"kind", "comparison"}
        ):
            raise ReportReadError(
                "report_request does not match the financial report contract"
            )
        report_kind = report_request.get("kind")
        comparison_value = report_request.get("comparison")
    else:
        report_kind = "generic_tax"
        comparison_value = None
    if report_kind not in _REPORT_KINDS[family]:
        raise ReportReadError("report kind is unsupported")
    requested_from = _iso_date(parameters.get("date_from"), "date_from")
    requested_to = _iso_date(parameters.get("date_to"), "date_to")
    if requested_from > requested_to:
        raise ReportReadError("date_from must not be after date_to")
    requested_mode, resolved_mode, periods = _comparison(
        comparison_value,
        allowed=family == "financial" and report_kind != "cash_flow",
    )
    limit, offset = _pagination(parameters)
    move_state = parameters.get("move_state")
    journal_scope = parameters.get("journal_scope")
    tax_unit_id = parameters.get("tax_unit_id")
    unreconciled_only = parameters.get("unreconciled_only")
    hide_zero_lines = parameters.get("hide_zero_lines")
    line_expansion_request = parameters.get("line_expansion_request")
    if (
        move_state != "posted"
        or journal_scope != "all_report_eligible"
        or tax_unit_id is not None
        or unreconciled_only is not False
        or hide_zero_lines is not False
        or line_expansion_request != "none"
    ):
        raise ReportReadError("native report fixed filters are unsupported")

    backend.assert_read_access(company_id=company_id)
    company_currency = _currency(
        backend.company_currency(company_id=company_id)
    )
    requested_currency_id = parameters.get("currency_id")
    if requested_currency_id is not None:
        _positive_integer(requested_currency_id, "currency_id")
        if requested_currency_id != company_currency.id:
            raise ReportReadError(
                "presentation currency must be the company currency"
            )

    snapshot = backend.fetch_native_report(
        company_id=company_id,
        report_family=family,
        report_kind=report_kind,
        date_from=requested_from,
        date_to=requested_to,
        comparison_mode=resolved_mode,
        comparison_periods=periods,
        currency_id=company_currency.id,
        move_state=move_state,
        journal_scope=journal_scope,
        tax_unit_id=tax_unit_id,
        unreconciled_only=unreconciled_only,
        hide_zero_lines=hide_zero_lines,
        line_expansion_request=line_expansion_request,
    )
    snapshot = _validate_snapshot(
        snapshot,
        company_id=company_id,
        family=family,
        report_kind=report_kind,
        company_currency_id=company_currency.id,
        comparison_mode=resolved_mode,
        comparison_periods=periods,
    )
    effective_filters = _normalize_filters(snapshot.effective_filters)
    rows = _normalize_lines(
        snapshot,
        family=family,
        company_currency_id=company_currency.id,
        offset=offset,
        limit=limit,
    )
    comparison_context = None
    if requested_mode is not None:
        comparison_context = {
            "requested_mode": requested_mode,
            "resolved_mode": resolved_mode,
            "periods": periods,
            "resolved_periods": [
                _normalize_period(
                    period,
                    f"resolved comparison periods[{index}]",
                )
                for index, period in enumerate(
                    snapshot.resolved_comparison_periods
                )
            ],
        }
    return {
        "report": {
            "family": family,
            "kind": report_kind,
            "requested": {
                "id": snapshot.requested_report_id,
                "name": snapshot.requested_report_name,
            },
            "resolved": {
                "id": snapshot.resolved_report_id,
                "name": snapshot.resolved_report_name,
            },
        },
        "definition_binding": _normalize_definition_binding(
            snapshot.definition_binding
        ),
        "period": {
            "requested": {
                "mode": "range",
                "date_from": requested_from.isoformat(),
                "date_to": requested_to.isoformat(),
            },
            "resolved": {
                "key": _safe_period_key(
                    snapshot.period_key, "native report period key"
                ),
                "mode": snapshot.date_mode,
                "date_from": snapshot.date_from.isoformat(),
                "date_to": snapshot.date_to.isoformat(),
            },
            "comparison": comparison_context,
        },
        "effective_filters": effective_filters,
        "currency": {
            "id": company_currency.id,
            "name": company_currency.name,
            "symbol": company_currency.symbol or company_currency.name,
            "rounding": _decimal_text(
                company_currency.rounding,
                "company currency rounding",
                max_length=128,
            ),
        },
        "warnings": list(snapshot.warnings),
        "lines": rows,
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(rows),
            "total_count": len(snapshot.lines),
        },
    }


def read_financial_report(
    backend: ReportReadBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Normalize an Odoo-native financial report without presentation conversion."""

    return _read_report(backend, parameters, family="financial")


def read_tax_report(
    backend: ReportReadBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Normalize a tax report while keeping unproven source counts unavailable."""

    return _read_report(backend, parameters, family="tax")
