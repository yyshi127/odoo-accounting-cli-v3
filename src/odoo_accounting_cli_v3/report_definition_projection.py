"""Pure canonical projection for one trusted Odoo accounting report root."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Mapping, Sequence


PROJECTION_SCHEMA_VERSION = 1
ROOT_BASELINE_IDENTITIES = (
    ("tax", "generic_tax", "account.generic_tax_report"),
    ("financial", "balance_sheet", "account_reports.balance_sheet"),
    ("financial", "cash_flow", "account_reports.cash_flow_report"),
    ("financial", "profit_and_loss", "account_reports.profit_and_loss"),
)
BASELINE_IDENTITY_FIELDS = (
    "company_id",
    "database_uuid",
    "family",
    "kind",
    "root_xmlid",
)
ROOT_PROJECTION_FIELDS = (
    "baseline_identity",
    "company_profile",
    "module_graph",
    "reports",
    "schema_version",
    "source_projection",
)
COMPANY_PROFILE_FIELDS = (
    "account_fiscal_country_code",
    "chart_template",
    "company_id",
    "country_code",
    "currency",
    "fiscal",
    "name",
    "write_date",
)
CURRENCY_FIELDS = ("decimal_places", "name", "rounding", "symbol")
FISCAL_FIELDS = (
    "fiscalyear_last_day",
    "fiscalyear_last_month",
    "fiscalyear_lock_date",
    "hard_lock_date",
    "tax_lock_date",
)
REPORT_FIELDS = (
    "active",
    "availability_condition",
    "chart_template",
    "columns",
    "country_code",
    "custom_handler_model",
    "key",
    "lines",
    "name",
    "options",
    "root_report_key",
    "section_report_keys",
    "sequence",
    "use_sections",
    "write_date",
    "xmlid",
)
REPORT_OPTION_FIELDS = (
    "allow_foreign_vat",
    "currency_translation",
    "default_opening_date_filter",
    "filter_date_range",
    "filter_growth_comparison",
    "filter_hide_0_lines",
    "filter_journals",
    "filter_multi_company",
    "filter_period_comparison",
    "filter_show_draft",
    "filter_unfold_all",
    "filter_unreconciled",
    "integer_rounding",
    "load_more_limit",
    "only_tax_exigible",
    "prefix_groups_threshold",
    "search_bar",
)
COLUMN_FIELDS = (
    "blank_if_zero",
    "custom_audit_action_xmlid",
    "expression_label",
    "figure_type",
    "key",
    "name",
    "sequence",
    "sortable",
    "write_date",
)
LINE_FIELDS = (
    "action_xmlid",
    "code",
    "expressions",
    "foldable",
    "groupby",
    "hide_if_zero",
    "hierarchy_level",
    "horizontal_split_side",
    "key",
    "name",
    "parent_key",
    "print_on_new_page",
    "sequence",
    "user_groupby",
    "write_date",
)
EXPRESSION_FIELDS = (
    "auditable",
    "blank_if_zero",
    "carryover_target",
    "date_scope",
    "domain",
    "engine",
    "figure_type",
    "formula",
    "green_on_positive",
    "key",
    "label",
    "subformula",
    "write_date",
)
MODULE_GRAPH_FIELDS = ("digest", "modules", "schema_version")
MODULE_FIELDS = ("dependencies", "latest_version", "name", "write_date")
DEPENDENCY_FIELDS = ("auto_install_required", "name")
SOURCE_PROJECTION_FIELDS = ("digest", "projections", "schema_version")
SOURCE_PROJECTION_ROW_FIELDS = ("name", "row_count", "sha256")

_XMLID = re.compile(r"[a-z][a-z0-9_]{0,127}\.[A-Za-z0-9_.-]{1,128}")
_MODEL = re.compile(r"[a-z][a-z0-9_.]{0,255}")
_MODULE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class ReportDefinitionProjectionError(ValueError):
    """The definition cannot produce one unambiguous canonical projection."""


def canonical_projection_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise ReportDefinitionProjectionError(
            "report definition contains a non-JSON value"
        ) from exc


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_projection_json(value)).hexdigest()


def _plain(value: object) -> object:
    return json.loads(canonical_projection_json(value).decode("utf-8"))


def _exact(
    value: object, fields: Sequence[str], label: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ReportDefinitionProjectionError(f"{label} fields are invalid")
    return value


def _string(
    value: object,
    label: str,
    *,
    nullable: bool = False,
    maximum: int = 16_384,
) -> str | None:
    if nullable and value is None:
        return None
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    return value


def _xmlid(value: object, label: str, *, nullable: bool = False) -> str | None:
    text = _string(value, label, nullable=nullable, maximum=257)
    if text is not None and _XMLID.fullmatch(text) is None:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    return text


def _timestamp(value: object, label: str) -> str | None:
    if value is None:
        return None
    text = _string(value, label, maximum=27)
    assert text is not None
    if _TIMESTAMP.fullmatch(text) is None:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportDefinitionProjectionError(f"{label} is invalid") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
        != text
    ):
        raise ReportDefinitionProjectionError(f"{label} is not canonical")
    return text


def _date(value: object, label: str) -> str | None:
    if value is None:
        return None
    text = _string(value, label, maximum=10)
    assert text is not None
    if _DATE.fullmatch(text) is None:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise ReportDefinitionProjectionError(f"{label} is invalid") from exc
    if parsed.isoformat() != text:
        raise ReportDefinitionProjectionError(f"{label} is not canonical")
    return text


def _lower_sha(value: object, label: str) -> str:
    text = _string(value, label, maximum=64)
    assert text is not None
    if _HEX64.fullmatch(text) is None:
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    return text


def _sorted_strings(
    value: object, label: str, *, xmlids: bool = False
) -> list[str]:
    if not isinstance(value, list):
        raise ReportDefinitionProjectionError(f"{label} is invalid")
    result: list[str] = []
    for item in value:
        text = _xmlid(item, label) if xmlids else _string(item, label)
        assert text is not None
        result.append(text)
    if result != sorted(result) or len(set(result)) != len(result):
        raise ReportDefinitionProjectionError(
            f"{label} is not uniquely sorted"
        )
    return result


def _identity(
    *,
    database_uuid: object,
    company_id: object,
    family: object,
    kind: object,
    root_xmlid: object,
) -> dict[str, object]:
    if type(database_uuid) is not str:
        raise ReportDefinitionProjectionError("database UUID is invalid")
    try:
        normalized_uuid = str(uuid.UUID(database_uuid))
    except ValueError as exc:
        raise ReportDefinitionProjectionError("database UUID is invalid") from exc
    if normalized_uuid != database_uuid:
        raise ReportDefinitionProjectionError("database UUID is not canonical")
    company = _integer(company_id, "company id", minimum=1)
    if type(family) is not str or type(kind) is not str:
        raise ReportDefinitionProjectionError("report family or kind is invalid")
    normalized_xmlid = _xmlid(root_xmlid, "root report XMLID")
    triple = (family, kind, normalized_xmlid)
    if triple not in ROOT_BASELINE_IDENTITIES:
        raise ReportDefinitionProjectionError(
            "report baseline identity is not a fixed root"
        )
    return {
        "company_id": company,
        "database_uuid": normalized_uuid,
        "family": family,
        "kind": kind,
        "root_xmlid": normalized_xmlid,
    }


def _company_profile(value: object, *, company_id: int) -> dict[str, object]:
    row = _exact(value, COMPANY_PROFILE_FIELDS, "company profile")
    currency = _exact(row["currency"], CURRENCY_FIELDS, "company currency")
    fiscal = _exact(row["fiscal"], FISCAL_FIELDS, "company fiscal profile")
    rounding = _string(currency["rounding"], "currency rounding", maximum=128)
    assert rounding is not None
    try:
        decimal = Decimal(rounding)
    except InvalidOperation as exc:
        raise ReportDefinitionProjectionError(
            "currency rounding is invalid"
        ) from exc
    normalized_rounding = format(decimal, "f")
    if "." in normalized_rounding:
        normalized_rounding = normalized_rounding.rstrip("0").rstrip(".")
    if (
        not decimal.is_finite()
        or decimal <= 0
        or normalized_rounding != rounding
    ):
        raise ReportDefinitionProjectionError(
            "currency rounding is not canonical"
        )
    result = {
        "account_fiscal_country_code": _string(
            row["account_fiscal_country_code"],
            "account fiscal country",
            nullable=True,
            maximum=8,
        ),
        "chart_template": _string(
            row["chart_template"],
            "chart template",
            nullable=True,
            maximum=256,
        ),
        "company_id": _integer(row["company_id"], "profile company id", minimum=1),
        "country_code": _string(
            row["country_code"], "company country", maximum=8
        ),
        "currency": {
            "decimal_places": _integer(
                currency["decimal_places"],
                "currency decimal places",
                maximum=12,
            ),
            "name": _string(currency["name"], "currency name", maximum=32),
            "rounding": rounding,
            "symbol": _string(currency["symbol"], "currency symbol", maximum=32),
        },
        "fiscal": {
            "fiscalyear_last_day": _integer(
                fiscal["fiscalyear_last_day"],
                "fiscal year last day",
                minimum=1,
                maximum=31,
            ),
            "fiscalyear_last_month": _string(
                fiscal["fiscalyear_last_month"],
                "fiscal year last month",
                maximum=2,
            ),
            "fiscalyear_lock_date": _date(
                fiscal["fiscalyear_lock_date"], "fiscal year lock date"
            ),
            "hard_lock_date": _date(
                fiscal["hard_lock_date"], "hard lock date"
            ),
            "tax_lock_date": _date(fiscal["tax_lock_date"], "tax lock date"),
        },
        "name": _string(row["name"], "company name", maximum=256),
        "write_date": _timestamp(row["write_date"], "company write date"),
    }
    if result["company_id"] != company_id or result != value:
        raise ReportDefinitionProjectionError(
            "company profile binding or canonical form differs"
        )
    return result


def _module_graph(value: object) -> dict[str, object]:
    graph = _exact(value, MODULE_GRAPH_FIELDS, "module graph")
    if (
        type(graph["schema_version"]) is not int
        or graph["schema_version"] != PROJECTION_SCHEMA_VERSION
        or not isinstance(graph["modules"], list)
        or not graph["modules"]
        or len(graph["modules"]) > 8_192
    ):
        raise ReportDefinitionProjectionError("module graph is invalid")
    modules: list[dict[str, object]] = []
    names: set[str] = set()
    for raw in graph["modules"]:
        module = _exact(raw, MODULE_FIELDS, "module")
        name = _string(module["name"], "module name", maximum=128)
        assert name is not None
        if _MODULE.fullmatch(name) is None or name in names:
            raise ReportDefinitionProjectionError("module name is invalid")
        names.add(name)
        dependencies_raw = module["dependencies"]
        if not isinstance(dependencies_raw, list) or len(dependencies_raw) > 100_000:
            raise ReportDefinitionProjectionError("module dependencies are invalid")
        dependencies: list[dict[str, object]] = []
        dependency_names: set[str] = set()
        for dependency_raw in dependencies_raw:
            dependency = _exact(
                dependency_raw, DEPENDENCY_FIELDS, "module dependency"
            )
            dependency_name = _string(
                dependency["name"], "dependency name", maximum=128
            )
            assert dependency_name is not None
            if (
                _MODULE.fullmatch(dependency_name) is None
                or dependency_name in dependency_names
            ):
                raise ReportDefinitionProjectionError(
                    "module dependency is invalid"
                )
            dependency_names.add(dependency_name)
            dependencies.append(
                {
                    "auto_install_required": _boolean(
                        dependency["auto_install_required"],
                        "dependency auto-install flag",
                    ),
                    "name": dependency_name,
                }
            )
        if [item["name"] for item in dependencies] != sorted(dependency_names):
            raise ReportDefinitionProjectionError(
                "module dependencies are not sorted"
            )
        modules.append(
            {
                "dependencies": dependencies,
                "latest_version": _string(
                    module["latest_version"], "module version", maximum=256
                ),
                "name": name,
                "write_date": _timestamp(
                    module["write_date"], "module write date"
                ),
            }
        )
    if [item["name"] for item in modules] != sorted(names) or "account" not in names:
        raise ReportDefinitionProjectionError(
            "module graph is incomplete or unsorted"
        )
    payload = {"schema_version": PROJECTION_SCHEMA_VERSION, "modules": modules}
    digest = _lower_sha(graph["digest"], "module graph digest")
    if not hmac.compare_digest(_sha(payload), digest):
        raise ReportDefinitionProjectionError("module graph digest differs")
    result = {**payload, "digest": digest}
    if result != value:
        raise ReportDefinitionProjectionError("module graph is not canonical")
    return result


def _report_definitions(
    reports: object,
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    if (
        not isinstance(reports, Sequence)
        or isinstance(reports, (str, bytes, bytearray))
        or not reports
        or len(reports) > 10_000
    ):
        raise ReportDefinitionProjectionError("report definitions are invalid")
    normalized: list[dict[str, object]] = []
    by_key: dict[str, dict[str, object]] = {}
    for raw in reports:
        row = _exact(raw, REPORT_FIELDS, "report definition")
        key = _xmlid(row["key"], "report key")
        xmlid = _xmlid(row["xmlid"], "report XMLID")
        assert key is not None and xmlid is not None
        if key != xmlid or key in by_key:
            raise ReportDefinitionProjectionError(
                "report identity is duplicated"
            )
        root = _xmlid(
            row["root_report_key"], "variant root key", nullable=True
        )
        sections = _sorted_strings(
            row["section_report_keys"], "section report keys", xmlids=True
        )
        options = _report_options(row["options"])
        columns = _columns(row["columns"], key)
        lines = _lines(row["lines"], key)
        handler = _string(
            row["custom_handler_model"],
            "custom handler model",
            nullable=True,
            maximum=256,
        )
        if handler is not None and _MODEL.fullmatch(handler) is None:
            raise ReportDefinitionProjectionError(
                "custom handler model is invalid"
            )
        report = {
            "active": _boolean(row["active"], "report active flag"),
            "availability_condition": _string(
                row["availability_condition"],
                "report availability",
                nullable=True,
            ),
            "chart_template": _string(
                row["chart_template"], "report chart", nullable=True
            ),
            "columns": columns,
            "country_code": _string(
                row["country_code"],
                "report country",
                nullable=True,
                maximum=8,
            ),
            "custom_handler_model": handler,
            "key": key,
            "lines": lines,
            "name": _string(row["name"], "report name"),
            "options": options,
            "root_report_key": root,
            "section_report_keys": sections,
            "sequence": _integer(row["sequence"], "report sequence"),
            "use_sections": _boolean(
                row["use_sections"], "report use-sections flag"
            ),
            "write_date": _timestamp(row["write_date"], "report write date"),
            "xmlid": xmlid,
        }
        if report != raw:
            raise ReportDefinitionProjectionError(
                "report definition is not canonical"
            )
        normalized.append(report)
        by_key[key] = report
    if [item["key"] for item in normalized] != sorted(by_key):
        raise ReportDefinitionProjectionError(
            "report definitions are not uniquely sorted"
        )
    for report in normalized:
        root = report["root_report_key"]
        if root is not None and root not in by_key:
            raise ReportDefinitionProjectionError("variant root is absent")
        if any(key not in by_key for key in report["section_report_keys"]):
            raise ReportDefinitionProjectionError("section report is absent")
    return normalized, by_key


def _report_options(value: object) -> dict[str, object]:
    row = _exact(value, REPORT_OPTION_FIELDS, "report options")
    result = {
        "allow_foreign_vat": _boolean(
            row["allow_foreign_vat"], "foreign VAT option"
        ),
        "currency_translation": _string(
            row["currency_translation"],
            "currency translation",
            nullable=True,
        ),
        "default_opening_date_filter": _string(
            row["default_opening_date_filter"],
            "default opening date",
            nullable=True,
        ),
        "filter_date_range": _boolean(
            row["filter_date_range"], "date range option"
        ),
        "filter_growth_comparison": _boolean(
            row["filter_growth_comparison"], "growth comparison option"
        ),
        "filter_hide_0_lines": _string(
            row["filter_hide_0_lines"],
            "zero-line option",
            nullable=True,
        ),
        "filter_journals": _boolean(
            row["filter_journals"], "journal option"
        ),
        "filter_multi_company": _string(
            row["filter_multi_company"],
            "multi-company option",
            nullable=True,
        ),
        "filter_period_comparison": _boolean(
            row["filter_period_comparison"], "period comparison option"
        ),
        "filter_show_draft": _boolean(
            row["filter_show_draft"], "draft option"
        ),
        "filter_unfold_all": _boolean(
            row["filter_unfold_all"], "unfold option"
        ),
        "filter_unreconciled": _boolean(
            row["filter_unreconciled"], "unreconciled option"
        ),
        "integer_rounding": _string(
            row["integer_rounding"], "integer rounding", nullable=True
        ),
        "load_more_limit": _integer(
            row["load_more_limit"], "load-more limit"
        ),
        "only_tax_exigible": _boolean(
            row["only_tax_exigible"], "tax exigibility"
        ),
        "prefix_groups_threshold": _integer(
            row["prefix_groups_threshold"], "prefix group threshold"
        ),
        "search_bar": _boolean(row["search_bar"], "search bar option"),
    }
    if result != value:
        raise ReportDefinitionProjectionError(
            "report options are not canonical"
        )
    return result


def _columns(value: object, report_key: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 50_000:
        raise ReportDefinitionProjectionError("report columns are invalid")
    result: list[dict[str, object]] = []
    keys: set[str] = set()
    for raw in value:
        row = _exact(raw, COLUMN_FIELDS, "report column")
        key = _string(row["key"], "column key")
        assert key is not None
        if not key.startswith(f"{report_key}/column/") or key in keys:
            raise ReportDefinitionProjectionError("column key is invalid")
        keys.add(key)
        item = {
            "blank_if_zero": _boolean(
                row["blank_if_zero"], "column blank flag"
            ),
            "custom_audit_action_xmlid": _xmlid(
                row["custom_audit_action_xmlid"],
                "column audit action",
                nullable=True,
            ),
            "expression_label": _string(
                row["expression_label"], "column expression label"
            ),
            "figure_type": _string(row["figure_type"], "column figure type"),
            "key": key,
            "name": _string(row["name"], "column name"),
            "sequence": _integer(row["sequence"], "column sequence"),
            "sortable": _boolean(row["sortable"], "column sortable flag"),
            "write_date": _timestamp(row["write_date"], "column write date"),
        }
        if item != raw:
            raise ReportDefinitionProjectionError(
                "report column is not canonical"
            )
        result.append(item)
    if [item["key"] for item in result] != sorted(keys):
        raise ReportDefinitionProjectionError("report columns are not sorted")
    return result


def _lines(value: object, report_key: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 200_000:
        raise ReportDefinitionProjectionError("report lines are invalid")
    result: list[dict[str, object]] = []
    keys: set[str] = set()
    for raw in value:
        row = _exact(raw, LINE_FIELDS, "report line")
        key = _string(row["key"], "line key")
        assert key is not None
        if not key.startswith(f"{report_key}/line/") or key in keys:
            raise ReportDefinitionProjectionError("line key is invalid")
        keys.add(key)
        item = {
            "action_xmlid": _xmlid(
                row["action_xmlid"], "line action", nullable=True
            ),
            "code": _string(row["code"], "line code", nullable=True),
            "expressions": _expressions(row["expressions"], key),
            "foldable": _boolean(row["foldable"], "line foldable flag"),
            "groupby": _string(row["groupby"], "line groupby", nullable=True),
            "hide_if_zero": _boolean(
                row["hide_if_zero"], "line hide flag"
            ),
            "hierarchy_level": _integer(
                row["hierarchy_level"], "line hierarchy level", maximum=1_000
            ),
            "horizontal_split_side": _string(
                row["horizontal_split_side"],
                "line horizontal split",
                nullable=True,
            ),
            "key": key,
            "name": _string(row["name"], "line name"),
            "parent_key": _string(
                row["parent_key"], "line parent key", nullable=True
            ),
            "print_on_new_page": _boolean(
                row["print_on_new_page"], "line page flag"
            ),
            "sequence": _integer(row["sequence"], "line sequence"),
            "user_groupby": _string(
                row["user_groupby"], "line user groupby", nullable=True
            ),
            "write_date": _timestamp(row["write_date"], "line write date"),
        }
        if item != raw:
            raise ReportDefinitionProjectionError(
                "report line is not canonical"
            )
        result.append(item)
    if [item["key"] for item in result] != sorted(keys):
        raise ReportDefinitionProjectionError("report lines are not sorted")
    parents = {str(item["key"]): item["parent_key"] for item in result}
    for key, parent in parents.items():
        if parent is not None and parent not in parents:
            raise ReportDefinitionProjectionError("line parent is absent")
        seen = {key}
        while parent is not None:
            if parent in seen:
                raise ReportDefinitionProjectionError(
                    "line hierarchy contains a cycle"
                )
            seen.add(parent)
            parent = parents[parent]
    return result


def _expressions(value: object, line_key: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 500_000:
        raise ReportDefinitionProjectionError("expressions are invalid")
    result: list[dict[str, object]] = []
    keys: set[str] = set()
    for raw in value:
        row = _exact(raw, EXPRESSION_FIELDS, "report expression")
        key = _string(row["key"], "expression key")
        assert key is not None
        if not key.startswith(f"{line_key}/expression/") or key in keys:
            raise ReportDefinitionProjectionError("expression key is invalid")
        keys.add(key)
        engine = _string(row["engine"], "expression engine")
        formula = _string(row["formula"], "expression formula")
        assert engine is not None and formula is not None
        item = {
            "auditable": _boolean(row["auditable"], "expression audit flag"),
            "blank_if_zero": _boolean(
                row["blank_if_zero"], "expression blank flag"
            ),
            "carryover_target": _string(
                row["carryover_target"],
                "expression carryover target",
                nullable=True,
            ),
            "date_scope": _string(row["date_scope"], "expression date scope"),
            "domain": _string(
                row["domain"], "expression domain", nullable=True
            ),
            "engine": engine,
            "figure_type": _string(
                row["figure_type"], "expression figure type", nullable=True
            ),
            "formula": formula,
            "green_on_positive": _boolean(
                row["green_on_positive"], "expression growth sign"
            ),
            "key": key,
            "label": _string(row["label"], "expression label"),
            "subformula": _string(
                row["subformula"], "expression subformula", nullable=True
            ),
            "write_date": _timestamp(
                row["write_date"], "expression write date"
            ),
        }
        expected_domain = formula if engine == "domain" else None
        if item["domain"] != expected_domain or item != raw:
            raise ReportDefinitionProjectionError(
                "report expression is not canonical"
            )
        result.append(item)
    if [item["key"] for item in result] != sorted(keys):
        raise ReportDefinitionProjectionError("expressions are not sorted")
    return result


def _root_source_projection(
    company_profile: Mapping[str, object],
    module_graph: Mapping[str, object],
    reports: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    values = (
        ("company_profile", 1, company_profile),
        ("module_graph", 1, module_graph),
        ("reports", len(reports), list(reports)),
    )
    projections = [
        {"name": name, "row_count": count, "sha256": _sha(value)}
        for name, count, value in values
    ]
    payload = {
        "projections": projections,
        "schema_version": PROJECTION_SCHEMA_VERSION,
    }
    return {**payload, "digest": _sha(payload)}


def build_root_definition_projection(
    *,
    database_uuid: object,
    company_id: object,
    family: object,
    kind: object,
    root_xmlid: object,
    company_profile: Mapping[str, object],
    module_graph: Mapping[str, object],
    reports: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Return the semantic closure for one fixed report root without I/O."""

    identity = _identity(
        database_uuid=database_uuid,
        company_id=company_id,
        family=family,
        kind=kind,
        root_xmlid=root_xmlid,
    )
    company = _company_profile(
        _plain(company_profile), company_id=int(identity["company_id"])
    )
    modules = _module_graph(_plain(module_graph))
    normalized_reports, report_by_key = _report_definitions(_plain(reports))
    variants_by_root: dict[str, set[str]] = {}
    for report in normalized_reports:
        root = report["root_report_key"]
        if root is not None:
            variants_by_root.setdefault(str(root), set()).add(str(report["key"]))

    fixed_root = str(identity["root_xmlid"])
    root_report = report_by_key.get(fixed_root)
    if root_report is None or root_report["root_report_key"] is not None:
        raise ReportDefinitionProjectionError(
            "fixed report root is absent or is a variant"
        )
    reachable = {fixed_root}
    frontier = [fixed_root]
    while frontier:
        current = frontier.pop()
        report = report_by_key[current]
        children = set(report["section_report_keys"])
        children.update(variants_by_root.get(current, set()))
        for child in sorted(children):
            if child not in reachable:
                reachable.add(child)
                frontier.append(child)
    root_reports = [report_by_key[key] for key in sorted(reachable)]
    source_projection = _root_source_projection(
        company, modules, root_reports
    )
    projection = {
        "baseline_identity": identity,
        "company_profile": company,
        "module_graph": modules,
        "reports": root_reports,
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "source_projection": source_projection,
    }
    canonical = _plain(projection)
    assert isinstance(canonical, dict)
    return canonical


def validate_root_definition_projection(value: object) -> None:
    """Validate an exact projection by rebuilding all derived fields."""

    document = _exact(value, ROOT_PROJECTION_FIELDS, "root projection")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != PROJECTION_SCHEMA_VERSION
    ):
        raise ReportDefinitionProjectionError("root projection version is invalid")
    identity = _exact(
        document["baseline_identity"],
        BASELINE_IDENTITY_FIELDS,
        "root projection identity",
    )
    rebuilt = build_root_definition_projection(
        database_uuid=identity["database_uuid"],
        company_id=identity["company_id"],
        family=identity["family"],
        kind=identity["kind"],
        root_xmlid=identity["root_xmlid"],
        company_profile=document["company_profile"],
        module_graph=document["module_graph"],
        reports=document["reports"],
    )
    if rebuilt != value:
        raise ReportDefinitionProjectionError("root projection is not canonical")


__all__ = [
    "BASELINE_IDENTITY_FIELDS",
    "COLUMN_FIELDS",
    "COMPANY_PROFILE_FIELDS",
    "CURRENCY_FIELDS",
    "DEPENDENCY_FIELDS",
    "EXPRESSION_FIELDS",
    "FISCAL_FIELDS",
    "LINE_FIELDS",
    "MODULE_FIELDS",
    "MODULE_GRAPH_FIELDS",
    "PROJECTION_SCHEMA_VERSION",
    "REPORT_FIELDS",
    "REPORT_OPTION_FIELDS",
    "ROOT_BASELINE_IDENTITIES",
    "ROOT_PROJECTION_FIELDS",
    "SOURCE_PROJECTION_FIELDS",
    "SOURCE_PROJECTION_ROW_FIELDS",
    "ReportDefinitionProjectionError",
    "build_root_definition_projection",
    "canonical_projection_json",
    "validate_root_definition_projection",
]
