#!/usr/bin/env python3
"""Capture an unapproved, release-independent Odoo report-definition candidate.

The capture path is deliberately read-only.  It does not learn or approve a
baseline, and its output cannot authorize production report execution.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from odoo_accounting_cli_v3.report_definition_projection import (
    BASELINE_IDENTITY_FIELDS,
    COLUMN_FIELDS,
    COMPANY_PROFILE_FIELDS as COMPANY_FIELDS,
    CURRENCY_FIELDS,
    DEPENDENCY_FIELDS,
    EXPRESSION_FIELDS,
    FISCAL_FIELDS,
    LINE_FIELDS,
    MODULE_FIELDS,
    MODULE_GRAPH_FIELDS,
    REPORT_FIELDS,
    REPORT_OPTION_FIELDS,
    ROOT_BASELINE_IDENTITIES,
    SOURCE_PROJECTION_FIELDS,
    SOURCE_PROJECTION_ROW_FIELDS as PROJECTION_FIELDS,
    ReportDefinitionProjectionError,
    build_root_definition_projection,
)

SCHEMA_VERSION = 1
DOCUMENT_TYPE = "odoo_accounting_report_definition_candidate"
FIXED_REPORT_XMLIDS = tuple(item[2] for item in ROOT_BASELINE_IDENTITIES)

TOP_LEVEL_FIELDS = (
    "candidate_is_approval",
    "captured_at",
    "company",
    "database",
    "definition_sha256",
    "document_type",
    "module_graph",
    "production_promotion_allowed",
    "report_roots",
    "reports",
    "schema_version",
    "source_projection",
)
DATABASE_FIELDS = ("name", "postgresql_system_identifier", "uuid")
REPORT_ROOT_FIELDS = (
    "baseline_identity",
    "definition_sha256",
    "report_key",
    "section_report_keys",
    "variant_report_keys",
)
BOUNDARY_COLUMNS = (
    "database_name",
    "search_path",
    "system_identifier",
    "transaction_isolation",
    "transaction_read_only",
)
IDENTITY_COLUMNS = ("database_name", "database_uuid", "system_identifier")
COMPANY_COLUMNS = (
    "account_fiscal_country_code",
    "chart_template",
    "company_id",
    "company_name",
    "country_code",
    "currency_decimal_places",
    "currency_name",
    "currency_rounding",
    "currency_symbol",
    "fiscalyear_last_day",
    "fiscalyear_last_month",
    "fiscalyear_lock_date",
    "hard_lock_date",
    "tax_lock_date",
    "write_date",
)
REPORT_COLUMNS = (
    "active",
    "availability_condition",
    "chart_template",
    "country_code",
    "custom_handler_model",
    "filter_allow_foreign_vat",
    "filter_currency_translation",
    "filter_date_range",
    "filter_default_opening_date",
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
    "name",
    "only_tax_exigible",
    "prefix_groups_threshold",
    "record_id",
    "root_record_id",
    "search_bar",
    "sequence",
    "use_sections",
    "write_date",
    "xmlid",
    "xmlid_count",
)
SECTION_COLUMNS = ("main_report_id", "sub_report_id")
COLUMN_COLUMNS = (
    "blank_if_zero",
    "custom_audit_action_id",
    "custom_audit_action_xmlid",
    "custom_audit_action_xmlid_count",
    "expression_label",
    "figure_type",
    "name",
    "record_id",
    "report_id",
    "sequence",
    "sortable",
    "write_date",
)
LINE_COLUMNS = (
    "action_id",
    "action_xmlid",
    "action_xmlid_count",
    "code",
    "foldable",
    "groupby",
    "hide_if_zero",
    "hierarchy_level",
    "horizontal_split_side",
    "name",
    "parent_id",
    "print_on_new_page",
    "record_id",
    "report_id",
    "sequence",
    "user_groupby",
    "write_date",
)
EXPRESSION_COLUMNS = (
    "auditable",
    "blank_if_zero",
    "carryover_target",
    "date_scope",
    "engine",
    "figure_type",
    "formula",
    "green_on_positive",
    "label",
    "line_id",
    "record_id",
    "subformula",
    "write_date",
)
MODULE_COLUMNS = (
    "latest_version",
    "module_id",
    "name",
    "write_date",
)
DEPENDENCY_COLUMNS = (
    "auto_install_required",
    "dependency_name",
    "module_id",
)

_DATABASE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_$-]{0,62}")
_XMLID = re.compile(r"[a-z][a-z0-9_]{0,127}\.[A-Za-z0-9_.-]{1,128}")
_MODEL = re.compile(r"[a-z][a-z0-9_.]{0,255}")
_MODULE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SYSTEM_IDENTIFIER = re.compile(r"[1-9][0-9]{0,19}")
_ISO_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_MAX_TEXT = 16_384
_MAX_REPORTS = 10_000
_MAX_SECTIONS = 50_000
_MAX_COLUMNS = 50_000
_MAX_LINES = 200_000
_MAX_EXPRESSIONS = 500_000
_MAX_MODULES = 8_192
_MAX_DEPENDENCIES = 100_000
_MAX_DSN_BYTES = 65_536
_DEVELOPMENT_DSN_ENV = "ODOO_ACCOUNTING_CLI_V3_REPORT_DEFINITION_DSN"


class CaptureError(RuntimeError):
    """The candidate could not be captured without weakening an invariant."""


class DatabaseAdapter(Protocol):
    """Minimal injectable database boundary used by the capture function."""

    def transaction_status(self) -> str:
        ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        ...

    def fetch(
        self,
        query_id: str,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        ...

    def rollback(self) -> None:
        ...


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise CaptureError("candidate value cannot be canonicalized") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def canonical_document_bytes(document: Mapping[str, object]) -> bytes:
    validate_candidate_document(document)
    return canonical_json(document) + b"\n"


def _exact_fields(
    value: object, fields: Sequence[str], label: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise CaptureError(f"{label} fields are invalid")
    return value


def _text(
    value: object,
    label: str,
    *,
    nullable: bool = False,
    maximum: int = _MAX_TEXT,
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
        raise CaptureError(f"{label} is invalid")
    return value


def _nullable_text(value: object, label: str) -> str | None:
    return _text(value, label, nullable=True)


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CaptureError(f"{label} is invalid")
    return value


def _optional_id(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label, minimum=1)


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise CaptureError(f"{label} is invalid")
    return value


def _uuid(value: object, label: str) -> str:
    text = _text(value, label, maximum=36)
    assert text is not None
    try:
        normalized = str(uuid.UUID(text))
    except (AttributeError, ValueError) as exc:
        raise CaptureError(f"{label} is invalid") from exc
    if normalized != text:
        raise CaptureError(f"{label} is not canonical")
    return text


def _database_name(value: object, label: str) -> str:
    text = _text(value, label, maximum=63)
    assert text is not None
    if _DATABASE_NAME.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _system_identifier(value: object, label: str) -> str:
    text = _text(value, label, maximum=20)
    assert text is not None
    if _SYSTEM_IDENTIFIER.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _xmlid(value: object, label: str, *, nullable: bool = False) -> str | None:
    text = _text(value, label, nullable=nullable, maximum=257)
    if text is not None and _XMLID.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _model(value: object, label: str, *, nullable: bool = False) -> str | None:
    text = _text(value, label, nullable=nullable, maximum=256)
    if text is not None and _MODEL.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _module(value: object, label: str) -> str:
    text = _text(value, label, maximum=128)
    assert text is not None
    if _MODULE.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _timestamp(value: object, label: str, *, nullable: bool = True) -> str | None:
    if nullable and value is None:
        return None
    if isinstance(value, datetime):
        current = value
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        return current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    text = _text(value, label, maximum=27)
    assert text is not None
    if _ISO_TIMESTAMP.fullmatch(text) is None:
        raise CaptureError(f"{label} is not an ISO microsecond timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureError(f"{label} is invalid") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
        != text
    ):
        raise CaptureError(f"{label} is not canonical")
    return text


def _date(value: object, label: str, *, nullable: bool = True) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is date:
        return value.isoformat()
    text = _text(value, label, maximum=10)
    assert text is not None
    if _ISO_DATE.fullmatch(text) is None:
        raise CaptureError(f"{label} is not an ISO date")
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise CaptureError(f"{label} is invalid") from exc
    if parsed.isoformat() != text:
        raise CaptureError(f"{label} is not canonical")
    return text


def _decimal_text(value: object, label: str, *, positive: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise CaptureError(f"{label} is invalid")
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise CaptureError(f"{label} is invalid") from exc
    if not number.is_finite() or (positive and number <= 0):
        raise CaptureError(f"{label} is invalid")
    normalized = format(number, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    if normalized in {"", "-0"}:
        normalized = "0"
    if type(value) is str and value != normalized:
        raise CaptureError(f"{label} is not canonical")
    return normalized


def _sha(value: object, label: str) -> str:
    text = _text(value, label, maximum=64)
    assert text is not None
    if _HEX64.fullmatch(text) is None:
        raise CaptureError(f"{label} is invalid")
    return text


def _json_primitives(value: object, label: str = "candidate") -> None:
    if value is None or type(value) in {str, int, bool}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise CaptureError(f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_primitives(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is not str:
                raise CaptureError(f"{label} has a non-string key")
            _json_primitives(item, f"{label}.{key}")
        return
    raise CaptureError(f"{label} contains a non-JSON value")


def _sorted_unique_strings(
    value: object,
    label: str,
    *,
    xmlids: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise CaptureError(f"{label} is invalid")
    normalized: list[str] = []
    for index, item in enumerate(value):
        if xmlids:
            current = _xmlid(item, f"{label}[{index}]")
        else:
            current = _text(item, f"{label}[{index}]")
        assert current is not None
        normalized.append(current)
    if normalized != sorted(normalized) or len(set(normalized)) != len(normalized):
        raise CaptureError(f"{label} is not uniquely sorted")
    return normalized


def _strict_rows(
    value: object,
    columns: Sequence[str],
    label: str,
    *,
    maximum: int,
) -> list[Mapping[str, object]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or len(value) > maximum
    ):
        raise CaptureError(f"{label} rows are invalid")
    rows: list[Mapping[str, object]] = []
    for row in value:
        rows.append(_exact_fields(row, columns, f"{label} row"))
    return rows


def _module_graph(
    module_rows: Sequence[Mapping[str, object]],
    dependency_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    by_id: dict[int, dict[str, object]] = {}
    names: set[str] = set()
    for row in module_rows:
        module_id = _integer(row["module_id"], "module id", minimum=1)
        name = _module(row["name"], "module name")
        version = _text(row["latest_version"], "module version", maximum=256)
        assert version is not None
        if module_id in by_id or name in names:
            raise CaptureError("installed module graph is duplicated")
        names.add(name)
        by_id[module_id] = {
            "dependencies": [],
            "latest_version": version,
            "name": name,
            "write_date": _timestamp(row["write_date"], "module write date"),
        }
    if not by_id or "account" not in names:
        raise CaptureError("installed module graph is incomplete")
    seen_edges: set[tuple[int, str]] = set()
    for row in dependency_rows:
        module_id = _integer(row["module_id"], "dependency module id", minimum=1)
        dependency = _module(row["dependency_name"], "dependency name")
        edge = (module_id, dependency)
        if module_id not in by_id or edge in seen_edges:
            raise CaptureError("installed module dependency graph is invalid")
        seen_edges.add(edge)
        dependencies = by_id[module_id]["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.append(
            {
                "auto_install_required": _boolean(
                    row["auto_install_required"],
                    "dependency auto-install flag",
                ),
                "name": dependency,
            }
        )
    modules = sorted(by_id.values(), key=lambda item: str(item["name"]))
    for item in modules:
        dependencies = item["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.sort(key=lambda dependency: str(dependency["name"]))
    payload = {"schema_version": SCHEMA_VERSION, "modules": modules}
    return {**payload, "digest": canonical_sha256(payload)}


def _company_document(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "account_fiscal_country_code": _nullable_text(
            row["account_fiscal_country_code"],
            "company accounting fiscal country code",
        ),
        "chart_template": _nullable_text(
            row["chart_template"], "company chart template"
        ),
        "company_id": _integer(row["company_id"], "company id", minimum=1),
        "country_code": _text(
            row["country_code"], "company country code", maximum=8
        ),
        "currency": {
            "decimal_places": _integer(
                row["currency_decimal_places"],
                "currency decimal places",
                maximum=12,
            ),
            "name": _text(row["currency_name"], "currency name", maximum=32),
            "rounding": _decimal_text(
                row["currency_rounding"], "currency rounding", positive=True
            ),
            "symbol": _text(
                row["currency_symbol"], "currency symbol", maximum=32
            ),
        },
        "fiscal": {
            "fiscalyear_last_day": _integer(
                row["fiscalyear_last_day"],
                "fiscal year last day",
                minimum=1,
                maximum=31,
            ),
            "fiscalyear_last_month": _text(
                row["fiscalyear_last_month"],
                "fiscal year last month",
                maximum=2,
            ),
            "fiscalyear_lock_date": _date(
                row["fiscalyear_lock_date"], "fiscal year lock date"
            ),
            "hard_lock_date": _date(row["hard_lock_date"], "hard lock date"),
            "tax_lock_date": _date(row["tax_lock_date"], "tax lock date"),
        },
        "name": _text(row["company_name"], "company name", maximum=256),
        "write_date": _timestamp(row["write_date"], "company write date"),
    }


def _external_xmlid(
    *,
    record_id: int | None,
    xmlid_count: object,
    xmlid_value: object,
    label: str,
) -> str | None:
    count = _integer(xmlid_count, f"{label} XMLID count", maximum=2_147_483_647)
    if record_id is None:
        if count != 0 or xmlid_value is not None:
            raise CaptureError(f"{label} XMLID binding is invalid")
        return None
    if count != 1:
        raise CaptureError(f"{label} lacks one unique XMLID")
    return _xmlid(xmlid_value, f"{label} XMLID")


def _report_documents(
    report_rows: Sequence[Mapping[str, object]],
    section_rows: Sequence[Mapping[str, object]],
    column_rows: Sequence[Mapping[str, object]],
    line_rows: Sequence[Mapping[str, object]],
    expression_rows: Sequence[Mapping[str, object]],
    *,
    database_uuid: str,
    company_profile: Mapping[str, object],
    module_graph: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    raw_reports: dict[int, Mapping[str, object]] = {}
    report_xmlids: dict[int, str] = {}
    xmlid_ids: dict[str, int] = {}
    for row in report_rows:
        record_id = _integer(row["record_id"], "report id", minimum=1)
        count = _integer(row["xmlid_count"], "report XMLID count")
        xmlid = _external_xmlid(
            record_id=record_id,
            xmlid_count=count,
            xmlid_value=row["xmlid"],
            label="report",
        )
        assert xmlid is not None
        if record_id in raw_reports or xmlid in xmlid_ids:
            raise CaptureError("report identity is duplicated")
        raw_reports[record_id] = row
        report_xmlids[record_id] = xmlid
        xmlid_ids[xmlid] = record_id
    if not raw_reports:
        raise CaptureError("report definition closure is empty")
    if any(xmlid not in xmlid_ids for xmlid in FIXED_REPORT_XMLIDS):
        raise CaptureError("a fixed report XMLID is missing")

    sections_by_main: dict[int, set[int]] = {
        report_id: set() for report_id in raw_reports
    }
    raw_edges: set[tuple[int, int]] = set()
    for row in section_rows:
        main_id = _integer(row["main_report_id"], "section main id", minimum=1)
        sub_id = _integer(row["sub_report_id"], "section report id", minimum=1)
        edge = (main_id, sub_id)
        if (
            main_id not in raw_reports
            or sub_id not in raw_reports
            or main_id == sub_id
            or edge in raw_edges
        ):
            raise CaptureError("report section graph is invalid")
        raw_edges.add(edge)
        sections_by_main[main_id].add(sub_id)

    root_ids = {xmlid_ids[xmlid] for xmlid in FIXED_REPORT_XMLIDS}
    graph: dict[int, set[int]] = {record_id: set() for record_id in raw_reports}
    for record_id, row in raw_reports.items():
        root_id = _optional_id(row["root_record_id"], "report root id")
        if root_id is not None:
            if root_id not in raw_reports or root_id == record_id:
                raise CaptureError("report variant graph is invalid")
            graph[root_id].add(record_id)
    for main_id, children in sections_by_main.items():
        graph[main_id].update(children)
    reachable = set(root_ids)
    frontier = list(root_ids)
    while frontier:
        parent = frontier.pop()
        for child in graph[parent]:
            if child not in reachable:
                reachable.add(child)
                frontier.append(child)
    if reachable != set(raw_reports):
        raise CaptureError("report definition closure has extra records")

    columns_by_report: dict[int, list[Mapping[str, object]]] = {
        report_id: [] for report_id in raw_reports
    }
    seen_column_ids: set[int] = set()
    for row in column_rows:
        record_id = _integer(row["record_id"], "report column id", minimum=1)
        report_id = _integer(row["report_id"], "column report id", minimum=1)
        if record_id in seen_column_ids or report_id not in raw_reports:
            raise CaptureError("report column projection is invalid")
        seen_column_ids.add(record_id)
        columns_by_report[report_id].append(row)

    lines_by_report: dict[int, list[Mapping[str, object]]] = {
        report_id: [] for report_id in raw_reports
    }
    raw_lines: dict[int, Mapping[str, object]] = {}
    for row in line_rows:
        record_id = _integer(row["record_id"], "report line id", minimum=1)
        report_id = _integer(row["report_id"], "line report id", minimum=1)
        if record_id in raw_lines or report_id not in raw_reports:
            raise CaptureError("report line projection is invalid")
        raw_lines[record_id] = row
        lines_by_report[report_id].append(row)

    expressions_by_line: dict[int, list[Mapping[str, object]]] = {
        line_id: [] for line_id in raw_lines
    }
    seen_expression_ids: set[int] = set()
    for row in expression_rows:
        record_id = _integer(
            row["record_id"], "report expression id", minimum=1
        )
        line_id = _integer(row["line_id"], "expression line id", minimum=1)
        if record_id in seen_expression_ids or line_id not in raw_lines:
            raise CaptureError("report expression projection is invalid")
        seen_expression_ids.add(record_id)
        expressions_by_line[line_id].append(row)

    report_documents: list[dict[str, object]] = []
    for report_id, raw in raw_reports.items():
        report_xmlid = report_xmlids[report_id]
        root_id = _optional_id(raw["root_record_id"], "report root id")
        if report_id in root_ids and root_id is not None:
            raise CaptureError("a fixed report is not a root")

        line_key_by_id = _line_keys(
            report_xmlid, lines_by_report[report_id], raw_lines
        )
        lines: list[dict[str, object]] = []
        for line_raw in lines_by_report[report_id]:
            line_id = _integer(line_raw["record_id"], "report line id", minimum=1)
            parent_id = _optional_id(line_raw["parent_id"], "line parent id")
            action_id = _optional_id(line_raw["action_id"], "line action id")
            expressions: list[dict[str, object]] = []
            labels: set[str] = set()
            for expression_raw in expressions_by_line[line_id]:
                label = _text(
                    expression_raw["label"],
                    "expression label",
                    maximum=256,
                )
                assert label is not None
                if label in labels:
                    raise CaptureError("report expression label is duplicated")
                labels.add(label)
                engine = _text(
                    expression_raw["engine"],
                    "expression engine",
                    maximum=64,
                )
                formula = _text(
                    expression_raw["formula"],
                    "expression formula",
                )
                assert engine is not None and formula is not None
                expressions.append(
                    {
                        "auditable": _boolean(
                            expression_raw["auditable"],
                            "expression auditable flag",
                        ),
                        "blank_if_zero": _boolean(
                            expression_raw["blank_if_zero"],
                            "expression blank-if-zero flag",
                        ),
                        "carryover_target": _nullable_text(
                            expression_raw["carryover_target"],
                            "expression carryover target",
                        ),
                        "date_scope": _text(
                            expression_raw["date_scope"],
                            "expression date scope",
                            maximum=64,
                        ),
                        "domain": formula if engine == "domain" else None,
                        "engine": engine,
                        "figure_type": _nullable_text(
                            expression_raw["figure_type"],
                            "expression figure type",
                        ),
                        "formula": formula,
                        "green_on_positive": _boolean(
                            expression_raw["green_on_positive"],
                            "expression growth sign",
                        ),
                        "key": f"{line_key_by_id[line_id]}/expression/{label}",
                        "label": label,
                        "subformula": _nullable_text(
                            expression_raw["subformula"],
                            "expression subformula",
                        ),
                        "write_date": _timestamp(
                            expression_raw["write_date"],
                            "expression write date",
                        ),
                    }
                )
            expressions.sort(key=lambda item: str(item["key"]))
            lines.append(
                {
                    "action_xmlid": _external_xmlid(
                        record_id=action_id,
                        xmlid_count=line_raw["action_xmlid_count"],
                        xmlid_value=line_raw["action_xmlid"],
                        label="line action",
                    ),
                    "code": _nullable_text(line_raw["code"], "line code"),
                    "expressions": expressions,
                    "foldable": _boolean(
                        line_raw["foldable"], "line foldable flag"
                    ),
                    "groupby": _nullable_text(line_raw["groupby"], "line groupby"),
                    "hide_if_zero": _boolean(
                        line_raw["hide_if_zero"], "line hide-if-zero flag"
                    ),
                    "hierarchy_level": _integer(
                        line_raw["hierarchy_level"],
                        "line hierarchy level",
                        maximum=1_000,
                    ),
                    "horizontal_split_side": _nullable_text(
                        line_raw["horizontal_split_side"],
                        "line horizontal split side",
                    ),
                    "key": line_key_by_id[line_id],
                    "name": _text(line_raw["name"], "line name"),
                    "parent_key": (
                        line_key_by_id[parent_id] if parent_id is not None else None
                    ),
                    "print_on_new_page": _boolean(
                        line_raw["print_on_new_page"],
                        "line print-on-new-page flag",
                    ),
                    "sequence": _integer(
                        line_raw["sequence"], "line sequence"
                    ),
                    "user_groupby": _nullable_text(
                        line_raw["user_groupby"], "line user groupby"
                    ),
                    "write_date": _timestamp(
                        line_raw["write_date"], "line write date"
                    ),
                }
            )
        lines.sort(key=lambda item: str(item["key"]))

        columns: list[dict[str, object]] = []
        column_keys: set[str] = set()
        for column_raw in columns_by_report[report_id]:
            semantic = {
                "expression_label": _text(
                    column_raw["expression_label"],
                    "column expression label",
                    maximum=256,
                ),
                "name": _text(column_raw["name"], "column name"),
                "sequence": _integer(
                    column_raw["sequence"], "column sequence"
                ),
            }
            key = (
                f"{report_xmlid}/column/"
                f"{canonical_sha256(semantic)}"
            )
            if key in column_keys:
                raise CaptureError("report column semantics are duplicated")
            column_keys.add(key)
            action_id = _optional_id(
                column_raw["custom_audit_action_id"],
                "column custom audit action id",
            )
            columns.append(
                {
                    "blank_if_zero": _boolean(
                        column_raw["blank_if_zero"],
                        "column blank-if-zero flag",
                    ),
                    "custom_audit_action_xmlid": _external_xmlid(
                        record_id=action_id,
                        xmlid_count=column_raw[
                            "custom_audit_action_xmlid_count"
                        ],
                        xmlid_value=column_raw[
                            "custom_audit_action_xmlid"
                        ],
                        label="column custom audit action",
                    ),
                    "expression_label": semantic["expression_label"],
                    "figure_type": _text(
                        column_raw["figure_type"],
                        "column figure type",
                        maximum=64,
                    ),
                    "key": key,
                    "name": semantic["name"],
                    "sequence": semantic["sequence"],
                    "sortable": _boolean(
                        column_raw["sortable"], "column sortable flag"
                    ),
                    "write_date": _timestamp(
                        column_raw["write_date"], "column write date"
                    ),
                }
            )
        columns.sort(key=lambda item: str(item["key"]))

        options = {
            "allow_foreign_vat": _boolean(
                raw["filter_allow_foreign_vat"],
                "report foreign VAT filter",
            ),
            "currency_translation": _nullable_text(
                raw["filter_currency_translation"],
                "report currency translation",
            ),
            "default_opening_date_filter": _nullable_text(
                raw["filter_default_opening_date"],
                "report default opening date filter",
            ),
            "filter_date_range": _boolean(
                raw["filter_date_range"], "report date filter"
            ),
            "filter_growth_comparison": _boolean(
                raw["filter_growth_comparison"],
                "report growth comparison filter",
            ),
            "filter_hide_0_lines": _nullable_text(
                raw["filter_hide_0_lines"], "report zero-line filter"
            ),
            "filter_journals": _boolean(
                raw["filter_journals"], "report journal filter"
            ),
            "filter_multi_company": _nullable_text(
                raw["filter_multi_company"], "report company filter"
            ),
            "filter_period_comparison": _boolean(
                raw["filter_period_comparison"],
                "report period comparison filter",
            ),
            "filter_show_draft": _boolean(
                raw["filter_show_draft"], "report draft filter"
            ),
            "filter_unfold_all": _boolean(
                raw["filter_unfold_all"], "report unfold filter"
            ),
            "filter_unreconciled": _boolean(
                raw["filter_unreconciled"], "report unreconciled filter"
            ),
            "integer_rounding": _nullable_text(
                raw["integer_rounding"], "report integer rounding"
            ),
            "load_more_limit": _integer(
                raw["load_more_limit"], "report load-more limit"
            ),
            "only_tax_exigible": _boolean(
                raw["only_tax_exigible"], "report tax exigibility"
            ),
            "prefix_groups_threshold": _integer(
                raw["prefix_groups_threshold"],
                "report prefix group threshold",
            ),
            "search_bar": _boolean(raw["search_bar"], "report search bar"),
        }
        report_documents.append(
            {
                "active": _boolean(raw["active"], "report active flag"),
                "availability_condition": _nullable_text(
                    raw["availability_condition"],
                    "report availability condition",
                ),
                "chart_template": _nullable_text(
                    raw["chart_template"], "report chart template"
                ),
                "columns": columns,
                "country_code": _nullable_text(
                    raw["country_code"], "report country code"
                ),
                "custom_handler_model": _model(
                    raw["custom_handler_model"],
                    "report custom handler model",
                    nullable=True,
                ),
                "key": report_xmlid,
                "lines": lines,
                "name": _text(raw["name"], "report name"),
                "options": options,
                "root_report_key": (
                    report_xmlids[root_id] if root_id is not None else None
                ),
                "section_report_keys": sorted(
                    report_xmlids[item]
                    for item in sections_by_main[report_id]
                ),
                "sequence": _integer(raw["sequence"], "report sequence"),
                "use_sections": _boolean(
                    raw["use_sections"], "report sections flag"
                ),
                "write_date": _timestamp(
                    raw["write_date"], "report write date"
                ),
                "xmlid": report_xmlid,
            }
        )
    report_documents.sort(key=lambda item: str(item["key"]))

    report_roots: list[dict[str, object]] = []
    for family, kind, fixed_xmlid in ROOT_BASELINE_IDENTITIES:
        root_id = xmlid_ids[fixed_xmlid]
        variants = sorted(
            report_xmlids[report_id]
            for report_id, raw in raw_reports.items()
            if _optional_id(raw["root_record_id"], "report root id") == root_id
        )
        identity = {
            "company_id": company_profile["company_id"],
            "database_uuid": database_uuid,
            "family": family,
            "kind": kind,
            "root_xmlid": fixed_xmlid,
        }
        projection = build_root_definition_projection(
            **identity,
            company_profile=company_profile,
            module_graph=module_graph,
            reports=report_documents,
        )
        report_roots.append(
            {
                "baseline_identity": identity,
                "definition_sha256": canonical_sha256(projection),
                "report_key": kind,
                "section_report_keys": sorted(
                    report_xmlids[item] for item in sections_by_main[root_id]
                ),
                "variant_report_keys": variants,
            }
        )
    return report_roots, report_documents


def _line_keys(
    report_xmlid: str,
    rows: Sequence[Mapping[str, object]],
    all_rows: Mapping[int, Mapping[str, object]],
) -> dict[int, str]:
    ids = {
        _integer(row["record_id"], "line id", minimum=1)
        for row in rows
    }
    parent_by_id: dict[int, int | None] = {}
    descriptors: dict[tuple[int | None, int, str, str | None], int] = {}
    for row in rows:
        line_id = _integer(row["record_id"], "line id", minimum=1)
        parent_id = _optional_id(row["parent_id"], "line parent id")
        if parent_id is not None:
            if parent_id not in ids or parent_id not in all_rows:
                raise CaptureError("line parent is outside its report")
            if _integer(
                all_rows[parent_id]["report_id"],
                "parent line report id",
                minimum=1,
            ) != _integer(row["report_id"], "line report id", minimum=1):
                raise CaptureError("line parent belongs to another report")
        parent_by_id[line_id] = parent_id
        descriptor = (
            parent_id,
            _integer(row["sequence"], "line sequence"),
            str(_text(row["name"], "line name")),
            _nullable_text(row["code"], "line code"),
        )
        if descriptor in descriptors:
            raise CaptureError("line semantic identity is duplicated")
        descriptors[descriptor] = line_id

    keys: dict[int, str] = {}
    used_keys: set[str] = set()
    active: set[int] = set()

    def resolve(line_id: int) -> str:
        if line_id in keys:
            return keys[line_id]
        if line_id in active:
            raise CaptureError("line hierarchy contains a cycle")
        active.add(line_id)
        row = all_rows[line_id]
        parent_id = parent_by_id[line_id]
        parent_key = resolve(parent_id) if parent_id is not None else report_xmlid
        code = _nullable_text(row["code"], "line code")
        if code is not None:
            semantic = {"code": code, "parent_key": parent_key}
        else:
            semantic = {
                "name": _text(row["name"], "line name"),
                "parent_key": parent_key,
                "sequence": _integer(row["sequence"], "line sequence"),
            }
        key = f"{report_xmlid}/line/{canonical_sha256(semantic)}"
        if key in used_keys:
            raise CaptureError("line semantic key is duplicated")
        keys[line_id] = key
        used_keys.add(key)
        active.remove(line_id)
        return key

    for line_id in sorted(ids):
        resolve(line_id)
    return keys


def _projection_document(
    database: Mapping[str, object],
    company: Mapping[str, object],
    report_roots: Sequence[Mapping[str, object]],
    reports: Sequence[Mapping[str, object]],
    module_graph: Mapping[str, object],
) -> dict[str, object]:
    columns: list[dict[str, object]] = []
    lines: list[dict[str, object]] = []
    expressions: list[dict[str, object]] = []
    for report in reports:
        report_key = report["key"]
        for column in report["columns"]:  # type: ignore[index]
            columns.append({"report_key": report_key, **column})
        for line in report["lines"]:  # type: ignore[index]
            line_without_expressions = {
                key: value
                for key, value in line.items()
                if key != "expressions"
            }
            lines.append({"report_key": report_key, **line_without_expressions})
            for expression in line["expressions"]:
                expressions.append(
                    {
                        "line_key": line["key"],
                        "report_key": report_key,
                        **expression,
                    }
                )
    modules = module_graph["modules"]
    dependencies: list[dict[str, object]] = []
    module_projection: list[dict[str, object]] = []
    for module in modules:  # type: ignore[union-attr]
        module_projection.append(
            {
                key: value
                for key, value in module.items()
                if key != "dependencies"
            }
        )
        for dependency in module["dependencies"]:
            dependencies.append(
                {"module": module["name"], **dependency}
            )
    values = (
        ("company", 1, company),
        ("database", 1, database),
        ("module_dependencies", len(dependencies), dependencies),
        ("modules", len(module_projection), module_projection),
        ("report_columns", len(columns), columns),
        ("report_expressions", len(expressions), expressions),
        ("report_lines", len(lines), lines),
        ("report_roots", len(report_roots), list(report_roots)),
        ("reports", len(reports), list(reports)),
    )
    projections = [
        {"name": name, "row_count": count, "sha256": canonical_sha256(value)}
        for name, count, value in values
    ]
    payload = {"schema_version": SCHEMA_VERSION, "projections": projections}
    return {**payload, "digest": canonical_sha256(payload)}


def definition_payload(document: Mapping[str, object]) -> dict[str, object]:
    return {
        "company": document["company"],
        "database": document["database"],
        "module_graph": document["module_graph"],
        "report_roots": document["report_roots"],
        "reports": document["reports"],
        "schema_version": document["schema_version"],
        "source_projection": document["source_projection"],
    }


def build_candidate_document(
    *,
    captured_at: object,
    database: Mapping[str, object],
    company: Mapping[str, object],
    report_roots: list[dict[str, object]],
    reports: list[dict[str, object]],
    module_graph: dict[str, object],
) -> dict[str, object]:
    source_projection = _projection_document(
        database, company, report_roots, reports, module_graph
    )
    document: dict[str, object] = {
        "candidate_is_approval": False,
        "captured_at": _timestamp(
            captured_at, "capture time", nullable=False
        ),
        "company": dict(company),
        "database": dict(database),
        "definition_sha256": "",
        "document_type": DOCUMENT_TYPE,
        "module_graph": module_graph,
        "production_promotion_allowed": False,
        "report_roots": report_roots,
        "reports": reports,
        "schema_version": SCHEMA_VERSION,
        "source_projection": source_projection,
    }
    document["definition_sha256"] = canonical_sha256(
        definition_payload(document)
    )
    validate_candidate_document(document)
    return document


def validate_candidate_document(document: Mapping[str, object]) -> None:
    top = _exact_fields(document, TOP_LEVEL_FIELDS, "candidate")
    if (
        type(top["schema_version"]) is not int
        or top["schema_version"] != SCHEMA_VERSION
        or top["document_type"] != DOCUMENT_TYPE
        or top["candidate_is_approval"] is not False
        or top["production_promotion_allowed"] is not False
    ):
        raise CaptureError("candidate safety identity is invalid")
    _timestamp(top["captured_at"], "candidate capture time", nullable=False)
    database = _validate_database(top["database"])
    company = _validate_company(top["company"])
    reports = _validate_reports(top["reports"])
    module_graph = _validate_module_graph(top["module_graph"])
    report_roots = _validate_report_roots(
        top["report_roots"],
        reports,
        database=database,
        company=company,
        module_graph=module_graph,
    )
    expected_projection = _projection_document(
        database, company, report_roots, reports, module_graph
    )
    if top["source_projection"] != expected_projection:
        raise CaptureError("candidate source projection differs")
    _validate_source_projection(top["source_projection"])
    expected_definition_sha = canonical_sha256(definition_payload(top))
    supplied_definition_sha = _sha(
        top["definition_sha256"], "candidate definition digest"
    )
    if not hmac.compare_digest(expected_definition_sha, supplied_definition_sha):
        raise CaptureError("candidate definition digest differs")
    _json_primitives(top)


def _validate_database(value: object) -> dict[str, object]:
    row = _exact_fields(value, DATABASE_FIELDS, "candidate database")
    return {
        "name": _database_name(row["name"], "candidate database name"),
        "postgresql_system_identifier": _system_identifier(
            row["postgresql_system_identifier"],
            "candidate PostgreSQL system identifier",
        ),
        "uuid": _uuid(row["uuid"], "candidate database UUID"),
    }


def _validate_company(value: object) -> dict[str, object]:
    row = _exact_fields(value, COMPANY_FIELDS, "candidate company")
    currency = _exact_fields(
        row["currency"], CURRENCY_FIELDS, "candidate currency"
    )
    fiscal = _exact_fields(row["fiscal"], FISCAL_FIELDS, "candidate fiscal")
    normalized = {
        "account_fiscal_country_code": _nullable_text(
            row["account_fiscal_country_code"],
            "candidate accounting fiscal country",
        ),
        "chart_template": _nullable_text(
            row["chart_template"], "candidate chart template"
        ),
        "company_id": _integer(
            row["company_id"], "candidate company id", minimum=1
        ),
        "country_code": _text(
            row["country_code"], "candidate country code", maximum=8
        ),
        "currency": {
            "decimal_places": _integer(
                currency["decimal_places"],
                "candidate currency decimal places",
                maximum=12,
            ),
            "name": _text(
                currency["name"], "candidate currency name", maximum=32
            ),
            "rounding": _decimal_text(
                currency["rounding"],
                "candidate currency rounding",
                positive=True,
            ),
            "symbol": _text(
                currency["symbol"], "candidate currency symbol", maximum=32
            ),
        },
        "fiscal": {
            "fiscalyear_last_day": _integer(
                fiscal["fiscalyear_last_day"],
                "candidate fiscal year last day",
                minimum=1,
                maximum=31,
            ),
            "fiscalyear_last_month": _text(
                fiscal["fiscalyear_last_month"],
                "candidate fiscal year last month",
                maximum=2,
            ),
            "fiscalyear_lock_date": _date(
                fiscal["fiscalyear_lock_date"],
                "candidate fiscal year lock date",
            ),
            "hard_lock_date": _date(
                fiscal["hard_lock_date"], "candidate hard lock date"
            ),
            "tax_lock_date": _date(
                fiscal["tax_lock_date"], "candidate tax lock date"
            ),
        },
        "name": _text(row["name"], "candidate company name", maximum=256),
        "write_date": _timestamp(
            row["write_date"], "candidate company write date"
        ),
    }
    if normalized != value:
        raise CaptureError("candidate company is not canonical")
    return normalized


def _validate_reports(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value or len(value) > _MAX_REPORTS:
        raise CaptureError("candidate reports are invalid")
    normalized: list[dict[str, object]] = []
    keys: set[str] = set()
    for index, item in enumerate(value):
        report = _exact_fields(item, REPORT_FIELDS, f"candidate report {index}")
        key = _xmlid(report["key"], f"candidate report {index} key")
        xmlid = _xmlid(report["xmlid"], f"candidate report {index} XMLID")
        assert key is not None and xmlid is not None
        if key != xmlid or key in keys:
            raise CaptureError("candidate report key is invalid")
        keys.add(key)
        options = _exact_fields(
            report["options"],
            REPORT_OPTION_FIELDS,
            f"candidate report {index} options",
        )
        columns = _validate_columns(report["columns"], key)
        lines = _validate_lines(report["lines"], key)
        current = {
            "active": _boolean(report["active"], "candidate report active flag"),
            "availability_condition": _nullable_text(
                report["availability_condition"],
                "candidate report availability",
            ),
            "chart_template": _nullable_text(
                report["chart_template"], "candidate report chart"
            ),
            "columns": columns,
            "country_code": _nullable_text(
                report["country_code"], "candidate report country"
            ),
            "custom_handler_model": _model(
                report["custom_handler_model"],
                "candidate report custom handler",
                nullable=True,
            ),
            "key": key,
            "lines": lines,
            "name": _text(report["name"], "candidate report name"),
            "options": {
                "allow_foreign_vat": _boolean(
                    options["allow_foreign_vat"],
                    "candidate foreign VAT option",
                ),
                "currency_translation": _nullable_text(
                    options["currency_translation"],
                    "candidate currency translation",
                ),
                "default_opening_date_filter": _nullable_text(
                    options["default_opening_date_filter"],
                    "candidate default opening date",
                ),
                "filter_date_range": _boolean(
                    options["filter_date_range"],
                    "candidate date range option",
                ),
                "filter_growth_comparison": _boolean(
                    options["filter_growth_comparison"],
                    "candidate growth comparison option",
                ),
                "filter_hide_0_lines": _nullable_text(
                    options["filter_hide_0_lines"],
                    "candidate zero-line option",
                ),
                "filter_journals": _boolean(
                    options["filter_journals"],
                    "candidate journal option",
                ),
                "filter_multi_company": _nullable_text(
                    options["filter_multi_company"],
                    "candidate multi-company option",
                ),
                "filter_period_comparison": _boolean(
                    options["filter_period_comparison"],
                    "candidate period comparison option",
                ),
                "filter_show_draft": _boolean(
                    options["filter_show_draft"],
                    "candidate draft option",
                ),
                "filter_unfold_all": _boolean(
                    options["filter_unfold_all"],
                    "candidate unfold option",
                ),
                "filter_unreconciled": _boolean(
                    options["filter_unreconciled"],
                    "candidate unreconciled option",
                ),
                "integer_rounding": _nullable_text(
                    options["integer_rounding"],
                    "candidate integer rounding",
                ),
                "load_more_limit": _integer(
                    options["load_more_limit"],
                    "candidate load-more limit",
                ),
                "only_tax_exigible": _boolean(
                    options["only_tax_exigible"],
                    "candidate tax exigibility",
                ),
                "prefix_groups_threshold": _integer(
                    options["prefix_groups_threshold"],
                    "candidate prefix threshold",
                ),
                "search_bar": _boolean(
                    options["search_bar"], "candidate search bar"
                ),
            },
            "root_report_key": _xmlid(
                report["root_report_key"],
                "candidate root report key",
                nullable=True,
            ),
            "section_report_keys": _sorted_unique_strings(
                report["section_report_keys"],
                "candidate report section keys",
                xmlids=True,
            ),
            "sequence": _integer(
                report["sequence"], "candidate report sequence"
            ),
            "use_sections": _boolean(
                report["use_sections"], "candidate use-sections flag"
            ),
            "write_date": _timestamp(
                report["write_date"], "candidate report write date"
            ),
            "xmlid": xmlid,
        }
        if current != item:
            raise CaptureError("candidate report is not canonical")
        normalized.append(current)
    if [report["key"] for report in normalized] != sorted(keys):
        raise CaptureError("candidate reports are not uniquely sorted")
    for report in normalized:
        if report["root_report_key"] is not None and report["root_report_key"] not in keys:
            raise CaptureError("candidate report root is missing")
        if any(key not in keys for key in report["section_report_keys"]):
            raise CaptureError("candidate report section is missing")
    return normalized


def _validate_columns(value: object, report_key: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_COLUMNS:
        raise CaptureError("candidate report columns are invalid")
    normalized: list[dict[str, object]] = []
    keys: set[str] = set()
    for item in value:
        row = _exact_fields(item, COLUMN_FIELDS, "candidate report column")
        key = _text(row["key"], "candidate column key")
        assert key is not None
        if not key.startswith(f"{report_key}/column/") or key in keys:
            raise CaptureError("candidate report column key is invalid")
        keys.add(key)
        current = {
            "blank_if_zero": _boolean(
                row["blank_if_zero"], "candidate column blank flag"
            ),
            "custom_audit_action_xmlid": _xmlid(
                row["custom_audit_action_xmlid"],
                "candidate column audit action",
                nullable=True,
            ),
            "expression_label": _text(
                row["expression_label"], "candidate column expression label"
            ),
            "figure_type": _text(
                row["figure_type"], "candidate column figure type"
            ),
            "key": key,
            "name": _text(row["name"], "candidate column name"),
            "sequence": _integer(
                row["sequence"], "candidate column sequence"
            ),
            "sortable": _boolean(
                row["sortable"], "candidate column sortable flag"
            ),
            "write_date": _timestamp(
                row["write_date"], "candidate column write date"
            ),
        }
        if current != item:
            raise CaptureError("candidate report column is not canonical")
        normalized.append(current)
    if [item["key"] for item in normalized] != sorted(keys):
        raise CaptureError("candidate report columns are not uniquely sorted")
    return normalized


def _validate_lines(value: object, report_key: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_LINES:
        raise CaptureError("candidate report lines are invalid")
    normalized: list[dict[str, object]] = []
    keys: set[str] = set()
    for item in value:
        row = _exact_fields(item, LINE_FIELDS, "candidate report line")
        key = _text(row["key"], "candidate line key")
        assert key is not None
        if not key.startswith(f"{report_key}/line/") or key in keys:
            raise CaptureError("candidate report line key is invalid")
        keys.add(key)
        current = {
            "action_xmlid": _xmlid(
                row["action_xmlid"],
                "candidate line action",
                nullable=True,
            ),
            "code": _nullable_text(row["code"], "candidate line code"),
            "expressions": _validate_expressions(row["expressions"], key),
            "foldable": _boolean(
                row["foldable"], "candidate line foldable flag"
            ),
            "groupby": _nullable_text(
                row["groupby"], "candidate line groupby"
            ),
            "hide_if_zero": _boolean(
                row["hide_if_zero"], "candidate line hide flag"
            ),
            "hierarchy_level": _integer(
                row["hierarchy_level"],
                "candidate line hierarchy level",
                maximum=1_000,
            ),
            "horizontal_split_side": _nullable_text(
                row["horizontal_split_side"],
                "candidate line horizontal split",
            ),
            "key": key,
            "name": _text(row["name"], "candidate line name"),
            "parent_key": _nullable_text(
                row["parent_key"], "candidate line parent key"
            ),
            "print_on_new_page": _boolean(
                row["print_on_new_page"],
                "candidate line page flag",
            ),
            "sequence": _integer(
                row["sequence"], "candidate line sequence"
            ),
            "user_groupby": _nullable_text(
                row["user_groupby"], "candidate line user groupby"
            ),
            "write_date": _timestamp(
                row["write_date"], "candidate line write date"
            ),
        }
        if current != item:
            raise CaptureError("candidate report line is not canonical")
        normalized.append(current)
    if [item["key"] for item in normalized] != sorted(keys):
        raise CaptureError("candidate report lines are not uniquely sorted")
    parents = {item["key"]: item["parent_key"] for item in normalized}
    for key, parent in parents.items():
        if parent is not None and parent not in parents:
            raise CaptureError("candidate line parent is missing")
        seen = {key}
        cursor = parent
        while cursor is not None:
            if cursor in seen:
                raise CaptureError("candidate line hierarchy contains a cycle")
            seen.add(cursor)
            cursor = parents[cursor]
    return normalized


def _validate_expressions(
    value: object, line_key: str
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_EXPRESSIONS:
        raise CaptureError("candidate expressions are invalid")
    normalized: list[dict[str, object]] = []
    keys: set[str] = set()
    for item in value:
        row = _exact_fields(
            item, EXPRESSION_FIELDS, "candidate report expression"
        )
        key = _text(row["key"], "candidate expression key")
        assert key is not None
        if not key.startswith(f"{line_key}/expression/") or key in keys:
            raise CaptureError("candidate expression key is invalid")
        keys.add(key)
        engine = _text(row["engine"], "candidate expression engine")
        formula = _text(row["formula"], "candidate expression formula")
        assert engine is not None and formula is not None
        expected_domain = formula if engine == "domain" else None
        current = {
            "auditable": _boolean(
                row["auditable"], "candidate expression audit flag"
            ),
            "blank_if_zero": _boolean(
                row["blank_if_zero"], "candidate expression blank flag"
            ),
            "carryover_target": _nullable_text(
                row["carryover_target"],
                "candidate expression carryover target",
            ),
            "date_scope": _text(
                row["date_scope"], "candidate expression date scope"
            ),
            "domain": _nullable_text(
                row["domain"], "candidate expression domain"
            ),
            "engine": engine,
            "figure_type": _nullable_text(
                row["figure_type"], "candidate expression figure type"
            ),
            "formula": formula,
            "green_on_positive": _boolean(
                row["green_on_positive"],
                "candidate expression growth sign",
            ),
            "key": key,
            "label": _text(row["label"], "candidate expression label"),
            "subformula": _nullable_text(
                row["subformula"], "candidate expression subformula"
            ),
            "write_date": _timestamp(
                row["write_date"], "candidate expression write date"
            ),
        }
        if current["domain"] != expected_domain or current != item:
            raise CaptureError("candidate report expression is not canonical")
        normalized.append(current)
    if [item["key"] for item in normalized] != sorted(keys):
        raise CaptureError("candidate expressions are not uniquely sorted")
    return normalized


def _validate_report_roots(
    value: object,
    reports: Sequence[Mapping[str, object]],
    *,
    database: Mapping[str, object],
    company: Mapping[str, object],
    module_graph: Mapping[str, object],
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(FIXED_REPORT_XMLIDS):
        raise CaptureError("candidate report roots are invalid")
    report_by_key = {str(report["key"]): report for report in reports}
    normalized: list[dict[str, object]] = []
    for index, (family, kind, fixed_xmlid) in enumerate(
        ROOT_BASELINE_IDENTITIES
    ):
        row = _exact_fields(
            value[index], REPORT_ROOT_FIELDS, "candidate report root"
        )
        identity = _exact_fields(
            row["baseline_identity"],
            BASELINE_IDENTITY_FIELDS,
            "candidate report baseline identity",
        )
        expected_identity = {
            "company_id": company["company_id"],
            "database_uuid": database["uuid"],
            "family": family,
            "kind": kind,
            "root_xmlid": fixed_xmlid,
        }
        if identity != expected_identity or row["report_key"] != kind:
            raise CaptureError("candidate fixed report binding differs")
        report = report_by_key.get(fixed_xmlid)
        if report is None:
            raise CaptureError("candidate fixed report is missing")
        if report["root_report_key"] is not None:
            raise CaptureError("candidate fixed report is not a root")
        sections = _sorted_unique_strings(
            row["section_report_keys"],
            "candidate root sections",
            xmlids=True,
        )
        variants = _sorted_unique_strings(
            row["variant_report_keys"],
            "candidate root variants",
            xmlids=True,
        )
        if (
            sections != report["section_report_keys"]
            or any(item not in report_by_key for item in sections + variants)
            or any(
                report_by_key[item]["root_report_key"] != fixed_xmlid
                for item in variants
            )
        ):
            raise CaptureError("candidate fixed report relations differ")
        try:
            projection = build_root_definition_projection(
                database_uuid=database["uuid"],
                company_id=company["company_id"],
                family=family,
                kind=kind,
                root_xmlid=fixed_xmlid,
                company_profile=company,
                module_graph=module_graph,
                reports=reports,
            )
        except ReportDefinitionProjectionError as exc:
            raise CaptureError(
                "candidate fixed report projection is invalid"
            ) from exc
        definition_sha = _sha(
            row["definition_sha256"],
            "candidate fixed report definition digest",
        )
        if not hmac.compare_digest(
            definition_sha, canonical_sha256(projection)
        ):
            raise CaptureError("candidate fixed report definition differs")
        normalized.append(
            {
                "baseline_identity": dict(identity),
                "definition_sha256": definition_sha,
                "report_key": kind,
                "section_report_keys": sections,
                "variant_report_keys": variants,
            }
        )
    if normalized != value:
        raise CaptureError("candidate report roots are not canonical")
    return normalized


def _validate_module_graph(value: object) -> dict[str, object]:
    graph = _exact_fields(value, MODULE_GRAPH_FIELDS, "candidate module graph")
    if (
        type(graph["schema_version"]) is not int
        or graph["schema_version"] != SCHEMA_VERSION
        or not isinstance(graph["modules"], list)
        or not graph["modules"]
        or len(graph["modules"]) > _MAX_MODULES
    ):
        raise CaptureError("candidate module graph is invalid")
    modules: list[dict[str, object]] = []
    names: set[str] = set()
    for item in graph["modules"]:
        module = _exact_fields(item, MODULE_FIELDS, "candidate module")
        name = _module(module["name"], "candidate module name")
        if name in names:
            raise CaptureError("candidate module name is duplicated")
        names.add(name)
        dependencies_raw = module["dependencies"]
        if (
            not isinstance(dependencies_raw, list)
            or len(dependencies_raw) > _MAX_DEPENDENCIES
        ):
            raise CaptureError("candidate module dependencies are invalid")
        dependencies: list[dict[str, object]] = []
        dependency_names: set[str] = set()
        for dependency_raw in dependencies_raw:
            dependency = _exact_fields(
                dependency_raw,
                DEPENDENCY_FIELDS,
                "candidate module dependency",
            )
            dependency_name = _module(
                dependency["name"], "candidate dependency name"
            )
            if dependency_name in dependency_names:
                raise CaptureError("candidate module dependency is duplicated")
            dependency_names.add(dependency_name)
            dependencies.append(
                {
                    "auto_install_required": _boolean(
                        dependency["auto_install_required"],
                        "candidate dependency auto-install flag",
                    ),
                    "name": dependency_name,
                }
            )
        if [item["name"] for item in dependencies] != sorted(dependency_names):
            raise CaptureError("candidate dependencies are not sorted")
        modules.append(
            {
                "dependencies": dependencies,
                "latest_version": _text(
                    module["latest_version"], "candidate module version"
                ),
                "name": name,
                "write_date": _timestamp(
                    module["write_date"], "candidate module write date"
                ),
            }
        )
    if [module["name"] for module in modules] != sorted(names) or "account" not in names:
        raise CaptureError("candidate modules are incomplete or unsorted")
    payload = {"schema_version": SCHEMA_VERSION, "modules": modules}
    digest = _sha(graph["digest"], "candidate module graph digest")
    if not hmac.compare_digest(canonical_sha256(payload), digest):
        raise CaptureError("candidate module graph digest differs")
    normalized = {**payload, "digest": digest}
    if normalized != value:
        raise CaptureError("candidate module graph is not canonical")
    return normalized


def _validate_source_projection(value: object) -> None:
    projection = _exact_fields(
        value, SOURCE_PROJECTION_FIELDS, "candidate source projection"
    )
    if (
        type(projection["schema_version"]) is not int
        or projection["schema_version"] != SCHEMA_VERSION
        or not isinstance(projection["projections"], list)
    ):
        raise CaptureError("candidate source projection is invalid")
    names: list[str] = []
    for item in projection["projections"]:
        row = _exact_fields(item, PROJECTION_FIELDS, "source projection row")
        names.append(str(_text(row["name"], "source projection name")))
        _integer(row["row_count"], "source projection row count")
        _sha(row["sha256"], "source projection digest")
    if names != sorted(names) or len(set(names)) != len(names):
        raise CaptureError("source projections are not uniquely sorted")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "projections": projection["projections"],
    }
    digest = _sha(projection["digest"], "source projection aggregate digest")
    if not hmac.compare_digest(canonical_sha256(payload), digest):
        raise CaptureError("source projection aggregate digest differs")


def _validate_boundary(
    row: Mapping[str, object],
    *,
    expected_database_name: str,
    expected_system_identifier: str,
) -> None:
    if (
        row["database_name"] != expected_database_name
        or row["system_identifier"] != expected_system_identifier
        or row["transaction_isolation"] != "repeatable read"
        or row["transaction_read_only"] != "on"
        or row["search_path"] != "pg_catalog"
    ):
        raise CaptureError("database read-only boundary differs")


def _validate_identity(
    row: Mapping[str, object],
    *,
    expected_database_name: str,
    expected_database_uuid: str,
    expected_system_identifier: str,
) -> dict[str, object]:
    database = {
        "name": _database_name(row["database_name"], "database name"),
        "postgresql_system_identifier": _system_identifier(
            row["system_identifier"], "PostgreSQL system identifier"
        ),
        "uuid": _uuid(row["database_uuid"], "database UUID"),
    }
    if database != {
        "name": expected_database_name,
        "postgresql_system_identifier": expected_system_identifier,
        "uuid": expected_database_uuid,
    }:
        raise CaptureError("database identity differs")
    return database


BEGIN_READ_ONLY = (
    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
)
SET_SEARCH_PATH = "SET LOCAL search_path = pg_catalog"
BOUNDARY_SQL = """
/* dev253:boundary */
SELECT
    pg_catalog.current_database()::text AS database_name,
    pg_catalog.current_setting('search_path')::text AS search_path,
    (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,
    pg_catalog.current_setting('transaction_isolation')::text AS transaction_isolation,
    pg_catalog.current_setting('transaction_read_only')::text AS transaction_read_only
""".strip()
IDENTITY_SQL = """
/* dev253:identity */
SELECT
    pg_catalog.current_database()::text AS database_name,
    parameter.value::text AS database_uuid,
    (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier
FROM ONLY public.ir_config_parameter AS parameter
WHERE parameter.key OPERATOR(pg_catalog.=) 'database.uuid'
ORDER BY parameter.id
""".strip()
COMPANY_SQL = """
/* dev253:company */
SELECT
    fiscal_country.code::text AS account_fiscal_country_code,
    pg_catalog.to_jsonb(company)->>'chart_template' AS chart_template,
    company.id AS company_id,
    company.name::text AS company_name,
    country.code::text AS country_code,
    currency.decimal_places AS currency_decimal_places,
    currency.name::text AS currency_name,
    currency.rounding::text AS currency_rounding,
    currency.symbol::text AS currency_symbol,
    (pg_catalog.to_jsonb(company)->>'fiscalyear_last_day')::integer AS fiscalyear_last_day,
    pg_catalog.to_jsonb(company)->>'fiscalyear_last_month' AS fiscalyear_last_month,
    (pg_catalog.to_jsonb(company)->>'fiscalyear_lock_date')::date AS fiscalyear_lock_date,
    (pg_catalog.to_jsonb(company)->>'hard_lock_date')::date AS hard_lock_date,
    (pg_catalog.to_jsonb(company)->>'tax_lock_date')::date AS tax_lock_date,
    company.write_date AS write_date
FROM ONLY public.res_company AS company
JOIN ONLY public.res_currency AS currency
  ON currency.id OPERATOR(pg_catalog.=) company.currency_id
LEFT JOIN ONLY public.res_country AS country
  ON country.id OPERATOR(pg_catalog.=) company.country_id
LEFT JOIN ONLY public.res_country AS fiscal_country
  ON fiscal_country.id OPERATOR(pg_catalog.=)
     (pg_catalog.to_jsonb(company)->>'account_fiscal_country_id')::integer
WHERE company.id OPERATOR(pg_catalog.=) %s
""".strip()

_REPORT_CTE = """
WITH RECURSIVE
fixed(module, name) AS (
    VALUES
      ('account', 'generic_tax_report'),
      ('account_reports', 'balance_sheet'),
      ('account_reports', 'cash_flow_report'),
      ('account_reports', 'profit_and_loss')
),
roots(record_id) AS (
    SELECT data.res_id
    FROM fixed
    JOIN ONLY public.ir_model_data AS data
      ON data.module OPERATOR(pg_catalog.=) fixed.module
     AND data.name OPERATOR(pg_catalog.=) fixed.name
     AND data.model OPERATOR(pg_catalog.=) 'account.report'
),
edges(parent_id, child_id) AS (
    SELECT report.root_report_id, report.id
    FROM ONLY public.account_report AS report
    WHERE report.root_report_id IS NOT NULL
    UNION
    SELECT relation.main_report_id, relation.sub_report_id
    FROM public.account_report_section_rel AS relation
),
selected(record_id) AS (
    SELECT roots.record_id FROM roots
    UNION
    SELECT edges.child_id
    FROM selected
    JOIN edges ON edges.parent_id OPERATOR(pg_catalog.=) selected.record_id
),
xmlids(record_id, xmlid_count, xmlid) AS (
    SELECT
      data.res_id,
      pg_catalog.count(*)::integer,
      pg_catalog.min(data.module || '.' || data.name)
    FROM ONLY public.ir_model_data AS data
    WHERE data.model OPERATOR(pg_catalog.=) 'account.report'
    GROUP BY data.res_id
)
"""

REPORT_SQL = (_REPORT_CTE + """
SELECT
    report.active,
    pg_catalog.to_jsonb(report)->>'availability_condition' AS availability_condition,
    pg_catalog.to_jsonb(report)->>'chart_template' AS chart_template,
    country.code::text AS country_code,
    handler.model::text AS custom_handler_model,
    (pg_catalog.to_jsonb(report)->>'allow_foreign_vat')::boolean AS filter_allow_foreign_vat,
    pg_catalog.to_jsonb(report)->>'currency_translation' AS filter_currency_translation,
    (pg_catalog.to_jsonb(report)->>'filter_date_range')::boolean AS filter_date_range,
    pg_catalog.to_jsonb(report)->>'default_opening_date_filter' AS filter_default_opening_date,
    (pg_catalog.to_jsonb(report)->>'filter_growth_comparison')::boolean AS filter_growth_comparison,
    pg_catalog.to_jsonb(report)->>'filter_hide_0_lines' AS filter_hide_0_lines,
    (pg_catalog.to_jsonb(report)->>'filter_journals')::boolean AS filter_journals,
    pg_catalog.to_jsonb(report)->>'filter_multi_company' AS filter_multi_company,
    (pg_catalog.to_jsonb(report)->>'filter_period_comparison')::boolean AS filter_period_comparison,
    (pg_catalog.to_jsonb(report)->>'filter_show_draft')::boolean AS filter_show_draft,
    (pg_catalog.to_jsonb(report)->>'filter_unfold_all')::boolean AS filter_unfold_all,
    (pg_catalog.to_jsonb(report)->>'filter_unreconciled')::boolean AS filter_unreconciled,
    pg_catalog.to_jsonb(report)->>'integer_rounding' AS integer_rounding,
    report.load_more_limit,
    pg_catalog.coalesce(
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(report), 'name', 'en_US'),
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(report), 'name')
    ) AS name,
    report.only_tax_exigible,
    report.prefix_groups_threshold,
    report.id AS record_id,
    report.root_report_id AS root_record_id,
    report.search_bar,
    report.sequence,
    report.use_sections,
    report.write_date,
    xmlids.xmlid,
    pg_catalog.coalesce(xmlids.xmlid_count, 0) AS xmlid_count
FROM selected
JOIN ONLY public.account_report AS report
  ON report.id OPERATOR(pg_catalog.=) selected.record_id
LEFT JOIN xmlids ON xmlids.record_id OPERATOR(pg_catalog.=) report.id
LEFT JOIN ONLY public.res_country AS country
  ON country.id OPERATOR(pg_catalog.=) report.country_id
LEFT JOIN ONLY public.ir_model AS handler
  ON handler.id OPERATOR(pg_catalog.=)
     (pg_catalog.to_jsonb(report)->>'custom_handler_model_id')::integer
ORDER BY report.id
""").strip()

SECTION_SQL = (_REPORT_CTE + """
SELECT relation.main_report_id, relation.sub_report_id
FROM public.account_report_section_rel AS relation
JOIN selected AS main_selected
  ON main_selected.record_id OPERATOR(pg_catalog.=) relation.main_report_id
JOIN selected AS sub_selected
  ON sub_selected.record_id OPERATOR(pg_catalog.=) relation.sub_report_id
ORDER BY relation.main_report_id, relation.sub_report_id
""").strip()

COLUMN_SQL = (_REPORT_CTE + """
SELECT
    column_definition.blank_if_zero,
    column_definition.custom_audit_action_id,
    action_xmlid.xmlid AS custom_audit_action_xmlid,
    pg_catalog.coalesce(action_xmlid.xmlid_count, 0) AS custom_audit_action_xmlid_count,
    column_definition.expression_label::text AS expression_label,
    column_definition.figure_type::text AS figure_type,
    pg_catalog.coalesce(
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(column_definition), 'name', 'en_US'),
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(column_definition), 'name')
    ) AS name,
    column_definition.id AS record_id,
    column_definition.report_id,
    column_definition.sequence,
    column_definition.sortable,
    column_definition.write_date
FROM ONLY public.account_report_column AS column_definition
JOIN selected ON selected.record_id OPERATOR(pg_catalog.=) column_definition.report_id
LEFT JOIN LATERAL (
    SELECT
      pg_catalog.count(*)::integer AS xmlid_count,
      pg_catalog.min(data.module || '.' || data.name) AS xmlid
    FROM ONLY public.ir_model_data AS data
    WHERE data.model OPERATOR(pg_catalog.=) 'ir.actions.act_window'
      AND data.res_id OPERATOR(pg_catalog.=) column_definition.custom_audit_action_id
) AS action_xmlid ON true
ORDER BY column_definition.id
""").strip()

LINE_SQL = (_REPORT_CTE + """
SELECT
    line.action_id,
    action_xmlid.xmlid AS action_xmlid,
    pg_catalog.coalesce(action_xmlid.xmlid_count, 0) AS action_xmlid_count,
    line.code::text AS code,
    line.foldable,
    line.groupby::text AS groupby,
    line.hide_if_zero,
    line.hierarchy_level,
    line.horizontal_split_side::text AS horizontal_split_side,
    pg_catalog.coalesce(
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(line), 'name', 'en_US'),
      pg_catalog.jsonb_extract_path_text(pg_catalog.to_jsonb(line), 'name')
    ) AS name,
    line.parent_id,
    line.print_on_new_page,
    line.id AS record_id,
    line.report_id,
    line.sequence,
    line.user_groupby::text AS user_groupby,
    line.write_date
FROM ONLY public.account_report_line AS line
JOIN selected ON selected.record_id OPERATOR(pg_catalog.=) line.report_id
LEFT JOIN LATERAL (
    SELECT
      pg_catalog.count(*)::integer AS xmlid_count,
      pg_catalog.min(data.module || '.' || data.name) AS xmlid
    FROM ONLY public.ir_model_data AS data
    WHERE data.model OPERATOR(pg_catalog.=) 'ir.actions.actions'
      AND data.res_id OPERATOR(pg_catalog.=) line.action_id
) AS action_xmlid ON true
ORDER BY line.id
""").strip()

EXPRESSION_SQL = (_REPORT_CTE + """
SELECT
    expression.auditable,
    expression.blank_if_zero,
    expression.carryover_target::text AS carryover_target,
    expression.date_scope::text AS date_scope,
    expression.engine::text AS engine,
    expression.figure_type::text AS figure_type,
    expression.formula::text AS formula,
    expression.green_on_positive,
    expression.label::text AS label,
    expression.report_line_id AS line_id,
    expression.id AS record_id,
    expression.subformula::text AS subformula,
    expression.write_date
FROM ONLY public.account_report_expression AS expression
JOIN ONLY public.account_report_line AS line
  ON line.id OPERATOR(pg_catalog.=) expression.report_line_id
JOIN selected ON selected.record_id OPERATOR(pg_catalog.=) line.report_id
ORDER BY expression.id
""").strip()

MODULE_SQL = """
/* dev253:modules */
SELECT
    module.latest_version::text AS latest_version,
    module.id AS module_id,
    module.name::text AS name,
    module.write_date
FROM ONLY public.ir_module_module AS module
WHERE module.state OPERATOR(pg_catalog.=) 'installed'
ORDER BY module.name, module.id
""".strip()
DEPENDENCY_SQL = """
/* dev253:module_dependencies */
SELECT
    pg_catalog.coalesce(
      (pg_catalog.to_jsonb(dependency)->>'auto_install_required')::boolean,
      false
    ) AS auto_install_required,
    dependency.name::text AS dependency_name,
    dependency.module_id
FROM ONLY public.ir_module_module_dependency AS dependency
JOIN ONLY public.ir_module_module AS module
  ON module.id OPERATOR(pg_catalog.=) dependency.module_id
WHERE module.state OPERATOR(pg_catalog.=) 'installed'
ORDER BY dependency.module_id, dependency.name
""".strip()


def capture_report_definition(
    adapter: DatabaseAdapter,
    *,
    expected_database_name: str,
    expected_database_uuid: str,
    expected_postgresql_system_identifier: str,
    company_id: int,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    expected_database_name = _database_name(
        expected_database_name, "expected database name"
    )
    expected_database_uuid = _uuid(
        expected_database_uuid, "expected database UUID"
    )
    expected_postgresql_system_identifier = _system_identifier(
        expected_postgresql_system_identifier,
        "expected PostgreSQL system identifier",
    )
    company_id = _integer(company_id, "expected company id", minimum=1)
    clock = clock or (lambda: datetime.now(timezone.utc))
    candidate: dict[str, object] | None = None
    capture_error: BaseException | None = None
    try:
        if adapter.transaction_status() != "IDLE":
            raise CaptureError("database adapter is not idle")
        adapter.execute(BEGIN_READ_ONLY)
        if adapter.transaction_status() != "INTRANS":
            raise CaptureError("read-only transaction did not start")
        adapter.execute(SET_SEARCH_PATH)
        if adapter.transaction_status() != "INTRANS":
            raise CaptureError("database transaction state changed")

        boundary_before = _fetch_rows(
            adapter,
            "boundary_before",
            BOUNDARY_SQL,
            (),
            BOUNDARY_COLUMNS,
            maximum=1,
            exact=1,
        )[0]
        _validate_boundary(
            boundary_before,
            expected_database_name=expected_database_name,
            expected_system_identifier=expected_postgresql_system_identifier,
        )
        identity_before = _fetch_rows(
            adapter,
            "identity_before",
            IDENTITY_SQL,
            (),
            IDENTITY_COLUMNS,
            maximum=2,
            exact=1,
        )[0]
        database = _validate_identity(
            identity_before,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
            expected_system_identifier=expected_postgresql_system_identifier,
        )
        company_rows = _fetch_rows(
            adapter,
            "company",
            COMPANY_SQL,
            (company_id,),
            COMPANY_COLUMNS,
            maximum=1,
            exact=1,
        )
        company = _company_document(company_rows[0])
        if company["company_id"] != company_id:
            raise CaptureError("company binding differs")

        report_rows = _fetch_rows(
            adapter,
            "reports",
            REPORT_SQL,
            (),
            REPORT_COLUMNS,
            maximum=_MAX_REPORTS,
        )
        section_rows = _fetch_rows(
            adapter,
            "sections",
            SECTION_SQL,
            (),
            SECTION_COLUMNS,
            maximum=_MAX_SECTIONS,
        )
        column_rows = _fetch_rows(
            adapter,
            "columns",
            COLUMN_SQL,
            (),
            COLUMN_COLUMNS,
            maximum=_MAX_COLUMNS,
        )
        line_rows = _fetch_rows(
            adapter,
            "lines",
            LINE_SQL,
            (),
            LINE_COLUMNS,
            maximum=_MAX_LINES,
        )
        expression_rows = _fetch_rows(
            adapter,
            "expressions",
            EXPRESSION_SQL,
            (),
            EXPRESSION_COLUMNS,
            maximum=_MAX_EXPRESSIONS,
        )
        module_rows = _fetch_rows(
            adapter,
            "modules",
            MODULE_SQL,
            (),
            MODULE_COLUMNS,
            maximum=_MAX_MODULES,
        )
        dependency_rows = _fetch_rows(
            adapter,
            "module_dependencies",
            DEPENDENCY_SQL,
            (),
            DEPENDENCY_COLUMNS,
            maximum=_MAX_DEPENDENCIES,
        )
        identity_after = _fetch_rows(
            adapter,
            "identity_after",
            IDENTITY_SQL,
            (),
            IDENTITY_COLUMNS,
            maximum=2,
            exact=1,
        )[0]
        if identity_after != identity_before:
            raise CaptureError("database identity changed during capture")
        boundary_after = _fetch_rows(
            adapter,
            "boundary_after",
            BOUNDARY_SQL,
            (),
            BOUNDARY_COLUMNS,
            maximum=1,
            exact=1,
        )[0]
        _validate_boundary(
            boundary_after,
            expected_database_name=expected_database_name,
            expected_system_identifier=expected_postgresql_system_identifier,
        )
        module_graph = _module_graph(module_rows, dependency_rows)
        report_roots, reports = _report_documents(
            report_rows,
            section_rows,
            column_rows,
            line_rows,
            expression_rows,
            database_uuid=expected_database_uuid,
            company_profile=company,
            module_graph=module_graph,
        )
        candidate = build_candidate_document(
            captured_at=clock(),
            database=database,
            company=company,
            report_roots=report_roots,
            reports=reports,
            module_graph=module_graph,
        )
    except BaseException as exc:
        capture_error = exc
    try:
        adapter.rollback()
        if adapter.transaction_status() != "IDLE":
            raise CaptureError("database adapter did not return to idle")
    except BaseException as exc:
        raise CaptureError("database rollback boundary failed") from exc
    if capture_error is not None:
        if isinstance(capture_error, CaptureError):
            raise capture_error
        raise CaptureError("database capture query failed") from capture_error
    if candidate is None:
        raise CaptureError("database capture produced no candidate")
    validate_candidate_document(candidate)
    return candidate


def _fetch_rows(
    adapter: DatabaseAdapter,
    query_id: str,
    statement: str,
    parameters: Sequence[object],
    columns: Sequence[str],
    *,
    maximum: int,
    exact: int | None = None,
) -> list[Mapping[str, object]]:
    if adapter.transaction_status() != "INTRANS":
        raise CaptureError("database transaction state changed")
    try:
        raw = adapter.fetch(query_id, statement, parameters)
    except Exception as exc:
        raise CaptureError(f"{query_id} query failed") from exc
    if adapter.transaction_status() != "INTRANS":
        raise CaptureError("database transaction state changed")
    rows = _strict_rows(raw, columns, query_id, maximum=maximum)
    if exact is not None and len(rows) != exact:
        raise CaptureError(f"{query_id} row count differs")
    return rows


class PsycopgAdapter:
    """Production adapter; psycopg2 is imported only when explicitly used."""

    def __init__(self, connection: object, extensions: object) -> None:
        self._connection = connection
        self._extensions = extensions

    @classmethod
    def connect(cls, dsn: str) -> "PsycopgAdapter":
        if type(dsn) is not str or not dsn:
            raise CaptureError("database connection environment is empty")
        try:
            import psycopg2  # type: ignore[import-not-found]
            from psycopg2 import extensions  # type: ignore[import-not-found]

            connection = psycopg2.connect(dsn)
            connection.autocommit = False
        except Exception as exc:
            raise CaptureError("database connection failed") from exc
        return cls(connection, extensions)

    def transaction_status(self) -> str:
        try:
            raw = self._connection.get_transaction_status()
            values = {
                self._extensions.TRANSACTION_STATUS_IDLE: "IDLE",
                self._extensions.TRANSACTION_STATUS_ACTIVE: "ACTIVE",
                self._extensions.TRANSACTION_STATUS_INTRANS: "INTRANS",
                self._extensions.TRANSACTION_STATUS_INERROR: "INERROR",
                self._extensions.TRANSACTION_STATUS_UNKNOWN: "UNKNOWN",
            }
            return values.get(raw, "UNKNOWN")
        except Exception as exc:
            raise CaptureError("database transaction status is unavailable") from exc

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(statement, tuple(parameters))
        except Exception as exc:
            raise CaptureError("database boundary statement failed") from exc

    def fetch(
        self,
        query_id: str,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        del query_id
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(statement, tuple(parameters))
                description = cursor.description
                if description is None:
                    raise CaptureError("database query returned no columns")
                names = [str(item.name) for item in description]
                return [
                    dict(zip(names, row, strict=True))
                    for row in cursor.fetchall()
                ]
        except CaptureError:
            raise
        except Exception as exc:
            raise CaptureError("database query failed") from exc

    def rollback(self) -> None:
        try:
            self._connection.rollback()
        except Exception as exc:
            raise CaptureError("database rollback failed") from exc

    def close(self) -> None:
        try:
            self._connection.close()
        except Exception as exc:
            raise CaptureError("database close failed") from exc


def _write_new(path: Path, payload: bytes) -> None:
    requested = path.absolute()
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as exc:
        raise CaptureError("output parent is unavailable") from exc
    if os.name == "posix":
        root = Path("/root")
        try:
            parent.relative_to(root)
        except ValueError:
            pass
        else:
            raise CaptureError("output beneath /root is forbidden")
    if requested.parent != parent:
        raise CaptureError("output parent must be canonical")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(requested, flags, 0o600)
        created = True
        total = 0
        while total < len(payload):
            total += os.write(descriptor, payload[total:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                requested.unlink()
            except OSError:
                pass
        raise CaptureError("output file could not be created") from exc


def _dsn_text(payload: bytes) -> str:
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > _MAX_DSN_BYTES
        or b"\x00" in payload
        or b"\r" in payload
    ):
        raise CaptureError("database connection material is invalid")
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    if not payload or payload.endswith(b"\n"):
        raise CaptureError("database connection material is invalid")
    try:
        value = payload.decode("utf-8")
    except UnicodeError as exc:
        raise CaptureError("database connection material is invalid") from exc
    if value != value.strip():
        raise CaptureError("database connection material is not canonical")
    return value


def _read_dsn_fd(descriptor: int) -> str:
    if type(descriptor) is not int or descriptor < 3:
        raise CaptureError("private DSN descriptor is invalid")
    payload = bytearray()
    try:
        while True:
            block = os.read(descriptor, min(8_192, _MAX_DSN_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
            if len(payload) > _MAX_DSN_BYTES:
                raise CaptureError("database connection material is too large")
    except CaptureError:
        raise
    except OSError as exc:
        raise CaptureError("private DSN descriptor cannot be read") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return _dsn_text(bytes(payload))


def _read_dsn_file(path: Path) -> str:
    requested = path.absolute()
    descriptor: int | None = None
    try:
        before = requested.lstat()
        if (
            requested.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_DSN_BYTES
        ):
            raise CaptureError("DSN file metadata is unsafe")
        if os.name == "posix" and (
            before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise CaptureError("DSN file must be root-owned mode 0600")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(requested, flags)
        opened = os.fstat(descriptor)
        fingerprint = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(opened):
            raise CaptureError("DSN file changed while opening")
        payload = bytearray()
        while True:
            block = os.read(
                descriptor, min(8_192, _MAX_DSN_BYTES + 1 - len(payload))
            )
            if not block:
                break
            payload.extend(block)
            if len(payload) > _MAX_DSN_BYTES:
                raise CaptureError("database connection material is too large")
        after = os.fstat(descriptor)
        final = requested.lstat()
        if (
            fingerprint(opened) != fingerprint(after)
            or fingerprint(after) != fingerprint(final)
        ):
            raise CaptureError("DSN file changed while reading")
        return _dsn_text(bytes(payload))
    except CaptureError:
        raise
    except OSError as exc:
        raise CaptureError("DSN file cannot be read safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture an unapproved Odoo report-definition candidate."
    )
    parser.add_argument("--database-name", required=True)
    parser.add_argument("--database-uuid", required=True)
    parser.add_argument("--postgresql-system-identifier", required=True)
    parser.add_argument("--company-id", required=True, type=int)
    parser.add_argument(
        "--environment",
        choices=("development", "test", "production"),
        required=True,
    )
    connection = parser.add_mutually_exclusive_group(required=True)
    connection.add_argument(
        "--dsn-fd",
        type=int,
        help="inherited private descriptor containing the DSN",
    )
    connection.add_argument(
        "--dsn-file",
        type=Path,
        help="root-owned mode-0600 DSN file (not the formal production path)",
    )
    connection.add_argument(
        "--allow-development-dsn-env",
        action="store_true",
        help="use the fixed DSN environment variable in development only",
    )
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    adapter: PsycopgAdapter | None = None
    try:
        if arguments.dsn_fd is not None:
            dsn = _read_dsn_fd(arguments.dsn_fd)
        elif arguments.dsn_file is not None:
            if arguments.environment == "production":
                raise CaptureError(
                    "production capture requires a sealed private DSN descriptor"
                )
            dsn = _read_dsn_file(arguments.dsn_file)
        else:
            if (
                not arguments.allow_development_dsn_env
                or arguments.environment != "development"
            ):
                raise CaptureError(
                    "DSN environment access is limited to explicit development"
                )
            raw_dsn = os.environ.get(_DEVELOPMENT_DSN_ENV)
            if raw_dsn is None:
                raise CaptureError(
                    "development database connection environment is missing"
                )
            dsn = _dsn_text(raw_dsn.encode("utf-8"))
        adapter = PsycopgAdapter.connect(dsn)
        document = capture_report_definition(
            adapter,
            expected_database_name=arguments.database_name,
            expected_database_uuid=arguments.database_uuid,
            expected_postgresql_system_identifier=(
                arguments.postgresql_system_identifier
            ),
            company_id=arguments.company_id,
        )
        payload = canonical_document_bytes(document)
        if arguments.output is None:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        else:
            _write_new(arguments.output, payload)
        return 0
    except CaptureError as exc:
        print(f"report_definition_capture_failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("report_definition_capture_failed: unexpected failure", file=sys.stderr)
        return 1
    finally:
        if adapter is not None:
            try:
                adapter.close()
            except CaptureError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
