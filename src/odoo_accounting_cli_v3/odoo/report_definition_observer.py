"""Read-only Odoo ORM observer for canonical accounting report definitions.

The public boundary deliberately has two phases:

``capture_technical_definition_state``
    Runs with the trusted root environment and captures only installed module
    metadata, module dependencies, and exact external-ID bindings.

``observe_report_definition_projections``
    Runs with the user- and company-bound environment, enforces read ACLs and
    record rules, and returns the four fixed canonical root projections.

Both phases are ORM-only.  The returned technical state stores its module
graph as canonical bytes and its identity map as immutable tuples so a caller
can safely inject the same state into repeated pre/post observations in one
transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
import uuid
from typing import Any, Iterable, Mapping, Sequence

from ..report_definition_projection import (
    PROJECTION_SCHEMA_VERSION,
    ROOT_BASELINE_IDENTITIES,
    ReportDefinitionProjectionError,
    build_root_definition_projection,
    canonical_projection_json,
)


_FIXED_ROOT_XMLIDS = tuple(item[2] for item in ROOT_BASELINE_IDENTITIES)
_EXTERNAL_ID_MODELS = (
    "account.report",
    "ir.actions.actions",
    "ir.actions.act_window",
)
_MODULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
_XMLID = re.compile(r"[a-z][a-z0-9_]{0,127}\.[A-Za-z0-9_.-]{1,128}")
_MODEL_NAME = re.compile(r"[a-z][a-z0-9_.]{0,255}")
_MAX_MODULES = 8_192
_MAX_DEPENDENCIES = 100_000
_MAX_EXTERNAL_IDS = 1_000_000
_MAX_REPORTS = 10_000
_MAX_COLUMNS = 50_000
_MAX_LINES = 200_000
_MAX_EXPRESSIONS = 500_000

_MODULE_FIELDS = ("latest_version", "name", "state", "write_date")
_DEPENDENCY_FIELDS = ("auto_install_required", "module_id", "name")
_EXTERNAL_ID_FIELDS = ("model", "module", "name", "res_id")
_COMPANY_FIELDS = (
    "account_fiscal_country_id",
    "chart_template",
    "country_id",
    "currency_id",
    "fiscalyear_last_day",
    "fiscalyear_last_month",
    "fiscalyear_lock_date",
    "hard_lock_date",
    "name",
    "tax_lock_date",
    "write_date",
)
_COUNTRY_FIELDS = ("code",)
_CURRENCY_FIELDS = ("decimal_places", "name", "rounding", "symbol")
_HANDLER_FIELDS = ("model",)
_REPORT_FIELDS = (
    "active",
    "allow_foreign_vat",
    "availability_condition",
    "chart_template",
    "column_ids",
    "country_id",
    "currency_translation",
    "custom_handler_model_id",
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
    "line_ids",
    "load_more_limit",
    "name",
    "only_tax_exigible",
    "prefix_groups_threshold",
    "root_report_id",
    "search_bar",
    "section_report_ids",
    "sequence",
    "use_sections",
    "write_date",
)
_COLUMN_FIELDS = (
    "blank_if_zero",
    "custom_audit_action_id",
    "expression_label",
    "figure_type",
    "name",
    "report_id",
    "sequence",
    "sortable",
    "write_date",
)
_LINE_FIELDS = (
    "action_id",
    "code",
    "expression_ids",
    "foldable",
    "groupby",
    "hide_if_zero",
    "hierarchy_level",
    "horizontal_split_side",
    "name",
    "parent_id",
    "print_on_new_page",
    "report_id",
    "sequence",
    "user_groupby",
    "write_date",
)
_EXPRESSION_FIELDS = (
    "auditable",
    "blank_if_zero",
    "carryover_target",
    "date_scope",
    "engine",
    "figure_type",
    "formula",
    "green_on_positive",
    "label",
    "report_line_id",
    "subformula",
    "write_date",
)


class ReportDefinitionObserverError(RuntimeError):
    """A complete, authorized, unambiguous observation was not possible."""


@dataclass(frozen=True, order=True)
class ExternalIdBinding:
    """One exact external-ID binding captured by the trusted environment."""

    model: str
    record_id: int
    xmlid: str


@dataclass(frozen=True)
class TechnicalDefinitionState:
    """Immutable technical inputs injected into user-bound observations."""

    database_uuid: str
    module_graph_json: bytes
    external_ids: tuple[ExternalIdBinding, ...]

    @property
    def module_graph(self) -> dict[str, object]:
        """Return a detached module graph after exact state validation."""

        graph, _bindings = _validate_technical_state(self)
        return json.loads(canonical_projection_json(graph).decode("utf-8"))


def _text(
    value: object,
    label: str,
    *,
    nullable: bool = False,
    maximum: int = 16_384,
) -> str | None:
    if nullable and value in (None, False):
        return None
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return value


def _canonical_uuid(value: object) -> str:
    if type(value) is not str:
        raise ReportDefinitionObserverError("database UUID is invalid")
    try:
        normalized = str(uuid.UUID(value))
    except ValueError as exc:
        raise ReportDefinitionObserverError("database UUID is invalid") from exc
    if normalized != value:
        raise ReportDefinitionObserverError("database UUID is not canonical")
    return value


def _xmlid(value: object, label: str) -> str:
    result = _text(value, label, maximum=257)
    assert result is not None
    if _XMLID.fullmatch(result) is None:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return result


def _model_name(value: object, label: str) -> str:
    result = _text(value, label, maximum=256)
    assert result is not None
    if _MODEL_NAME.fullmatch(result) is None:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return result


def _module_name(value: object, label: str) -> str:
    result = _text(value, label, maximum=128)
    assert result is not None
    if _MODULE_NAME.fullmatch(result) is None:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    return result


def _timestamp(value: object, label: str) -> str | None:
    if value in (None, False):
        return None
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ReportDefinitionObserverError(f"{label} is not UTC")
        return parsed.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    result = _text(value, label, maximum=27)
    assert result is not None
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportDefinitionObserverError(f"{label} is invalid") from exc
    canonical = parsed.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    if result != canonical:
        raise ReportDefinitionObserverError(f"{label} is not canonical")
    return result


def _date_text(value: object, label: str) -> str | None:
    if value in (None, False):
        return None
    if isinstance(value, datetime):
        raise ReportDefinitionObserverError(f"{label} is invalid")
    if isinstance(value, date):
        return value.isoformat()
    result = _text(value, label, maximum=10)
    assert result is not None
    try:
        parsed = date.fromisoformat(result)
    except ValueError as exc:
        raise ReportDefinitionObserverError(f"{label} is invalid") from exc
    if parsed.isoformat() != result:
        raise ReportDefinitionObserverError(f"{label} is not canonical")
    return result


def _decimal_text(value: object, label: str) -> str:
    if type(value) is bool:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ReportDefinitionObserverError(f"{label} is invalid") from exc
    if not decimal.is_finite() or decimal <= 0:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    result = format(decimal, "f")
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return result


def _many2one_id(
    value: object, label: str, *, nullable: bool = True
) -> int | None:
    if nullable and value in (None, False):
        return None
    candidate = value
    if isinstance(value, (list, tuple)):
        if len(value) != 2:
            raise ReportDefinitionObserverError(f"{label} is invalid")
        candidate = value[0]
    return _integer(candidate, label, minimum=1)


def _relation_ids(
    value: object,
    label: str,
    *,
    maximum: int,
) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise ReportDefinitionObserverError(f"{label} is invalid")
    result = tuple(
        _integer(item, label, minimum=1)
        for item in value
    )
    if len(set(result)) != len(result):
        raise ReportDefinitionObserverError(f"{label} is duplicated")
    return result


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_projection_json(value)).hexdigest()


def _strict_read_rows(
    raw: object,
    fields: Sequence[str],
    label: str,
) -> list[Mapping[str, object]]:
    if not isinstance(raw, list):
        raise ReportDefinitionObserverError(f"{label} readback is invalid")
    expected = {"id", *fields}
    rows: list[Mapping[str, object]] = []
    ids: set[int] = set()
    for value in raw:
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ReportDefinitionObserverError(
                f"{label} readback fields are invalid"
            )
        record_id = _integer(value["id"], f"{label} id", minimum=1)
        if record_id in ids:
            raise ReportDefinitionObserverError(
                f"{label} readback is duplicated"
            )
        ids.add(record_id)
        rows.append(value)
    return rows


def _require_fields(model: object, fields: Iterable[str], label: str) -> None:
    available = getattr(model, "_fields", None)
    if not isinstance(available, Mapping):
        raise ReportDefinitionObserverError(
            f"{label} model field metadata is unavailable"
        )
    missing = sorted(set(fields) - set(available))
    if missing:
        raise ReportDefinitionObserverError(
            f"{label} required field is missing"
        )


def _technical_search_read(
    root_env: object,
    model_name: str,
    domain: list[tuple[str, str, object]],
    fields: Sequence[str],
    *,
    order: str,
) -> list[Mapping[str, object]]:
    model = root_env[model_name]
    _require_fields(model, fields, model_name)
    contextual = model.with_context(active_test=False, lang="en_US")
    records = contextual.search(domain, order=order)
    return _strict_read_rows(records.read(list(fields)), fields, model_name)


def _build_module_graph(
    module_rows: Sequence[Mapping[str, object]],
    dependency_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    modules_by_id: dict[int, dict[str, object]] = {}
    names: set[str] = set()
    for row in module_rows:
        module_id = _integer(row["id"], "module id", minimum=1)
        if row["state"] != "installed":
            raise ReportDefinitionObserverError(
                "installed module readback is invalid"
            )
        name = _module_name(row["name"], "module name")
        if module_id in modules_by_id or name in names:
            raise ReportDefinitionObserverError(
                "installed module graph is duplicated"
            )
        names.add(name)
        modules_by_id[module_id] = {
            "dependencies": [],
            "latest_version": _text(
                row["latest_version"], "module version", maximum=256
            ),
            "name": name,
            "write_date": _timestamp(row["write_date"], "module write date"),
        }
    if (
        not modules_by_id
        or len(modules_by_id) > _MAX_MODULES
        or "account" not in names
    ):
        raise ReportDefinitionObserverError(
            "installed module graph is incomplete or account is absent"
        )
    seen_dependencies: set[tuple[int, str]] = set()
    for row in dependency_rows:
        module_id = _many2one_id(
            row["module_id"], "dependency module id", nullable=False
        )
        assert module_id is not None
        dependency = _module_name(row["name"], "dependency name")
        edge = (module_id, dependency)
        if (
            module_id not in modules_by_id
            or edge in seen_dependencies
            or len(seen_dependencies) >= _MAX_DEPENDENCIES
        ):
            raise ReportDefinitionObserverError(
                "installed module dependency graph is invalid"
            )
        seen_dependencies.add(edge)
        dependencies = modules_by_id[module_id]["dependencies"]
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
    modules = sorted(
        modules_by_id.values(), key=lambda value: str(value["name"])
    )
    for module in modules:
        dependencies = module["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.sort(key=lambda value: str(value["name"]))
    payload = {
        "modules": modules,
        "schema_version": PROJECTION_SCHEMA_VERSION,
    }
    return {**payload, "digest": _sha(payload)}


def _build_external_ids(
    rows: Sequence[Mapping[str, object]],
) -> tuple[ExternalIdBinding, ...]:
    bindings: list[ExternalIdBinding] = []
    by_record: set[tuple[str, int]] = set()
    xmlids: set[str] = set()
    for row in rows:
        model = _model_name(row["model"], "external-ID model")
        if model not in _EXTERNAL_ID_MODELS:
            raise ReportDefinitionObserverError(
                "external-ID model is outside the technical projection"
            )
        record_id = _integer(row["res_id"], "external-ID record id", minimum=1)
        xmlid = _xmlid(
            f"{_module_name(row['module'], 'external-ID module')}."
            f"{_text(row['name'], 'external-ID name', maximum=128)}",
            "external ID",
        )
        record_key = (model, record_id)
        if (
            record_key in by_record
            or xmlid in xmlids
            or len(bindings) >= _MAX_EXTERNAL_IDS
        ):
            raise ReportDefinitionObserverError(
                "external XMLID binding is duplicated"
            )
        by_record.add(record_key)
        xmlids.add(xmlid)
        bindings.append(
            ExternalIdBinding(
                model=model,
                record_id=record_id,
                xmlid=xmlid,
            )
        )
    bindings.sort()
    fixed = {
        binding.xmlid
        for binding in bindings
        if binding.model == "account.report"
    }
    if any(xmlid not in fixed for xmlid in _FIXED_ROOT_XMLIDS):
        raise ReportDefinitionObserverError(
            "a fixed report XMLID is missing"
        )
    return tuple(bindings)


def _validate_module_graph_document(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "digest",
        "modules",
        "schema_version",
    }:
        raise ReportDefinitionObserverError("module graph fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PROJECTION_SCHEMA_VERSION
    ):
        raise ReportDefinitionObserverError("module graph version is invalid")
    raw_modules = value["modules"]
    if (
        not isinstance(raw_modules, list)
        or not raw_modules
        or len(raw_modules) > _MAX_MODULES
    ):
        raise ReportDefinitionObserverError("module graph is invalid")
    modules: list[dict[str, object]] = []
    names: set[str] = set()
    dependency_count = 0
    for raw in raw_modules:
        if not isinstance(raw, Mapping) or set(raw) != {
            "dependencies",
            "latest_version",
            "name",
            "write_date",
        }:
            raise ReportDefinitionObserverError(
                "module graph module fields are invalid"
            )
        name = _module_name(raw["name"], "module name")
        if name in names:
            raise ReportDefinitionObserverError(
                "module graph module is duplicated"
            )
        names.add(name)
        raw_dependencies = raw["dependencies"]
        if not isinstance(raw_dependencies, list):
            raise ReportDefinitionObserverError(
                "module graph dependencies are invalid"
            )
        dependencies: list[dict[str, object]] = []
        dependency_names: set[str] = set()
        for dependency in raw_dependencies:
            dependency_count += 1
            if (
                dependency_count > _MAX_DEPENDENCIES
                or not isinstance(dependency, Mapping)
                or set(dependency) != {"auto_install_required", "name"}
            ):
                raise ReportDefinitionObserverError(
                    "module graph dependency fields are invalid"
                )
            dependency_name = _module_name(
                dependency["name"], "dependency name"
            )
            if dependency_name in dependency_names:
                raise ReportDefinitionObserverError(
                    "module graph dependency is duplicated"
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
        if [item["name"] for item in dependencies] != sorted(
            dependency_names
        ):
            raise ReportDefinitionObserverError(
                "module graph dependencies are not canonical"
            )
        modules.append(
            {
                "dependencies": dependencies,
                "latest_version": _text(
                    raw["latest_version"], "module version", maximum=256
                ),
                "name": name,
                "write_date": _timestamp(
                    raw["write_date"], "module write date"
                ),
            }
        )
    if [item["name"] for item in modules] != sorted(names) or "account" not in names:
        raise ReportDefinitionObserverError(
            "module graph is incomplete or not canonical"
        )
    payload = {
        "modules": modules,
        "schema_version": PROJECTION_SCHEMA_VERSION,
    }
    digest = value["digest"]
    if type(digest) is not str or digest != _sha(payload):
        raise ReportDefinitionObserverError("module graph digest differs")
    result = {**payload, "digest": digest}
    if result != value:
        raise ReportDefinitionObserverError("module graph is not canonical")
    return result


def _validate_technical_state(
    state: object,
) -> tuple[dict[str, object], dict[tuple[str, int], str]]:
    if not isinstance(state, TechnicalDefinitionState):
        raise ReportDefinitionObserverError(
            "technical definition state is unavailable"
        )
    _canonical_uuid(state.database_uuid)
    if type(state.module_graph_json) is not bytes:
        raise ReportDefinitionObserverError(
            "module graph canonical bytes are invalid"
        )
    try:
        raw_graph = json.loads(state.module_graph_json.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReportDefinitionObserverError(
            "module graph canonical bytes are invalid"
        ) from exc
    if canonical_projection_json(raw_graph) != state.module_graph_json:
        raise ReportDefinitionObserverError(
            "module graph bytes are not canonical"
        )
    graph = _validate_module_graph_document(raw_graph)
    if (
        type(state.external_ids) is not tuple
        or len(state.external_ids) > _MAX_EXTERNAL_IDS
    ):
        raise ReportDefinitionObserverError(
            "external XMLID state is not immutable"
        )
    bindings: dict[tuple[str, int], str] = {}
    xmlids: set[str] = set()
    normalized: list[ExternalIdBinding] = []
    for binding in state.external_ids:
        if type(binding) is not ExternalIdBinding:
            raise ReportDefinitionObserverError(
                "external XMLID binding is invalid"
            )
        model = _model_name(binding.model, "external-ID model")
        if model not in _EXTERNAL_ID_MODELS:
            raise ReportDefinitionObserverError(
                "external XMLID model is invalid"
            )
        record_id = _integer(
            binding.record_id, "external-ID record id", minimum=1
        )
        xmlid = _xmlid(binding.xmlid, "external ID")
        key = (model, record_id)
        if key in bindings or xmlid in xmlids:
            raise ReportDefinitionObserverError(
                "external XMLID binding is duplicated"
            )
        bindings[key] = xmlid
        xmlids.add(xmlid)
        normalized.append(binding)
    if tuple(sorted(normalized)) != state.external_ids:
        raise ReportDefinitionObserverError(
            "external XMLID bindings are not canonical"
        )
    report_xmlids = {
        xmlid
        for (model, _record_id), xmlid in bindings.items()
        if model == "account.report"
    }
    if any(xmlid not in report_xmlids for xmlid in _FIXED_ROOT_XMLIDS):
        raise ReportDefinitionObserverError(
            "a fixed report XMLID is missing"
        )
    return graph, bindings


def capture_technical_definition_state(
    root_env: Any,
    *,
    database_uuid: str,
) -> TechnicalDefinitionState:
    """Capture immutable root-only module and external-ID state with ORM reads."""

    if getattr(root_env, "su", None) is not True:
        raise ReportDefinitionObserverError(
            "technical definition capture requires the trusted root environment"
        )
    canonical_uuid = _canonical_uuid(database_uuid)
    try:
        module_rows = _technical_search_read(
            root_env,
            "ir.module.module",
            [("state", "=", "installed")],
            _MODULE_FIELDS,
            order="name, id",
        )
        installed_ids = [row["id"] for row in module_rows]
        dependency_rows = _technical_search_read(
            root_env,
            "ir.module.module.dependency",
            [("module_id", "in", installed_ids)],
            _DEPENDENCY_FIELDS,
            order="module_id, name, id",
        )
        external_rows = _technical_search_read(
            root_env,
            "ir.model.data",
            [("model", "in", list(_EXTERNAL_ID_MODELS))],
            _EXTERNAL_ID_FIELDS,
            order="model, res_id, module, name, id",
        )
        graph = _build_module_graph(module_rows, dependency_rows)
        state = TechnicalDefinitionState(
            database_uuid=canonical_uuid,
            module_graph_json=canonical_projection_json(graph),
            external_ids=_build_external_ids(external_rows),
        )
        _validate_technical_state(state)
        return state
    except ReportDefinitionObserverError:
        raise
    except Exception as exc:
        raise ReportDefinitionObserverError(
            "trusted technical definition cannot be read"
        ) from exc


def _bound_context(bound_env: object, company_id: int) -> dict[str, object]:
    if getattr(bound_env, "su", None) is not False:
        raise ReportDefinitionObserverError(
            "report definition observation requires a user-bound environment"
        )
    company = getattr(getattr(bound_env, "company", None), "id", None)
    user = getattr(getattr(bound_env, "user", None), "id", None)
    context = getattr(bound_env, "context", None)
    if (
        company != company_id
        or type(user) is not int
        or user < 1
        or not isinstance(context, Mapping)
        or context.get("allowed_company_ids") != [company_id]
    ):
        raise ReportDefinitionObserverError(
            "user environment is not bound to exactly one company"
        )
    return {
        "active_test": False,
        "allowed_company_ids": [company_id],
        "lang": "en_US",
    }


def _user_model(
    bound_env: object,
    model_name: str,
    fields: Sequence[str],
    context: Mapping[str, object],
) -> object:
    model = bound_env[model_name]
    _require_fields(model, fields, model_name)
    checker = getattr(model, "check_access_rights", None)
    if not callable(checker):
        raise ReportDefinitionObserverError(
            f"{model_name} read ACL checker is unavailable"
        )
    checker("read")
    contextual = model.with_context(**dict(context))
    return contextual


def _recordset_ids(records: object, label: str) -> tuple[int, ...]:
    raw = getattr(records, "ids", None)
    if not isinstance(raw, (list, tuple)):
        raise ReportDefinitionObserverError(f"{label} recordset is invalid")
    result = tuple(_integer(item, f"{label} id", minimum=1) for item in raw)
    if len(set(result)) != len(result):
        raise ReportDefinitionObserverError(
            f"{label} recordset is duplicated"
        )
    return result


def _authorize_records(records: object, expected_ids: Iterable[int], label: str):
    exists = getattr(records, "exists", None)
    if not callable(exists):
        raise ReportDefinitionObserverError(
            f"{label} read existence checker is unavailable"
        )
    existing = exists()
    observed_ids = set(_recordset_ids(existing, label))
    expected = set(expected_ids)
    if observed_ids != expected:
        raise ReportDefinitionObserverError(
            f"{label} read scope is incomplete"
        )
    checker = getattr(existing, "check_access_rule", None)
    if not callable(checker):
        raise ReportDefinitionObserverError(
            f"{label} read record-rule checker is unavailable"
        )
    checker("read")
    return existing


def _browse_read(
    model: object,
    ids: Iterable[int],
    fields: Sequence[str],
    label: str,
) -> list[Mapping[str, object]]:
    requested = tuple(sorted(set(ids)))
    if not requested:
        return []
    records = model.browse(list(requested))
    authorized = _authorize_records(records, requested, label)
    rows = _strict_read_rows(authorized.read(list(fields)), fields, label)
    if {row["id"] for row in rows} != set(requested):
        raise ReportDefinitionObserverError(
            f"{label} readback is incomplete"
        )
    return rows


def _search_read(
    model: object,
    domain: list[tuple[str, str, object]],
    fields: Sequence[str],
    label: str,
) -> list[Mapping[str, object]]:
    records = model.search(domain, order="id")
    ids = _recordset_ids(records, label)
    authorized = _authorize_records(records, ids, label)
    rows = _strict_read_rows(authorized.read(list(fields)), fields, label)
    if {row["id"] for row in rows} != set(ids):
        raise ReportDefinitionObserverError(
            f"{label} readback is incomplete"
        )
    return rows


def _rows_by_id(
    rows: Sequence[Mapping[str, object]], label: str
) -> dict[int, Mapping[str, object]]:
    result: dict[int, Mapping[str, object]] = {}
    for row in rows:
        record_id = _integer(row["id"], f"{label} id", minimum=1)
        if record_id in result:
            raise ReportDefinitionObserverError(f"{label} is duplicated")
        result[record_id] = row
    return result


def _read_company_profile(
    bound_env: object,
    *,
    company_id: int,
    context: Mapping[str, object],
) -> dict[str, object]:
    company_model = _user_model(
        bound_env, "res.company", _COMPANY_FIELDS, context
    )
    company = _browse_read(
        company_model, [company_id], _COMPANY_FIELDS, "company"
    )[0]
    country_id = _many2one_id(
        company["country_id"], "company country", nullable=False
    )
    assert country_id is not None
    fiscal_country_id = _many2one_id(
        company["account_fiscal_country_id"],
        "company fiscal country",
    )
    currency_id = _many2one_id(
        company["currency_id"], "company currency", nullable=False
    )
    assert currency_id is not None
    country_model = _user_model(
        bound_env, "res.country", _COUNTRY_FIELDS, context
    )
    country_ids = {country_id}
    if fiscal_country_id is not None:
        country_ids.add(fiscal_country_id)
    countries = _rows_by_id(
        _browse_read(
            country_model,
            country_ids,
            _COUNTRY_FIELDS,
            "company country",
        ),
        "company country",
    )
    currency_model = _user_model(
        bound_env, "res.currency", _CURRENCY_FIELDS, context
    )
    currency = _browse_read(
        currency_model,
        [currency_id],
        _CURRENCY_FIELDS,
        "company currency",
    )[0]
    country_code = _text(
        countries[country_id]["code"], "company country code", maximum=8
    )
    fiscal_code = (
        _text(
            countries[fiscal_country_id]["code"],
            "company fiscal country code",
            maximum=8,
        )
        if fiscal_country_id is not None
        else None
    )
    return {
        "account_fiscal_country_code": fiscal_code,
        "chart_template": _text(
            company["chart_template"],
            "company chart template",
            nullable=True,
            maximum=256,
        ),
        "company_id": company_id,
        "country_code": country_code,
        "currency": {
            "decimal_places": _integer(
                currency["decimal_places"],
                "currency decimal places",
                maximum=12,
            ),
            "name": _text(
                currency["name"], "currency name", maximum=32
            ),
            "rounding": _decimal_text(
                currency["rounding"], "currency rounding"
            ),
            "symbol": _text(
                currency["symbol"], "currency symbol", maximum=32
            ),
        },
        "fiscal": {
            "fiscalyear_last_day": _integer(
                company["fiscalyear_last_day"],
                "fiscal year last day",
                minimum=1,
                maximum=31,
            ),
            "fiscalyear_last_month": _text(
                company["fiscalyear_last_month"],
                "fiscal year last month",
                maximum=2,
            ),
            "fiscalyear_lock_date": _date_text(
                company["fiscalyear_lock_date"],
                "fiscal year lock date",
            ),
            "hard_lock_date": _date_text(
                company["hard_lock_date"], "hard lock date"
            ),
            "tax_lock_date": _date_text(
                company["tax_lock_date"], "tax lock date"
            ),
        },
        "name": _text(company["name"], "company name", maximum=256),
        "write_date": _timestamp(
            company["write_date"], "company write date"
        ),
    }


def _report_xmlid_map(
    bindings: Mapping[tuple[str, int], str],
) -> tuple[dict[int, str], dict[str, int]]:
    by_id: dict[int, str] = {}
    by_xmlid: dict[str, int] = {}
    for (model, record_id), xmlid in bindings.items():
        if model != "account.report":
            continue
        by_id[record_id] = xmlid
        by_xmlid[xmlid] = record_id
    if any(xmlid not in by_xmlid for xmlid in _FIXED_ROOT_XMLIDS):
        raise ReportDefinitionObserverError(
            "a fixed report XMLID is missing"
        )
    return by_id, by_xmlid


def _read_report_closure(
    report_model: object,
    *,
    root_ids: Iterable[int],
    report_fields: Sequence[str],
) -> dict[int, Mapping[str, object]]:
    result: dict[int, Mapping[str, object]] = {}
    pending = set(root_ids)
    expanded: set[int] = set()
    while pending:
        batch = sorted(pending - expanded)
        if not batch:
            break
        expanded.update(batch)
        pending.difference_update(batch)
        for row in _browse_read(
            report_model, batch, report_fields, "account report"
        ):
            record_id = _integer(row["id"], "report id", minimum=1)
            previous = result.get(record_id)
            if previous is not None and previous != row:
                raise ReportDefinitionObserverError(
                    "report definition changed during observation"
                )
            result[record_id] = row
            pending.update(
                _relation_ids(
                    row["section_report_ids"],
                    "section report IDs",
                    maximum=_MAX_REPORTS,
                )
            )
        variants = _search_read(
            report_model,
            [("root_report_id", "in", batch)],
            report_fields,
            "account report variant",
        )
        for row in variants:
            record_id = _integer(row["id"], "variant report id", minimum=1)
            previous = result.get(record_id)
            if previous is not None and previous != row:
                raise ReportDefinitionObserverError(
                    "report definition changed during observation"
                )
            result[record_id] = row
            pending.add(record_id)
            pending.update(
                _relation_ids(
                    row["section_report_ids"],
                    "variant section report IDs",
                    maximum=_MAX_REPORTS,
                )
            )
        if len(result) + len(pending) > _MAX_REPORTS:
            raise ReportDefinitionObserverError(
                "report definition closure is too large"
            )
    return result


def _assert_acyclic_report_graph(
    rows: Mapping[int, Mapping[str, object]]
) -> None:
    edges: dict[int, set[int]] = {record_id: set() for record_id in rows}
    for record_id, row in rows.items():
        root_id = _many2one_id(
            row["root_report_id"], "variant root report"
        )
        if root_id is not None:
            if root_id not in rows or root_id == record_id:
                raise ReportDefinitionObserverError(
                    "report variant graph is invalid"
                )
            edges[root_id].add(record_id)
        for section_id in _relation_ids(
            row["section_report_ids"],
            "section report IDs",
            maximum=_MAX_REPORTS,
        ):
            if section_id not in rows or section_id == record_id:
                raise ReportDefinitionObserverError(
                    "report section graph is invalid"
                )
            edges[record_id].add(section_id)
    visited: set[int] = set()
    active: set[int] = set()

    def visit(record_id: int) -> None:
        if record_id in active:
            raise ReportDefinitionObserverError(
                "report definition graph contains a cycle"
            )
        if record_id in visited:
            return
        active.add(record_id)
        for child_id in sorted(edges[record_id]):
            visit(child_id)
        active.remove(record_id)
        visited.add(record_id)

    for record_id in sorted(rows):
        visit(record_id)


def _read_child_definitions(
    bound_env: object,
    *,
    context: Mapping[str, object],
    reports: Mapping[int, Mapping[str, object]],
) -> tuple[
    dict[int, Mapping[str, object]],
    dict[int, Mapping[str, object]],
    dict[int, Mapping[str, object]],
]:
    report_ids = sorted(reports)
    column_model = _user_model(
        bound_env, "account.report.column", _COLUMN_FIELDS, context
    )
    line_model = _user_model(
        bound_env, "account.report.line", _LINE_FIELDS, context
    )
    expression_model = _user_model(
        bound_env,
        "account.report.expression",
        _EXPRESSION_FIELDS,
        context,
    )
    columns = _rows_by_id(
        _search_read(
            column_model,
            [("report_id", "in", report_ids)],
            _COLUMN_FIELDS,
            "report column",
        ),
        "report column",
    )
    declared_columns = {
        item
        for report in reports.values()
        for item in _relation_ids(
            report["column_ids"],
            "report column IDs",
            maximum=_MAX_COLUMNS,
        )
    }
    declared_column_count = sum(
        len(
            _relation_ids(
                report["column_ids"],
                "report column IDs",
                maximum=_MAX_COLUMNS,
            )
        )
        for report in reports.values()
    )
    if (
        set(columns) != declared_columns
        or declared_column_count != len(declared_columns)
    ):
        raise ReportDefinitionObserverError(
            "report column read scope is incomplete"
        )
    lines = _rows_by_id(
        _search_read(
            line_model,
            [("report_id", "in", report_ids)],
            _LINE_FIELDS,
            "report line",
        ),
        "report line",
    )
    declared_lines = {
        item
        for report in reports.values()
        for item in _relation_ids(
            report["line_ids"],
            "report line IDs",
            maximum=_MAX_LINES,
        )
    }
    declared_line_count = sum(
        len(
            _relation_ids(
                report["line_ids"],
                "report line IDs",
                maximum=_MAX_LINES,
            )
        )
        for report in reports.values()
    )
    if (
        set(lines) != declared_lines
        or declared_line_count != len(declared_lines)
    ):
        raise ReportDefinitionObserverError(
            "report line read scope is incomplete"
        )
    line_ids = sorted(lines)
    expressions = _rows_by_id(
        _search_read(
            expression_model,
            [("report_line_id", "in", line_ids)],
            _EXPRESSION_FIELDS,
            "report expression",
        ),
        "report expression",
    )
    declared_expressions = {
        item
        for line in lines.values()
        for item in _relation_ids(
            line["expression_ids"],
            "report expression IDs",
            maximum=_MAX_EXPRESSIONS,
        )
    }
    declared_expression_count = sum(
        len(
            _relation_ids(
                line["expression_ids"],
                "report expression IDs",
                maximum=_MAX_EXPRESSIONS,
            )
        )
        for line in lines.values()
    )
    if (
        set(expressions) != declared_expressions
        or declared_expression_count != len(declared_expressions)
    ):
        raise ReportDefinitionObserverError(
            "report expression read scope is incomplete"
        )
    return columns, lines, expressions


def _related_values(
    bound_env: object,
    *,
    context: Mapping[str, object],
    reports: Mapping[int, Mapping[str, object]],
) -> tuple[dict[int, str], dict[int, str]]:
    country_ids = {
        country_id
        for row in reports.values()
        if (
            country_id := _many2one_id(
                row["country_id"], "report country"
            )
        )
        is not None
    }
    handler_ids = {
        handler_id
        for row in reports.values()
        if (
            handler_id := _many2one_id(
                row["custom_handler_model_id"],
                "report custom handler",
            )
        )
        is not None
    }
    countries: dict[int, str] = {}
    handlers: dict[int, str] = {}
    if country_ids:
        model = _user_model(
            bound_env, "res.country", _COUNTRY_FIELDS, context
        )
        for row in _browse_read(
            model, country_ids, _COUNTRY_FIELDS, "report country"
        ):
            countries[int(row["id"])] = str(
                _text(row["code"], "report country code", maximum=8)
            )
    if handler_ids:
        model = _user_model(
            bound_env, "ir.model", _HANDLER_FIELDS, context
        )
        for row in _browse_read(
            model, handler_ids, _HANDLER_FIELDS, "report custom handler"
        ):
            handlers[int(row["id"])] = _model_name(
                row["model"], "report custom handler model"
            )
    return countries, handlers


def _line_keys(
    report_xmlid: str,
    rows: Sequence[Mapping[str, object]],
) -> dict[int, str]:
    by_id = _rows_by_id(rows, "report line")
    parent_by_id: dict[int, int | None] = {}
    descriptors: set[tuple[int | None, int, str, str | None]] = set()
    for line_id, row in by_id.items():
        parent_id = _many2one_id(row["parent_id"], "line parent")
        report_id = _many2one_id(
            row["report_id"], "line report", nullable=False
        )
        if parent_id is not None:
            parent = by_id.get(parent_id)
            if (
                parent is None
                or _many2one_id(
                    parent["report_id"], "parent line report", nullable=False
                )
                != report_id
            ):
                raise ReportDefinitionObserverError(
                    "line parent is outside its report"
                )
        parent_by_id[line_id] = parent_id
        descriptor = (
            parent_id,
            _integer(row["sequence"], "line sequence"),
            str(_text(row["name"], "line name")),
            _text(row["code"], "line code", nullable=True),
        )
        if descriptor in descriptors:
            raise ReportDefinitionObserverError(
                "line semantic identity is duplicated"
            )
        descriptors.add(descriptor)
    result: dict[int, str] = {}
    used: set[str] = set()
    active: set[int] = set()

    def resolve(line_id: int) -> str:
        if line_id in result:
            return result[line_id]
        if line_id in active:
            raise ReportDefinitionObserverError(
                "line hierarchy contains a cycle"
            )
        active.add(line_id)
        row = by_id[line_id]
        parent_id = parent_by_id[line_id]
        semantic_parent = (
            resolve(parent_id) if parent_id is not None else report_xmlid
        )
        code = _text(row["code"], "line code", nullable=True)
        if code is None:
            semantic = {
                "name": _text(row["name"], "line name"),
                "parent_key": semantic_parent,
                "sequence": _integer(row["sequence"], "line sequence"),
            }
        else:
            semantic = {"code": code, "parent_key": semantic_parent}
        key = f"{report_xmlid}/line/{_sha(semantic)}"
        if key in used:
            raise ReportDefinitionObserverError(
                "line semantic key is duplicated"
            )
        used.add(key)
        result[line_id] = key
        active.remove(line_id)
        return key

    for line_id in sorted(by_id):
        resolve(line_id)
    return result


def _external_xmlid(
    bindings: Mapping[tuple[str, int], str],
    *,
    model: str,
    record_id: int | None,
    label: str,
) -> str | None:
    if record_id is None:
        return None
    value = bindings.get((model, record_id))
    if value is None:
        raise ReportDefinitionObserverError(
            f"{label} lacks one exact XMLID"
        )
    return value


def _build_report_documents(
    bound_env: object,
    *,
    company_id: int,
    context: Mapping[str, object],
    reports: Mapping[int, Mapping[str, object]],
    columns: Mapping[int, Mapping[str, object]],
    lines: Mapping[int, Mapping[str, object]],
    expressions: Mapping[int, Mapping[str, object]],
    bindings: Mapping[tuple[str, int], str],
) -> list[dict[str, object]]:
    report_xmlids, _by_xmlid = _report_xmlid_map(bindings)
    countries, handlers = _related_values(
        bound_env, context=context, reports=reports
    )
    columns_by_report: dict[int, list[Mapping[str, object]]] = {
        record_id: [] for record_id in reports
    }
    for row in columns.values():
        report_id = _many2one_id(
            row["report_id"], "column report", nullable=False
        )
        assert report_id is not None
        if report_id not in reports:
            raise ReportDefinitionObserverError(
                "report column belongs outside the definition closure"
            )
        columns_by_report[report_id].append(row)
    lines_by_report: dict[int, list[Mapping[str, object]]] = {
        record_id: [] for record_id in reports
    }
    for row in lines.values():
        report_id = _many2one_id(
            row["report_id"], "line report", nullable=False
        )
        assert report_id is not None
        if report_id not in reports:
            raise ReportDefinitionObserverError(
                "report line belongs outside the definition closure"
            )
        lines_by_report[report_id].append(row)
    expressions_by_line: dict[int, list[Mapping[str, object]]] = {
        record_id: [] for record_id in lines
    }
    for row in expressions.values():
        line_id = _many2one_id(
            row["report_line_id"], "expression line", nullable=False
        )
        assert line_id is not None
        if line_id not in lines:
            raise ReportDefinitionObserverError(
                "report expression belongs outside the definition closure"
            )
        expressions_by_line[line_id].append(row)

    documents: list[dict[str, object]] = []
    for report_id, raw in reports.items():
        report_xmlid = report_xmlids.get(report_id)
        if report_xmlid is None:
            raise ReportDefinitionObserverError(
                "report lacks one exact XMLID"
            )
        if "company_id" in raw:
            report_company_id = _many2one_id(
                raw["company_id"], "report company"
            )
            if report_company_id not in (None, company_id):
                raise ReportDefinitionObserverError(
                    "report belongs to another company"
                )
        line_rows = lines_by_report[report_id]
        line_keys = _line_keys(report_xmlid, line_rows)
        line_documents: list[dict[str, object]] = []
        for line in line_rows:
            line_id = _integer(line["id"], "line id", minimum=1)
            parent_id = _many2one_id(line["parent_id"], "line parent")
            action_id = _many2one_id(line["action_id"], "line action")
            expression_documents: list[dict[str, object]] = []
            labels: set[str] = set()
            for expression in expressions_by_line[line_id]:
                label = _text(
                    expression["label"],
                    "expression label",
                    maximum=256,
                )
                assert label is not None
                if label in labels:
                    raise ReportDefinitionObserverError(
                        "report expression label is duplicated"
                    )
                labels.add(label)
                engine = _text(
                    expression["engine"],
                    "expression engine",
                    maximum=64,
                )
                formula = _text(
                    expression["formula"], "expression formula"
                )
                assert engine is not None and formula is not None
                expression_documents.append(
                    {
                        "auditable": _boolean(
                            expression["auditable"],
                            "expression auditable flag",
                        ),
                        "blank_if_zero": _boolean(
                            expression["blank_if_zero"],
                            "expression blank-if-zero flag",
                        ),
                        "carryover_target": _text(
                            expression["carryover_target"],
                            "expression carryover target",
                            nullable=True,
                        ),
                        "date_scope": _text(
                            expression["date_scope"],
                            "expression date scope",
                            maximum=64,
                        ),
                        "domain": formula if engine == "domain" else None,
                        "engine": engine,
                        "figure_type": _text(
                            expression["figure_type"],
                            "expression figure type",
                            nullable=True,
                        ),
                        "formula": formula,
                        "green_on_positive": _boolean(
                            expression["green_on_positive"],
                            "expression growth sign",
                        ),
                        "key": (
                            f"{line_keys[line_id]}/expression/{label}"
                        ),
                        "label": label,
                        "subformula": _text(
                            expression["subformula"],
                            "expression subformula",
                            nullable=True,
                        ),
                        "write_date": _timestamp(
                            expression["write_date"],
                            "expression write date",
                        ),
                    }
                )
            expression_documents.sort(key=lambda item: str(item["key"]))
            line_documents.append(
                {
                    "action_xmlid": _external_xmlid(
                        bindings,
                        model="ir.actions.actions",
                        record_id=action_id,
                        label="line action",
                    ),
                    "code": _text(
                        line["code"], "line code", nullable=True
                    ),
                    "expressions": expression_documents,
                    "foldable": _boolean(
                        line["foldable"], "line foldable flag"
                    ),
                    "groupby": _text(
                        line["groupby"], "line groupby", nullable=True
                    ),
                    "hide_if_zero": _boolean(
                        line["hide_if_zero"], "line hide-if-zero flag"
                    ),
                    "hierarchy_level": _integer(
                        line["hierarchy_level"],
                        "line hierarchy level",
                        maximum=1_000,
                    ),
                    "horizontal_split_side": _text(
                        line["horizontal_split_side"],
                        "line horizontal split side",
                        nullable=True,
                    ),
                    "key": line_keys[line_id],
                    "name": _text(line["name"], "line name"),
                    "parent_key": (
                        line_keys[parent_id]
                        if parent_id is not None
                        else None
                    ),
                    "print_on_new_page": _boolean(
                        line["print_on_new_page"],
                        "line print-on-new-page flag",
                    ),
                    "sequence": _integer(
                        line["sequence"], "line sequence"
                    ),
                    "user_groupby": _text(
                        line["user_groupby"],
                        "line user groupby",
                        nullable=True,
                    ),
                    "write_date": _timestamp(
                        line["write_date"], "line write date"
                    ),
                }
            )
        line_documents.sort(key=lambda item: str(item["key"]))

        column_documents: list[dict[str, object]] = []
        column_keys: set[str] = set()
        for column in columns_by_report[report_id]:
            semantic = {
                "expression_label": _text(
                    column["expression_label"],
                    "column expression label",
                    maximum=256,
                ),
                "name": _text(column["name"], "column name"),
                "sequence": _integer(
                    column["sequence"], "column sequence"
                ),
            }
            key = f"{report_xmlid}/column/{_sha(semantic)}"
            if key in column_keys:
                raise ReportDefinitionObserverError(
                    "report column semantics are duplicated"
                )
            column_keys.add(key)
            action_id = _many2one_id(
                column["custom_audit_action_id"],
                "column custom audit action",
            )
            column_documents.append(
                {
                    "blank_if_zero": _boolean(
                        column["blank_if_zero"],
                        "column blank-if-zero flag",
                    ),
                    "custom_audit_action_xmlid": _external_xmlid(
                        bindings,
                        model="ir.actions.act_window",
                        record_id=action_id,
                        label="column custom audit action",
                    ),
                    "expression_label": semantic["expression_label"],
                    "figure_type": _text(
                        column["figure_type"],
                        "column figure type",
                        maximum=64,
                    ),
                    "key": key,
                    "name": semantic["name"],
                    "sequence": semantic["sequence"],
                    "sortable": _boolean(
                        column["sortable"], "column sortable flag"
                    ),
                    "write_date": _timestamp(
                        column["write_date"], "column write date"
                    ),
                }
            )
        column_documents.sort(key=lambda item: str(item["key"]))
        root_id = _many2one_id(
            raw["root_report_id"], "variant root report"
        )
        country_id = _many2one_id(raw["country_id"], "report country")
        handler_id = _many2one_id(
            raw["custom_handler_model_id"], "report custom handler"
        )
        documents.append(
            {
                "active": _boolean(raw["active"], "report active flag"),
                "availability_condition": _text(
                    raw["availability_condition"],
                    "report availability condition",
                    nullable=True,
                ),
                "chart_template": _text(
                    raw["chart_template"],
                    "report chart template",
                    nullable=True,
                ),
                "columns": column_documents,
                "country_code": (
                    countries[country_id] if country_id is not None else None
                ),
                "custom_handler_model": (
                    handlers[handler_id] if handler_id is not None else None
                ),
                "key": report_xmlid,
                "lines": line_documents,
                "name": _text(raw["name"], "report name"),
                "options": {
                    "allow_foreign_vat": _boolean(
                        raw["allow_foreign_vat"],
                        "report foreign VAT filter",
                    ),
                    "currency_translation": _text(
                        raw["currency_translation"],
                        "report currency translation",
                        nullable=True,
                    ),
                    "default_opening_date_filter": _text(
                        raw["default_opening_date_filter"],
                        "report default opening date filter",
                        nullable=True,
                    ),
                    "filter_date_range": _boolean(
                        raw["filter_date_range"], "report date filter"
                    ),
                    "filter_growth_comparison": _boolean(
                        raw["filter_growth_comparison"],
                        "report growth comparison filter",
                    ),
                    "filter_hide_0_lines": _text(
                        raw["filter_hide_0_lines"],
                        "report zero-line filter",
                        nullable=True,
                    ),
                    "filter_journals": _boolean(
                        raw["filter_journals"],
                        "report journal filter",
                    ),
                    "filter_multi_company": _text(
                        raw["filter_multi_company"],
                        "report company filter",
                        nullable=True,
                    ),
                    "filter_period_comparison": _boolean(
                        raw["filter_period_comparison"],
                        "report period comparison filter",
                    ),
                    "filter_show_draft": _boolean(
                        raw["filter_show_draft"],
                        "report draft filter",
                    ),
                    "filter_unfold_all": _boolean(
                        raw["filter_unfold_all"],
                        "report unfold filter",
                    ),
                    "filter_unreconciled": _boolean(
                        raw["filter_unreconciled"],
                        "report unreconciled filter",
                    ),
                    "integer_rounding": _text(
                        raw["integer_rounding"],
                        "report integer rounding",
                        nullable=True,
                    ),
                    "load_more_limit": _integer(
                        raw["load_more_limit"],
                        "report load-more limit",
                    ),
                    "only_tax_exigible": _boolean(
                        raw["only_tax_exigible"],
                        "report tax exigibility",
                    ),
                    "prefix_groups_threshold": _integer(
                        raw["prefix_groups_threshold"],
                        "report prefix group threshold",
                    ),
                    "search_bar": _boolean(
                        raw["search_bar"], "report search bar"
                    ),
                },
                "root_report_key": (
                    report_xmlids[root_id] if root_id is not None else None
                ),
                "section_report_keys": sorted(
                    report_xmlids[section_id]
                    for section_id in _relation_ids(
                        raw["section_report_ids"],
                        "section report IDs",
                        maximum=_MAX_REPORTS,
                    )
                ),
                "sequence": _integer(
                    raw["sequence"], "report sequence"
                ),
                "use_sections": _boolean(
                    raw["use_sections"], "report sections flag"
                ),
                "write_date": _timestamp(
                    raw["write_date"], "report write date"
                ),
                "xmlid": report_xmlid,
            }
        )
    documents.sort(key=lambda item: str(item["key"]))
    return documents


def observe_report_definition_projections(
    bound_env: Any,
    *,
    company_id: int,
    technical_state: TechnicalDefinitionState,
) -> tuple[dict[str, object], ...]:
    """Observe and return the four fixed canonical projections via read ORM."""

    company = _integer(company_id, "company id", minimum=1)
    module_graph, bindings = _validate_technical_state(technical_state)
    context = _bound_context(bound_env, company)
    try:
        company_profile = _read_company_profile(
            bound_env, company_id=company, context=context
        )
        report_xmlids, root_ids_by_xmlid = _report_xmlid_map(bindings)
        report_model_base = bound_env["account.report"]
        _require_fields(report_model_base, _REPORT_FIELDS, "account.report")
        report_fields = list(_REPORT_FIELDS)
        if "company_id" in report_model_base._fields:
            report_fields.append("company_id")
        report_model = _user_model(
            bound_env, "account.report", report_fields, context
        )
        reports = _read_report_closure(
            report_model,
            root_ids=(
                root_ids_by_xmlid[xmlid]
                for xmlid in _FIXED_ROOT_XMLIDS
            ),
            report_fields=report_fields,
        )
        if any(record_id not in report_xmlids for record_id in reports):
            raise ReportDefinitionObserverError(
                "report lacks one exact XMLID"
            )
        _assert_acyclic_report_graph(reports)
        columns, lines, expressions = _read_child_definitions(
            bound_env,
            context=context,
            reports=reports,
        )
        documents = _build_report_documents(
            bound_env,
            company_id=company,
            context=context,
            reports=reports,
            columns=columns,
            lines=lines,
            expressions=expressions,
            bindings=bindings,
        )
        projections: list[dict[str, object]] = []
        for family, kind, root_xmlid in ROOT_BASELINE_IDENTITIES:
            projections.append(
                build_root_definition_projection(
                    database_uuid=technical_state.database_uuid,
                    company_id=company,
                    family=family,
                    kind=kind,
                    root_xmlid=root_xmlid,
                    company_profile=company_profile,
                    module_graph=module_graph,
                    reports=documents,
                )
            )
        return tuple(projections)
    except ReportDefinitionObserverError:
        raise
    except ReportDefinitionProjectionError as exc:
        raise ReportDefinitionObserverError(
            "report definition cannot produce a canonical projection"
        ) from exc
    except Exception as exc:
        raise ReportDefinitionObserverError(
            "authorized report definition read failed closed"
        ) from exc


__all__ = [
    "ExternalIdBinding",
    "ReportDefinitionObserverError",
    "TechnicalDefinitionState",
    "capture_technical_definition_state",
    "observe_report_definition_projections",
]
