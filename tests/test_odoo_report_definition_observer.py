from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime
import json

import pytest

from odoo_accounting_cli_v3.odoo.report_definition_observer import (
    ExternalIdBinding,
    ReportDefinitionObserverError,
    TechnicalDefinitionState,
    capture_technical_definition_state,
    observe_report_definition_projections,
)
from odoo_accounting_cli_v3.report_definition_projection import (
    ROOT_BASELINE_IDENTITIES,
    build_root_definition_projection,
    canonical_projection_json,
    validate_root_definition_projection,
)


DATABASE_UUID = "12345678-1234-5678-9234-567812345678"
STAMP = datetime(2026, 7, 29, 1, 2, 3, 4000)


class FakeRecordset:
    def __init__(self, model, ids):
        self.model = model
        self.ids = tuple(ids)

    def exists(self):
        self.model.events.append(("exists", self.model.name, self.ids))
        return FakeRecordset(
            self.model,
            [item for item in self.ids if item in self.model.rows],
        )

    def check_access_rule(self, operation):
        self.model.events.append(
            ("check_access_rule", self.model.name, operation, self.ids)
        )
        if operation != "read" or set(self.ids) & self.model.denied_rules:
            raise PermissionError("record rule denied")
        return None

    def read(self, fields):
        self.model.events.append(
            ("read", self.model.name, tuple(fields), self.ids)
        )
        result = []
        for record_id in self.ids:
            row = self.model.rows[record_id]
            result.append(
                {"id": record_id, **{field: row[field] for field in fields}}
            )
        return result

    def __len__(self):
        return len(self.ids)


class FakeModel:
    def __init__(
        self,
        name,
        rows,
        *,
        events,
        denied_acl,
        denied_rules,
        context=None,
        declared_fields=None,
    ):
        self.name = name
        self.rows = rows
        self.events = events
        self.denied_acl = denied_acl
        self.denied_rules = denied_rules.setdefault(name, set())
        self.context = dict(context or {})
        fields = set(declared_fields or ())
        for row in rows.values():
            fields.update(row)
        fields.add("id")
        self._fields = {field: object() for field in fields}

    def with_context(self, **context):
        merged = {**self.context, **context}
        self.events.append(("with_context", self.name, merged))
        return FakeModel(
            self.name,
            self.rows,
            events=self.events,
            denied_acl=self.denied_acl,
            denied_rules={self.name: self.denied_rules},
            context=merged,
            declared_fields=self._fields,
        )

    def check_access_rights(self, operation):
        self.events.append(("check_access_rights", self.name, operation))
        if operation != "read" or self.name in self.denied_acl:
            raise PermissionError("ACL denied")
        return True

    def browse(self, ids):
        if type(ids) is int:
            values = [ids]
        else:
            values = list(ids)
        self.events.append(("browse", self.name, tuple(values)))
        return FakeRecordset(self, values)

    def search(self, domain, *, order):
        self.events.append(
            ("search", self.name, tuple(tuple(item) for item in domain), order)
        )
        ids = []
        for record_id, row in self.rows.items():
            if all(_matches(record_id, row, item) for item in domain):
                ids.append(record_id)
        return FakeRecordset(self, sorted(ids))


class FakeIdentity:
    def __init__(self, record_id):
        self.id = record_id


class FakeEnv:
    def __init__(
        self,
        rows,
        *,
        su,
        company_id=1,
        allowed_company_ids=(1,),
        denied_acl=(),
        denied_rules=None,
        missing_fields=None,
    ):
        self.su = su
        self.company = FakeIdentity(company_id)
        self.user = FakeIdentity(7)
        self.context = {"allowed_company_ids": list(allowed_company_ids)}
        self.events = []
        denied_acl_set = set(denied_acl)
        denied_rules_map = {
            name: set(values)
            for name, values in (denied_rules or {}).items()
        }
        missing = missing_fields or {}
        self.models = {}
        for name, model_rows in rows.items():
            model = FakeModel(
                name,
                model_rows,
                events=self.events,
                denied_acl=denied_acl_set,
                denied_rules=denied_rules_map,
            )
            for field in missing.get(name, ()):
                model._fields.pop(field, None)
            self.models[name] = model

    def __getitem__(self, model_name):
        self.events.append(("model", model_name))
        return self.models[model_name]


def _many2one_id(value):
    if value in (False, None):
        return None
    if type(value) is int:
        return value
    if isinstance(value, (list, tuple)):
        return value[0]
    return value


def _matches(record_id, row, term):
    field, operator, expected = term
    actual = record_id if field == "id" else row[field]
    actual = _many2one_id(actual)
    if operator == "=":
        return actual == expected
    if operator == "in":
        return actual in expected
    raise AssertionError(f"unsupported fake domain operator: {operator}")


def _report(
    name,
    *,
    root_report_id=False,
    section_report_ids=(),
    column_ids=(),
    line_ids=(),
):
    return {
        "active": True,
        "allow_foreign_vat": False,
        "availability_condition": "always",
        "chart_template": False,
        "country_id": False,
        "currency_translation": False,
        "custom_handler_model_id": False,
        "default_opening_date_filter": "this_year",
        "filter_date_range": True,
        "filter_growth_comparison": False,
        "filter_hide_0_lines": "never",
        "filter_journals": True,
        "filter_multi_company": "selector",
        "filter_period_comparison": True,
        "filter_show_draft": True,
        "filter_unfold_all": False,
        "filter_unreconciled": False,
        "integer_rounding": False,
        "load_more_limit": 80,
        "name": name,
        "only_tax_exigible": False,
        "prefix_groups_threshold": 4,
        "root_report_id": root_report_id,
        "search_bar": True,
        "section_report_ids": list(section_report_ids),
        "sequence": 10,
        "use_sections": bool(section_report_ids),
        "write_date": STAMP,
        "column_ids": list(column_ids),
        "line_ids": list(line_ids),
    }


def _rows():
    reports = {
        101: _report("Tax Report"),
        102: _report("Balance Sheet"),
        103: _report("Cash Flow Statement"),
        104: _report(
            "Profit and Loss",
            section_report_ids=(106,),
            column_ids=(301,),
            line_ids=(401, 402),
        ),
        105: _report("Balance Sheet Variant", root_report_id=102),
        106: _report("Profit and Loss Section"),
    }
    return {
        "ir.module.module": {
            1: {
                "name": "account",
                "latest_version": "19.0.1.0",
                "state": "installed",
                "write_date": STAMP,
            },
            2: {
                "name": "account_reports",
                "latest_version": "19.0.1.0",
                "state": "installed",
                "write_date": STAMP,
            },
        },
        "ir.module.module.dependency": {
            11: {
                "module_id": 2,
                "name": "account",
                "auto_install_required": True,
            }
        },
        "ir.model.data": {
            1001: {
                "model": "account.report",
                "res_id": 101,
                "module": "account",
                "name": "generic_tax_report",
            },
            1002: {
                "model": "account.report",
                "res_id": 102,
                "module": "account_reports",
                "name": "balance_sheet",
            },
            1003: {
                "model": "account.report",
                "res_id": 103,
                "module": "account_reports",
                "name": "cash_flow_report",
            },
            1004: {
                "model": "account.report",
                "res_id": 104,
                "module": "account_reports",
                "name": "profit_and_loss",
            },
            1005: {
                "model": "account.report",
                "res_id": 105,
                "module": "test_reports",
                "name": "balance_sheet_variant",
            },
            1006: {
                "model": "account.report",
                "res_id": 106,
                "module": "test_reports",
                "name": "profit_and_loss_section",
            },
        },
        "res.company": {
            1: {
                "account_fiscal_country_id": 20,
                "chart_template": "sg",
                "country_id": 20,
                "currency_id": 30,
                "fiscalyear_last_day": 31,
                "fiscalyear_last_month": "12",
                "fiscalyear_lock_date": date(2025, 12, 31),
                "hard_lock_date": False,
                "name": "ACME SG",
                "tax_lock_date": date(2026, 6, 30),
                "write_date": STAMP,
            }
        },
        "res.country": {20: {"code": "SG"}},
        "res.currency": {
            30: {
                "decimal_places": 2,
                "name": "SGD",
                "rounding": 0.01,
                "symbol": "$",
            }
        },
        "ir.model": {},
        "account.report": reports,
        "account.report.column": {
            301: {
                "blank_if_zero": False,
                "custom_audit_action_id": False,
                "expression_label": "balance",
                "figure_type": "monetary",
                "name": "Balance",
                "report_id": 104,
                "sequence": 10,
                "sortable": True,
                "write_date": STAMP,
            }
        },
        "account.report.line": {
            401: {
                "action_id": False,
                "code": False,
                "expression_ids": [501],
                "foldable": True,
                "groupby": False,
                "hide_if_zero": False,
                "hierarchy_level": 0,
                "horizontal_split_side": False,
                "name": "测试",
                "parent_id": False,
                "print_on_new_page": False,
                "report_id": 104,
                "sequence": 10,
                "user_groupby": False,
                "write_date": STAMP,
            },
            402: {
                "action_id": False,
                "code": "CHILD",
                "expression_ids": [],
                "foldable": False,
                "groupby": False,
                "hide_if_zero": True,
                "hierarchy_level": 1,
                "horizontal_split_side": False,
                "name": "Child",
                "parent_id": 401,
                "print_on_new_page": False,
                "report_id": 104,
                "sequence": 20,
                "user_groupby": False,
                "write_date": STAMP,
            },
        },
        "account.report.expression": {
            501: {
                "auditable": True,
                "blank_if_zero": False,
                "carryover_target": False,
                "date_scope": "normal",
                "engine": "domain",
                "figure_type": "monetary",
                "formula": "[('account_id.internal_group','=','income')]",
                "green_on_positive": True,
                "label": "balance",
                "report_line_id": 401,
                "subformula": "sum",
                "write_date": STAMP,
            }
        },
    }


def _fixture(
    *,
    rows=None,
    denied_acl=(),
    denied_rules=None,
    company_id=1,
    allowed_company_ids=(1,),
    missing_fields=None,
):
    values = rows or _rows()
    root = FakeEnv(values, su=True)
    state = capture_technical_definition_state(
        root, database_uuid=DATABASE_UUID
    )
    user = FakeEnv(
        values,
        su=False,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        denied_acl=denied_acl,
        denied_rules=denied_rules,
        missing_fields=missing_fields,
    )
    return root, user, state


def _observe(user, state):
    return observe_report_definition_projections(
        user, company_id=1, technical_state=state
    )


def test_public_state_is_frozen_and_deeply_detached():
    _root, _user, state = _fixture()

    with pytest.raises(FrozenInstanceError):
        state.database_uuid = DATABASE_UUID  # type: ignore[misc]
    first = state.module_graph
    first["modules"][0]["name"] = "forged"

    assert state.module_graph["modules"][0]["name"] == "account"


def test_technical_capture_requires_root_environment():
    with pytest.raises(ReportDefinitionObserverError, match="root"):
        capture_technical_definition_state(
            FakeEnv(_rows(), su=False),
            database_uuid=DATABASE_UUID,
        )


def test_technical_capture_builds_candidate_compatible_module_graph():
    _root, _user, state = _fixture()

    assert [item["name"] for item in state.module_graph["modules"]] == [
        "account",
        "account_reports",
    ]
    assert state.module_graph["modules"][1]["dependencies"] == [
        {"auto_install_required": True, "name": "account"}
    ]


def test_technical_capture_uses_only_read_orm_calls():
    root, _user, _state = _fixture()

    operations = {event[0] for event in root.events}

    assert operations <= {"model", "with_context", "search", "read"}


def test_technical_capture_rejects_noncanonical_database_uuid():
    with pytest.raises(ReportDefinitionObserverError, match="UUID"):
        capture_technical_definition_state(
            FakeEnv(_rows(), su=True),
            database_uuid=DATABASE_UUID.replace("12345678", "1234567A"),
        )


def test_technical_capture_rejects_missing_account_module():
    rows = _rows()
    del rows["ir.module.module"][1]

    with pytest.raises(ReportDefinitionObserverError, match="account"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_technical_capture_rejects_duplicate_module_name():
    rows = _rows()
    rows["ir.module.module"][3] = {
        **rows["ir.module.module"][1],
        "latest_version": "19.0.2.0",
    }

    with pytest.raises(ReportDefinitionObserverError, match="module"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_technical_capture_rejects_duplicate_dependency():
    rows = _rows()
    rows["ir.module.module.dependency"][12] = deepcopy(
        rows["ir.module.module.dependency"][11]
    )

    with pytest.raises(ReportDefinitionObserverError, match="dependency"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_technical_capture_rejects_duplicate_xmlid_for_record():
    rows = _rows()
    rows["ir.model.data"][1010] = {
        **rows["ir.model.data"][1001],
        "name": "generic_tax_report_alias",
    }

    with pytest.raises(ReportDefinitionObserverError, match="XMLID"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_technical_capture_rejects_same_xmlid_for_two_records():
    rows = _rows()
    rows["ir.model.data"][1010] = {
        **rows["ir.model.data"][1001],
        "res_id": 999,
    }

    with pytest.raises(ReportDefinitionObserverError, match="XMLID"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_technical_capture_rejects_missing_fixed_root_xmlid():
    rows = _rows()
    del rows["ir.model.data"][1004]

    with pytest.raises(ReportDefinitionObserverError, match="fixed"):
        capture_technical_definition_state(
            FakeEnv(rows, su=True), database_uuid=DATABASE_UUID
        )


def test_observer_returns_four_valid_canonical_root_projections():
    _root, user, state = _fixture()

    projections = _observe(user, state)

    assert tuple(
        (
            item["baseline_identity"]["family"],
            item["baseline_identity"]["kind"],
            item["baseline_identity"]["root_xmlid"],
        )
        for item in projections
    ) == ROOT_BASELINE_IDENTITIES
    for projection in projections:
        validate_root_definition_projection(projection)


def test_observer_preserves_custom_non_xmlid_chinese_line_semantics():
    _root, user, state = _fixture()

    projection = _observe(user, state)[3]
    root = next(
        item
        for item in projection["reports"]
        if item["xmlid"] == "account_reports.profit_and_loss"
    )
    line = next(item for item in root["lines"] if item["name"] == "测试")

    assert line["code"] is None
    assert line["parent_key"] is None
    assert line["sequence"] == 10
    assert line["key"].startswith(
        "account_reports.profit_and_loss/line/"
    )


def test_observer_recursively_includes_variant_report():
    _root, user, state = _fixture()

    balance = _observe(user, state)[1]

    assert [item["xmlid"] for item in balance["reports"]] == [
        "account_reports.balance_sheet",
        "test_reports.balance_sheet_variant",
    ]


def test_observer_recursively_includes_nested_variant_report():
    rows = _rows()
    rows["account.report"][107] = _report(
        "Nested Balance Sheet Variant", root_report_id=105
    )
    rows["ir.model.data"][1007] = {
        "model": "account.report",
        "res_id": 107,
        "module": "test_reports",
        "name": "nested_balance_sheet_variant",
    }
    _root, user, state = _fixture(rows=rows)

    balance = _observe(user, state)[1]

    assert [item["xmlid"] for item in balance["reports"]] == [
        "account_reports.balance_sheet",
        "test_reports.balance_sheet_variant",
        "test_reports.nested_balance_sheet_variant",
    ]


def test_observer_recursively_includes_section_report():
    _root, user, state = _fixture()

    profit = _observe(user, state)[3]

    assert [item["xmlid"] for item in profit["reports"]] == [
        "account_reports.profit_and_loss",
        "test_reports.profit_and_loss_section",
    ]


def test_observer_is_repeatable_and_matches_pure_projection_builder():
    _root, user, state = _fixture()

    first = _observe(user, state)
    second = _observe(user, state)
    identity = first[0]["baseline_identity"]
    rebuilt = build_root_definition_projection(
        **identity,
        company_profile=first[0]["company_profile"],
        module_graph=first[0]["module_graph"],
        reports=[
            report
            for projection in first
            for report in projection["reports"]
        ][:1],
    )

    assert canonical_projection_json(first) == canonical_projection_json(second)
    assert first[0] == rebuilt


def test_observer_rejects_superuser_environment():
    root, _user, state = _fixture()

    with pytest.raises(ReportDefinitionObserverError, match="user-bound"):
        _observe(root, state)


def test_observer_rejects_current_company_mismatch():
    _root, user, state = _fixture(company_id=2, allowed_company_ids=(1,))

    with pytest.raises(ReportDefinitionObserverError, match="company"):
        _observe(user, state)


def test_observer_rejects_multi_company_context():
    _root, user, state = _fixture(allowed_company_ids=(1, 2))

    with pytest.raises(ReportDefinitionObserverError, match="company"):
        _observe(user, state)


@pytest.mark.parametrize(
    "model_name",
    [
        "res.company",
        "account.report",
        "account.report.line",
        "account.report.column",
        "account.report.expression",
    ],
)
def test_observer_rejects_read_acl_denial(model_name):
    _root, user, state = _fixture(denied_acl=(model_name,))

    with pytest.raises(ReportDefinitionObserverError, match="read"):
        _observe(user, state)


@pytest.mark.parametrize(
    ("model_name", "record_id"),
    [
        ("res.company", 1),
        ("account.report", 104),
        ("account.report.line", 401),
        ("account.report.column", 301),
        ("account.report.expression", 501),
    ],
)
def test_observer_rejects_record_rule_denial(model_name, record_id):
    _root, user, state = _fixture(
        denied_rules={model_name: {record_id}}
    )

    with pytest.raises(ReportDefinitionObserverError, match="read"):
        _observe(user, state)


@pytest.mark.parametrize(
    ("model_name", "field"),
    [
        ("res.company", "chart_template"),
        ("account.report", "section_report_ids"),
        ("account.report.line", "expression_ids"),
        ("account.report.column", "expression_label"),
        ("account.report.expression", "formula"),
    ],
)
def test_observer_rejects_missing_definition_field(model_name, field):
    _root, user, state = _fixture(
        missing_fields={model_name: {field}}
    )

    with pytest.raises(ReportDefinitionObserverError, match="field"):
        _observe(user, state)


def test_observer_rejects_cross_company_report():
    rows = _rows()
    for report in rows["account.report"].values():
        report["company_id"] = False
    rows["account.report"][104]["company_id"] = 2
    _root, user, state = _fixture(rows=rows)

    with pytest.raises(ReportDefinitionObserverError, match="company"):
        _observe(user, state)


def test_observer_rejects_duplicate_column_semantics():
    rows = _rows()
    rows["account.report"][104]["column_ids"].append(302)
    rows["account.report.column"][302] = deepcopy(
        rows["account.report.column"][301]
    )
    _root, user, state = _fixture(rows=rows)

    with pytest.raises(ReportDefinitionObserverError, match="column"):
        _observe(user, state)


def test_observer_rejects_duplicate_line_semantics():
    rows = _rows()
    rows["account.report"][104]["line_ids"].append(403)
    rows["account.report.line"][403] = {
        **deepcopy(rows["account.report.line"][401]),
        "expression_ids": [],
    }
    _root, user, state = _fixture(rows=rows)

    with pytest.raises(ReportDefinitionObserverError, match="line"):
        _observe(user, state)


def test_observer_rejects_duplicate_expression_label():
    rows = _rows()
    rows["account.report.line"][401]["expression_ids"].append(502)
    rows["account.report.expression"][502] = deepcopy(
        rows["account.report.expression"][501]
    )
    _root, user, state = _fixture(rows=rows)

    with pytest.raises(ReportDefinitionObserverError, match="expression"):
        _observe(user, state)


def test_observer_rejects_report_without_exact_xmlid():
    rows = _rows()
    del rows["ir.model.data"][1006]
    root = FakeEnv(rows, su=True)
    state = capture_technical_definition_state(
        root, database_uuid=DATABASE_UUID
    )
    user = FakeEnv(rows, su=False)

    with pytest.raises(ReportDefinitionObserverError, match="XMLID"):
        _observe(user, state)


def test_observer_rejects_forged_noncanonical_module_graph():
    _root, user, state = _fixture()
    graph = state.module_graph
    graph["modules"].reverse()
    forged = replace(
        state,
        module_graph_json=json.dumps(graph).encode("utf-8"),
    )

    with pytest.raises(ReportDefinitionObserverError, match="module"):
        _observe(user, forged)


def test_observer_rejects_boolean_module_graph_schema_version():
    _root, user, state = _fixture()
    graph = state.module_graph
    graph["schema_version"] = True
    forged = replace(
        state,
        module_graph_json=canonical_projection_json(graph),
    )

    with pytest.raises(ReportDefinitionObserverError, match="module"):
        _observe(user, forged)


def test_observer_rejects_forged_duplicate_external_binding():
    _root, user, state = _fixture()
    forged = replace(
        state,
        external_ids=(
            *state.external_ids,
            ExternalIdBinding(
                model="account.report",
                record_id=101,
                xmlid="test_reports.alias",
            ),
        ),
    )

    with pytest.raises(ReportDefinitionObserverError, match="XMLID"):
        _observe(user, forged)


def test_company_drift_changes_every_projection():
    _root, user, state = _fixture()
    before = _observe(user, state)
    user.models["res.company"].rows[1]["name"] = "ACME SG Changed"

    after = _observe(user, state)

    assert all(
        canonical_projection_json(left) != canonical_projection_json(right)
        for left, right in zip(before, after)
    )


def test_definition_drift_changes_affected_projection_only():
    _root, user, state = _fixture()
    before = _observe(user, state)
    user.models["account.report"].rows[104]["name"] = "P&L Changed"

    after = _observe(user, state)

    assert before[:3] == after[:3]
    assert before[3] != after[3]


def test_module_drift_changes_every_projection():
    rows = _rows()
    root, user, state = _fixture(rows=rows)
    before = _observe(user, state)
    root.models["ir.module.module"].rows[1]["latest_version"] = "19.0.2.0"
    changed_state = capture_technical_definition_state(
        root, database_uuid=DATABASE_UUID
    )

    after = _observe(user, changed_state)

    assert all(left != right for left, right in zip(before, after))


def test_observer_forces_english_and_single_company_context():
    _root, user, state = _fixture()

    _observe(user, state)

    contexts = [
        event[2]
        for event in user.events
        if event[0] == "with_context"
    ]
    assert contexts
    assert all(item["lang"] == "en_US" for item in contexts)
    assert all(item["allowed_company_ids"] == [1] for item in contexts)


def test_observer_uses_only_read_orm_calls():
    _root, user, state = _fixture()

    _observe(user, state)
    operations = {event[0] for event in user.events}

    assert operations <= {
        "model",
        "with_context",
        "check_access_rights",
        "browse",
        "exists",
        "check_access_rule",
        "read",
        "search",
    }
