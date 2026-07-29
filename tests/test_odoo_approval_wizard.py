from __future__ import annotations

import ast
from copy import deepcopy
import csv
import importlib.util
import json
import sys
import types
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control"
CLIENT = ADDON / "models" / "approval_client.py"
WIZARD = ADDON / "models" / "approval_wizard.py"
SECURITY = ADDON / "security" / "odoo_accounting_cli_v3_security.xml"
ACL = ADDON / "security" / "ir.model.access.csv"
VIEWS = ADDON / "views" / "approval_wizard_views.xml"
REGISTRY = ROOT / "registry" / "capabilities.json"
VENDOR_BILL_CAPABILITY_ID = "acct.bill.vendor_create.v1"


class FakeTransientModel:
    pass


class FakeField:
    def __call__(self, *_args: object, **_kwargs: object) -> object:
        return object()


class FakeDatetimeField(FakeField):
    @staticmethod
    def now() -> str:
        return "2026-07-15 08:00:00"


def _load_wizard(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    odoo = types.ModuleType("odoo")
    odoo.api = types.SimpleNamespace(model_create_multi=lambda function: function)
    odoo.fields = types.SimpleNamespace(
        Char=FakeField(),
        Datetime=FakeDatetimeField(),
        Integer=FakeField(),
        Many2one=FakeField(),
        Selection=FakeField(),
        Text=FakeField(),
    )
    odoo.models = types.SimpleNamespace(TransientModel=FakeTransientModel)
    exceptions = types.ModuleType("odoo.exceptions")
    exceptions.AccessError = type("FakeAccessError", (Exception,), {})
    exceptions.UserError = type("FakeUserError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)

    module_name = "test_odoo_v3_approval_wizard_module"
    spec = importlib.util.spec_from_file_location(module_name, WIZARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _inspection(wizard: types.ModuleType) -> dict[str, Any]:
    parameters = {
        "amount_total": "1280.50",
        "currency": "USD",
        "invoice_date": "2026-07-15",
        "supplier": {"id": 314, "name": "Tokyo Parts Co."},
    }
    parameters_digest = wizard._digest(parameters)
    evidence = {
        "capability_id": VENDOR_BILL_CAPABILITY_ID,
        "company_id": 7,
        "parameters_digest": parameters_digest,
        "registry_digest": "b" * 64,
        "release_digest": "c" * 64,
        "runtime_binding": {
            "user_id": 42,
            "odoo_instance_id": "Tokyo Odoo sandbox / 01",
            "database_name": "accounting sandbox",
            "database_uuid": "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81",
            "environment": "sandbox",
        },
        "handler_details": {
            "financial_preview": {
                "amount_total": "1280.50",
                "currency": "USD",
                "invoice_date": "2026-07-15",
                "supplier_id": 314,
            },
            "dependencies": [{"model": "res.partner", "id": 314}],
        },
    }
    precheck_digest = wizard._digest(evidence)
    operation_core = {
        "capability_id": VENDOR_BILL_CAPABILITY_ID,
        "parameters": parameters,
        "principal": "Odoo requester / accounting tenant",
        "user_id": 42,
        "company_id": 7,
        "idempotency_key": "vendor-bill-20260715-1",
        "odoo_instance_id": "Tokyo Odoo sandbox / 01",
        "database_name": "accounting sandbox",
        "database_uuid": "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81",
        "environment": "sandbox",
        "registry_digest": "b" * 64,
        "release_digest": "c" * 64,
    }
    operation_digest = wizard._digest(operation_core)
    operation = {
        "operation_id": "operation-1",
        "request_id": "request-1",
        "capability_id": operation_core["capability_id"],
        "parameters": parameters,
        "parameters_digest": parameters_digest,
        "principal": operation_core["principal"],
        "user_id": 42,
        "company_id": 7,
        "idempotency_key": operation_core["idempotency_key"],
        "odoo_instance_id": operation_core["odoo_instance_id"],
        "database_name": operation_core["database_name"],
        "database_uuid": operation_core["database_uuid"],
        "environment": "sandbox",
        "registry_digest": "b" * 64,
        "release_digest": "c" * 64,
        "operation_digest": operation_digest,
        "precheck_digest": precheck_digest,
        "state": "awaiting_approval",
        "revision": 2,
        "protocol_version": 4,
    }
    binding_digest = wizard._digest(
        {
            "company_id": 7,
            "database_name": operation["database_name"],
            "database_uuid": operation["database_uuid"],
            "environment": "sandbox",
            "odoo_instance_id": operation["odoo_instance_id"],
            "operation_digest": operation_digest,
            "operation_id": "operation-1",
            "operation_revision": 2,
            "precheck_digest": precheck_digest,
            "principal": operation["principal"],
            "request_id": "request-1",
            "user_id": 42,
        }
    )
    challenge = {
        "challenge_id": "challenge-1",
        "binding_digest": binding_digest,
        "issued_at": "2026-07-15T08:00:00+00:00",
        "expires_at": "2026-07-15T08:15:00+00:00",
        "ttl_seconds": 900,
        "state": "pending",
        "version": 0,
    }
    summary = {
        "binding_digest": binding_digest,
        "capability_id": operation["capability_id"],
        "challenge_id": "challenge-1",
        "company_id": 7,
        "operation_digest": operation_digest,
        "operation_id": "operation-1",
        "parameters_digest": parameters_digest,
        "precheck_digest": precheck_digest,
        "requester_principal": operation["principal"],
        "requester_user_id": 42,
    }
    preview = {
        "schema_version": 1,
        "challenge": challenge,
        "operation": operation,
        "summary": summary,
    }
    precheck = {
        "operation_id": "operation-1",
        "request_id": "request-1",
        "operation_digest": operation_digest,
        "operation_revision": 2,
        "source_operation_revision": 0,
        "principal": operation["principal"],
        "user_id": 42,
        "company_id": 7,
        "evidence_digest": precheck_digest,
        "occurred_at": "2026-07-15T07:59:00+00:00",
        "evidence": evidence,
    }
    unsigned = {
        **preview,
        "preview_digest": wizard._digest(preview),
        "precheck": precheck,
    }
    return {**unsigned, "inspection_digest": wizard._digest(unsigned)}


def _class_methods(path: Path, class_name: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text("utf-8"), filename=str(path))
    model = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return {
        node.name: node
        for node in model.body
        if isinstance(node, ast.FunctionDef)
    }


def test_vendor_bill_approval_fixture_uses_registered_capability_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wizard = _load_wizard(monkeypatch)
    inspection = _inspection(wizard)
    registered_ids = {
        item["id"]
        for item in json.loads(REGISTRY.read_text(encoding="utf-8"))[
            "capabilities"
        ]
    }

    assert inspection["operation"]["capability_id"] == VENDOR_BILL_CAPABILITY_ID
    assert inspection["precheck"]["evidence"]["capability_id"] == (
        VENDOR_BILL_CAPABILITY_ID
    )
    assert VENDOR_BILL_CAPABILITY_ID in registered_ids


def test_inspection_validator_preserves_complete_business_and_precheck_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wizard = _load_wizard(monkeypatch)
    inspection = _inspection(wizard)

    validated = wizard._validated_inspection(inspection)

    assert validated == inspection
    assert validated is not inspection
    assert validated["operation"]["parameters"] == {
        "amount_total": "1280.50",
        "currency": "USD",
        "invoice_date": "2026-07-15",
        "supplier": {"id": 314, "name": "Tokyo Parts Co."},
    }
    assert validated["precheck"]["evidence"]["handler_details"][
        "financial_preview"
    ] == {
        "amount_total": "1280.50",
        "currency": "USD",
        "invoice_date": "2026-07-15",
        "supplier_id": 314,
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("operation", "parameters", "amount_total"), "1.00"),
        (
            (
                "precheck",
                "evidence",
                "handler_details",
                "financial_preview",
                "amount_total",
            ),
            "1.00",
        ),
        (("operation", "company_id"), 9),
        (("precheck", "source_operation_revision"), 1),
        (("operation", "parameters", "Auth-Signature"), "forged"),
    ],
)
def test_inspection_validator_rejects_rehashed_binding_or_authority_drift(
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: object,
) -> None:
    wizard = _load_wizard(monkeypatch)
    tampered = deepcopy(_inspection(wizard))
    target: dict[str, Any] = tampered
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    preview = {
        name: tampered[name]
        for name in ("schema_version", "challenge", "operation", "summary")
    }
    tampered["preview_digest"] = wizard._digest(preview)
    unsigned = {
        name: tampered[name]
        for name in (
            "schema_version",
            "challenge",
            "operation",
            "summary",
            "preview_digest",
            "precheck",
        )
    }
    tampered["inspection_digest"] = wizard._digest(unsigned)

    with pytest.raises(wizard.ApprovalWizardError):
        wizard._validated_inspection(tampered)


def test_denial_reason_is_exact_bounded_and_required_for_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wizard = _load_wizard(monkeypatch)

    assert wizard._denial_reason(None, required=False) is False
    assert wizard._denial_reason("Duplicate vendor bill", required=True) == (
        "Duplicate vendor bill"
    )
    for value in ("", " padded ", "line\nbreak", "x" * 513):
        with pytest.raises(wizard.ApprovalWizardError):
            wizard._denial_reason(value, required=True)


def test_approval_entry_is_wizard_only_and_has_no_bare_client_rpc() -> None:
    assert WIZARD.is_file()
    client_methods = _class_methods(
        CLIENT, "OdooAccountingCliV3ApprovalClient"
    )
    assert "request_v3_approval" not in client_methods
    assert "decide_v3_approval" not in client_methods
    assert "inspect_v3_approval" not in client_methods
    assert "_odoo_v3_request_approval" in client_methods
    assert "_odoo_v3_inspect_approval" in client_methods
    assert "_odoo_v3_decide_approval" in client_methods

    init = (ADDON / "models" / "__init__.py").read_text("utf-8").splitlines()
    manifest = ast.literal_eval((ADDON / "__manifest__.py").read_text("utf-8"))
    assert "from . import approval_wizard" in init
    assert manifest["version"] == "19.0.0.7.0"
    assert "views/approval_wizard_views.xml" in manifest["data"]


def test_wizard_public_surface_is_record_bound_and_argument_free() -> None:
    source = WIZARD.read_text("utf-8")
    methods = _class_methods(WIZARD, "OdooAccountingCliV3ApprovalWizard")
    assert {
        name for name in methods if not name.startswith("_")
    } == {"create", "write", "action_approve", "action_deny", "action_refresh"}
    for name in ("action_approve", "action_deny", "action_refresh"):
        method = methods[name]
        assert [argument.arg for argument in method.args.args] == ["self"]
        assert method.args.kwonlyargs == []
        method_source = ast.get_source_segment(source, method)
        assert "self.ensure_one()" in method_source
        assert "self._assert_record_bound()" in method_source
    assert ".sudo(" not in source
    assert "env.context" not in source
    assert ".with_context(" not in source


def test_create_write_and_decision_paths_accept_no_caller_authority() -> None:
    source = WIZARD.read_text("utf-8")
    methods = _class_methods(WIZARD, "OdooAccountingCliV3ApprovalWizard")
    create = ast.get_source_segment(source, methods["create"])
    write = ast.get_source_segment(source, methods["write"])
    decide = ast.get_source_segment(source, methods["_decide"])
    pending = ast.get_source_segment(source, methods["_assert_pending_snapshot"])
    approver = ast.get_source_segment(source, methods["_assert_approver"])

    assert 'set(vals_list[0]) != {"challenge_id"}' in create
    assert '_odoo_v3_inspect_approval({"challenge_id": challenge_id})' in create
    assert "super().create([self._snapshot_values(inspection)])" in create
    assert 'set(values) != {"denial_reason"}' in write
    assert "wizard._assert_record_bound()" in write
    assert "self.env.su" in approver
    assert "before = self._inspect()" in decide
    assert "self._assert_pending_snapshot(before)" in decide
    assert "after = self._inspect()" in decide
    assert "self._assert_final_transition(before, after" in decide
    assert '"challenge_id": self.challenge_id' in decide
    assert '"decision": decision' in decide
    assert '"reason": reason' in decide
    for forbidden in (
        '"company_id":',
        '"user_id":',
        '"parameters":',
        '"operation_digest":',
        '"session_handle":',
    ):
        assert forbidden not in decide
    for field_name in (
        "parameters_json",
        "precheck_json",
        "snapshot_json",
        "preview_digest",
        "inspection_digest",
    ):
        assert f'"{field_name}": self.{field_name}' in pending


def test_wizard_acl_rule_view_action_menu_and_buttons_are_approver_only() -> None:
    with ACL.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    wizard_acl = [
        row
        for row in rows
        if row["model_id:id"] == "model_odoo_accounting_cli_v3_approval_wizard"
    ]
    assert len(wizard_acl) == 1
    assert wizard_acl[0]["group_id:id"] == (
        "odoo_accounting_cli_v3_control.group_approver"
    )
    assert [
        wizard_acl[0][f"perm_{name}"]
        for name in ("read", "write", "create", "unlink")
    ] == ["1", "1", "1", "0"]

    security = SECURITY.read_text("utf-8")
    assert "approval_wizard_approver_company_rule" in security
    assert "('create_uid', '=', user.id)" in security
    assert "('company_id', 'in', company_ids)" in security

    tree = ET.parse(VIEWS)
    root = tree.getroot()
    buttons = root.findall(".//button[@type='object']")
    assert {button.attrib["name"] for button in buttons} == {
        "action_approve",
        "action_deny",
        "action_refresh",
    }
    for button in buttons:
        assert button.attrib["groups"] == (
            "odoo_accounting_cli_v3_control.group_approver"
        )
        assert "invisible" in button.attrib
    text = VIEWS.read_text("utf-8")
    for field_name in (
        "parameters_json",
        "precheck_json",
        "snapshot_json",
        "operation_digest",
        "precheck_digest",
        "inspection_digest",
    ):
        assert f'name="{field_name}"' in text
    for field_name in ("parameters_json", "precheck_json", "snapshot_json"):
        field = root.find(f".//field[@name='{field_name}']")
        assert field is not None
        assert field.attrib["readonly"] == "1"
    action = next(
        record
        for record in root.findall("record")
        if record.attrib.get("id")
        == "action_odoo_accounting_cli_v3_approval_wizard"
    )
    action_fields = {
        field.attrib["name"]: field for field in action.findall("field")
    }
    assert action_fields["res_model"].text == (
        "odoo.accounting.cli.v3.approval.wizard"
    )
    assert action_fields["target"].text == "new"
    assert "group_approver" in action_fields["group_ids"].attrib["eval"]
    assert "menu_odoo_accounting_cli_v3_approval" in text
    assert "action_odoo_accounting_cli_v3_approval_wizard" in text
