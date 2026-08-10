from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control" / "models"
SCOPE = MODELS / "execution_scope.py"
METADATA = MODELS / "accounting_metadata.py"
MANIFEST = MODELS.parent / "__manifest__.py"


class FakeValidationError(Exception):
    pass


class FakeRecord(dict[str, Any]):
    def __getitem__(self, key: str) -> Any:
        return self.get(key, False)

    def __getattr__(self, key: str) -> Any:
        return self.get(key, False)


class FakeBaseModel:
    def __init__(
        self,
        rows: list[dict[str, Any]] | None = None,
        *,
        context: dict[str, Any] | None = None,
        su: bool = False,
    ) -> None:
        self._rows = [FakeRecord(row) for row in (rows or [])]
        self.created_values: list[dict[str, Any]] = []
        self.env = SimpleNamespace(context=context or {}, su=su)

    def __iter__(self):
        return iter(self._rows)

    def create(self, values_list: list[dict[str, Any]]):
        created: list[dict[str, Any]] = []
        for raw in values_list:
            values = dict(raw)
            for key, value in self.env.context.items():
                if key.startswith("default_"):
                    values.setdefault(key.removeprefix("default_"), value)
            created.append(FakeRecord(values))
        self.created_values.extend(created)
        return type(self)(created, context=self.env.context, su=self.env.su)

    def write(self, values: dict[str, Any]) -> bool:
        for row in self._rows:
            row.update(values)
        return True


def _load_guard_modules(monkeypatch: pytest.MonkeyPatch):
    package_name = "_odoo_v3_metadata_guard_test_models"
    package = ModuleType(package_name)
    package.__path__ = [str(MODELS)]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, package_name, package)

    odoo = ModuleType("odoo")
    odoo.api = SimpleNamespace(
        constrains=lambda *_names: (lambda function: function),
        model_create_multi=lambda function: function,
    )
    odoo.fields = SimpleNamespace(
        Char=lambda **_kwargs: None,
        Date=lambda **_kwargs: None,
        Json=lambda **_kwargs: None,
    )
    odoo.models = SimpleNamespace(
        Model=FakeBaseModel,
        Constraint=lambda *_args: None,
    )
    exceptions = ModuleType("odoo.exceptions")
    exceptions.ValidationError = FakeValidationError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)

    def load(name: str, path: Path) -> ModuleType:
        spec = importlib.util.spec_from_file_location(f"{package_name}.{name}", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        return module

    return load("execution_scope", SCOPE), load("accounting_metadata", METADATA)


CASES = (
    ("AccountMove", "odoo_cli_v3_document_binding", "a" * 64),
    ("AccountMove", "odoo_cli_v3_document_binding_v2", "f" * 64),
    ("AccountMoveLine", "odoo_cli_v3_line_reference", "line-1"),
    (
        "AccountPayment",
        "odoo_cli_v3_payment_binding",
        {"version": 1, "payment_id": 42},
    ),
    ("AccountBankStatement", "odoo_cli_v3_source_digest", "b" * 64),
    (
        "AccountBankStatementLine",
        "odoo_cli_v3_source_line_digest",
        "c" * 64,
    ),
)


def test_document_binding_v2_static_contract_and_addon_patch_version() -> None:
    source = METADATA.read_text(encoding="utf-8")
    tree = ast.parse(source)
    manifest = ast.literal_eval(MANIFEST.read_text(encoding="utf-8"))
    account_move = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AccountMove"
    )
    field_assignment = next(
        node
        for node in account_move.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "odoo_cli_v3_document_binding_v2"
            for target in node.targets
        )
    )
    assert isinstance(field_assignment.value, ast.Call)
    assert isinstance(field_assignment.value.func, ast.Attribute)
    assert field_assignment.value.func.attr == "Char"
    field_options = {
        keyword.arg: ast.literal_eval(keyword.value)
        for keyword in field_assignment.value.keywords
    }

    assert '"odoo_cli_v3_document_binding_v2",' in source
    assert field_options == {
        "copy": False,
        "index": True,
        "readonly": True,
        "size": 64,
    }
    assert (
        "UNIQUE(company_id, move_type, odoo_cli_v3_document_binding_v2)"
        in source
    )
    assert '@api.constrains("odoo_cli_v3_document_binding_v2")' in source
    assert "document binding V2 must be lowercase SHA-256" in source
    assert manifest["version"] == "19.0.0.7.3"


def test_document_binding_v2_can_only_be_assigned_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, metadata = _load_guard_modules(monkeypatch)
    field = "odoo_cli_v3_document_binding_v2"
    value = "f" * 64

    with scope._accounting_metadata_execution_scope():
        created = metadata.AccountMove().create([{field: value}])
        initially_empty = metadata.AccountMove([{field: False}])
        assert initially_empty.write({field: value}) is True

        for record in (created, initially_empty):
            for replacement in (value, "e" * 64, False):
                with pytest.raises(FakeValidationError, match="immutable"):
                    record.write({field: replacement})


def test_document_binding_v2_digest_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scope, metadata = _load_guard_modules(monkeypatch)
    field = "odoo_cli_v3_document_binding_v2"

    metadata.AccountMove([{field: False}])._check_odoo_cli_v3_document_binding_v2()
    metadata.AccountMove([{field: "f" * 64}])._check_odoo_cli_v3_document_binding_v2()
    for invalid in ("f" * 63, "F" * 64, "not-a-digest"):
        with pytest.raises(
            FakeValidationError,
            match="document binding V2 must be lowercase SHA-256",
        ):
            metadata.AccountMove(
                [{field: invalid}]
            )._check_odoo_cli_v3_document_binding_v2()


@pytest.mark.parametrize("class_name,field_name,value", CASES)
def test_public_orm_cannot_create_or_first_write_v3_metadata(
    monkeypatch: pytest.MonkeyPatch,
    class_name: str,
    field_name: str,
    value: Any,
) -> None:
    _scope, metadata = _load_guard_modules(monkeypatch)
    model_type = getattr(metadata, class_name)

    model = model_type()
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        model.create([{field_name: value}])
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        model.create([{field_name: False}])
    assert model.created_values == []

    record = model_type([{field_name: False}])
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        record.write({field_name: value})
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        record.write({field_name: False})
    assert record._rows == [{field_name: False}]


@pytest.mark.parametrize("class_name,field_name,value", CASES)
def test_ordinary_orm_create_and_write_remain_available(
    monkeypatch: pytest.MonkeyPatch,
    class_name: str,
    field_name: str,
    value: Any,
) -> None:
    del field_name, value
    _scope, metadata = _load_guard_modules(monkeypatch)
    model_type = getattr(metadata, class_name)

    created = model_type().create([{"ordinary_field": "initial"}])
    assert created._rows == [{"ordinary_field": "initial"}]
    assert created.write({"ordinary_field": "changed"}) is True
    assert created._rows == [{"ordinary_field": "changed"}]


def test_public_batch_defaults_context_and_sudo_cannot_forge_the_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scope, metadata = _load_guard_modules(monkeypatch)
    field = "odoo_cli_v3_document_binding"
    value = "d" * 64

    mixed = metadata.AccountMove()
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        mixed.create([{}, {field: value}])
    assert mixed.created_values == []

    defaulted = metadata.AccountMove(
        context={f"default_{field}": value, "odoo_cli_v3_trusted": True},
        su=True,
    )
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        defaulted.create([{}])

    record = metadata.AccountMove(
        [{field: False}],
        context={"odoo_cli_v3_trusted": True},
        su=True,
    )
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        record.write({field: value})


@pytest.mark.parametrize("class_name,field_name,value", CASES)
def test_private_execution_scope_allows_only_the_initial_metadata_assignment(
    monkeypatch: pytest.MonkeyPatch,
    class_name: str,
    field_name: str,
    value: Any,
) -> None:
    scope, metadata = _load_guard_modules(monkeypatch)
    model_type = getattr(metadata, class_name)

    with scope._accounting_metadata_execution_scope():
        created = model_type().create([{field_name: value}])
        initially_empty = model_type([{field_name: False}])
        assert initially_empty.write({field_name: value}) is True
        with pytest.raises(FakeValidationError, match="immutable"):
            initially_empty.write({field_name: value})

    assert created._rows == [{field_name: value}]
    assert initially_empty._rows == [{field_name: value}]


def test_execution_scope_is_context_local_nested_and_reset_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, metadata = _load_guard_modules(monkeypatch)
    field = "odoo_cli_v3_document_binding"
    value = "e" * 64
    assert scope._accounting_metadata_write_is_allowed() is False

    with pytest.raises(RuntimeError, match="abort"):
        with scope._accounting_metadata_execution_scope():
            assert scope._accounting_metadata_write_is_allowed() is True
            with scope._accounting_metadata_execution_scope():
                assert scope._accounting_metadata_write_is_allowed() is True
            raise RuntimeError("abort")

    assert scope._accounting_metadata_write_is_allowed() is False
    with pytest.raises(FakeValidationError, match="trusted V3 execution"):
        metadata.AccountMove([{field: False}]).write({field: value})


def test_metadata_authority_never_uses_odoo_context_or_superuser_state() -> None:
    source = METADATA.read_text(encoding="utf-8") + SCOPE.read_text(encoding="utf-8")
    assert "env.context" not in source
    assert ".sudo(" not in source
    assert "ContextVar(" in source
    assert "is _SCOPE_TOKEN" in source
