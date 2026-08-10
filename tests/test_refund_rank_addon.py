from __future__ import annotations

import importlib.util
import sys
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control" / "models"
SCOPE = MODELS / "execution_scope.py"
REFUND_RANK = MODELS / "refund_rank.py"

CAPABILITY_ID = "acct.refund.post_reconcile_origin.v1"
CAPABILITY_CONTEXT = "odoo_accounting_cli_v3_rank_capability_id"
FIELD_CONTEXT = "odoo_accounting_cli_v3_rank_field"
PARTNER_IDS_CONTEXT = "odoo_accounting_cli_v3_rank_partner_ids"
EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"


class FakeAccessError(Exception):
    pass


class FakeValidationError(Exception):
    pass


class FakeAtomicFailure(Exception):
    pass


class FakePartnerRow:
    def __init__(self, env: "FakeEnvironment", partner_id: int):
        self.env = env
        self.id = partner_id

    def __getitem__(self, field: str) -> int:
        return self.env.partner_values[self.id][field]

    def __setitem__(self, field: str, value: int) -> None:
        if self.id in self.env.direct_failure_ids:
            raise FakeAtomicFailure("rank update failed")
        self.env.partner_values[self.id][field] = value


class FakePartnerCatalog:
    def __init__(self, env: "FakeEnvironment"):
        self.env = env

    def browse(self, partner_ids):
        return self.env.model_type(self.env, partner_ids)


class FakeEnvironment:
    def __init__(
        self,
        *,
        context: dict[str, object] | None = None,
        executor: bool = True,
        su: bool = False,
    ) -> None:
        self.context = dict(context or {})
        self.su = su
        self.user = SimpleNamespace(
            has_group=lambda xmlid: executor and xmlid == EXECUTOR_GROUP
        )
        self.partner_values = {
            101: {"customer_rank": 4, "supplier_rank": 2},
            202: {"customer_rank": 7, "supplier_rank": 3},
            303: {"customer_rank": 9, "supplier_rank": 5},
        }
        self.model_type = None
        self.base_calls: list[tuple[tuple[int, ...], str, int]] = []
        self.sudo_calls = 0
        self.direct_failure_ids: set[int] = set()

    def __getitem__(self, model_name: str):
        assert model_name == "res.partner"
        return FakePartnerCatalog(self)


class FakeBaseModel:
    _inherit = ""

    def __init__(self, env: FakeEnvironment, partner_ids=()) -> None:
        self.env = env
        if isinstance(partner_ids, int):
            partner_ids = [partner_ids]
        self.ids = list(partner_ids)

    def __iter__(self):
        return iter(FakePartnerRow(self.env, partner_id) for partner_id in self.ids)

    def browse(self, partner_ids):
        return type(self)(self.env, partner_ids)

    def sudo(self):
        self.env.sudo_calls += 1
        return self

    def _increase_rank(self, field, n=1):
        ids = tuple(self.ids)
        self.env.base_calls.append((ids, field, n))
        if set(ids) & self.env.direct_failure_ids:
            raise FakeAtomicFailure("rank update failed")

        # Model the upstream implementation as one atomic update: validation
        # completes before any row is changed.
        updated = {
            partner_id: self.env.partner_values[partner_id][field] + n
            for partner_id in ids
        }
        for partner_id, value in updated.items():
            self.env.partner_values[partner_id][field] = value


def _load(monkeypatch: pytest.MonkeyPatch):
    package_name = "_odoo_v3_refund_rank_test_models"
    package = ModuleType(package_name)
    package.__path__ = [str(MODELS)]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, package_name, package)

    odoo = ModuleType("odoo")
    odoo.models = SimpleNamespace(Model=FakeBaseModel)
    exceptions = ModuleType("odoo.exceptions")
    exceptions.AccessError = FakeAccessError
    exceptions.ValidationError = FakeValidationError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)

    def load(name: str, path: Path) -> ModuleType:
        spec = importlib.util.spec_from_file_location(
            f"{package_name}.{name}", path
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        return module

    return load("execution_scope", SCOPE), load("refund_rank", REFUND_RANK)


def _trusted_context(
    *,
    field: str = "customer_rank",
    partner_ids: tuple[int, ...] = (101, 202),
) -> dict[str, object]:
    return {
        CAPABILITY_CONTEXT: CAPABILITY_ID,
        FIELD_CONTEXT: field,
        PARTNER_IDS_CONTEXT: partner_ids,
    }


def _partners(module, env: FakeEnvironment, partner_ids=(101,)):
    env.model_type = module.ResPartner
    return module.ResPartner(env, partner_ids)


@contextmanager
def _main_transaction(env: FakeEnvironment):
    before = deepcopy(env.partner_values)
    try:
        yield
    except Exception:
        env.partner_values = before
        raise


def test_trusted_refund_scope_increments_selected_and_commercial_partner_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=_trusted_context())
    selected_and_commercial = _partners(refund_rank, env, (101, 202))

    with scope._accounting_metadata_execution_scope():
        selected_and_commercial._increase_rank("customer_rank", 1)

    assert env.partner_values[101] == {
        "customer_rank": 5,
        "supplier_rank": 2,
    }
    assert env.partner_values[202] == {
        "customer_rank": 8,
        "supplier_rank": 3,
    }
    assert env.base_calls == []
    assert env.sudo_calls == 1


def test_trusted_refund_scope_deduplicates_selected_commercial_partner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(
        context=_trusted_context(partner_ids=(101,))
    )
    selected = _partners(refund_rank, env, (101,))

    with scope._accounting_metadata_execution_scope():
        selected._increase_rank("customer_rank", 1)

    assert env.partner_values[101]["customer_rank"] == 5
    assert env.base_calls == []
    assert env.sudo_calls == 1


@pytest.mark.parametrize(
    "context",
    (
        {},
        {CAPABILITY_CONTEXT: "acct.invoice.customer_post.v1"},
    ),
)
def test_ordinary_or_other_capability_rank_update_uses_super(
    monkeypatch: pytest.MonkeyPatch, context: dict[str, object]
) -> None:
    _scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=context)

    _partners(refund_rank, env, (101,))._increase_rank("supplier_rank", 2)

    assert env.partner_values[101]["supplier_rank"] == 4
    assert env.base_calls == [((101,), "supplier_rank", 2)]


def test_refund_context_without_execution_scope_uses_super(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=_trusted_context())

    _partners(refund_rank, env, (101,))._increase_rank("customer_rank", 1)

    assert env.partner_values[101]["customer_rank"] == 5
    assert env.partner_values[202]["customer_rank"] == 7
    assert env.base_calls == [((101,), "customer_rank", 1)]


@pytest.mark.parametrize(
    ("context", "selected_ids", "field", "delta"),
    (
        (
            _trusted_context(field="customer_rank"),
            (101, 202),
            "supplier_rank",
            1,
        ),
        (_trusted_context(), (101, 202), "customer_rank", 2),
        (_trusted_context(), (101, 202), "customer_rank", True),
        (
            _trusted_context(partner_ids=(101, 999)),
            (101, 202),
            "customer_rank",
            1,
        ),
        (_trusted_context(partner_ids=(101, 101)), (101,), "customer_rank", 1),
        (
            _trusted_context(partner_ids=(202, 101)),
            (101, 202),
            "customer_rank",
            1,
        ),
        (_trusted_context(), (303,), "customer_rank", 1),
    ),
)
def test_trusted_refund_scope_rejects_inexact_field_delta_or_partner_ids(
    monkeypatch: pytest.MonkeyPatch,
    context: dict[str, object],
    selected_ids: tuple[int, ...],
    field: str,
    delta: int,
) -> None:
    scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=context)
    selected = _partners(refund_rank, env, selected_ids)
    before = {
        partner_id: dict(values)
        for partner_id, values in env.partner_values.items()
    }

    with scope._accounting_metadata_execution_scope():
        with pytest.raises(FakeValidationError, match="binding"):
            selected._increase_rank(field, delta)

    assert env.partner_values == before
    assert env.base_calls == []


@pytest.mark.parametrize(("executor", "su"), ((False, False), (True, True)))
def test_trusted_refund_scope_rejects_non_executor_or_superuser(
    monkeypatch: pytest.MonkeyPatch, executor: bool, su: bool
) -> None:
    scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=_trusted_context(), executor=executor, su=su)
    selected = _partners(refund_rank, env, (101, 202))

    with scope._accounting_metadata_execution_scope():
        with pytest.raises(FakeAccessError, match="executor"):
            selected._increase_rank("customer_rank", 1)

    assert env.partner_values[101]["customer_rank"] == 4
    assert env.partner_values[202]["customer_rank"] == 7
    assert env.base_calls == []


def test_trusted_refund_rank_failure_is_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, refund_rank = _load(monkeypatch)
    env = FakeEnvironment(context=_trusted_context())
    env.direct_failure_ids.add(202)
    selected_and_commercial = _partners(refund_rank, env, (101, 202))

    with pytest.raises(FakeAtomicFailure, match="rank update failed"):
        with _main_transaction(env):
            with scope._accounting_metadata_execution_scope():
                selected_and_commercial._increase_rank("customer_rank", 1)

    assert env.partner_values[101]["customer_rank"] == 4
    assert env.partner_values[202]["customer_rank"] == 7
    assert env.base_calls == []


def test_trusted_refund_rank_uses_the_existing_transaction_only() -> None:
    source = REFUND_RANK.read_text(encoding="utf-8")

    assert "postcommit" not in source
    assert "registry.cursor" not in source
    assert ".commit(" not in source
    assert "for partner in self.sudo():" in source
