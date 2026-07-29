from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    _resource_lock_digests,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    _bank_statement_sequence_lock_digest as handler_lock_digest,
)


ROOT = Path(__file__).resolve().parents[1]
GUARD = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "models"
    / "bank_statement_sequence_guard.py"
)
CAPABILITY_ID = "acct.bank.statement_compensate.v1"
COMPANY_ID = 7


class FakeValidationError(Exception):
    pass


class Record(SimpleNamespace):
    def exists(self):
        return self

    def __len__(self):
        return 1

    def check_access_rule(self, operation):
        assert operation == "read"


class EmptyRecord:
    id = False

    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class BrowseModel:
    def __init__(self, records: dict[int, Record]):
        self.records = records

    def browse(self, record_id: int):
        return self.records.get(record_id, EmptyRecord())

    def check_access_rights(self, operation):
        assert operation == "read"


class OperationModel:
    def __init__(self, events):
        self.locks: list[str] = []
        self.events = events

    def _acquire_scope_lock(self, digest: str):
        self.locks.append(digest)
        self.events.append(("lock", digest))


class FakeEnvironment:
    def __init__(self):
        self.events: list[tuple[str, str]] = []
        self.operation = OperationModel(self.events)
        self.models: dict[str, Any] = {
            "odoo.accounting.cli.operation": self.operation,
        }
        self.super_calls: list[tuple[str, str]] = []

    def __getitem__(self, model_name: str):
        return self.models[model_name]


class FakeBaseModel:
    _inherit = ""

    def __init__(
        self, env: FakeEnvironment, records: list[Record] | None = None
    ):
        self.env = env
        self.records = list(records or [])

    def __iter__(self):
        return iter(self.records)

    def create(self, _values_list):
        self.env.super_calls.append((self._inherit, "create"))
        self.env.events.append((self._inherit, "create"))
        return True

    def write(self, _values):
        self.env.super_calls.append((self._inherit, "write"))
        self.env.events.append((self._inherit, "write"))
        return True

    def unlink(self):
        self.env.super_calls.append((self._inherit, "unlink"))
        self.env.events.append((self._inherit, "unlink"))
        return True

    def action_post(self):
        self.env.super_calls.append((self._inherit, "action_post"))
        self.env.events.append((self._inherit, "action_post"))
        return True

    def _post(self, soft=True):
        del soft
        self.env.super_calls.append((self._inherit, "_post"))
        self.env.events.append((self._inherit, "_post"))
        return True

    def button_draft(self):
        self.env.super_calls.append((self._inherit, "button_draft"))
        self.env.events.append((self._inherit, "button_draft"))
        return True

    def button_cancel(self):
        self.env.super_calls.append((self._inherit, "button_cancel"))
        self.env.events.append((self._inherit, "button_cancel"))
        return True


def _load_guard(monkeypatch: pytest.MonkeyPatch):
    odoo = ModuleType("odoo")
    odoo.api = SimpleNamespace(model_create_multi=lambda function: function)
    odoo.models = SimpleNamespace(Model=FakeBaseModel)
    exceptions = ModuleType("odoo.exceptions")
    exceptions.ValidationError = FakeValidationError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)

    name = "_odoo_v3_bank_statement_sequence_guard_test"
    spec = importlib.util.spec_from_file_location(name, GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def _harness(module):
    env = FakeEnvironment()
    company = Record(id=COMPANY_ID)
    journal_2 = Record(id=2, company_id=company)
    journal_3 = Record(id=3, company_id=company)
    statement_100 = Record(
        id=100, company_id=company, journal_id=journal_2
    )
    statement_110 = Record(
        id=110, company_id=company, journal_id=journal_3
    )
    line_101 = Record(
        id=101,
        company_id=company,
        journal_id=journal_2,
        statement_id=statement_100,
    )
    line_111 = Record(
        id=111,
        company_id=company,
        journal_id=journal_3,
        statement_id=statement_110,
    )
    linked_move_200 = Record(
        id=200,
        company_id=company,
        journal_id=journal_2,
        statement_line_id=line_101,
        statement_line_ids=[line_101],
    )
    linked_move_210 = Record(
        id=210,
        company_id=company,
        journal_id=journal_3,
        statement_line_id=line_111,
        statement_line_ids=[line_111],
    )
    ordinary_move = Record(
        id=220,
        company_id=company,
        journal_id=journal_2,
        statement_line_id=False,
        statement_line_ids=[],
    )
    linked_item = Record(
        id=301, company_id=company, move_id=linked_move_200
    )
    ordinary_item = Record(
        id=302, company_id=company, move_id=ordinary_move
    )
    partial = Record(
        id=401,
        debit_move_id=linked_item,
        credit_move_id=ordinary_item,
    )
    ordinary_partial = Record(
        id=402,
        debit_move_id=ordinary_item,
        credit_move_id=ordinary_item,
    )
    full_reconcile = Record(
        id=501,
        reconciled_line_ids=[linked_item, ordinary_item],
        partial_reconcile_ids=[partial],
    )
    ordinary_full_reconcile = Record(
        id=502,
        reconciled_line_ids=[ordinary_item],
        partial_reconcile_ids=[ordinary_partial],
    )
    for model_name, records in {
        "account.journal": [journal_2, journal_3],
        "account.bank.statement": [statement_100, statement_110],
        "account.bank.statement.line": [line_101, line_111],
        "account.move": [linked_move_200, linked_move_210, ordinary_move],
        "account.move.line": [linked_item, ordinary_item],
        "account.partial.reconcile": [partial, ordinary_partial],
        "account.full.reconcile": [
            full_reconcile,
            ordinary_full_reconcile,
        ],
    }.items():
        env.models[model_name] = BrowseModel(
            {record.id: record for record in records}
        )
    expected = {
        journal_id: module._bank_statement_sequence_lock_digest(
            COMPANY_ID, journal_id
        )
        for journal_id in (2, 3)
    }
    return SimpleNamespace(
        env=env,
        company=company,
        journals=(journal_2, journal_3),
        statements=(statement_100, statement_110),
        lines=(line_101, line_111),
        moves=(linked_move_200, linked_move_210, ordinary_move),
        items=(linked_item, ordinary_item),
        partials=(partial, ordinary_partial),
        full_reconciles=(full_reconcile, ordinary_full_reconcile),
        expected=expected,
    )


def _locks(harness, *journal_ids):
    assert harness.env.operation.locks == sorted(
        {harness.expected[journal_id] for journal_id in journal_ids}
    )
    harness.env.operation.locks.clear()


def test_addon_digest_is_exactly_the_bootstrap_resource_digest(monkeypatch):
    module = _load_guard(monkeypatch)
    parameters = {"expected_journal_id": 2}

    digest = module._bank_statement_sequence_lock_digest(COMPANY_ID, 2)

    assert digest == handler_lock_digest(COMPANY_ID, 2)
    assert digest in _resource_lock_digests(
        CAPABILITY_ID, COMPANY_ID, parameters, None
    )


def test_statement_and_statement_line_crud_lock_old_and_new_journals(
    monkeypatch,
):
    module = _load_guard(monkeypatch)
    h = _harness(module)

    statements = module.AccountBankStatement(h.env, [h.statements[0]])
    statements.create(
        [
            {"journal_id": 3, "company_id": COMPANY_ID},
            {"journal_id": 2, "company_id": COMPANY_ID},
        ]
    )
    _locks(h, 2, 3)
    statements.write({"journal_id": 3, "company_id": COMPANY_ID})
    _locks(h, 2, 3)
    statements.unlink()
    _locks(h, 2)

    lines = module.AccountBankStatementLine(h.env, [h.lines[0]])
    lines.create(
        [
            {"statement_id": 110, "company_id": COMPANY_ID},
            {"journal_id": 2, "company_id": COMPANY_ID},
        ]
    )
    _locks(h, 2, 3)
    lines.write({"statement_id": 110, "company_id": COMPANY_ID})
    _locks(h, 2, 3)
    lines.unlink()
    _locks(h, 2)


def test_linked_move_crud_and_post_lock_but_ordinary_moves_do_not(
    monkeypatch,
):
    module = _load_guard(monkeypatch)
    h = _harness(module)
    linked = module.AccountMove(h.env, [h.moves[0], h.moves[1]])

    linked.create(
        [
            {"statement_line_id": 101, "company_id": COMPANY_ID},
            {"statement_line_ids": [(4, 111)], "company_id": COMPANY_ID},
        ]
    )
    _locks(h, 2, 3)
    linked.write({"date": "2026-07-29"})
    _locks(h, 2, 3)
    linked.action_post()
    _locks(h, 2, 3)
    linked._post(soft=False)
    _locks(h, 2, 3)
    linked.button_draft()
    _locks(h, 2, 3)
    linked.button_cancel()
    _locks(h, 2, 3)
    linked.unlink()
    _locks(h, 2, 3)

    state_methods = ("action_post", "_post", "button_draft", "button_cancel")
    for method_name in state_methods:
        super_index = h.env.events.index(("account.move", method_name))
        assert h.env.events[super_index - 1][0] == "lock"

    ordinary = module.AccountMove(h.env, [h.moves[2]])
    ordinary.create([{"journal_id": 2, "date": "2026-07-29"}])
    ordinary.write({"date": "2026-07-30"})
    ordinary.action_post()
    ordinary.unlink()
    assert h.env.operation.locks == []


def test_linked_move_line_crud_locks_but_ordinary_items_do_not(monkeypatch):
    module = _load_guard(monkeypatch)
    h = _harness(module)
    linked = module.AccountMoveLine(h.env, [h.items[0]])

    linked.create([{"move_id": 200, "company_id": COMPANY_ID}])
    _locks(h, 2)
    linked.write({"name": "changed"})
    _locks(h, 2)
    linked.unlink()
    _locks(h, 2)

    ordinary = module.AccountMoveLine(h.env, [h.items[1]])
    ordinary.create([{"move_id": 220, "company_id": COMPANY_ID}])
    ordinary.write({"name": "ordinary"})
    ordinary.unlink()
    assert h.env.operation.locks == []


def test_reconcile_crud_cannot_bypass_the_linked_bank_move_lock(monkeypatch):
    module = _load_guard(monkeypatch)
    h = _harness(module)
    partial = module.AccountPartialReconcile(h.env, [h.partials[0]])

    partial.create(
        [
            {"debit_move_id": 301, "credit_move_id": 302},
            {"debit_move_id": 302, "credit_move_id": 302},
        ]
    )
    _locks(h, 2)
    partial.write({"credit_move_id": 301})
    _locks(h, 2)
    partial.unlink()
    _locks(h, 2)

    full = module.AccountFullReconcile(
        h.env, [h.full_reconciles[0]]
    )
    full.create(
        [
            {"reconciled_line_ids": [(6, 0, [301, 302])]},
            {"partial_reconcile_ids": [(4, 401)]},
        ]
    )
    _locks(h, 2)
    full.write({"partial_reconcile_ids": [(6, 0, [401])]})
    _locks(h, 2)
    full.unlink()
    _locks(h, 2)

    ordinary_partial = module.AccountPartialReconcile(
        h.env, [h.partials[1]]
    )
    ordinary_partial.create(
        [{"debit_move_id": 302, "credit_move_id": 302}]
    )
    ordinary_partial.write({"credit_move_id": 302})
    ordinary_partial.unlink()
    ordinary_full = module.AccountFullReconcile(
        h.env, [h.full_reconciles[1]]
    )
    ordinary_full.create(
        [{"reconciled_line_ids": [(6, 0, [302])]}]
    )
    ordinary_full.write(
        {"partial_reconcile_ids": [(6, 0, [402])]}
    )
    ordinary_full.unlink()
    assert h.env.operation.locks == []


def test_partial_unlink_expands_shared_full_reconcile_graph_before_locking(
    monkeypatch,
):
    module = _load_guard(monkeypatch)
    h = _harness(module)
    partial_a = h.partials[0]
    partial_a.full_reconcile_id = False

    module.AccountPartialReconcile(h.env, [partial_a]).unlink()
    _locks(h, 2)

    bank_b_item = Record(
        id=303, company_id=h.company, move_id=h.moves[1]
    )
    partial_b = Record(
        id=403,
        debit_move_id=bank_b_item,
        credit_move_id=h.items[1],
    )
    shared_full = Record(
        id=503,
        reconciled_line_ids=[],
        partial_reconcile_ids=[partial_a, partial_b],
    )
    partial_a.full_reconcile_id = shared_full
    partial_b.full_reconcile_id = shared_full

    module.AccountPartialReconcile(h.env, [partial_a]).unlink()
    _locks(h, 2, 3)
    module.AccountPartialReconcile(h.env, [partial_b]).unlink()
    _locks(h, 2, 3)


def test_guard_fails_closed_and_never_uses_context_or_sudo(monkeypatch):
    module = _load_guard(monkeypatch)
    h = _harness(module)

    with pytest.raises(
        FakeValidationError, match="explicit journal"
    ):
        module.AccountBankStatement(h.env).create([{"date": "2026-07-29"}])
    with pytest.raises(
        FakeValidationError, match="missing or inconsistent"
    ):
        module.AccountBankStatementLine(h.env).create(
            [{"date": "2026-07-29"}]
        )
    source = GUARD.read_text(encoding="utf-8")
    assert ".sudo(" not in source
    assert "env.context" not in source
    assert "with_context" not in source
