from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.recovery_actions import (
    RECOVERY_ACTION_METHODS,
    RecoveryActionError,
    RecoveryActionExecutor,
    execute_recovery_action,
)
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)

_NO_ACTION_OVERRIDE = object()


class FakeRecord:
    def __init__(self, record_id, **values):
        self.id = record_id
        self._exists = True
        self._context_calls = []
        self._write_calls = []
        self._remove_calls = 0
        self._adapter = None
        self.__dict__.update(values)

    @property
    def ids(self):
        return [self.id] if self._exists else []

    def __bool__(self):
        return self._exists

    def __len__(self):
        return 1 if self._exists else 0

    def exists(self):
        return self

    def with_context(self, **values):
        self._context_calls.append(values)
        return self

    def write(self, values):
        self._write_calls.append(dict(values))
        self.__dict__.update(values)
        if values.get("state") == "cancel":
            for line in getattr(self, "line_ids", []):
                line.parent_state = "cancel"
        return True

    def action_post(self):
        self.state = "posted"
        return True

    def button_cancel(self):
        self.state = "cancel"
        return True

    def action_cancel(self):
        callback = getattr(self, "_cancel_callback", None)
        if callback:
            callback()
        self.state = "canceled"
        return True

    def remove_move_reconcile(self):
        self._remove_calls += 1
        callback = getattr(self, "_remove_callback", None)
        if callback:
            callback()
        return True

    def set_to_cancelled(self):
        callback = getattr(self, "_asset_cancel_callback", None)
        if callback:
            callback()
        self.state = "cancelled"
        return True


class FakeWizard(FakeRecord):
    def __init__(self, record_id, adapter, context, values):
        super().__init__(record_id)
        self.adapter = adapter
        self.context = dict(context)
        self.values = dict(values)

    def reverse_moves(self, is_modify=False):
        self.adapter.reverse_calls.append(
            {
                "context": self.context,
                "values": self.values,
                "is_modify": is_modify,
            }
        )
        if self.adapter.action_override is not _NO_ACTION_OVERRIDE:
            return self.adapter.action_override
        origin = self.adapter.record(
            "account.move", self.context["active_ids"][0], self.adapter.company
        )
        move_type = {
            "out_invoice": "out_refund",
            "in_invoice": "in_refund",
            "out_refund": "out_invoice",
            "in_refund": "in_invoice",
            "entry": "entry",
        }[origin.move_type]
        reversal = self.adapter.make_move(
            self.adapter.next_id(),
            state="draft",
            move_type=move_type,
            journal=origin.journal_id,
            move_date=self.values["date"],
            line_count=0,
            reversed_entry_id=origin,
        )
        origin.reversal_move_ids = [
            *getattr(origin, "reversal_move_ids", []),
            reversal,
        ]
        if getattr(origin, "deferred_move_ids", []):
            inverse_schedule = self.adapter.make_move(
                self.adapter.next_id(),
                state="draft",
                move_type="entry",
                journal=origin.journal_id,
                move_date=self.values["date"],
                line_count=0,
                reversed_entry_id=False,
            )
            reversal.deferred_move_ids = [inverse_schedule]
        return {
            "res_model": "account.move",
            "res_id": reversal.id,
            "res_ids": [reversal.id],
        }


class FakeModel:
    def __init__(self, adapter, model_name, context):
        self.adapter = adapter
        self.model_name = model_name
        self.context = dict(context or {})

    def create(self, values):
        self.adapter.create_calls.append(
            (self.model_name, self.context, dict(values))
        )
        if self.model_name == "account.move.reversal":
            return FakeWizard(
                self.adapter.next_id(), self.adapter, self.context, values
            )
        if self.model_name == "account.bank.statement.line":
            move = self.adapter.make_move(
                self.adapter.next_id(),
                state="posted",
                move_type="entry",
                journal=self.adapter.records[
                    ("account.journal", values["journal_id"])
                ],
                move_date=values["date"],
                line_count=0,
            )
            line = FakeRecord(
                self.adapter.next_id(),
                statement_id=False,
                move_id=move,
                **values,
            )
            self.adapter.add("account.bank.statement.line", line)
            return line
        if self.model_name == "account.bank.statement":
            line_ids = values["line_ids"][0][2]
            lines = [
                self.adapter.record(
                    "account.bank.statement.line",
                    line_id,
                    self.adapter.company,
                )
                for line_id in line_ids
            ]
            statement = FakeRecord(
                self.adapter.next_id(),
                is_complete=True,
                is_valid=True,
                balance_end=values["balance_end_real"],
                line_ids=lines,
                **{
                    key: value
                    for key, value in values.items()
                    if key != "line_ids"
                },
            )
            self.adapter.add("account.bank.statement", statement)
            for line in lines:
                line.statement_id = statement
            if self.adapter.mutate_original_bank:
                self.adapter.original_bank.balance_start += 1
            return statement
        raise AssertionError(f"unexpected create model {self.model_name}")


class FakeAdapter:
    def __init__(self):
        self.records = {}
        self.create_calls = []
        self.reverse_calls = []
        self.action_override = _NO_ACTION_OVERRIDE
        self._sequence = 9000
        self.company = FakeRecord(1)
        self.add("res.company", self.company)
        self.journal = FakeRecord(10, company_id=self.company)
        self.add("account.journal", self.journal)
        self.mutate_original_bank = False
        self.original_bank = None

    def next_id(self):
        self._sequence += 1
        return self._sequence

    def add(self, model_name, record):
        record._adapter = self
        self.records[(model_name, record.id)] = record
        return record

    def create_model(self, model_name, company, *, context=None):
        assert company is self.company
        return FakeModel(self, model_name, context)

    def record(
        self,
        model_name,
        record_id,
        company,
        *,
        write=False,
        shared=False,
    ):
        assert company is self.company
        record = self.records[(model_name, record_id)]
        if not record:
            raise RecoveryActionError("fake record was deleted")
        return record

    def require_created(self, record, model_name, company):
        assert company is self.company
        assert self.records[(model_name, record.id)] is record
        assert record

    def move_records(self, move, company):
        assert company is self.company
        result = [("account.move", move)]
        for relation in getattr(move, "line_ids", []):
            line = (
                relation
                if isinstance(relation, FakeRecord)
                else self.record("account.move.line", relation, company)
            )
            if line:
                result.append(("account.move.line", line))
        return result

    def make_move(
        self,
        move_id,
        *,
        state="posted",
        move_type="entry",
        journal=None,
        move_date="2026-07-20",
        line_count=1,
        **values,
    ):
        move = FakeRecord(
            move_id,
            state=state,
            move_type=move_type,
            journal_id=journal or self.journal,
            date=move_date,
            line_ids=[],
            reversal_move_ids=[],
            deferred_move_ids=[],
            deferred_original_move_ids=[],
            **values,
        )
        self.add("account.move", move)
        for _index in range(line_count):
            line = FakeRecord(
                self.next_id(),
                move_id=move,
                parent_state=state,
                reconciled=False,
                full_reconcile_id=False,
                matched_debit_ids=[],
                matched_credit_ids=[],
                payment_id=False,
                statement_line_id=False,
                statement_id=False,
                asset_ids=[],
                deferred_start_date=False,
                deferred_end_date=False,
            )
            self.add("account.move.line", line)
            move.line_ids.append(line)
        return move


def graph(move):
    return [
        ("account.move", move),
        *(("account.move.line", line) for line in move.line_ids),
    ]


def guard_outcomes_for(method, guards):
    outcomes = {}
    if method in RECOVERY_ACTION_CONTRACTS:
        allowed = RECOVERY_ACTION_CONTRACTS[method].allowed_guard_outcomes
        for model, record in guards:
            if method == "post_compensating_bank_statement_v1":
                outcome = "survive_exact"
            elif (
                method == "cancel_and_unreconcile_payment_v1"
                and model
                in {"account.partial.reconcile", "account.full.reconcile"}
            ):
                outcome = "absent"
            elif (
                method == "cancel_asset_and_reverse_schedule_v1"
                and (
                    (
                        model == "account.move"
                        and record.state == "draft"
                    )
                    or (
                        model == "account.move.line"
                        and record.parent_state == "draft"
                    )
                )
            ):
                outcome = "absent"
            else:
                outcome = (
                    "survive_exact"
                    if "survive_exact" in allowed
                    else "survive_allowed_delta"
                )
            outcomes[(model, record.id)] = outcome
    return outcomes


def run(adapter, method, actions, guards):
    return execute_recovery_action(
        adapter,
        method,
        company=adapter.company,
        action_records=actions,
        guard_records=guards,
        guard_outcomes=guard_outcomes_for(method, guards),
        recovery_date="2026-07-29",
        reason="Approved recovery",
    )


@pytest.mark.parametrize(
    ("method", "move_type"),
    [
        ("reverse_posted_customer_invoice_v1", "out_invoice"),
        ("reverse_posted_vendor_bill_v1", "in_invoice"),
        ("reverse_posted_refund_v1", "out_refund"),
        ("reverse_posted_refund_v1", "in_refund"),
        ("reverse_posted_period_adjustment_v1", "entry"),
        ("reverse_the_reversal_v1", "entry"),
    ],
)
def test_public_reversal_methods_return_exact_posted_linked_receipt(
    method, move_type
):
    adapter = FakeAdapter()
    values = (
        {"reversed_entry_id": FakeRecord(777)}
        if method == "reverse_the_reversal_v1"
        else {}
    )
    origin = adapter.make_move(
        100, move_type=move_type, line_count=2, **values
    )

    result = run(
        adapter,
        method,
        [("account.move", origin)],
        [("account.move.line", line) for line in origin.line_ids],
    )

    reversals = [
        record
        for model, record in result.records
        if model == "account.move" and record.id != origin.id
    ]
    assert len(reversals) == 1
    assert reversals[0].state == "posted"
    assert reversals[0].reversed_entry_id is origin
    assert reversals[0].odoo_cli_v3_reason == "Approved recovery"
    assert reversals[0]._write_calls == [
        {"odoo_cli_v3_reason": "Approved recovery"}
    ]
    assert result.tombstones == frozenset()
    assert adapter.reverse_calls == [
        {
            "context": {
                "active_model": "account.move",
                "active_ids": [origin.id],
            },
            "values": {
                "date": "2026-07-29",
                "journal_id": adapter.journal.id,
                "reason": "Approved recovery",
            },
            "is_modify": False,
        }
    ]
    assert "public_reversal_wizard" in result.checks


@pytest.mark.parametrize(
    ("method", "move_type"),
    [
        ("cancel_draft_refund_v1", "out_refund"),
        ("cancel_draft_refund_v1", "in_refund"),
        ("cancel_draft_period_adjustment_v1", "entry"),
    ],
)
def test_draft_refund_and_period_cancel_use_controlled_public_write(
    method, move_type
):
    adapter = FakeAdapter()
    move = adapter.make_move(
        110, state="draft", move_type=move_type, line_count=2
    )
    origin_guard = adapter.make_move(120, move_type="out_invoice")

    result = run(
        adapter,
        method,
        [("account.move", move)],
        [
            *(("account.move.line", line) for line in move.line_ids),
            *graph(origin_guard),
        ],
    )

    assert move.state == "cancel"
    assert all(line.parent_state == "cancel" for line in move.line_ids)
    assert move._write_calls == [{"state": "cancel"}]
    assert move._context_calls == [
        {
            "tracking_disable": True,
            "skip_account_move_synchronization": True,
            "skip_invoice_sync": True,
            "skip_is_manually_modified": True,
        }
    ]
    assert origin_guard.state == "posted"
    assert result.tombstones == frozenset()
    assert "external_guard_graph_unchanged" in result.checks


def payment_harness():
    adapter = FakeAdapter()
    payment_move = adapter.make_move(200, line_count=2)
    target_move = adapter.make_move(
        210, move_type="out_invoice", line_count=1
    )
    payment = FakeRecord(
        220, state="paid", move_id=payment_move
    )
    adapter.add("account.payment", payment)
    partial = adapter.add(
        "account.partial.reconcile",
        FakeRecord(
            230,
            debit_move_id=payment_move.line_ids[0],
            credit_move_id=target_move.line_ids[0],
        ),
    )
    full = adapter.add(
        "account.full.reconcile", FakeRecord(240)
    )

    def remove():
        partial._exists = False
        full._exists = False

    for line in payment_move.line_ids:
        line._remove_callback = remove

    def cancel():
        payment_move.state = "cancel"

    payment._cancel_callback = cancel
    guards = [
        *graph(payment_move),
        *graph(target_move),
        ("account.partial.reconcile", partial),
        ("account.full.reconcile", full),
    ]
    return adapter, payment, payment_move, partial, full, guards


def test_payment_unreconciles_exact_payment_lines_then_cancels_and_tombstones():
    adapter, payment, payment_move, partial, full, guards = payment_harness()

    result = run(
        adapter,
        "cancel_and_unreconcile_payment_v1",
        [("account.payment", payment)],
        guards,
    )

    assert [line._remove_calls for line in payment_move.line_ids] == [1, 1]
    assert payment.state == "canceled"
    assert payment_move.state == "cancel"
    assert result.tombstones == frozenset(
        {
            ("account.partial.reconcile", partial.id),
            ("account.full.reconcile", full.id),
        }
    )
    assert all(
        model not in {"account.partial.reconcile", "account.full.reconcile"}
        for model, _record in result.records
    )


def test_payment_tombstones_only_guards_bound_to_absent_outcome():
    adapter, payment, _move, partial, full, guards = payment_harness()
    prior_partial = adapter.add(
        "account.partial.reconcile", FakeRecord(241)
    )
    prior_full = adapter.add(
        "account.full.reconcile", FakeRecord(242)
    )
    guards.extend(
        [
            ("account.partial.reconcile", prior_partial),
            ("account.full.reconcile", prior_full),
        ]
    )
    outcomes = guard_outcomes_for(
        "cancel_and_unreconcile_payment_v1", guards
    )
    outcomes[("account.partial.reconcile", prior_partial.id)] = (
        "survive_exact"
    )
    outcomes[("account.full.reconcile", prior_full.id)] = "survive_exact"

    result = execute_recovery_action(
        adapter,
        "cancel_and_unreconcile_payment_v1",
        company=adapter.company,
        action_records=[("account.payment", payment)],
        guard_records=guards,
        guard_outcomes=outcomes,
        recovery_date="2026-07-29",
        reason="Approved recovery",
    )

    assert result.tombstones == frozenset(
        {
            ("account.partial.reconcile", partial.id),
            ("account.full.reconcile", full.id),
        }
    )
    assert prior_partial and prior_full
    assert {
        (model, record.id) for model, record in result.records
    } >= {
        ("account.partial.reconcile", prior_partial.id),
        ("account.full.reconcile", prior_full.id),
    }


def bank_harness():
    adapter = FakeAdapter()
    line_one_move = adapter.make_move(300, line_count=0)
    line_two_move = adapter.make_move(301, line_count=0)
    line_one = adapter.add(
        "account.bank.statement.line",
        FakeRecord(
            310,
            date="2026-07-20",
            amount=25,
            amount_currency=30,
            payment_ref="A",
            ref="TX-A",
            partner_id=FakeRecord(31),
            foreign_currency_id=FakeRecord(32),
            journal_id=adapter.journal,
            statement_id=False,
            move_id=line_one_move,
        ),
    )
    line_two = adapter.add(
        "account.bank.statement.line",
        FakeRecord(
            311,
            date="2026-07-21",
            amount=-5,
            amount_currency=0,
            payment_ref="B",
            ref="TX-B",
            partner_id=False,
            foreign_currency_id=False,
            journal_id=adapter.journal,
            statement_id=False,
            move_id=line_two_move,
        ),
    )
    statement = adapter.add(
        "account.bank.statement",
        FakeRecord(
            320,
            date="2026-07-21",
            reference="ORIGINAL",
            balance_start=100,
            balance_end=120,
            balance_end_real=120,
            is_complete=True,
            is_valid=True,
            line_ids=[line_one, line_two],
        ),
    )
    line_one.statement_id = statement
    line_two.statement_id = statement
    adapter.original_bank = statement
    guards = [
        ("account.bank.statement.line", line_one),
        ("account.bank.statement.line", line_two),
        *graph(line_one_move),
        *graph(line_two_move),
    ]
    return adapter, statement, guards


def test_bank_recovery_creates_independent_inverse_statement_and_keeps_original():
    adapter, original, guards = bank_harness()

    result = run(
        adapter,
        "post_compensating_bank_statement_v1",
        [("account.bank.statement", original)],
        guards,
    )

    statements = [
        record
        for model, record in result.records
        if model == "account.bank.statement"
    ]
    assert len(statements) == 2
    compensating = next(item for item in statements if item is not original)
    assert compensating.balance_start == 120
    assert compensating.balance_end_real == 100
    assert compensating.reference == "Approved recovery"
    assert [line.amount for line in compensating.line_ids] == [-25.0, 5.0]
    assert all(line.date == "2026-07-29" for line in compensating.line_ids)
    assert all(
        line.payment_ref == "Approved recovery"
        for line in compensating.line_ids
    )
    assert all(
        line.statement_id is compensating for line in compensating.line_ids
    )
    assert original.reference == "ORIGINAL"
    assert original.balance_start == 100
    assert (
        "original_statement_and_bank_lines_unchanged_during_action"
        in result.checks
    )


def reconciliation_harness(*, writeoff):
    adapter = FakeAdapter()
    source_a = adapter.make_move(
        400, move_type="out_invoice", line_count=1
    )
    source_b = adapter.make_move(
        401, move_type="in_invoice", line_count=1
    )
    actions = []
    guards = [*graph(source_a), *graph(source_b)]
    endpoints = [source_a.line_ids[0], source_b.line_ids[0]]
    writeoff_move = None
    if writeoff:
        writeoff_move = adapter.make_move(402, line_count=1)
        endpoints[1] = writeoff_move.line_ids[0]
        actions.append(("account.move", writeoff_move))
        guards.extend(
            ("account.move.line", line) for line in writeoff_move.line_ids
        )
    partial = adapter.add(
        "account.partial.reconcile",
        FakeRecord(
            410,
            debit_move_id=endpoints[0],
            credit_move_id=endpoints[1],
        ),
    )
    full = adapter.add("account.full.reconcile", FakeRecord(411))
    actions.extend(
        [
            ("account.partial.reconcile", partial),
            ("account.full.reconcile", full),
        ]
    )

    def remove():
        partial._exists = False
        full._exists = False

    for line in (source_a.line_ids[0], source_b.line_ids[0]):
        line._remove_callback = remove
    return (
        adapter,
        source_a,
        source_b,
        writeoff_move,
        partial,
        full,
        actions,
        guards,
    )


@pytest.mark.parametrize("writeoff", [False, True])
def test_reconciliation_derives_sources_from_bound_writeoff_actions(writeoff):
    (
        adapter,
        source_a,
        source_b,
        writeoff_move,
        partial,
        full,
        actions,
        guards,
    ) = reconciliation_harness(writeoff=writeoff)

    result = run(
        adapter,
        "undo_reconciliation_and_reverse_writeoff_v1",
        actions,
        guards,
    )

    assert source_a.line_ids[0]._remove_calls == 1
    assert source_b.line_ids[0]._remove_calls == (0 if writeoff else 1)
    assert result.tombstones == frozenset(
        {
            ("account.partial.reconcile", partial.id),
            ("account.full.reconcile", full.id),
        }
    )
    if writeoff:
        assert len(adapter.reverse_calls) == 1
        assert adapter.reverse_calls[0]["context"]["active_ids"] == [
            writeoff_move.id
        ]
        assert "writeoff_reversed_publicly" in result.checks
    else:
        assert adapter.reverse_calls == []
        assert "writeoff_not_applicable" in result.checks


def test_reconciliation_retains_prior_survive_exact_reconcile_guards():
    (
        adapter,
        _source_a,
        _source_b,
        _writeoff,
        partial,
        full,
        actions,
        guards,
    ) = reconciliation_harness(writeoff=False)
    prior_partial = adapter.add(
        "account.partial.reconcile", FakeRecord(412)
    )
    prior_full = adapter.add(
        "account.full.reconcile", FakeRecord(413)
    )
    guards.extend(
        [
            ("account.partial.reconcile", prior_partial),
            ("account.full.reconcile", prior_full),
        ]
    )
    outcomes = guard_outcomes_for(
        "undo_reconciliation_and_reverse_writeoff_v1", guards
    )
    outcomes[("account.partial.reconcile", prior_partial.id)] = (
        "survive_exact"
    )
    outcomes[("account.full.reconcile", prior_full.id)] = "survive_exact"

    result = execute_recovery_action(
        adapter,
        "undo_reconciliation_and_reverse_writeoff_v1",
        company=adapter.company,
        action_records=actions,
        guard_records=guards,
        guard_outcomes=outcomes,
        recovery_date="2026-07-29",
        reason="Approved recovery",
    )

    assert result.tombstones == frozenset(
        {
            ("account.partial.reconcile", partial.id),
            ("account.full.reconcile", full.id),
        }
    )
    assert prior_partial and prior_full


def asset_harness():
    adapter = FakeAdapter()
    draft = adapter.make_move(500, state="draft", line_count=1)
    posted = adapter.make_move(501, state="posted", line_count=1)
    asset = adapter.add(
        "account.asset",
        FakeRecord(
            510,
            state="open",
            depreciation_move_ids=[draft, posted],
        ),
    )

    def cancel_asset():
        draft._exists = False
        for line in draft.line_ids:
            line._exists = False
        asset.depreciation_move_ids = [posted]
        reversal = adapter.make_move(
            adapter.next_id(),
            state="posted",
            line_count=0,
            reversed_entry_id=posted,
        )
        posted.reversal_move_ids = [reversal]

    asset._asset_cancel_callback = cancel_asset
    guards = [*graph(draft), *graph(posted)]
    return adapter, asset, draft, posted, guards


def test_asset_cancel_tombstones_draft_schedule_and_reads_posted_reversal():
    adapter, asset, draft, posted, guards = asset_harness()

    result = run(
        adapter,
        "cancel_asset_and_reverse_schedule_v1",
        [("account.asset", asset)],
        guards,
    )

    assert asset.state == "cancelled"
    assert result.tombstones == frozenset(
        {
            ("account.move", draft.id),
            *(
                ("account.move.line", line.id)
                for line in draft.line_ids
            ),
        }
    )
    assert len(posted.reversal_move_ids) == 1
    assert posted.reversal_move_ids[0].state == "posted"
    assert (
        posted.reversal_move_ids[0].odoo_cli_v3_reason
        == "Approved recovery"
    )
    assert "posted_schedule_reversed" in result.checks
    assert "asset_schedule_reversal_reason_persisted" in result.checks


def test_depreciation_uses_public_reversal_and_retains_asset_schedule():
    adapter = FakeAdapter()
    asset = adapter.add(
        "account.asset",
        FakeRecord(600, state="open", depreciation_move_ids=[]),
    )
    move = adapter.make_move(
        601,
        state="posted",
        line_count=2,
        asset_move_type="depreciation",
        asset_id=asset,
    )
    asset.depreciation_move_ids = [move]

    result = run(
        adapter,
        "reverse_depreciation_and_restore_schedule_v1",
        [("account.move", move)],
        [
            ("account.asset", asset),
            *(("account.move.line", line) for line in move.line_ids),
        ],
    )

    assert asset.depreciation_move_ids == [move]
    assert len(adapter.reverse_calls) == 1
    assert "asset_schedule_restored" in result.checks


def test_accrual_cancels_future_schedule_then_reverses_origin():
    adapter = FakeAdapter()
    origin = adapter.make_move(700, line_count=2)
    scheduled = adapter.make_move(
        701,
        state="draft",
        move_date="2026-08-31",
        line_count=2,
        reversed_entry_id=origin,
        auto_post="at_date",
    )

    result = run(
        adapter,
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        [("account.move", origin), ("account.move", scheduled)],
        [
            *(("account.move.line", line) for line in origin.line_ids),
            *(("account.move.line", line) for line in scheduled.line_ids),
        ],
    )

    assert scheduled.state == "cancel"
    assert len(adapter.reverse_calls) == 1
    assert adapter.reverse_calls[0]["context"]["active_ids"] == [origin.id]
    assert "future_scheduled_accrual_cancelled" in result.checks


def test_deferred_reverses_source_and_requires_compensating_schedule():
    adapter = FakeAdapter()
    source = adapter.make_move(
        800, move_type="in_invoice", line_count=2
    )
    scheduled = adapter.make_move(
        801, state="draft", line_count=2
    )
    source.deferred_move_ids = [scheduled]

    result = run(
        adapter,
        "reverse_deferred_source_and_schedule_v1",
        [("account.move", source)],
        [
            *(("account.move.line", line) for line in source.line_ids),
            *graph(scheduled),
        ],
    )

    reversals = [
        record
        for model, record in result.records
        if model == "account.move"
        and getattr(record, "reversed_entry_id", None) is source
    ]
    assert len(reversals) == 1
    assert reversals[0].deferred_move_ids
    assert "compensating_deferred_schedule_created" in result.checks


def test_catalog_coverage_excludes_only_two_specialized_invoice_bill_actions():
    assert set(RECOVERY_ACTION_METHODS) == {
        method
        for method in RECOVERY_ACTION_CONTRACTS
        if method
        not in {
            "cancel_pristine_v3_draft_customer_invoice_v1",
            "cancel_pristine_v3_draft_vendor_bill_v1",
        }
    }


@pytest.mark.parametrize(
    ("recovery_date", "reason", "message"),
    [
        ("2026-7-29", "Approved", "recovery_date"),
        ("2026-02-30", "Approved", "recovery_date"),
        (" 2026-07-29", "Approved", "recovery_date"),
        ("2026-07-29", "", "reason"),
        ("2026-07-29", " spaced ", "reason"),
        ("2026-07-29", "line\nbreak", "reason"),
    ],
)
def test_input_date_and_reason_are_strict(recovery_date, reason, message):
    adapter = FakeAdapter()
    origin = adapter.make_move(1000, move_type="out_invoice")

    with pytest.raises(RecoveryActionError, match=message):
        execute_recovery_action(
            adapter,
            "reverse_posted_customer_invoice_v1",
            company=adapter.company,
            action_records=[("account.move", origin)],
            guard_records=[
                ("account.move.line", origin.line_ids[0])
            ],
            guard_outcomes={
                ("account.move.line", origin.line_ids[0].id):
                    "survive_exact"
            },
            recovery_date=recovery_date,
            reason=reason,
        )


@pytest.mark.parametrize(
    "outcomes",
    [
        {},
        {("account.move.line", 999999): "survive_exact"},
        {("account.move.line", 9001): "survive_allowed_delta"},
        {("account.move.line", 9001): "absent"},
        {("account.move.line", 9001): "unknown"},
    ],
)
def test_guard_outcomes_must_exactly_cover_guards_and_match_contract(outcomes):
    adapter = FakeAdapter()
    origin = adapter.make_move(1800, move_type="out_invoice")
    line = origin.line_ids[0]
    normalized = {
        (model, line.id if record_id == 9001 else record_id): outcome
        for (model, record_id), outcome in outcomes.items()
    }

    with pytest.raises(RecoveryActionError, match="guard_outcomes"):
        execute_recovery_action(
            adapter,
            "reverse_posted_customer_invoice_v1",
            company=adapter.company,
            action_records=[("account.move", origin)],
            guard_records=[("account.move.line", line)],
            guard_outcomes=normalized,
            recovery_date="2026-07-29",
            reason="Approved recovery",
        )


def test_asset_rejects_tombstone_outcome_that_does_not_match_draft_schedule():
    adapter, asset, _draft, _posted, guards = asset_harness()
    outcomes = guard_outcomes_for(
        "cancel_asset_and_reverse_schedule_v1", guards
    )
    draft_move_key = next(
        (model, record.id)
        for model, record in guards
        if model == "account.move" and record.state == "draft"
    )
    outcomes[draft_move_key] = "survive_exact"

    with pytest.raises(RecoveryActionError, match="tombstone outcomes"):
        execute_recovery_action(
            adapter,
            "cancel_asset_and_reverse_schedule_v1",
            company=adapter.company,
            action_records=[("account.asset", asset)],
            guard_records=guards,
            guard_outcomes=outcomes,
            recovery_date="2026-07-29",
            reason="Approved recovery",
        )


@pytest.mark.parametrize(
    "method",
    [
        "cancel_pristine_v3_draft_customer_invoice_v1",
        "cancel_pristine_v3_draft_vendor_bill_v1",
        "unknown_recovery_v1",
    ],
)
def test_executor_rejects_methods_owned_by_specialized_or_unknown_paths(method):
    adapter = FakeAdapter()
    move = adapter.make_move(1100, state="draft")
    with pytest.raises(RecoveryActionError, match="not executable"):
        run(
            adapter,
            method,
            [("account.move", move)],
            [("account.move.line", move.line_ids[0])],
        )


@pytest.mark.parametrize(
    ("state", "move_type"),
    [
        ("draft", "out_invoice"),
        ("cancel", "out_invoice"),
        ("posted", "entry"),
        ("posted", "in_invoice"),
    ],
)
def test_customer_invoice_reversal_rejects_wrong_state_or_type(
    state, move_type
):
    adapter = FakeAdapter()
    move = adapter.make_move(
        1200, state=state, move_type=move_type
    )
    with pytest.raises(RecoveryActionError, match="state or type"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move", move)],
            [("account.move.line", move.line_ids[0])],
        )


def test_wrong_action_model_and_action_guard_overlap_are_rejected():
    adapter = FakeAdapter()
    move = adapter.make_move(1300, move_type="out_invoice")
    line = move.line_ids[0]
    with pytest.raises(RecoveryActionError, match="outside its contract"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move.line", line)],
            [("account.move", move)],
        )
    with pytest.raises(RecoveryActionError, match="overlap"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move", move)],
            [("account.move", move)],
        )


def test_duplicate_and_absent_input_records_are_rejected():
    adapter = FakeAdapter()
    move = adapter.make_move(1400, move_type="out_invoice")
    line = move.line_ids[0]
    with pytest.raises(RecoveryActionError, match="duplicate"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move", move), ("account.move", move)],
            [("account.move.line", line)],
        )
    line._exists = False
    with pytest.raises(RecoveryActionError, match="absent"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move", move)],
            [("account.move.line", line)],
        )


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {},
        {"res_id": True},
        {"res_id": 0},
        {"res_id": 1500},
        {"res_id": 9999, "res_model": "res.partner"},
        {"res_id": 9999, "res_ids": [9999, 10000]},
    ],
)
def test_reversal_rejects_ambiguous_action_receipts(receipt):
    adapter = FakeAdapter()
    move = adapter.make_move(1500, move_type="out_invoice")
    adapter.action_override = receipt
    with pytest.raises(RecoveryActionError, match="receipt"):
        run(
            adapter,
            "reverse_posted_customer_invoice_v1",
            [("account.move", move)],
            [("account.move.line", move.line_ids[0])],
        )


def test_payment_rejects_incomplete_exact_move_line_graph():
    adapter, payment, _move, _partial, _full, guards = payment_harness()
    guards = [
        item
        for item in guards
        if not (
            item[0] == "account.move.line"
            and item[1].move_id.id == 200
            and item[1].id == item[1].move_id.line_ids[-1].id
        )
    ]
    with pytest.raises(RecoveryActionError, match="guard graph"):
        run(
            adapter,
            "cancel_and_unreconcile_payment_v1",
            [("account.payment", payment)],
            guards,
        )


def test_payment_rejects_tombstone_that_survives_unreconcile():
    adapter, payment, payment_move, _partial, _full, guards = payment_harness()
    for line in payment_move.line_ids:
        line._remove_callback = None
    with pytest.raises(RecoveryActionError, match="did not delete"):
        run(
            adapter,
            "cancel_and_unreconcile_payment_v1",
            [("account.payment", payment)],
            guards,
        )


def test_bank_rejects_original_graph_mutation_and_incomplete_lines():
    adapter, original, guards = bank_harness()
    adapter.mutate_original_bank = True
    with pytest.raises(RecoveryActionError, match="original bank"):
        run(
            adapter,
            "post_compensating_bank_statement_v1",
            [("account.bank.statement", original)],
            guards,
        )

    adapter, original, guards = bank_harness()
    with pytest.raises(RecoveryActionError, match="guard graph"):
        run(
            adapter,
            "post_compensating_bank_statement_v1",
            [("account.bank.statement", original)],
            guards[1:],
        )


def test_reconciliation_rejects_unbound_or_ambiguous_writeoff_action():
    (
        adapter,
        _source_a,
        _source_b,
        _writeoff,
        _partial,
        _full,
        actions,
        guards,
    ) = reconciliation_harness(writeoff=False)
    unrelated = adapter.make_move(1600)
    actions.insert(0, ("account.move", unrelated))
    with pytest.raises(RecoveryActionError, match="ambiguous"):
        run(
            adapter,
            "undo_reconciliation_and_reverse_writeoff_v1",
            actions,
            guards,
        )


def test_asset_rejects_missing_schedule_line_and_missing_posted_reversal():
    adapter, asset, draft, _posted, guards = asset_harness()
    guards = [
        item
        for item in guards
        if item != ("account.move.line", draft.line_ids[0])
    ]
    with pytest.raises(RecoveryActionError, match="line graph"):
        run(
            adapter,
            "cancel_asset_and_reverse_schedule_v1",
            [("account.asset", asset)],
            guards,
        )

    adapter, asset, draft, posted, guards = asset_harness()

    def cancel_without_reversal():
        draft._exists = False
        for line in draft.line_ids:
            line._exists = False
        asset.state = "cancelled"
        asset.depreciation_move_ids = [posted]

    asset._asset_cancel_callback = cancel_without_reversal
    with pytest.raises(RecoveryActionError, match="gained no reversal"):
        run(
            adapter,
            "cancel_asset_and_reverse_schedule_v1",
            [("account.asset", asset)],
            guards,
        )


def test_deferred_rejects_missing_generated_schedule_guard():
    adapter = FakeAdapter()
    source = adapter.make_move(1700, move_type="out_invoice")
    scheduled = adapter.make_move(1701, state="draft")
    source.deferred_move_ids = [scheduled]
    with pytest.raises(RecoveryActionError, match="guard graph"):
        run(
            adapter,
            "reverse_deferred_source_and_schedule_v1",
            [("account.move", source)],
            [("account.move.line", source.line_ids[0])],
        )


def test_adapter_surface_is_strict():
    with pytest.raises(RecoveryActionError, match="adapter"):
        RecoveryActionExecutor(SimpleNamespace())


def test_module_uses_no_elevated_transaction_or_private_orm_calls():
    import odoo_accounting_cli_v3.odoo.recovery_actions as module

    source = inspect.getsource(module)
    for forbidden in (
        ".sudo(",
        ".commit(",
        ".rollback(",
        "._reverse_moves(",
        "._cancel_future_moves(",
        ".unlink(",
    ):
        assert forbidden not in source
