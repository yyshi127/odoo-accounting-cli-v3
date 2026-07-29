from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import hashlib
import inspect
from typing import Any, Mapping

import pytest

from odoo_accounting_cli_v3.odoo.recovery_verifier import (
    RECOVERY_VERIFICATION_METHODS,
    RecoveryVerificationError,
    verify_recovery_action,
)
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_record_snapshot,
    create_recovery_plan_v2,
)


RECOVERY_DATE = "2026-07-29"
REASON = "Approved recovery"


class Ref:
    def __init__(self, record_id: int):
        self.id = record_id

    @property
    def ids(self):
        return [self.id]


class Record(Ref):
    def __init__(self, model: str, record_id: int, **values: Any):
        super().__init__(record_id)
        self._model = model
        self.__dict__.update(values)


def _primitive(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, float):
        return format(Decimal(str(value)), "f")
    if isinstance(value, Mapping):
        return {
            str(key): _primitive(value[key])
            for key in sorted(value)
        }
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    if isinstance(value, Ref):
        return value.id
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def _values(record: Record) -> dict[str, Any]:
    return {
        key: _primitive(value)
        for key, value in sorted(record.__dict__.items())
        if not key.startswith("_") and key != "id"
    }


def _amount(value: Any) -> Decimal:
    return Decimal(str(value))


class FreshAdapter:
    def __init__(self, company: Ref):
        self.company = company
        self.live: dict[tuple[str, int], Record] = {}
        self.snapshot_reads: list[tuple[str, int]] = []
        self.absence_reads: list[tuple[str, int]] = []
        self.linewise_reads: list[tuple[int, int]] = []
        self.balance_reads: list[int] = []

    def add(self, record: Record) -> Record:
        key = (record._model, record.id)
        assert key not in self.live
        self.live[key] = record
        return record

    def snapshot(self, model_name, record, company):
        assert company is self.company
        assert self.live[(model_name, record.id)] is record
        self.snapshot_reads.append((model_name, record.id))
        values = _values(record)
        state = str(getattr(record, "state", "unknown") or "unknown")
        return {
            "model": model_name,
            "record_id": record.id,
            "company_id": company.id,
            "state": state,
            "values": values,
            "values_digest": hashlib.sha256(
                canonical_json(values)
            ).hexdigest(),
        }

    def record_is_absent(self, model_name, record_id, company):
        assert company is self.company
        self.absence_reads.append((model_name, record_id))
        return (model_name, record_id) not in self.live

    def move_records(self, move, company):
        assert company is self.company
        return [
            ("account.move", move),
            *(("account.move.line", line) for line in move.line_ids),
        ]

    def assert_linewise_reversal(self, origin, reversal, company):
        assert company is self.company
        self.linewise_reads.append((origin.id, reversal.id))
        original = sorted(
            (
                _amount(line.debit),
                _amount(line.credit),
                _amount(line.balance),
                _amount(line.amount_currency),
            )
            for line in origin.line_ids
        )
        inverse = sorted(
            (
                _amount(line.credit),
                _amount(line.debit),
                -_amount(line.balance),
                -_amount(line.amount_currency),
            )
            for line in reversal.line_ids
        )
        if original != inverse:
            raise AssertionError("journal items are not linewise inverse")

    def assert_move_balanced(self, move, company):
        assert company is self.company
        self.balance_reads.append(move.id)
        if (
            sum((_amount(line.debit) for line in move.line_ids), Decimal())
            != sum(
                (_amount(line.credit) for line in move.line_ids), Decimal()
            )
            or sum(
                (_amount(line.balance) for line in move.line_ids), Decimal()
            )
            != 0
        ):
            raise AssertionError("move is not balanced")


class Case:
    def __init__(self, method: str):
        self.method = method
        self.company = Ref(7)
        self.adapter = FreshAdapter(self.company)
        self.result_keys: set[tuple[str, int]] = set()
        self.before: dict[tuple[str, int], dict[str, Any]] = {}
        self.plan: dict[str, Any] | None = None
        self.tombstones: set[tuple[str, int]] = set()

    def add(
        self, model: str, record_id: int, *, result: bool = True, **values
    ) -> Record:
        record = self.adapter.add(Record(model, record_id, **values))
        if result:
            self.result_keys.add((model, record_id))
        return record

    def delete(self, record: Record) -> None:
        key = (record._model, record.id)
        self.adapter.live.pop(key)
        self.result_keys.discard(key)
        self.tombstones.add(key)

    def approve(
        self,
        actions: list[Record],
        guards: list[tuple[Record, str]],
    ) -> None:
        contract = RECOVERY_ACTION_CONTRACTS[self.method]
        action_refs = []
        guard_refs = []
        for record, outcome in [
            *((item, None) for item in actions),
            *guards,
        ]:
            identity = (record._model, record.id)
            values = deepcopy(_values(record))
            self.before[identity] = values
            state = str(getattr(record, "state", "unknown") or "unknown")
            snapshot = create_record_snapshot(
                model=record._model,
                record_id=record.id,
                exists=True,
                record_state=state,
                values=values,
            )
            reference = {
                "model": record._model,
                "record_id": record.id,
                "company_id": self.company.id,
                "record_state": state,
                "record_fingerprint": hashlib.sha256(
                    canonical_json(snapshot)
                ).hexdigest(),
            }
            if outcome is None:
                action_refs.append(reference)
            else:
                guard_refs.append(
                    {**reference, "expected_outcome": outcome}
                )
        self.plan = create_recovery_plan_v2(
            origin_operation_id=f"origin-{self.method}",
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method=self.method,
            requires_approval=True,
            action_targets=action_refs,
            guard_records=guard_refs,
            oracle_id=contract.oracle_id,
            parameters={},
        )

    def records(self) -> list[tuple[str, Record]]:
        return [
            (model, self.adapter.live[(model, record_id)])
            for model, record_id in sorted(self.result_keys)
        ]

    def verify(self, **overrides):
        assert self.plan is not None
        arguments = {
            "plan": self.plan,
            "company": self.company,
            "records": self.records(),
            "before_values": self.before,
            "tombstone_keys": self.tombstones,
            "recovery_date": RECOVERY_DATE,
            "reason": REASON,
        }
        arguments.update(overrides)
        return verify_recovery_action(
            self.adapter, self.method, **arguments
        )


def make_move(
    case: Case,
    record_id: int,
    *,
    state: str = "posted",
    move_type: str = "entry",
    move_date: str = "2026-07-20",
    line_ids: tuple[int, int] | None = None,
    **values: Any,
) -> Record:
    move_values = {
        "state": state,
        "move_type": move_type,
        "date": move_date,
        "line_ids": [],
        "reversal_move_ids": [],
        "reversed_entry_id": False,
        "deferred_move_ids": [],
        "deferred_original_move_ids": [],
        "amount_residual": "0",
        "payment_state": "not_paid",
    }
    move_values.update(values)
    move = case.add(
        "account.move",
        record_id,
        **move_values,
    )
    ids = line_ids or (record_id * 10 + 1, record_id * 10 + 2)
    specifications = (
        ("100", "0", "100", "100"),
        ("0", "100", "-100", "-100"),
    )
    for line_id, (debit, credit, balance, currency_amount) in zip(
        ids, specifications
    ):
        line = case.add(
            "account.move.line",
            line_id,
            move_id=move,
            parent_state=state,
            debit=debit,
            credit=credit,
            balance=balance,
            amount_currency=currency_amount,
            amount_residual="0",
            amount_residual_currency="0",
            reconciled=False,
            full_reconcile_id=False,
            matched_debit_ids=[],
            matched_credit_ids=[],
            matching_number=False,
        )
        move.line_ids.append(line)
    return move


def make_reversal(
    case: Case,
    origin: Record,
    record_id: int,
    *,
    move_date: str = RECOVERY_DATE,
    reason: str = REASON,
) -> Record:
    reverse_type = {
        "out_invoice": "out_refund",
        "in_invoice": "in_refund",
        "out_refund": "out_invoice",
        "in_refund": "in_invoice",
        "entry": "entry",
    }[origin.move_type]
    reversal = make_move(
        case,
        record_id,
        state="posted",
        move_type=reverse_type,
        move_date=move_date,
        line_ids=(record_id * 10 + 1, record_id * 10 + 2),
        reversed_entry_id=origin,
        odoo_cli_v3_reason=reason,
    )
    for source, inverse in zip(origin.line_ids, reversal.line_ids):
        inverse.debit = source.credit
        inverse.credit = source.debit
        inverse.balance = str(-_amount(source.balance))
        inverse.amount_currency = str(-_amount(source.amount_currency))
    origin.reversal_move_ids.append(reversal)
    return reversal


@pytest.mark.parametrize(
    ("method", "move_type"),
    [
        ("cancel_pristine_v3_draft_customer_invoice_v1", "out_invoice"),
        ("cancel_pristine_v3_draft_vendor_bill_v1", "in_invoice"),
        ("cancel_draft_refund_v1", "out_refund"),
        ("cancel_draft_period_adjustment_v1", "entry"),
    ],
)
def test_draft_cancellation_uses_fresh_exact_delta_oracle(
    method, move_type
):
    case = Case(method)
    move = make_move(case, 10, state="draft", move_type=move_type)
    case.approve(
        [move],
        [(line, "survive_allowed_delta") for line in move.line_ids],
    )
    move.state = "cancel"
    for line in move.line_ids:
        line.parent_state = "cancel"

    checks = case.verify()

    assert "fresh_result_graph_unique_and_complete" in checks
    assert len(case.adapter.snapshot_reads) == 3
    assert not case.adapter.linewise_reads


@pytest.mark.parametrize(
    ("method", "move_type", "outcome"),
    [
        (
            "reverse_posted_customer_invoice_v1",
            "out_invoice",
            "survive_exact",
        ),
        (
            "reverse_posted_vendor_bill_v1",
            "in_invoice",
            "survive_exact",
        ),
        ("reverse_posted_refund_v1", "out_refund", "survive_exact"),
        (
            "reverse_posted_period_adjustment_v1",
            "entry",
            "survive_allowed_delta",
        ),
        (
            "reverse_the_reversal_v1",
            "entry",
            "survive_allowed_delta",
        ),
    ],
)
def test_generic_reversal_uses_fresh_linewise_business_oracle(
    method, move_type, outcome
):
    case = Case(method)
    guards: list[tuple[Record, str]] = []
    if method == "reverse_the_reversal_v1":
        original = make_move(case, 5)
        origin = make_move(
            case, 10, move_type=move_type, reversed_entry_id=original
        )
        original.reversal_move_ids = [origin]
        guards.extend(
            [
                (original, "survive_exact"),
                *((line, "survive_allowed_delta")
                  for line in original.line_ids),
            ]
        )
    else:
        origin = make_move(case, 10, move_type=move_type)
    guards.extend((line, outcome) for line in origin.line_ids)
    case.approve([origin], guards)
    reversal = make_reversal(case, origin, 20)

    checks = case.verify()

    assert (origin.id, reversal.id) in case.adapter.linewise_reads
    assert set(case.adapter.balance_reads) >= {origin.id, reversal.id}
    assert f"{method}_fresh_reversal_matches" in checks


def make_payment_case() -> tuple[Case, dict[str, Record]]:
    case = Case("cancel_and_unreconcile_payment_v1")
    payment_move = make_move(case, 20)
    target_move = make_move(
        case, 30, move_type="out_invoice", amount_residual="0"
    )
    partial = case.add(
        "account.partial.reconcile",
        40,
        debit_move_id=target_move.line_ids[0],
        credit_move_id=payment_move.line_ids[1],
        amount="100",
        debit_amount_currency="100",
        credit_amount_currency="100",
        full_reconcile_id=False,
    )
    full = case.add(
        "account.full.reconcile",
        41,
        partial_reconcile_ids=[partial],
        reconciled_line_ids=[
            target_move.line_ids[0],
            payment_move.line_ids[1],
        ],
    )
    for line in payment_move.line_ids:
        line.reconciled = True
        line.full_reconcile_id = full
        line.matched_debit_ids = [partial]
    target_line = target_move.line_ids[0]
    target_line.reconciled = True
    target_line.full_reconcile_id = full
    target_line.matched_credit_ids = [partial]
    binding = {
        "payment_id": 10,
        "payment_move_id": payment_move.id,
        "payment_line_ids": [line.id for line in payment_move.line_ids],
        "target_move_ids": [target_move.id],
        "target_before": [
            {"move_id": target_move.id, "amount_residual": "100"}
        ],
        "target_line_before": [
            {
                "line_id": target_line.id,
                "move_id": target_move.id,
                "amount_residual": "100",
                "amount_residual_currency": "100",
                "reconciled": False,
                "full_reconcile_id": False,
                "matched_debit_ids": [],
                "matched_credit_ids": [],
            }
        ],
    }
    payment = case.add(
        "account.payment",
        10,
        state="paid",
        move_id=payment_move,
        odoo_cli_v3_payment_binding=binding,
    )
    delta_records = [
        payment_move,
        *payment_move.line_ids,
        target_move,
        *target_move.line_ids,
    ]
    case.approve(
        [payment],
        [
            *((record, "survive_allowed_delta")
              for record in delta_records),
            (partial, "absent"),
            (full, "absent"),
        ],
    )
    payment.state = "canceled"
    payment_move.state = "cancel"
    for line in payment_move.line_ids:
        line.parent_state = "cancel"
        line.reconciled = False
        line.full_reconcile_id = False
        line.matched_debit_ids = []
        line.matched_credit_ids = []
    target_move.amount_residual = "100"
    target_line.amount_residual = "100"
    target_line.amount_residual_currency = "100"
    target_line.reconciled = False
    target_line.full_reconcile_id = False
    target_line.matched_debit_ids = []
    target_line.matched_credit_ids = []
    case.delete(partial)
    case.delete(full)
    return case, {
        "payment": payment,
        "payment_move": payment_move,
        "target_move": target_move,
        "target_line": target_line,
        "partial": partial,
        "full": full,
    }


def test_payment_recovery_freshly_proves_cancel_unreconcile_and_restoration():
    case, records = make_payment_case()

    checks = case.verify()

    assert "payment_target_residuals_restored" in checks
    assert set(case.adapter.absence_reads) == {
        ("account.partial.reconcile", records["partial"].id),
        ("account.full.reconcile", records["full"].id),
    }
    assert records["payment_move"].id in case.adapter.balance_reads


def make_bank_case(
    *,
    foreign_journal_currency: bool = False,
    transaction_currency_is_company: bool = False,
    unmarked_source_amount_currency: str = "0",
) -> tuple[Case, dict[str, Record]]:
    if transaction_currency_is_company and not foreign_journal_currency:
        raise ValueError(
            "company transaction currency requires a foreign journal currency"
        )
    case = Case("post_compensating_bank_statement_v1")
    company_currency = Ref(70)
    company_currency.rounding = "0.01"
    case.company.currency_id = company_currency
    journal_currency = (
        Ref(71) if foreign_journal_currency else company_currency
    )
    journal_currency.rounding = "0.01"
    journal_currency_rate = (
        Decimal("0.2") if foreign_journal_currency else Decimal("1")
    )
    transaction_currency = (
        company_currency if transaction_currency_is_company else Ref(90)
    )
    transaction_currency.rounding = "0.01"
    original_moves = [
        make_move(case, 20),
        make_move(case, 30),
    ]
    journal = Ref(80)
    journal.company_id = case.company
    journal.currency_id = (
        journal_currency if foreign_journal_currency else False
    )
    journal.default_account_id = Ref(91)
    journal.suspense_account_id = Ref(92)
    partners = (Ref(81), Ref(82))
    original_lines = [
        case.add(
            "account.bank.statement.line",
            101,
            date="2026-07-20",
            amount="70",
            amount_currency="77",
            payment_ref="Original A",
            ref="A",
            journal_id=journal,
            partner_id=partners[0],
            foreign_currency_id=transaction_currency,
            currency_id=journal_currency,
            company_id=case.company,
            is_reconciled=False,
            payment_ids=[],
            move_id=original_moves[0],
            statement_id=False,
        ),
        case.add(
            "account.bank.statement.line",
            102,
            date="2026-07-20",
            amount="30",
            amount_currency=unmarked_source_amount_currency,
            payment_ref="Original B",
            ref="B",
            journal_id=journal,
            partner_id=partners[1],
            foreign_currency_id=False,
            currency_id=journal_currency,
            company_id=case.company,
            is_reconciled=False,
            payment_ids=[],
            move_id=original_moves[1],
            statement_id=False,
        ),
    ]
    original = case.add(
        "account.bank.statement",
        100,
        date="2026-07-20",
        reference="Original",
        balance_start="50",
        balance_end="150",
        balance_end_real="150",
        is_complete=True,
        is_valid=True,
        company_id=case.company,
        journal_id=journal,
        currency_id=journal_currency,
        line_ids=original_lines,
    )
    for line in original_lines:
        line.statement_id = original

    def configure_move(move, bank_line, statement):
        amount = _amount(bank_line.amount)
        foreign_currency_id = (
            bank_line.foreign_currency_id.id
            if bank_line.foreign_currency_id
            else None
        )
        foreign_amount = (
            _amount(bank_line.amount_currency)
            if foreign_currency_id is not None
            else amount
        )
        if journal_currency is company_currency:
            company_amount = amount
        elif foreign_currency_id == company_currency.id:
            company_amount = foreign_amount
        else:
            company_amount = amount / journal_currency_rate
        move.company_id = case.company
        move.journal_id = journal
        move.currency_id = (
            bank_line.foreign_currency_id
            if foreign_currency_id is not None
            else journal_currency
        )
        move.partner_id = bank_line.partner_id
        move.date = bank_line.date
        move.statement_line_id = bank_line
        move.statement_line_ids = [bank_line]
        for field in (
            "payment_ids",
            "matched_payment_ids",
            "reconciled_payment_ids",
            "tax_cash_basis_created_move_ids",
            "exchange_diff_partial_ids",
            "asset_ids",
            "transaction_ids",
            "authorized_transaction_ids",
        ):
            setattr(move, field, [])
        for field in (
            "origin_payment_id",
            "tax_cash_basis_rec_id",
            "tax_cash_basis_origin_move_id",
            "asset_id",
        ):
            setattr(move, field, False)
        move.deferred_move_ids = []
        move.deferred_original_move_ids = []
        specifications = (
            (
                journal.default_account_id,
                journal_currency,
                max(company_amount, Decimal()),
                max(-company_amount, Decimal()),
                company_amount,
                amount,
                journal_currency_rate,
            ),
            (
                journal.suspense_account_id,
                bank_line.foreign_currency_id or journal_currency,
                max(-company_amount, Decimal()),
                max(company_amount, Decimal()),
                -company_amount,
                -foreign_amount,
                (
                    Decimal("0.14")
                    if foreign_currency_id is not None
                    else journal_currency_rate
                ),
            ),
        )
        for move_line, specification in zip(move.line_ids, specifications):
            (
                account,
                line_currency,
                debit,
                credit,
                balance,
                amount_currency,
                currency_rate,
            ) = specification
            move_line.company_id = case.company
            move_line.account_id = account
            move_line.currency_id = line_currency
            move_line.partner_id = bank_line.partner_id
            move_line.debit = str(debit)
            move_line.credit = str(credit)
            move_line.balance = str(balance)
            move_line.amount_currency = str(amount_currency)
            move_line.currency_rate = str(currency_rate)
            move_line.payment_id = False
            move_line.statement_line_id = bank_line
            move_line.statement_id = statement
            move_line.tax_ids = []
            move_line.tax_line_id = False
            move_line.tax_tag_ids = []
            move_line.analytic_distribution = False
            move_line.analytic_line_ids = []
            move_line.asset_ids = []
            move_line.deferred_start_date = False
            move_line.deferred_end_date = False

    for move, line in zip(original_moves, original_lines):
        configure_move(move, line, original)
    guards: list[tuple[Record, str]] = [
        *((line, "survive_exact") for line in original_lines),
        *((move, "survive_exact") for move in original_moves),
        *(
            (line, "survive_exact")
            for move in original_moves
            for line in move.line_ids
        ),
    ]
    case.approve([original], guards)
    inverse_moves = [
        make_move(case, 220),
        make_move(case, 230),
    ]
    inverse_lines = [
        case.add(
            "account.bank.statement.line",
            201,
            date=RECOVERY_DATE,
            amount="-70",
            amount_currency="-77",
            payment_ref=REASON,
            ref="Recovery of bank line 101",
            journal_id=journal,
            partner_id=partners[0],
            foreign_currency_id=transaction_currency,
            currency_id=journal_currency,
            company_id=case.company,
            is_reconciled=False,
            payment_ids=[],
            move_id=inverse_moves[0],
            statement_id=False,
        ),
        case.add(
            "account.bank.statement.line",
            202,
            date=RECOVERY_DATE,
            amount="-30",
            amount_currency="0",
            payment_ref=REASON,
            ref="Recovery of bank line 102",
            journal_id=journal,
            partner_id=partners[1],
            foreign_currency_id=False,
            currency_id=journal_currency,
            company_id=case.company,
            is_reconciled=False,
            payment_ids=[],
            move_id=inverse_moves[1],
            statement_id=False,
        ),
    ]
    compensating = case.add(
        "account.bank.statement",
        200,
        date=RECOVERY_DATE,
        reference=REASON,
        balance_start="150",
        balance_end="50",
        balance_end_real="50",
        is_complete=True,
        is_valid=True,
        company_id=case.company,
        journal_id=journal,
        currency_id=journal_currency,
        line_ids=inverse_lines,
    )
    for line in inverse_lines:
        line.statement_id = compensating
    for move, line in zip(inverse_moves, inverse_lines):
        configure_move(move, line, compensating)
    return case, {
        "original": original,
        "original_line": original_lines[0],
        "compensating": compensating,
        "inverse_line": inverse_lines[0],
    }


def test_bank_recovery_freshly_proves_independent_inverse_statement():
    case, records = make_bank_case()

    checks = case.verify()

    assert "bank_line_amounts_fresh_inverse" in checks
    assert records["compensating"].id != records["original"].id
    assert set(case.adapter.balance_reads) >= {220, 230}


def test_bank_company_currency_amounts_use_one_to_one_company_balance():
    case, records = make_bank_case()
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids

    case.verify()

    assert liquidity_line.amount_currency == "-70"
    assert liquidity_line.balance == "-70"
    assert suspense_line.balance == "70"


def test_bank_company_currency_rejects_balanced_wrong_company_amount():
    case, records = make_bank_case()
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids
    liquidity_line.credit = "69"
    liquidity_line.balance = "-69"
    suspense_line.debit = "69"
    suspense_line.balance = "69"

    with pytest.raises(
        RecoveryVerificationError, match="journal currency conversion differs"
    ):
        case.verify()


def test_bank_foreign_journal_uses_fresh_company_currency_conversion():
    case, records = make_bank_case(foreign_journal_currency=True)
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids

    case.verify()

    assert liquidity_line.amount_currency == "-70"
    assert liquidity_line.balance == "-3.5E+2"
    assert suspense_line.amount_currency == "77"
    assert suspense_line.balance == "3.5E+2"


def test_bank_foreign_journal_rejects_balanced_one_to_one_valuation():
    case, records = make_bank_case(foreign_journal_currency=True)
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids
    liquidity_line.credit = "70"
    liquidity_line.balance = "-70"
    suspense_line.debit = "70"
    suspense_line.balance = "70"

    with pytest.raises(
        RecoveryVerificationError, match="journal currency conversion differs"
    ):
        case.verify()


def test_bank_company_transaction_currency_uses_transaction_amount():
    case, records = make_bank_case(
        foreign_journal_currency=True,
        transaction_currency_is_company=True,
    )
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids

    case.verify()

    assert liquidity_line.amount_currency == "-70"
    assert liquidity_line.balance == "-77"
    assert suspense_line.amount_currency == "77"
    assert suspense_line.balance == "77"


def test_bank_company_transaction_currency_rejects_journal_rate_valuation():
    case, records = make_bank_case(
        foreign_journal_currency=True,
        transaction_currency_is_company=True,
    )
    liquidity_line, suspense_line = records["inverse_line"].move_id.line_ids
    liquidity_line.credit = "350"
    liquidity_line.balance = "-350"
    suspense_line.debit = "350"
    suspense_line.balance = "350"

    with pytest.raises(
        RecoveryVerificationError, match="journal currency conversion differs"
    ):
        case.verify()


def test_bank_without_foreign_currency_requires_zero_compensating_amount_currency():
    case, records = make_bank_case()
    records["compensating"].line_ids[1].amount_currency = "1"

    with pytest.raises(
        RecoveryVerificationError, match="unmarked foreign amount differs"
    ):
        case.verify()


def test_bank_without_foreign_currency_requires_zero_source_amount_currency():
    case, _records = make_bank_case(unmarked_source_amount_currency="1")

    with pytest.raises(
        RecoveryVerificationError, match="unmarked foreign amount differs"
    ):
        case.verify()


def make_reconciliation_case(
    *, writeoff: bool
) -> tuple[Case, dict[str, Record]]:
    case = Case("undo_reconciliation_and_reverse_writeoff_v1")
    debit_move = make_move(case, 20)
    debit_line = debit_move.line_ids[0]
    if writeoff:
        credit_move = make_move(case, 30)
        credit_line = credit_move.line_ids[1]
    else:
        credit_move = make_move(case, 30)
        credit_line = credit_move.line_ids[1]
    partial = case.add(
        "account.partial.reconcile",
        40,
        debit_move_id=debit_line,
        credit_move_id=credit_line,
        amount="100",
        debit_amount_currency="100",
        credit_amount_currency="100",
        full_reconcile_id=False,
    )
    full = case.add(
        "account.full.reconcile",
        41,
        partial_reconcile_ids=[partial],
        reconciled_line_ids=[debit_line, credit_line],
    )
    partial.full_reconcile_id = full
    debit_line.reconciled = True
    debit_line.full_reconcile_id = full
    debit_line.matched_credit_ids = [partial]
    credit_line.reconciled = True
    credit_line.full_reconcile_id = full
    credit_line.matched_debit_ids = [partial]
    actions = [partial, full]
    guard_moves = [debit_move, credit_move]
    if writeoff:
        actions.append(credit_move)
        guard_moves = [debit_move]
    guard_records = [
        *guard_moves,
        *(line for move in (debit_move, credit_move) for line in move.line_ids),
    ]
    case.approve(
        actions,
        [
            (record, "survive_allowed_delta")
            for record in guard_records
        ],
    )
    debit_line.amount_residual = "100"
    debit_line.amount_residual_currency = "100"
    debit_line.reconciled = False
    debit_line.full_reconcile_id = False
    debit_line.matched_credit_ids = []
    credit_line.amount_residual = "-100"
    credit_line.amount_residual_currency = "-100"
    credit_line.reconciled = False
    credit_line.full_reconcile_id = False
    credit_line.matched_debit_ids = []
    case.delete(partial)
    case.delete(full)
    reversal = (
        make_reversal(case, credit_move, 50) if writeoff else None
    )
    return case, {
        "partial": partial,
        "full": full,
        "debit_line": debit_line,
        "credit_line": credit_line,
        "writeoff": credit_move if writeoff else None,
        "reversal": reversal,
    }


@pytest.mark.parametrize("writeoff", [False, True])
def test_reconciliation_recovery_freshly_proves_unlink_residual_and_writeoff(
    writeoff
):
    case, records = make_reconciliation_case(writeoff=writeoff)

    checks = case.verify()

    assert "reconciliation_source_residuals_fresh_restored" in checks
    expected = (
        "reconciliation_writeoff_fresh_reversed"
        if writeoff
        else "reconciliation_writeoff_not_applicable"
    )
    assert expected in checks
    assert set(case.adapter.absence_reads) == {
        ("account.partial.reconcile", records["partial"].id),
        ("account.full.reconcile", records["full"].id),
    }


def make_asset_case() -> tuple[Case, dict[str, Record]]:
    case = Case("cancel_asset_and_reverse_schedule_v1")
    source = make_move(case, 10)
    posted = make_move(case, 20)
    draft = make_move(case, 30, state="draft")
    asset = case.add(
        "account.asset",
        40,
        state="open",
        depreciation_move_ids=[posted, draft],
        value_residual="60",
        book_value="60",
    )
    case.approve(
        [asset],
        [
            (source, "survive_exact"),
            *((line, "survive_exact") for line in source.line_ids),
            (posted, "survive_allowed_delta"),
            *((line, "survive_allowed_delta") for line in posted.line_ids),
            (draft, "absent"),
            *((line, "absent") for line in draft.line_ids),
        ],
    )
    asset.state = "cancelled"
    asset.depreciation_move_ids = [posted]
    for line in list(draft.line_ids):
        case.delete(line)
    case.delete(draft)
    reversal = make_reversal(case, posted, 50)
    return case, {
        "asset": asset,
        "source": source,
        "posted": posted,
        "draft": draft,
        "reversal": reversal,
    }


def test_asset_recovery_freshly_proves_schedule_tombstones_and_reversals():
    case, records = make_asset_case()

    checks = case.verify()

    assert "asset_draft_schedule_fresh_absent" in checks
    assert "asset_posted_schedule_fresh_reversed" in checks
    assert ("account.move", records["draft"].id) in set(
        case.adapter.absence_reads
    )


def make_depreciation_case() -> tuple[Case, dict[str, Record]]:
    case = Case("reverse_depreciation_and_restore_schedule_v1")
    asset = case.add(
        "account.asset",
        10,
        state="open",
        depreciation_move_ids=[],
        value_residual="40",
        book_value="40",
    )
    move = make_move(
        case,
        20,
        asset_id=asset,
        asset_move_type="depreciation",
        depreciation_value="20",
    )
    asset.depreciation_move_ids = [move]
    case.approve(
        [move],
        [
            (asset, "survive_allowed_delta"),
            *((line, "survive_allowed_delta") for line in move.line_ids),
        ],
    )
    asset.value_residual = "60"
    asset.book_value = "60"
    reversal = make_reversal(case, move, 30)
    return case, {
        "asset": asset,
        "move": move,
        "reversal": reversal,
    }


def test_depreciation_recovery_freshly_proves_asset_value_restoration():
    case, records = make_depreciation_case()

    checks = case.verify()

    assert "depreciation_asset_values_fresh_restored" in checks
    assert (records["move"].id, records["reversal"].id) in (
        case.adapter.linewise_reads
    )


def make_accrual_case() -> tuple[Case, dict[str, Record]]:
    case = Case("cancel_scheduled_and_reverse_accrual_origin_v1")
    origin = make_move(case, 10)
    scheduled = make_move(
        case,
        20,
        state="draft",
        move_date="2026-08-31",
        reversed_entry_id=origin,
        auto_post="at_date",
    )
    case.approve(
        [origin, scheduled],
        [
            (
                line,
                "survive_allowed_delta",
            )
            for move in (origin, scheduled)
            for line in move.line_ids
        ],
    )
    scheduled.state = "cancel"
    for line in scheduled.line_ids:
        line.parent_state = "cancel"
    reversal = make_reversal(case, origin, 30)
    return case, {
        "origin": origin,
        "scheduled": scheduled,
        "reversal": reversal,
    }


def test_accrual_recovery_freshly_proves_future_cancel_and_origin_reversal():
    case, records = make_accrual_case()

    checks = case.verify()

    assert "accrual_future_schedule_fresh_cancelled" in checks
    assert "accrual_origin_fresh_reversed" in checks
    assert records["scheduled"].state == "cancel"


def _make_linewise_inverse_move(
    case: Case, origin: Record, record_id: int
) -> Record:
    inverse = make_move(
        case,
        record_id,
        state=origin.state,
        move_type="entry",
        move_date=origin.date,
    )
    for source, target in zip(origin.line_ids, inverse.line_ids):
        target.debit = source.credit
        target.credit = source.debit
        target.balance = str(-_amount(source.balance))
        target.amount_currency = str(-_amount(source.amount_currency))
    return inverse


def make_deferred_case() -> tuple[Case, dict[str, Record]]:
    case = Case("reverse_deferred_source_and_schedule_v1")
    source = make_move(case, 10, move_type="out_invoice")
    schedule_a = make_move(
        case, 20, move_date="2026-08-31"
    )
    schedule_b = make_move(
        case, 30, move_date="2026-09-30"
    )
    source.deferred_move_ids = [schedule_a, schedule_b]
    case.approve(
        [source],
        [
            *((line, "survive_exact") for line in source.line_ids),
            (schedule_a, "survive_exact"),
            *((line, "survive_exact") for line in schedule_a.line_ids),
            (schedule_b, "survive_exact"),
            *((line, "survive_exact") for line in schedule_b.line_ids),
        ],
    )
    reversal = make_reversal(case, source, 40)
    inverse_a = _make_linewise_inverse_move(case, schedule_a, 50)
    inverse_b = _make_linewise_inverse_move(case, schedule_b, 60)
    reversal.deferred_move_ids = [inverse_a, inverse_b]
    inverse_a.deferred_original_move_ids = [reversal]
    inverse_b.deferred_original_move_ids = [reversal]
    return case, {
        "source": source,
        "schedule_a": schedule_a,
        "schedule_b": schedule_b,
        "reversal": reversal,
        "inverse_a": inverse_a,
        "inverse_b": inverse_b,
    }


def test_deferred_recovery_freshly_proves_schedule_by_date_linewise_inverse():
    case, records = make_deferred_case()

    checks = case.verify()

    assert "deferred_inverse_schedule_fresh_linewise" in checks
    assert {
        (records["schedule_a"].id, records["inverse_a"].id),
        (records["schedule_b"].id, records["inverse_b"].id),
    }.issubset(case.adapter.linewise_reads)


def make_generic_case() -> tuple[Case, dict[str, Record]]:
    case = Case("reverse_posted_customer_invoice_v1")
    origin = make_move(case, 10, move_type="out_invoice")
    case.approve(
        [origin],
        [(line, "survive_exact") for line in origin.line_ids],
    )
    reversal = make_reversal(case, origin, 20)
    return case, {"origin": origin, "reversal": reversal}


def test_verification_registry_is_exactly_the_immutable_contract_catalog():
    assert isinstance(RECOVERY_VERIFICATION_METHODS, frozenset)
    assert RECOVERY_VERIFICATION_METHODS == frozenset(
        RECOVERY_ACTION_CONTRACTS
    )
    assert len(RECOVERY_VERIFICATION_METHODS) == 16


def test_public_verifier_accepts_no_executor_check_labels():
    signature = inspect.signature(verify_recovery_action)
    assert "checks" not in signature.parameters
    assert tuple(signature.parameters) == (
        "adapter",
        "method",
        "plan",
        "company",
        "records",
        "before_values",
        "tombstone_keys",
        "recovery_date",
        "reason",
    )


def test_verifier_source_has_no_orm_write_elevation_or_transaction_calls():
    module = inspect.getmodule(verify_recovery_action)
    assert module is not None
    source = inspect.getsource(module)
    forbidden = (
        ".write(",
        ".unlink(",
        ".sudo(",
        ".commit(",
        ".rollback(",
        "action_post(",
        "reverse_moves(",
        "remove_move_reconcile(",
        "set_to_cancelled(",
        "create_model(",
    )
    assert all(token not in source for token in forbidden)


def test_changed_survive_exact_record_is_rejected():
    case, records = make_generic_case()
    records["origin"].line_ids[0].debit = "99"

    with pytest.raises(
        RecoveryVerificationError, match="survive_exact guard changed"
    ):
        case.verify()


def test_missing_survivor_is_rejected_even_when_it_still_exists():
    case, records = make_generic_case()
    missing = (
        "account.move.line",
        records["origin"].line_ids[0].id,
    )
    case.result_keys.remove(missing)

    with pytest.raises(
        RecoveryVerificationError, match="omits a survivor"
    ):
        case.verify()


def test_duplicate_result_identity_is_rejected():
    case, _records = make_generic_case()
    duplicated = [*case.records(), case.records()[0]]

    with pytest.raises(
        RecoveryVerificationError, match="duplicate identity"
    ):
        case.verify(records=duplicated)


def test_unlinked_extra_result_record_is_rejected():
    case, records = make_generic_case()
    case.add(
        "account.move.line",
        999,
        move_id=records["origin"],
        parent_state="posted",
    )

    with pytest.raises(
        RecoveryVerificationError, match="incomplete or extra graph"
    ):
        case.verify()


def test_tombstone_must_be_absent_in_a_fresh_read():
    case, records = make_payment_case()
    case.adapter.add(records["partial"])

    with pytest.raises(
        RecoveryVerificationError, match="still exists"
    ):
        case.verify()


def test_before_values_must_reconstruct_signed_plan_fingerprints():
    case, _records = make_generic_case()
    forged = deepcopy(case.before)
    forged[("account.move", 10)]["date"] = "2026-07-21"

    with pytest.raises(
        RecoveryVerificationError, match="differ from the recovery plan"
    ):
        case.verify(before_values=forged)


def test_wrong_company_binding_is_rejected_before_business_oracle():
    case, _records = make_generic_case()

    with pytest.raises(
        RecoveryVerificationError, match="crosses company"
    ):
        case.verify(company=Ref(8))


def test_reversal_date_reason_and_linewise_amount_are_oracles():
    case, records = make_generic_case()
    records["reversal"].odoo_cli_v3_reason = "Tampered"

    with pytest.raises(
        RecoveryVerificationError, match="reason differs"
    ):
        case.verify()

    case, records = make_generic_case()
    records["reversal"].line_ids[0].debit = "1"
    with pytest.raises(
        RecoveryVerificationError, match="linewise reversal oracle failed"
    ):
        case.verify()


def test_payment_delta_allowlist_rejects_unrelated_target_change():
    case, records = make_payment_case()
    records["target_move"].date = "2026-07-21"

    with pytest.raises(
        RecoveryVerificationError, match="outside its recovery allowlist"
    ):
        case.verify()


def test_payment_residual_must_match_immutable_creation_binding():
    case, records = make_payment_case()
    records["target_line"].amount_residual = "99"

    with pytest.raises(
        RecoveryVerificationError, match="state was not restored"
    ):
        case.verify()


def test_bank_inverse_amount_is_not_proven_by_record_existence():
    case, records = make_bank_case()
    records["inverse_line"].amount = "-69"

    with pytest.raises(
        RecoveryVerificationError, match="bank line differs"
    ):
        case.verify()


def test_bank_original_graph_must_remain_snapshot_exact():
    case, records = make_bank_case()
    records["original_line"].payment_ref = "Changed"

    with pytest.raises(
        RecoveryVerificationError, match="survive_exact guard changed"
    ):
        case.verify()


def test_bank_compensating_move_must_use_exact_journal_accounts():
    case, records = make_bank_case()
    records["inverse_line"].move_id.line_ids[0].account_id = Ref(999)

    with pytest.raises(
        RecoveryVerificationError,
        match="does not use liquidity and suspense accounts",
    ):
        case.verify()


def test_bank_compensating_move_must_preserve_linewise_amounts():
    case, records = make_bank_case()
    records["inverse_line"].move_id.line_ids[0].balance = "-69"

    with pytest.raises(
        RecoveryVerificationError, match="journal item amount differs"
    ):
        case.verify()


def test_bank_compensating_move_rejects_external_payment_effects():
    case, records = make_bank_case()
    records["inverse_line"].move_id.payment_ids = [Ref(999)]

    with pytest.raises(
        RecoveryVerificationError, match="external side effect"
    ):
        case.verify()


def test_bank_optional_asset_and_deferred_fields_may_be_absent():
    case, records = make_bank_case()
    for bank_line in records["compensating"].line_ids:
        for move_line in bank_line.move_id.line_ids:
            del move_line.asset_ids
            del move_line.deferred_start_date
            del move_line.deferred_end_date

    case.verify()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("asset_ids", [Ref(999)]),
        ("deferred_start_date", "2026-07-29"),
        ("deferred_end_date", "2026-08-29"),
    ],
)
def test_bank_present_optional_asset_or_deferred_effect_is_rejected(
    field: str, value: Any
):
    case, records = make_bank_case()
    setattr(records["inverse_line"].move_id.line_ids[0], field, value)

    with pytest.raises(
        RecoveryVerificationError, match="asset, deferred, or external effect"
    ):
        case.verify()


def test_reconciliation_residual_math_is_freshly_recomputed():
    case, records = make_reconciliation_case(writeoff=False)
    records["debit_line"].amount_residual = "99"

    with pytest.raises(
        RecoveryVerificationError, match="residual was not restored"
    ):
        case.verify()


def test_asset_schedule_reversal_reason_is_required():
    case, records = make_asset_case()
    records["reversal"].odoo_cli_v3_reason = "Wrong"

    with pytest.raises(
        RecoveryVerificationError, match="reason differs"
    ):
        case.verify()


def test_depreciation_asset_values_are_financial_oracles():
    case, records = make_depreciation_case()
    records["asset"].book_value = "59"

    with pytest.raises(
        RecoveryVerificationError, match="values were not restored"
    ):
        case.verify()


def test_accrual_future_schedule_must_really_be_cancelled():
    case, records = make_accrual_case()
    records["scheduled"].state = "draft"

    with pytest.raises(
        RecoveryVerificationError, match="state or future schedule differs"
    ):
        case.verify()


def test_deferred_inverse_schedule_requires_fresh_bidirectional_binding():
    case, records = make_deferred_case()
    records["inverse_a"].deferred_original_move_ids = []

    with pytest.raises(
        RecoveryVerificationError, match="linkage differs"
    ):
        case.verify()


def test_adapter_business_assertions_cannot_return_truthy_self_reports():
    case, _records = make_generic_case()
    case.adapter.assert_move_balanced = lambda *_args: True

    with pytest.raises(
        RecoveryVerificationError, match="ambiguous result"
    ):
        case.verify()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("recovery_date", "2026-7-29", "ISO date"),
        ("reason", " Approved recovery", "reason is invalid"),
    ],
)
def test_recovery_execution_parameters_are_strictly_rebound(
    field, value, message
):
    case, _records = make_generic_case()

    with pytest.raises(RecoveryVerificationError, match=message):
        case.verify(**{field: value})
