from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import date
from decimal import Decimal
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo import write_handlers as handlers_module
from odoo_accounting_cli_v3.odoo.recovery_verifier import (
    RecoveryVerificationError,
)
from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    EXCLUSIVE_BEFORE_LOCK_CAPABILITIES,
    OdooWriteBootstrapError,
    _precheck_lock_targets,
    _resource_lock_digests,
    _trusted_recovery_plan as bootstrap_trusted_plan,
)
from odoo_accounting_cli_v3.odoo.recovery_actions import RecoveryActionResult
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlerError,
    OdooWriteHandlers,
    _bank_statement_sequence_lock_digest,
)
from odoo_accounting_cli_v3.odoo.write_precheck import (
    OdooWritePrecheckError,
    _trusted_recovery_plan as precheck_trusted_plan,
)
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan_v2
from odoo_accounting_cli_v3.operations import canonical_json


CAPABILITY_ID = "acct.bank.statement_compensate.v1"
METHOD = "post_compensating_bank_statement_v1"
ORACLE = "post_compensating_bank_statement_exact_v1"
ORIGIN_ID = "bank-import-operation"
COMPANY_ID = 7
STATEMENT_ID = 100
JOURNAL_ID = 2
CURRENCY_ID = 1
MODULE_GRAPH_DIGEST = "a" * 64
SOURCE_DIGEST = "b" * 64
SOURCE_LINE_INDEX = "2026072000000000000000000101"
LATER_LINE_INDEX = "2026072000000000000000000102"
HISTORICAL_LINE_INDEX = "2026071900000000000000000999"
COMPENSATION_LINE_INDEX = "2026072900000000000000000301"
AFTER_COMPENSATION_LINE_INDEX = "2026073000000000000000000302"


class Record(SimpleNamespace):
    @property
    def ids(self):
        return [self.id]


def _reference(
    model: str,
    record_id: int,
    *,
    guard: bool = False,
) -> dict[str, object]:
    value: dict[str, object] = {
        "model": model,
        "record_id": record_id,
        "company_id": COMPANY_ID,
        "record_state": "posted",
        "record_fingerprint": f"{record_id:064x}",
    }
    if guard:
        value["expected_outcome"] = "survive_exact"
    return value


def _plan(
    *,
    method: str = METHOD,
    oracle: str = ORACLE,
    action_id: int = STATEMENT_ID,
    guards: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    actions = [_reference("account.bank.statement", action_id)]
    guards = guards or [
        _reference("account.bank.statement.line", 101, guard=True),
        _reference("account.move", 200, guard=True),
        _reference("account.move.line", 201, guard=True),
        _reference("account.move.line", 202, guard=True),
    ]
    parameters = {
        "company_id": COMPANY_ID,
        "origin_operation_id": ORIGIN_ID,
        "module_graph_digest": MODULE_GRAPH_DIGEST,
        "method": method,
        "action_targets": [
            {"model": item["model"], "record_id": item["record_id"]}
            for item in actions
        ],
        "guard_records": [
            {"model": item["model"], "record_id": item["record_id"]}
            for item in guards
        ],
        "oracle_id": oracle,
    }
    return create_recovery_plan_v2(
        origin_operation_id=ORIGIN_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=actions,
        guard_records=guards,
        oracle_id=oracle,
        parameters=parameters,
    )


def _parameters(plan: dict[str, object]) -> dict[str, object]:
    return {
        "company_id": COMPANY_ID,
        "origin_operation_id": ORIGIN_ID,
        "expected_origin_revision": 8,
        "expected_origin_final_receipt_body_digest": "c" * 64,
        "expected_recovery_plan_digest": plan["plan_digest"],
        "expected_statement_id": STATEMENT_ID,
        "expected_journal_id": JOURNAL_ID,
        "expected_currency_id": CURRENCY_ID,
        "expected_source_digest": SOURCE_DIGEST,
        "compensation_date": "2026-07-29",
        "reason": "Approved bank statement compensation",
        "idempotency_key": "bank-compensation-1",
    }


def _bank_before_values():
    return {
        ("account.bank.statement", STATEMENT_ID): {
            "company_id": [COMPANY_ID, "Company"],
            "journal_id": [JOURNAL_ID, "Bank"],
        }
    }


def test_bank_compensation_boundaries_require_the_exact_statement_plan():
    plan = _plan()
    parameters = _parameters(plan)

    assert precheck_trusted_plan(
        plan,
        capability_id=CAPABILITY_ID,
        parameters=parameters,
        company_id=COMPANY_ID,
    ) == plan
    operation = SimpleNamespace(
        capability_id=CAPABILITY_ID,
        parameters=parameters,
        company_id=COMPANY_ID,
    )
    context = SimpleNamespace(company_id=COMPANY_ID)
    assert bootstrap_trusted_plan(plan, operation, context) == plan

    wrong = _plan(
        method="reverse_the_reversal_v1",
        oracle="reverse_the_reversal_exact_v1",
    )
    wrong_parameters = _parameters(wrong)
    with pytest.raises(
        OdooWritePrecheckError, match="exact bank statement compensation"
    ):
        precheck_trusted_plan(
            wrong,
            capability_id=CAPABILITY_ID,
            parameters=wrong_parameters,
            company_id=COMPANY_ID,
        )
    with pytest.raises(
        OdooWriteBootstrapError, match="exact bank statement compensation"
    ):
        bootstrap_trusted_plan(
            wrong,
            SimpleNamespace(
                capability_id=CAPABILITY_ID,
                parameters=wrong_parameters,
                company_id=COMPANY_ID,
            ),
            context,
        )

    wrong_statement = _plan(action_id=STATEMENT_ID + 1)
    with pytest.raises(
        OdooWritePrecheckError, match="exact bank statement compensation"
    ):
        precheck_trusted_plan(
            wrong_statement,
            capability_id=CAPABILITY_ID,
            parameters=_parameters(wrong_statement),
            company_id=COMPANY_ID,
        )


def test_bank_compensation_dispatch_and_locks_cover_plan_and_journal_sequence():
    plan = _plan()
    locks = _resource_lock_digests(
        CAPABILITY_ID, COMPANY_ID, _parameters(plan), plan
    )

    assert CAPABILITY_ID in EXCLUSIVE_BEFORE_LOCK_CAPABILITIES
    assert len(locks) == 6
    assert locks == sorted(set(locks))
    assert (
        _bank_statement_sequence_lock_digest(COMPANY_ID, JOURNAL_ID)
        in locks
    )
    assert (
        OdooWriteHandlers.dispatch_name(CAPABILITY_ID, "precheck")
        == "precheck_bank_statement_compensate"
    )
    assert (
        OdooWriteHandlers.dispatch_name(CAPABILITY_ID, "execute")
        == "execute_bank_statement_compensate"
    )
    assert (
        OdooWriteHandlers.dispatch_name(CAPABILITY_ID, "verify")
        == "verify_bank_statement_compensate"
    )


def _source_harness():
    plan = _plan()
    parameters = _parameters(plan)
    currency = Record(id=CURRENCY_ID, rounding="0.01")
    company = Record(id=COMPANY_ID, currency_id=currency)
    liquidity = Record(id=901)
    suspense = Record(id=902)
    journal = Record(
        id=JOURNAL_ID,
        company_id=company,
        type="bank",
        active=True,
        currency_id=False,
        default_account_id=liquidity,
        suspense_account_id=suspense,
    )
    partner = Record(id=10)
    statement = Record(
        id=STATEMENT_ID,
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-20",
        balance_start="0",
        balance_end="100",
        balance_end_real="100",
        is_complete=True,
        is_valid=True,
        first_line_index=SOURCE_LINE_INDEX,
        line_ids=[],
        odoo_cli_v3_source_digest=SOURCE_DIGEST,
    )
    bank_line = Record(
        id=101,
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-20",
        amount="100",
        amount_currency="0",
        partner_id=partner,
        foreign_currency_id=False,
        is_reconciled=False,
        payment_ids=[],
        statement_id=statement,
        state="posted",
        internal_index=SOURCE_LINE_INDEX,
    )
    move = Record(
        id=200,
        state="posted",
        move_type="entry",
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        partner_id=partner,
        date="2026-07-20",
        statement_line_id=bank_line,
        statement_line_ids=[bank_line],
        line_ids=[],
    )
    bank_line.move_id = move

    def move_line(record_id, account, debit, credit, balance):
        return Record(
            id=record_id,
            move_id=move,
            company_id=company,
            account_id=account,
            currency_id=currency,
            partner_id=partner,
            parent_state="posted",
            debit=debit,
            credit=credit,
            balance=balance,
            amount_currency=balance,
            reconciled=False,
            full_reconcile_id=False,
            matched_debit_ids=[],
            matched_credit_ids=[],
            payment_id=False,
            statement_line_id=bank_line,
            statement_id=statement,
            tax_ids=[],
            tax_line_id=False,
            tax_tag_ids=[],
            tax_repartition_line_id=False,
            analytic_distribution=False,
            analytic_line_ids=[],
            asset_ids=[],
            deferred_start_date=False,
            deferred_end_date=False,
            reconciled_lines_ids=[],
            reconciled_lines_excluding_exchange_diff_ids=[],
        )

    debit_line = move_line(201, liquidity, "100", "0", "100")
    credit_line = move_line(202, suspense, "0", "100", "-100")
    move.line_ids = [debit_line, credit_line]
    statement.line_ids = [bank_line]
    actions = [("account.bank.statement", statement)]
    guards = [
        ("account.bank.statement.line", bank_line),
        ("account.move", move),
        ("account.move.line", debit_line),
        ("account.move.line", credit_line),
    ]
    records = [*actions, *guards]
    flags = {
        "partial": False,
        "later_statement": False,
        "standalone_line": False,
        "lock": False,
        "statement_candidates": [],
        "line_candidates": [],
        "searches": [],
        "events": [],
        "invalidations": 0,
        "on_invalidate": None,
    }

    class OperationModel:
        def _acquire_scope_lock(self, digest):
            flags["events"].append(("lock", digest))

    class Environment:
        uid = 42
        su = False

        def __getitem__(self, model_name):
            if model_name != "odoo.accounting.cli.operation":
                raise KeyError(model_name)
            return OperationModel()

        def invalidate_all(self):
            flags["invalidations"] += 1
            flags["events"].append(("invalidate", None))
            callback = flags["on_invalidate"]
            if callback is not None:
                callback()

    handler = object.__new__(OdooWriteHandlers)
    handler.context = SimpleNamespace(
        trusted_recovery_plan=plan,
        module_graph=SimpleNamespace(
            digest=MODULE_GRAPH_DIGEST,
            evidence={"digest": MODULE_GRAPH_DIGEST},
        ),
        today=date(2026, 7, 29),
        env=Environment(),
    )
    handler._recovery_records_by_role = (
        lambda *_args: (actions, guards, records)
    )
    handler.record = lambda model, record_id, *_args, **_kwargs: {
        ("account.journal", JOURNAL_ID): journal,
    }[(model, record_id)]
    handler.assert_currency = lambda *_args, **_kwargs: currency
    handler.check_account = lambda account_id, *_args: {
        liquidity.id: liquidity,
        suspense.id: suspense,
    }[account_id]

    def assert_amount(actual, expected, _currency, field):
        if Decimal(str(actual)) != Decimal(str(expected)):
            raise OdooWriteHandlerError(f"{field} differs")

    handler.assert_amount = assert_amount
    handler.assert_move_balanced = lambda *_args: None

    def open_date(_company, value, field, **_kwargs):
        if flags["lock"]:
            raise OdooWriteHandlerError(f"{field} violates lock")
        return date.fromisoformat(value)

    handler.assert_open_date = open_date
    handler.assert_effective_open_date = open_date

    def domain_values(record, field):
        values = [record]
        for part in field.split("."):
            values = [
                child
                for value in values
                for child in (
                    list(getattr(value, part, []))
                    if isinstance(getattr(value, part, None), list)
                    else [getattr(value, part, None)]
                )
            ]
        return values

    def normalize(value):
        return value.id if isinstance(value, Record) else value

    def matches(record, domain):
        for field, operator, expected in domain:
            values = [normalize(item) for item in domain_values(record, field)]
            if operator == "=" and not any(
                value == expected for value in values
            ):
                return False
            if operator == "not in" and any(
                value in expected for value in values
            ):
                return False
            if operator == ">" and not any(
                value is not None and value > expected for value in values
            ):
                return False
            if operator == "<=" and not any(
                value is not None and value <= expected for value in values
            ):
                return False
        return True

    def search(model, domain, *_args, **kwargs):
        flags["searches"].append((model, list(domain)))
        flags["events"].append(("search", model))
        if model == "account.partial.reconcile":
            return [Record(id=999)] if flags["partial"] else []
        if model == "account.bank.statement":
            candidates = list(flags["statement_candidates"])
            if flags["later_statement"]:
                candidates.append(
                    Record(
                        id=50,
                        company_id=company,
                        journal_id=journal,
                        date=statement.date,
                        first_line_index=LATER_LINE_INDEX,
                        line_ids=[Record(id=51, state="posted")],
                    )
                )
            found = [item for item in candidates if matches(item, domain)]
            return found[: kwargs.get("limit")] if kwargs.get("limit") else found
        if model == "account.bank.statement.line":
            candidates = list(flags["line_candidates"])
            if flags["standalone_line"]:
                candidates.append(
                    Record(
                        id=50,
                        company_id=company,
                        journal_id=journal,
                        statement_id=False,
                        state="posted",
                        internal_index=LATER_LINE_INDEX,
                    )
                )
            found = [item for item in candidates if matches(item, domain)]
            return found[: kwargs.get("limit")] if kwargs.get("limit") else found
        return []

    handler.search_records = search
    handler._test_boundary_flags = flags
    return (
        handler,
        company,
        parameters,
        flags,
        statement,
        bank_line,
        move,
        debit_line,
    )


def test_bank_compensation_source_accepts_only_the_pristine_exact_graph():
    handler, company, parameters, _flags, statement, line, move, _move_line = (
        _source_harness()
    )

    source = handler._bank_statement_compensation_source(
        parameters, company
    )

    assert source[0] is statement
    assert source[1] == [line]
    assert source[2] == [move]
    assert {
        (model, record.id) for model, record in source[3]
    } == {
        ("account.bank.statement", 100),
        ("account.bank.statement.line", 101),
        ("account.move", 200),
        ("account.move.line", 201),
        ("account.move.line", 202),
    }


def test_bank_compensation_source_accepts_missing_optional_module_fields():
    (
        handler,
        company,
        parameters,
        _flags,
        _statement,
        _line,
        move,
        _move_line,
    ) = _source_harness()
    for move_line in move.line_ids:
        del move_line.asset_ids
        del move_line.deferred_start_date
        del move_line.deferred_end_date

    handler._bank_statement_compensation_source(parameters, company)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda context: context["parameters"].__setitem__(
                "expected_source_digest", "f" * 64
            ),
            "business binding",
        ),
        (
            lambda context: setattr(
                context["line"], "foreign_currency_id", Record(id=9)
            ),
            "foreign-currency",
        ),
        (
            lambda context: setattr(context["line"], "is_reconciled", True),
            "reconciled",
        ),
        (
            lambda context: setattr(
                context["line"], "payment_ids", [Record(id=77)]
            ),
            "paid",
        ),
        (
            lambda context: context["flags"].__setitem__("partial", True),
            "hidden reconciliation",
        ),
        (
            lambda context: setattr(
                context["move"], "tax_cash_basis_rec_id", Record(id=44)
            ),
            "unsupported state",
        ),
        (
            lambda context: setattr(
                context["move"], "payment_ids", [Record(id=45)]
            ),
            "unsupported state",
        ),
        (
            lambda context: context["flags"].__setitem__(
                "later_statement", True
            ),
            "checkpoint",
        ),
        (
            lambda context: context["flags"].__setitem__(
                "standalone_line", True
            ),
            "later posted",
        ),
        (
            lambda context: context["flags"].__setitem__("lock", True),
            "violates lock",
        ),
        (
            lambda context: setattr(
                context["move_line"], "account_id", Record(id=999)
            ),
            "account pair",
        ),
        (
            lambda context: setattr(
                context["move_line"], "balance", "99"
            ),
            "balance differs",
        ),
        (
            lambda context: setattr(
                context["move_line"], "asset_ids", [Record(id=88)]
            ),
            "asset",
        ),
        (
            lambda context: setattr(
                context["move_line"],
                "deferred_start_date",
                date(2026, 7, 20),
            ),
            "deferred",
        ),
    ],
)
def test_bank_compensation_source_fails_closed_on_unsafe_graphs(
    mutation, match
):
    (
        handler,
        company,
        parameters,
        flags,
        _statement,
        line,
        move,
        move_line,
    ) = _source_harness()
    mutation(
        {
            "parameters": parameters,
            "flags": flags,
            "line": line,
            "move": move,
            "move_line": move_line,
        }
    )

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler._bank_statement_compensation_source(parameters, company)


def test_bank_boundary_uses_odoo_sequence_not_same_day_record_id():
    (
        handler,
        company,
        parameters,
        flags,
        statement,
        _line,
        _move,
        _move_line,
    ) = _source_harness()
    flags["later_statement"] = True

    with pytest.raises(OdooWriteHandlerError, match="later posted"):
        handler._bank_statement_compensation_source(parameters, company)

    statement_search = next(
        domain
        for model, domain in flags["searches"]
        if model == "account.bank.statement"
    )
    assert (
        "first_line_index",
        ">",
        statement.first_line_index,
    ) in statement_search
    assert not any(
        field == "date" or (field == "id" and operator == ">")
        for field, operator, _value in statement_search
    )


def test_bank_boundary_allows_historical_or_cancelled_orphan_lines():
    (
        handler,
        company,
        parameters,
        flags,
        _statement,
        line,
        _move,
        _move_line,
    ) = _source_harness()
    flags["line_candidates"] = [
        Record(
            id=999,
            company_id=company,
            journal_id=line.journal_id,
            statement_id=False,
            state="posted",
            internal_index=HISTORICAL_LINE_INDEX,
        ),
        Record(
            id=998,
            company_id=company,
            journal_id=line.journal_id,
            statement_id=False,
            state="cancel",
            internal_index=LATER_LINE_INDEX,
        ),
    ]

    handler._bank_statement_compensation_source(parameters, company)


def test_bank_boundary_rejects_later_posted_orphan_line_even_with_lower_id():
    (
        handler,
        company,
        parameters,
        flags,
        _statement,
        line,
        _move,
        _move_line,
    ) = _source_harness()
    flags["line_candidates"] = [
        Record(
            id=50,
            company_id=company,
            journal_id=line.journal_id,
            statement_id=False,
            state="posted",
            internal_index=LATER_LINE_INDEX,
        )
    ]

    with pytest.raises(OdooWriteHandlerError, match="later posted"):
        handler._bank_statement_compensation_source(parameters, company)


def _configure_recovery_precheck_stubs(handler):
    handler._approved_recovery_record_references = lambda *_args: []
    handler._current_recovery_record_references = lambda *_args, **_kwargs: []
    handler._validate_recovery_execution_guard = lambda *_args, **_kwargs: None
    handler._precheck_recovery_create_acl = lambda *_args, **_kwargs: None

    def snapshots(records, company, **_kwargs):
        result = []
        for model, record in records:
            values = {"bound_record_id": record.id}
            result.append(
                {
                    "model": model,
                    "record_id": record.id,
                    "company_id": company.id,
                    "state": str(
                        getattr(record, "state", "unknown") or "unknown"
                    ),
                    "values": values,
                    "values_digest": hashlib.sha256(
                        canonical_json(values)
                    ).hexdigest(),
                }
            )
        return sorted(
            result, key=lambda item: (item["model"], item["record_id"])
        )

    handler.snapshots = snapshots


def test_generic_and_specialized_bank_prechecks_strictly_lock_the_journal():
    handler, company, parameters, *_rest = _source_harness()
    _configure_recovery_precheck_stubs(handler)
    internal = handler._bank_statement_compensation_parameters(parameters)

    generic = handler.precheck_recovery(internal, company)
    specialized = handler.precheck_bank_statement_compensate(
        parameters, company
    )

    expected_before = {
        (item["model"], item["record_id"])
        for item in [*_plan()["action_targets"], *_plan()["guard_records"]]
    }
    for detail in (generic, specialized):
        assert {
            (item["model"], item["record_id"])
            for item in detail["before"]
        } == expected_before
        assert [
            (item["model"], item["record_id"])
            for item in detail["strict_dependencies"]
        ] == [("account.journal", JOURNAL_ID)]
        assert (
            "account.journal",
            [JOURNAL_ID],
            False,
        ) in _precheck_lock_targets(
            {"handler_details": detail},
            company_id=COMPANY_ID,
            exclusive_before=True,
        )


def _result_harness():
    (
        handler,
        company,
        parameters,
        _flags,
        source_statement,
        source_line,
        _source_move,
        _source_move_line,
    ) = _source_harness()
    source_records = handler._bank_statement_compensation_source(
        parameters, company
    )[3]
    journal = source_statement.journal_id
    currency = source_statement.currency_id
    partner = source_line.partner_id
    statement = Record(
        id=300,
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        date=parameters["compensation_date"],
        reference=parameters["reason"],
        balance_start="100",
        balance_end="0",
        balance_end_real="0",
        is_complete=True,
        is_valid=True,
        first_line_index=COMPENSATION_LINE_INDEX,
        line_ids=[],
    )
    bank_line = Record(
        id=301,
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        date=parameters["compensation_date"],
        amount="-100",
        amount_currency="0",
        payment_ref=parameters["reason"],
        ref="Recovery of bank line 101",
        partner_id=partner,
        foreign_currency_id=False,
        is_reconciled=False,
        payment_ids=[],
        statement_id=statement,
        state="posted",
        internal_index=COMPENSATION_LINE_INDEX,
    )
    move = Record(
        id=400,
        state="posted",
        move_type="entry",
        company_id=company,
        journal_id=journal,
        currency_id=currency,
        partner_id=partner,
        date=parameters["compensation_date"],
        statement_line_id=bank_line,
        statement_line_ids=[bank_line],
        line_ids=[],
    )
    bank_line.move_id = move

    def result_line(record_id, account, debit, credit, balance):
        return Record(
            id=record_id,
            move_id=move,
            company_id=company,
            account_id=account,
            currency_id=currency,
            partner_id=partner,
            parent_state="posted",
            debit=debit,
            credit=credit,
            balance=balance,
            amount_currency=balance,
            reconciled=False,
            full_reconcile_id=False,
            matched_debit_ids=[],
            matched_credit_ids=[],
            payment_id=False,
            statement_line_id=bank_line,
            statement_id=statement,
            tax_ids=[],
            tax_line_id=False,
            tax_tag_ids=[],
            tax_repartition_line_id=False,
            analytic_distribution=False,
            analytic_line_ids=[],
            asset_ids=[],
            deferred_start_date=False,
            deferred_end_date=False,
            reconciled_lines_ids=[],
            reconciled_lines_excluding_exchange_diff_ids=[],
        )

    liquidity_line = result_line(
        401, journal.default_account_id, "0", "100", "-100"
    )
    suspense_line = result_line(
        402, journal.suspense_account_id, "100", "0", "100"
    )
    move.line_ids = [liquidity_line, suspense_line]
    statement.line_ids = [bank_line]
    records = [
        *source_records,
        ("account.bank.statement", statement),
        ("account.bank.statement.line", bank_line),
        ("account.move", move),
        ("account.move.line", liquidity_line),
        ("account.move.line", suspense_line),
    ]
    record_map = {
        (model_name, record.id): record
        for model_name, record in records
    }
    source_record = handler.record
    handler.record = lambda model, record_id, *args, **kwargs: (
        record_map.get((model, record_id))
        or source_record(model, record_id, *args, **kwargs)
    )
    return (
        handler,
        company,
        parameters,
        records,
        statement,
        bank_line,
        move,
        liquidity_line,
    )


def test_bank_compensation_result_requires_exact_two_line_account_graph():
    handler, company, parameters, records, *_rest = _result_harness()

    handler._assert_bank_statement_compensation_result(
        parameters, company, records
    )


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda context: setattr(
                context["bank_line"], "amount_currency", "1"
            ),
            "FX",
        ),
        (
            lambda context: setattr(
                context["move"], "partner_id", Record(id=999)
            ),
            "unsupported identity",
        ),
        (
            lambda context: setattr(context["move"], "statement_line_ids", []),
            "unsupported identity",
        ),
        (
            lambda context: setattr(
                context["move_line"], "account_id", Record(id=999)
            ),
            "account pair",
        ),
        (
            lambda context: setattr(
                context["move_line"], "balance", "-99"
            ),
            "balance differs",
        ),
        (
            lambda context: setattr(
                context["move_line"], "tax_ids", [Record(id=55)]
            ),
            "external effects",
        ),
    ],
)
def test_bank_compensation_result_rejects_wrong_account_amount_or_links(
    mutation, match
):
    (
        handler,
        company,
        parameters,
        records,
        _statement,
        bank_line,
        move,
        move_line,
    ) = _result_harness()
    mutation(
        {
            "bank_line": bank_line,
            "move": move,
            "move_line": move_line,
        }
    )

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler._assert_bank_statement_compensation_result(
            parameters, company, records
        )


def _generic_recovery_execution_inputs(handler, company, parameters):
    handler._current_recovery_record_references = lambda *_args, **_kwargs: []
    handler._validate_recovery_execution_guard = lambda *_args, **_kwargs: None
    planned_records = handler._recovery_records_by_role(
        handler.context.trusted_recovery_plan, company
    )[2]
    checked = {
        "before": [
            {"model": model, "record_id": record.id}
            for model, record in planned_records
        ]
    }
    return handler._bank_statement_compensation_parameters(parameters), checked


def test_generic_recovery_rechecks_bank_boundary_immediately_before_action(
    monkeypatch,
):
    handler, company, parameters, flags, *_rest = _source_harness()
    internal, checked = _generic_recovery_execution_inputs(
        handler, company, parameters
    )
    flags["standalone_line"] = True
    called = False

    def action(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("the ORM action must not start")

    monkeypatch.setattr(handlers_module, "execute_recovery_action", action)

    with pytest.raises(OdooWriteHandlerError, match="later posted"):
        handler.execute_recovery(internal, company, checked)

    assert called is False
    assert flags["events"][0] == (
        "lock",
        _bank_statement_sequence_lock_digest(COMPANY_ID, JOURNAL_ID),
    )
    assert flags["events"][1] == ("invalidate", None)
    assert flags["events"].index(
        ("search", "account.bank.statement")
    ) > 1


def test_post_action_bank_phantom_aborts_and_savepoint_rolls_back(
    monkeypatch,
):
    (
        handler,
        company,
        parameters,
        result_records,
        *_rest,
    ) = _result_harness()
    flags = handler._test_boundary_flags
    internal, checked = _generic_recovery_execution_inputs(
        handler, company, parameters
    )
    database_writes = []

    @contextmanager
    def savepoint():
        original = list(database_writes)
        try:
            yield
        except Exception:
            database_writes[:] = original
            raise

    def action(*_args, **_kwargs):
        database_writes.append("compensating_statement")
        flags["line_candidates"] = [
            Record(
                id=50,
                company_id=company,
                journal_id=Record(id=JOURNAL_ID),
                statement_id=False,
                state="posted",
                internal_index=LATER_LINE_INDEX,
            )
        ]
        return RecoveryActionResult(
            records=tuple(result_records),
            tombstones=frozenset(),
            checks=("compensating_bank_statement_posted",),
        )

    monkeypatch.setattr(handlers_module, "execute_recovery_action", action)

    with pytest.raises(OdooWriteHandlerError, match="later posted"):
        with savepoint():
            handler.execute_recovery(internal, company, checked)

    assert database_writes == []


def test_execution_rejects_an_interleaved_returned_line_before_commit(
    monkeypatch,
):
    (
        handler,
        company,
        parameters,
        result_records,
        *_rest,
    ) = _result_harness()
    flags = handler._test_boundary_flags
    internal, checked = _generic_recovery_execution_inputs(
        handler, company, parameters
    )
    inserted = Record(
        id=998,
        company_id=company,
        journal_id=Record(id=JOURNAL_ID),
        statement_id=False,
        state="posted",
        internal_index=LATER_LINE_INDEX,
    )

    def action(*_args, **_kwargs):
        flags["line_candidates"] = [inserted]
        return RecoveryActionResult(
            records=(
                *result_records,
                ("account.bank.statement.line", inserted),
            ),
            tombstones=frozenset(),
            checks=("compensating_bank_statement_posted",),
        )

    monkeypatch.setattr(handlers_module, "execute_recovery_action", action)

    with pytest.raises(
        OdooWriteHandlerError, match="between source and compensation"
    ):
        handler.execute_recovery(internal, company, checked)


def test_bank_recovery_rejects_a_journal_change_after_sequence_lock(
    monkeypatch,
):
    (
        handler,
        company,
        parameters,
        flags,
        statement,
        *_rest,
    ) = _source_harness()
    internal, checked = _generic_recovery_execution_inputs(
        handler, company, parameters
    )
    flags["on_invalidate"] = lambda: setattr(
        statement,
        "journal_id",
        Record(id=3, company_id=company),
    )
    called = False

    def action(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("the ORM action must not start")

    monkeypatch.setattr(handlers_module, "execute_recovery_action", action)

    with pytest.raises(OdooWriteHandlerError, match="journal changed"):
        handler.execute_recovery(internal, company, checked)

    assert called is False
    assert flags["events"][:2] == [
        (
            "lock",
            _bank_statement_sequence_lock_digest(
                COMPANY_ID, JOURNAL_ID
            ),
        ),
        ("invalidate", None),
    ]


def test_bank_restart_verification_allows_later_activity_with_backfilled_date(
    monkeypatch,
):
    (
        handler,
        company,
        parameters,
        records,
        _statement,
        _line,
        _move,
        _move_line,
    ) = _result_harness()
    flags = handler._test_boundary_flags
    internal = handler._bank_statement_compensation_parameters(parameters)
    flags["events"].clear()
    flags["searches"].clear()
    oracle_calls = []

    def exact_oracle(*_args, **_kwargs):
        oracle_calls.append(True)
        flags["events"].append(("oracle", None))
        return ("bank_exact",)

    monkeypatch.setattr(
        handlers_module, "verify_recovery_action", exact_oracle
    )
    flags["line_candidates"] = [
        Record(
            id=999,
            company_id=company,
            journal_id=Record(id=JOURNAL_ID),
            statement_id=False,
            state="posted",
            internal_index=AFTER_COMPENSATION_LINE_INDEX,
        )
    ]

    checks = handler.verify_recovery(
        internal, company, records, before=_bank_before_values()
    )

    assert "bank_exact" in checks
    assert oracle_calls == [True]
    lock_index = flags["events"].index(
        (
            "lock",
            _bank_statement_sequence_lock_digest(
                COMPANY_ID, JOURNAL_ID
            ),
        )
    )
    oracle_index = flags["events"].index(("oracle", None))
    assert lock_index < oracle_index
    assert not any(
        model
        in {"account.bank.statement", "account.bank.statement.line"}
        for model, _domain in flags["searches"]
    )

    flags["events"].clear()
    flags["searches"].clear()
    flags["line_candidates"] = [
        Record(
            id=998,
            company_id=company,
            journal_id=Record(id=JOURNAL_ID),
            statement_id=False,
            state="posted",
            internal_index=LATER_LINE_INDEX,
        )
    ]
    checks = handler.verify_recovery(
        internal,
        company,
        records,
        before=_bank_before_values(),
    )

    assert "bank_exact" in checks
    assert oracle_calls == [True, True]
    assert flags["events"][0] == (
        "lock",
        _bank_statement_sequence_lock_digest(COMPANY_ID, JOURNAL_ID),
    )
    assert not any(
        model
        in {"account.bank.statement", "account.bank.statement.line"}
        for model, _domain in flags["searches"]
    )


def test_bank_compensation_maps_date_only_inside_the_recovery_facade(
    monkeypatch,
):
    plan = _plan()
    parameters = _parameters(plan)
    original = dict(parameters)
    company = Record(id=COMPANY_ID)
    handler = object.__new__(OdooWriteHandlers)
    handler.context = SimpleNamespace(
        trusted_recovery_plan=plan,
        module_graph=SimpleNamespace(digest=MODULE_GRAPH_DIGEST),
    )
    observed: list[dict[str, object]] = []
    result = ([], {"status": "not_applicable"}, frozenset())

    def execute(internal, *_args):
        observed.append(dict(internal))
        return result

    handler.execute_recovery = execute
    handler.trusted_before_values = lambda *_args: _bank_before_values()
    handler._assert_bank_statement_compensation_result = lambda *_args: None

    def verify(internal, *_args):
        observed.append(dict(internal))
        return ["bank_exact"]

    handler.verify_recovery = verify

    assert handler.execute_bank_statement_compensate(
        parameters, company, {"before": []}
    ) == result
    assert parameters == original
    assert "recovery_date" not in parameters
    assert observed[0]["recovery_date"] == parameters["compensation_date"]
    assert "compensation_date" not in observed[0]


def test_bank_compensation_exact_oracle_failure_aborts_execution(
    monkeypatch,
):
    handler, company, parameters, records, *_rest = _result_harness()
    handler.execute_recovery = lambda *_args: (
        records,
        {"status": "not_applicable"},
        frozenset(),
    )
    handler.trusted_before_values = lambda *_args: _bank_before_values()

    def reject(*_args, **_kwargs):
        raise RecoveryVerificationError("wrong bank accounts")

    monkeypatch.setattr(handlers_module, "verify_recovery_action", reject)

    with pytest.raises(
        OdooWriteHandlerError,
        match="fresh recovery verification failed closed",
    ):
        handler.execute_bank_statement_compensate(
            parameters, company, {"before": []}
        )
