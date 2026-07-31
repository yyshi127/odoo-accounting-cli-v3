from __future__ import annotations

from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.recovery_actions import (
    FAIL_CLOSED_RECOVERY_METHODS,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlerError,
    OdooWriteHandlers,
)
from test_odoo_write_handlers import Harness, Model, Record, company


_MISSING = object()


class NoOrmHarness(Harness):
    """Fail if a boundary check reaches an ORM-facing handler method."""

    def __init__(self, *, recovery_plan=None):
        super().__init__(recovery_plan=recovery_plan)
        self.orm_calls: list[str] = []

    def _unexpected_orm(self, name: str):
        self.orm_calls.append(name)
        raise AssertionError(f"{name} was reached before the fail-closed guard")

    def bound_model(self, *args, **kwargs):
        return self._unexpected_orm("bound_model")

    def create_model(self, *args, **kwargs):
        return self._unexpected_orm("create_model")

    def record(self, *args, **kwargs):
        return self._unexpected_orm("record")

    def search_records(self, *args, **kwargs):
        return self._unexpected_orm("search_records")


@pytest.mark.parametrize(
    ("method_name", "message"),
    (
        ("precheck_payment", "payment registration is fail-closed"),
        ("precheck_deferred", "deferred generation is fail-closed"),
    ),
)
def test_dormant_writes_fail_closed_before_any_orm(method_name, message):
    handler = NoOrmHarness()

    with pytest.raises(OdooWriteHandlerError, match=message):
        getattr(handler, method_name)({}, handler.test_company)

    assert handler.orm_calls == []


def _reconciliation_parameters(**overrides):
    parameters = {
        "tolerance_amount": "0",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
    }
    parameters.update(overrides)
    return parameters


@pytest.mark.parametrize("phase", ("precheck", "execute"))
@pytest.mark.parametrize(
    "overrides",
    (
        {"tolerance_amount": "0.01"},
        {"writeoff_account_id": 91},
        {"writeoff_journal_id": 92},
        {"writeoff_label": "Approved difference"},
    ),
    ids=(
        "nonzero-tolerance",
        "writeoff-account",
        "writeoff-journal",
        "writeoff-label",
    ),
)
def test_reconciliation_writeoff_inputs_fail_closed_before_any_orm(
    phase, overrides
):
    handler = NoOrmHarness()
    parameters = _reconciliation_parameters(**overrides)

    with pytest.raises(OdooWriteHandlerError, match="write-off is fail-closed"):
        if phase == "precheck":
            handler.precheck_reconciliation(parameters, handler.test_company)
        else:
            handler.execute_reconciliation(
                parameters, handler.test_company, {}
            )

    assert handler.orm_calls == []


@pytest.mark.parametrize(
    ("account_type", "reconcile"),
    (
        pytest.param("asset_receivable", False, id="receivable"),
        pytest.param("liability_payable", False, id="payable"),
        pytest.param("off_balance", False, id="off-balance"),
        pytest.param("asset_cash", False, id="cash"),
        pytest.param(
            "liability_credit_card", False, id="credit-card"
        ),
        pytest.param("asset_current", True, id="reconcile-enabled"),
        pytest.param(_MISSING, False, id="missing-account-type"),
        pytest.param("expense", _MISSING, id="missing-reconcile"),
    ),
)
def test_reversal_safe_account_helper_rejects_unsafe_or_incomplete_accounts(
    account_type, reconcile
):
    values = {}
    if account_type is not _MISSING:
        values["account_type"] = account_type
    if reconcile is not _MISSING:
        values["reconcile"] = reconcile
    account = SimpleNamespace(**values)

    with pytest.raises(OdooWriteHandlerError, match="unapproved"):
        OdooWriteHandlers.assert_reversal_safe_account(
            account, label="move reversal"
        )


def _reversal_precheck_fixture(*, account_type, reconcile):
    bound_company = company()
    currency = Record(
        1, company_id=bound_company, active=True, rounding="0.01"
    )
    journal = Record(
        2,
        company_id=bound_company,
        type="general",
        active=True,
        currency_id=currency,
    )
    account_values = {
        "company_id": bound_company,
        "deprecated": False,
    }
    if account_type is not _MISSING:
        account_values["account_type"] = account_type
    if reconcile is not _MISSING:
        account_values["reconcile"] = reconcile
    account = Record(10, **account_values)
    line = Record(
        1003,
        company_id=bound_company,
        parent_state="posted",
        account_id=account,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        asset_ids=[],
        deferred_start_date=None,
        deferred_end_date=None,
    )
    move = Record(
        1001,
        company_id=bound_company,
        state="posted",
        move_type="entry",
        journal_id=journal,
        currency_id=currency,
        amount_total=100,
        line_ids=SimpleNamespace(ids=[line.id]),
        statement_line_id=None,
        statement_id=None,
        asset_id=None,
        deferred_move_ids=[],
        deferred_original_move_ids=[],
        tax_cash_basis_rec_id=None,
        tax_cash_basis_origin_move_id=None,
        reversed_entry_id=None,
        reversal_move_ids=[],
    )
    line.move_id = move
    handler = Harness(
        models={"account.move.reversal": Model()},
        records={
            ("account.move", move.id): move,
            ("account.move.line", line.id): line,
            ("account.journal", journal.id): journal,
            ("res.currency", currency.id): currency,
            ("account.account", account.id): account,
        },
    )
    handler.test_company = bound_company
    parameters = {
        "move_id": move.id,
        "reversal_date": "2026-07-10",
        "journal_id": journal.id,
        "currency_id": currency.id,
        "expected_total_amount": "100",
        "reason": "correct approved entry",
        "posting_mode": "post",
    }
    return handler, bound_company, parameters


@pytest.mark.parametrize(
    ("account_type", "reconcile"),
    (
        pytest.param("asset_receivable", False, id="receivable"),
        pytest.param("liability_payable", False, id="payable"),
        pytest.param("off_balance", False, id="off-balance"),
        pytest.param("asset_cash", False, id="cash"),
        pytest.param(
            "liability_credit_card", False, id="credit-card"
        ),
        pytest.param("asset_current", True, id="reconcile-enabled"),
        pytest.param(_MISSING, False, id="missing-account-type"),
        pytest.param("expense", _MISSING, id="missing-reconcile"),
    ),
)
def test_reversal_precheck_rejects_unsafe_or_incomplete_accounts(
    account_type, reconcile
):
    handler, bound_company, parameters = _reversal_precheck_fixture(
        account_type=account_type, reconcile=reconcile
    )

    with pytest.raises(OdooWriteHandlerError, match="unapproved"):
        handler.precheck_reversal(parameters, bound_company)


@pytest.mark.parametrize(
    "account_type", ("expense", "liability_current")
)
def test_reversal_helper_and_precheck_allow_explicitly_safe_accounts(
    account_type,
):
    handler, bound_company, parameters = _reversal_precheck_fixture(
        account_type=account_type, reconcile=False
    )
    account = handler.records[("account.account", 10)]

    OdooWriteHandlers.assert_reversal_safe_account(
        account, label="move reversal"
    )
    checked = handler.precheck_reversal(parameters, bound_company)

    assert "reversal_safe_accounts" in checked["checks"]
    assert {
        (snapshot["model"], snapshot["record_id"])
        for snapshot in checked["dependencies"]
        if snapshot["model"] == "account.account"
    } == {("account.account", 10)}


@pytest.mark.parametrize(
    ("field", "value"),
    (
        pytest.param("tax_tag_ids", [Record(91)], id="tax-tags"),
        pytest.param(
            "tax_repartition_line_id",
            Record(92),
            id="tax-repartition",
        ),
        pytest.param("tax_base_amount", "1", id="tax-base"),
        pytest.param(
            "analytic_distribution",
            {"44": 100},
            id="analytic-distribution",
        ),
        pytest.param(
            "analytic_line_ids", [Record(93)], id="analytic-lines"
        ),
        pytest.param("product_id", Record(94), id="product"),
        pytest.param("date_maturity", "2026-08-01", id="maturity"),
        pytest.param("sale_line_ids", [Record(95)], id="sale-line"),
        pytest.param("purchase_line_id", Record(96), id="purchase-line"),
    ),
)
def test_move_reversal_plain_line_oracle_rejects_extension_graphs(
    field, value
):
    handler, bound_company, _parameters = _reversal_precheck_fixture(
        account_type="expense", reconcile=False
    )
    move = handler.records[("account.move", 1001)]
    line = handler.records[("account.move.line", 1003)]
    setattr(line, field, value)

    with pytest.raises(OdooWriteHandlerError, match="external business"):
        handler.assert_reversal_safe_line(
            line,
            move,
            bound_company,
            label="move reversal",
            allow_line_reference=True,
        )


def test_move_reversal_created_line_rejects_copied_v3_line_reference():
    handler, bound_company, _parameters = _reversal_precheck_fixture(
        account_type="expense", reconcile=False
    )
    move = handler.records[("account.move", 1001)]
    line = handler.records[("account.move.line", 1003)]
    line.odoo_cli_v3_line_reference = "must-not-be-copied"

    with pytest.raises(OdooWriteHandlerError, match="lineage"):
        handler.assert_reversal_safe_line(
            line,
            move,
            bound_company,
            label="created reversal",
            allow_line_reference=False,
        )


def test_move_reversal_precheck_rejects_storno_company_before_wizard():
    handler, bound_company, parameters = _reversal_precheck_fixture(
        account_type="expense", reconcile=False
    )
    bound_company.account_storno = True

    with pytest.raises(OdooWriteHandlerError, match="non-storno"):
        handler.precheck_reversal(parameters, bound_company)

    assert handler.models["account.move.reversal"].access == []


def test_move_reversal_execute_rechecks_line_graph_before_wizard():
    handler, bound_company, parameters = _reversal_precheck_fixture(
        account_type="expense", reconcile=False
    )
    line = handler.records[("account.move.line", 1003)]
    line.analytic_distribution = {"44": 100}

    with pytest.raises(OdooWriteHandlerError, match="external business"):
        handler.execute_reversal(
            parameters,
            bound_company,
            {"before": []},
        )

    assert handler.models["account.move.reversal"].creates == []


def _period_precheck_fixture(*, account_type, reconcile):
    bound_company = company()
    currency = Record(
        1, company_id=bound_company, active=True, rounding="0.01"
    )
    journal = Record(
        2,
        company_id=bound_company,
        type="general",
        active=True,
        currency_id=currency,
    )
    account_values = {
        "company_id": bound_company,
        "deprecated": False,
    }
    if account_type is not _MISSING:
        account_values["account_type"] = account_type
    if reconcile is not _MISSING:
        account_values["reconcile"] = reconcile
    first_account = Record(10, **account_values)
    second_account = Record(
        11,
        company_id=bound_company,
        deprecated=False,
        account_type="liability_current",
        reconcile=False,
    )
    handler = Harness(
        models={
            "account.move": Model(),
            "account.move.reversal": Model(),
        },
        records={
            ("res.currency", currency.id): currency,
            ("account.journal", journal.id): journal,
            ("account.account", first_account.id): first_account,
            ("account.account", second_account.id): second_account,
        },
    )
    handler.test_company = bound_company
    parameters = {
        "company_id": bound_company.id,
        "journal_id": journal.id,
        "currency_id": currency.id,
        "posting_date": "2026-07-10",
        "period_end_date": "2026-07-31",
        "reference": "PERIOD-SAFETY-1",
        "reason": "Verify reversal-safe account boundary",
        "posting_mode": "post",
        "reversal_date": "2026-08-01",
        "lines": [
            {
                "line_reference": "period-debit",
                "name": "Period debit",
                "account_id": first_account.id,
                "partner_id": None,
                "side": "debit",
                "amount": "100",
                "currency_id": currency.id,
                "amount_currency": "100",
                "tax_ids": [],
            },
            {
                "line_reference": "period-credit",
                "name": "Period credit",
                "account_id": second_account.id,
                "partner_id": None,
                "side": "credit",
                "amount": "100",
                "currency_id": currency.id,
                "amount_currency": "-100",
                "tax_ids": [],
            },
        ],
    }
    return handler, bound_company, parameters


@pytest.mark.parametrize(
    "precheck_name", ("precheck_accrual", "precheck_adjustment")
)
@pytest.mark.parametrize(
    ("account_type", "reconcile"),
    (
        pytest.param("asset_receivable", False, id="receivable"),
        pytest.param("liability_payable", False, id="payable"),
        pytest.param("off_balance", False, id="off-balance"),
        pytest.param("asset_cash", False, id="cash"),
        pytest.param(
            "liability_credit_card", False, id="credit-card"
        ),
        pytest.param("asset_current", True, id="reconcile-enabled"),
        pytest.param(_MISSING, False, id="missing-account-type"),
        pytest.param("expense", _MISSING, id="missing-reconcile"),
    ),
)
def test_period_entry_prechecks_reject_unsafe_or_incomplete_accounts(
    precheck_name, account_type, reconcile
):
    handler, bound_company, parameters = _period_precheck_fixture(
        account_type=account_type, reconcile=reconcile
    )

    with pytest.raises(OdooWriteHandlerError, match="unapproved"):
        getattr(handler, precheck_name)(parameters, bound_company)


@pytest.mark.parametrize(
    "precheck_name", ("precheck_accrual", "precheck_adjustment")
)
def test_period_entry_prechecks_bind_explicitly_safe_accounts(
    precheck_name,
):
    handler, bound_company, parameters = _period_precheck_fixture(
        account_type="expense", reconcile=False
    )

    checked = getattr(handler, precheck_name)(parameters, bound_company)

    assert "reversal_safe_accounts" in checked["checks"]
    assert {
        (snapshot["model"], snapshot["record_id"])
        for snapshot in checked["dependencies"]
        if snapshot["model"] == "account.account"
    } == {
        ("account.account", 10),
        ("account.account", 11),
    }


@pytest.mark.parametrize(
    "method", sorted(FAIL_CLOSED_RECOVERY_METHODS)
)
def test_blocked_recovery_execute_fails_before_any_orm_or_mutation(method):
    handler = NoOrmHarness(
        recovery_plan={"method": method, "action_targets": []}
    )

    with pytest.raises(OdooWriteHandlerError, match="fail-closed"):
        handler.execute_recovery({}, handler.test_company, {})

    assert handler.orm_calls == []


def test_writeoff_recovery_execute_fails_before_any_orm_or_mutation():
    handler = NoOrmHarness(
        recovery_plan={
            "method": "undo_reconciliation_without_writeoff_v1",
            "action_targets": [
                {"model": "account.move", "record_id": 901}
            ],
        }
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match="write-off recovery is fail-closed",
    ):
        handler.execute_recovery({}, handler.test_company, {})

    assert handler.orm_calls == []
