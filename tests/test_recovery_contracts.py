from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import inspect

import pytest

from odoo_accounting_cli_v3.recovery_contracts import (
    EXECUTABLE_RECOVERY_METHODS,
    RECOVERY_ACTION_CONTRACTS,
    RecoveryActionContract,
    RecoveryContractError,
    _build_contract_catalog,
    contracts_for_capability,
    select_recovery_action_contract,
)


EXPECTED = {
    "cancel_pristine_v3_draft_customer_invoice_v1": (
        "acct.invoice.customer_create.v1",
        "cancel_pristine_v3_draft_customer_invoice_exact_v1",
    ),
    "reverse_posted_customer_invoice_v1": (
        "acct.invoice.customer_create.v1",
        "reverse_posted_customer_invoice_exact_v1",
    ),
    "cancel_pristine_v3_draft_vendor_bill_v1": (
        "acct.bill.vendor_create.v1",
        "cancel_pristine_v3_draft_vendor_bill_exact_v1",
    ),
    "reverse_posted_vendor_bill_v1": (
        "acct.bill.vendor_create.v1",
        "reverse_posted_vendor_bill_exact_v1",
    ),
    "cancel_draft_refund_v1": (
        "acct.refund.create.v1",
        "cancel_draft_refund_exact_v1",
    ),
    "reverse_posted_refund_v1": (
        "acct.refund.create.v1",
        "reverse_posted_refund_exact_v1",
    ),
    "cancel_and_unreconcile_payment_v1": (
        "acct.payment.register.v1",
        "cancel_and_unreconcile_payment_exact_v1",
    ),
    "post_compensating_bank_statement_v1": (
        "acct.bank.statement_import.v1",
        "post_compensating_bank_statement_exact_v1",
    ),
    "undo_reconciliation_and_reverse_writeoff_v1": (
        "acct.reconciliation.apply.v1",
        "undo_reconciliation_and_reverse_writeoff_exact_v1",
    ),
    "cancel_asset_and_reverse_schedule_v1": (
        "acct.asset.create.v1",
        "cancel_asset_and_reverse_schedule_exact_v1",
    ),
    "reverse_depreciation_and_restore_schedule_v1": (
        "acct.depreciation.post.v1",
        "reverse_depreciation_and_restore_schedule_exact_v1",
    ),
    "cancel_scheduled_and_reverse_accrual_origin_v1": (
        "acct.accrual.create.v1",
        "cancel_scheduled_and_reverse_accrual_origin_exact_v1",
    ),
    "reverse_deferred_source_and_schedule_v1": (
        "acct.deferred.create.v1",
        "reverse_deferred_source_and_schedule_exact_v1",
    ),
    "cancel_draft_period_adjustment_v1": (
        "acct.period.adjustment_create.v1",
        "cancel_draft_period_adjustment_exact_v1",
    ),
    "reverse_posted_period_adjustment_v1": (
        "acct.period.adjustment_create.v1",
        "reverse_posted_period_adjustment_exact_v1",
    ),
    "reverse_the_reversal_v1": (
        "acct.move.reverse.v1",
        "reverse_the_reversal_exact_v1",
    ),
}

EXPECTED_BY_CAPABILITY = {
    capability_id: tuple(
        sorted(
            method
            for method, (origin, _oracle) in EXPECTED.items()
            if origin == capability_id
        )
    )
    for capability_id in {origin for origin, _oracle in EXPECTED.values()}
}

EXPECTED_ENTRY_REVERSAL_GUARD_OUTCOMES = {
    "reverse_posted_period_adjustment_v1": frozenset(
        {"survive_allowed_delta"}
    ),
    "reverse_the_reversal_v1": frozenset(
        {"survive_exact", "survive_allowed_delta"}
    ),
    "cancel_scheduled_and_reverse_accrual_origin_v1": frozenset(
        {"survive_allowed_delta"}
    ),
    "reverse_depreciation_and_restore_schedule_v1": frozenset(
        {"survive_exact", "survive_allowed_delta"}
    ),
}


def _base_contract(**changes):
    values = {
        "origin_capability_id": "acct.invoice.customer_create.v1",
        "method": "example_recovery_v1",
        "oracle_id": "example_recovery_exact_v1",
        "action_models": frozenset({"account.move"}),
        "guard_models": frozenset({"account.move.line"}),
        "result_models": frozenset({"account.move", "account.move.line"}),
        "allowed_guard_outcomes": frozenset({"survive_exact"}),
    }
    values.update(changes)
    return RecoveryActionContract(**values)


def test_catalog_has_the_exact_declared_contracts():
    assert len(RECOVERY_ACTION_CONTRACTS) == 16
    assert set(RECOVERY_ACTION_CONTRACTS) == set(EXPECTED)
    assert EXECUTABLE_RECOVERY_METHODS == frozenset(EXPECTED)


def test_catalog_mapping_is_immutable():
    with pytest.raises(TypeError):
        RECOVERY_ACTION_CONTRACTS["forged_v1"] = _base_contract()


@pytest.mark.parametrize("method", sorted(EXPECTED))
def test_exact_selection_returns_the_registered_frozen_contract(method):
    capability_id, oracle_id = EXPECTED[method]

    contract = select_recovery_action_contract(
        capability_id, method, oracle_id
    )

    assert contract is RECOVERY_ACTION_CONTRACTS[method]
    assert contract.origin_capability_id == capability_id
    assert contract.method == method
    assert contract.oracle_id == oracle_id


@pytest.mark.parametrize("method", sorted(EXPECTED))
def test_each_contract_is_nonproduction_and_test_sandbox_only(method):
    contract = RECOVERY_ACTION_CONTRACTS[method]

    assert contract.production_promotion_allowed is False
    assert contract.allowed_environments == frozenset({"test", "sandbox"})
    with pytest.raises(FrozenInstanceError):
        contract.method = "forged_v1"


@pytest.mark.parametrize("method", sorted(EXPECTED))
def test_each_contract_has_nonempty_account_model_closures(method):
    contract = RECOVERY_ACTION_CONTRACTS[method]

    for models in (
        contract.action_models,
        contract.guard_models,
        contract.result_models,
    ):
        assert type(models) is frozenset
        assert models
        assert all(model.startswith("account.") for model in models)
        assert all(model == model.strip().lower() for model in models)


@pytest.mark.parametrize("method", sorted(EXPECTED))
def test_each_contract_uses_only_executable_v2_guard_outcomes(method):
    outcomes = RECOVERY_ACTION_CONTRACTS[method].allowed_guard_outcomes

    assert type(outcomes) is frozenset
    assert outcomes
    assert outcomes <= frozenset(
        {"survive_exact", "survive_allowed_delta", "absent"}
    )
    assert "manual_review" not in outcomes
    assert "exact" not in outcomes
    assert "allowed_delta" not in outcomes


@pytest.mark.parametrize(
    ("method", "expected_outcomes"),
    sorted(EXPECTED_ENTRY_REVERSAL_GUARD_OUTCOMES.items()),
)
def test_entry_reversal_contracts_allow_only_their_required_guard_outcomes(
    method, expected_outcomes
):
    assert (
        RECOVERY_ACTION_CONTRACTS[method].allowed_guard_outcomes
        == expected_outcomes
    )


@pytest.mark.parametrize(
    ("capability_id", "methods"),
    sorted(EXPECTED_BY_CAPABILITY.items()),
)
def test_contracts_for_capability_is_complete_and_stably_sorted(
    capability_id, methods
):
    contracts = contracts_for_capability(capability_id)

    assert type(contracts) is tuple
    assert tuple(contract.method for contract in contracts) == methods
    assert contracts == tuple(
        sorted(contracts, key=lambda item: (item.method, item.oracle_id))
    )


@pytest.mark.parametrize(
    "capability_id",
    [
        "acct.move.draft_cancel.v1",
        "acct.refund.draft_cancel.v1",
        "acct.recovery.execute.v1",
    ],
)
def test_terminal_capabilities_have_no_follow_on_executable_recovery(
    capability_id,
):
    assert contracts_for_capability(capability_id) == ()
    assert all(
        contract.origin_capability_id != capability_id
        for contract in RECOVERY_ACTION_CONTRACTS.values()
    )


@pytest.mark.parametrize(
    "capability_id",
    [
        "acct.invoice.customer_post.v1",
        "acct.bill.vendor_post.v1",
    ],
)
def test_document_post_requires_a_future_separate_credit_note_capability(
    capability_id,
):
    assert contracts_for_capability(capability_id) == ()
    assert all(
        contract.origin_capability_id != capability_id
        for contract in RECOVERY_ACTION_CONTRACTS.values()
    )


@pytest.mark.parametrize("method", sorted(EXPECTED))
@pytest.mark.parametrize(
    "mismatch",
    ["origin", "method", "oracle"],
)
def test_selection_rejects_every_single_field_mismatch_with_one_stable_error(
    method, mismatch
):
    capability_id, oracle_id = EXPECTED[method]
    values = {
        "origin": capability_id,
        "method": method,
        "oracle": oracle_id,
    }
    values[mismatch] = {
        "origin": "acct.move.draft_cancel.v1",
        "method": "unregistered_recovery_v1",
        "oracle": "unregistered_recovery_exact_v1",
    }[mismatch]

    with pytest.raises(
        RecoveryContractError,
        match=(
            "^recovery action contract does not match the requested origin, "
            "method, and oracle$"
        ),
    ):
        select_recovery_action_contract(
            values["origin"], values["method"], values["oracle"]
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("origin_capability_id", "", "origin_capability_id is invalid"),
        (
            "origin_capability_id",
            "acct.Invoice.customer_create.v1",
            "origin_capability_id is invalid",
        ),
        (
            "origin_capability_id",
            "acct.invoice.customer_create",
            "origin_capability_id is invalid",
        ),
        (
            "origin_capability_id",
            "acct.move.draft_cancel.v1",
            "terminal capabilities",
        ),
        (
            "origin_capability_id",
            "acct.recovery.execute.v1",
            "terminal capabilities",
        ),
        (
            "origin_capability_id",
            "acct.refund.draft_cancel.v1",
            "terminal capabilities",
        ),
        ("method", "", "recovery method is invalid"),
        ("method", "Cancel_move_v1", "recovery method is invalid"),
        ("method", "cancel-move-v1", "recovery method is invalid"),
        ("method", "cancel_move", "recovery method is invalid"),
        ("oracle_id", "", "recovery oracle_id is invalid"),
        ("oracle_id", "Oracle_v1", "recovery oracle_id is invalid"),
        ("oracle_id", "oracle", "recovery oracle_id is invalid"),
        ("action_models", set({"account.move"}), "action_models"),
        ("action_models", frozenset(), "action_models"),
        ("action_models", frozenset({"res.partner"}), "action_models"),
        ("guard_models", set({"account.move"}), "guard_models"),
        ("guard_models", frozenset(), "guard_models"),
        ("guard_models", frozenset({"ir.module.module"}), "guard_models"),
        ("result_models", set({"account.move"}), "result_models"),
        ("result_models", frozenset(), "result_models"),
        ("result_models", frozenset({"res.company"}), "result_models"),
        (
            "allowed_guard_outcomes",
            set({"survive_exact"}),
            "allowed_guard_outcomes",
        ),
        (
            "allowed_guard_outcomes",
            frozenset(),
            "allowed_guard_outcomes",
        ),
        (
            "allowed_guard_outcomes",
            frozenset({"manual_review"}),
            "allowed_guard_outcomes",
        ),
        (
            "allowed_guard_outcomes",
            frozenset({"exact"}),
            "allowed_guard_outcomes",
        ),
        (
            "allowed_guard_outcomes",
            frozenset({"allowed_delta"}),
            "allowed_guard_outcomes",
        ),
        (
            "production_promotion_allowed",
            True,
            "production promotion is not allowed",
        ),
        (
            "production_promotion_allowed",
            0,
            "production_promotion_allowed must be boolean",
        ),
        (
            "allowed_environments",
            {"test", "sandbox"},
            "restricted to test and sandbox",
        ),
        (
            "allowed_environments",
            frozenset({"sandbox"}),
            "restricted to test and sandbox",
        ),
        (
            "allowed_environments",
            frozenset({"test", "sandbox", "production"}),
            "restricted to test and sandbox",
        ),
    ],
)
def test_contract_constructor_rejects_noncanonical_or_unsafe_values(
    field, value, message
):
    with pytest.raises(RecoveryContractError, match=message):
        _base_contract(**{field: value})


@pytest.mark.parametrize(
    "arguments",
    [
        (None, "example_recovery_v1", "example_recovery_exact_v1"),
        (
            "acct.invoice.customer_create.v1",
            None,
            "example_recovery_exact_v1",
        ),
        (
            "acct.invoice.customer_create.v1",
            "example_recovery_v1",
            None,
        ),
        (
            " acct.invoice.customer_create.v1",
            "example_recovery_v1",
            "example_recovery_exact_v1",
        ),
        (
            "acct.invoice.customer_create.v1",
            "example_recovery_v1 ",
            "example_recovery_exact_v1",
        ),
        (
            "acct.invoice.customer_create.v1",
            "example_recovery_v1",
            "example_recovery_exact_v1\n",
        ),
    ],
)
def test_lookup_rejects_invalid_shapes_without_fallback(arguments):
    with pytest.raises(RecoveryContractError):
        select_recovery_action_contract(*arguments)


@pytest.mark.parametrize(
    "capability_id",
    [
        "",
        "acct.invoice.customer_create",
        "acct.Invoice.customer_create.v1",
        " acct.invoice.customer_create.v1",
        "acct.invoice.customer_create.v1 ",
        None,
    ],
)
def test_contracts_for_capability_rejects_invalid_identifiers(capability_id):
    with pytest.raises(RecoveryContractError, match="capability_id is invalid"):
        contracts_for_capability(capability_id)


def test_unknown_but_well_formed_capability_has_no_contracts():
    assert contracts_for_capability("acct.unknown.write.v1") == ()


def test_catalog_builder_rejects_duplicate_methods():
    first = _base_contract()
    second = replace(first, oracle_id="other_recovery_exact_v1")

    with pytest.raises(RecoveryContractError, match="methods must be unique"):
        _build_contract_catalog((first, second))


def test_catalog_builder_rejects_duplicate_oracles():
    first = _base_contract()
    second = replace(first, method="other_recovery_v1")

    with pytest.raises(RecoveryContractError, match="oracle_ids must be unique"):
        _build_contract_catalog((first, second))


def test_catalog_builder_rejects_empty_and_noncontract_entries():
    with pytest.raises(RecoveryContractError, match="cannot be empty"):
        _build_contract_catalog(())
    with pytest.raises(RecoveryContractError, match="RecoveryActionContract"):
        _build_contract_catalog((object(),))


def test_module_is_pure_data_and_validation_without_runtime_io():
    import odoo_accounting_cli_v3.recovery_contracts as module

    source = inspect.getsource(module)
    for forbidden in (
        "import os",
        "import pathlib",
        "import subprocess",
        "import socket",
        "import sqlite3",
        "import requests",
        "open(",
        "os.environ",
        "os.getenv",
    ):
        assert forbidden not in source
