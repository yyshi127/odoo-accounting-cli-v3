from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
from types import MappingProxyType

import pytest

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)
from odoo_accounting_cli_v3.recovery_guard import (
    NormalizedRecoveryRecord,
    RecoveryPlanExecutionGuard,
    RecoveryPlanExecutionGuardError,
    validate_recovery_plan_execution,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_recovery_plan,
    create_recovery_plan_v2,
    index_recovery_guard_graph,
)


COMPANY_ID = 7
ORIGIN_OPERATION_ID = "origin-op-1001"
MODULE_GRAPH_DIGEST = "a" * 64


def _fingerprint(seed: int) -> str:
    return f"{seed % 16:x}" * 64


def _target(model: str, record_id: int, *, company_id: int = COMPANY_ID) -> dict:
    return {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "record_state": "posted",
        "record_fingerprint": _fingerprint(record_id),
    }


def _guard(
    model: str,
    record_id: int,
    outcome: str,
    *,
    company_id: int = COMPANY_ID,
) -> dict:
    return {
        **_target(model, record_id, company_id=company_id),
        "expected_outcome": outcome,
    }


def _parameters(
    *,
    origin_operation_id: str,
    module_graph_digest: str,
    method: str,
    action_targets: list[dict],
    guard_records: list[dict],
    oracle_id: str,
    company_id: int = COMPANY_ID,
    **extra,
) -> dict:
    value = {
        "company_id": company_id,
        "origin_operation_id": origin_operation_id,
        "module_graph_digest": module_graph_digest,
        "method": method,
        "action_targets": sorted(
            (
                {"model": item["model"], "record_id": item["record_id"]}
                for item in action_targets
            ),
            key=lambda item: (item["model"], item["record_id"]),
        ),
        "guard_records": sorted(
            (
                {"model": item["model"], "record_id": item["record_id"]}
                for item in guard_records
            ),
            key=lambda item: (item["model"], item["record_id"]),
        ),
        "oracle_id": oracle_id,
    }
    value.update(extra)
    return value


def _case(method: str, **changes):
    contract = RECOVERY_ACTION_CONTRACTS[method]
    action_model = sorted(contract.action_models)[0]
    guard_model = sorted(contract.guard_models)[0]
    outcome = sorted(contract.allowed_guard_outcomes)[0]
    action_targets = changes.pop(
        "action_targets", [_target(action_model, 101)]
    )
    guard_records = changes.pop(
        "guard_records", [_guard(guard_model, 201, outcome)]
    )
    origin_operation_id = changes.pop(
        "origin_operation_id", ORIGIN_OPERATION_ID
    )
    module_graph_digest = changes.pop(
        "module_graph_digest", MODULE_GRAPH_DIGEST
    )
    company_id = changes.pop("company_id", COMPANY_ID)
    parameters = changes.pop(
        "parameters",
        _parameters(
            origin_operation_id=origin_operation_id,
            module_graph_digest=module_graph_digest,
            method=method,
            action_targets=action_targets,
            guard_records=guard_records,
            oracle_id=contract.oracle_id,
            company_id=company_id,
        ),
    )
    plan = create_recovery_plan_v2(
        origin_operation_id=origin_operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status=changes.pop("status", "available"),
        method=changes.pop("plan_method", method),
        requires_approval=changes.pop("requires_approval", True),
        action_targets=action_targets,
        guard_records=guard_records,
        oracle_id=changes.pop("oracle_id", contract.oracle_id),
        parameters=parameters,
    )
    assert not changes
    current = index_recovery_guard_graph(
        plan, expected_company_id=company_id
    )
    arguments = {
        "origin_capability_id": contract.origin_capability_id,
        "origin_operation_id": origin_operation_id,
        "expected_plan_digest": plan["plan_digest"],
        "environment": "test",
        "company_id": company_id,
        "module_graph_digest": module_graph_digest,
        "current_record_references": current,
    }
    return contract, plan, current, arguments


def _validate(plan: dict, arguments: dict):
    return validate_recovery_plan_execution(plan, **arguments)


@pytest.mark.parametrize("method", sorted(RECOVERY_ACTION_CONTRACTS))
@pytest.mark.parametrize("environment", ["test", "sandbox"])
def test_all_sixteen_contracts_validate_in_each_nonproduction_environment(
    method, environment
):
    contract, plan, current, arguments = _case(method)
    arguments["environment"] = environment

    guarded = _validate(plan, arguments)

    assert isinstance(guarded, RecoveryPlanExecutionGuard)
    assert guarded.origin_capability_id == contract.origin_capability_id
    assert guarded.method == contract.method
    assert guarded.oracle_id == contract.oracle_id
    assert guarded.environment == environment
    assert guarded.action_identities == tuple(
        sorted(
            (item["model"], item["record_id"])
            for item in plan["action_targets"]
        )
    )
    assert guarded.guard_identities == tuple(
        sorted(
            (item["model"], item["record_id"])
            for item in plan["guard_records"]
        )
    )
    assert guarded.guard_outcomes == tuple(
        (
            item["model"],
            item["record_id"],
            item["expected_outcome"],
        )
        for item in sorted(
            plan["guard_records"],
            key=lambda value: (value["model"], value["record_id"]),
        )
    )
    assert all(type(item) is NormalizedRecoveryRecord for item in guarded.actions)
    assert all(type(item) is NormalizedRecoveryRecord for item in guarded.guards)
    assert set(current) == {
        *guarded.action_identities,
        *guarded.guard_identities,
    }


@pytest.mark.parametrize(
    ("method", "action_targets", "guard_records"),
    [
        (
            "reverse_posted_period_adjustment_v1",
            [_target("account.move", 101)],
            [_guard("account.move.line", 201, "survive_allowed_delta")],
        ),
        (
            "reverse_the_reversal_v1",
            [_target("account.move", 101)],
            [
                _guard("account.move", 201, "survive_exact"),
                _guard(
                    "account.move.line", 202, "survive_allowed_delta"
                ),
                _guard(
                    "account.move.line", 203, "survive_allowed_delta"
                ),
            ],
        ),
        (
            "cancel_scheduled_and_reverse_accrual_origin_v1",
            [
                _target("account.move", 101),
                _target("account.move", 102),
            ],
            [
                _guard(
                    "account.move.line", 201, "survive_allowed_delta"
                ),
                _guard(
                    "account.move.line", 202, "survive_allowed_delta"
                ),
            ],
        ),
        (
            "reverse_depreciation_and_restore_schedule_v1",
            [_target("account.move", 101)],
            [
                _guard(
                    "account.asset", 201, "survive_allowed_delta"
                ),
                _guard("account.move", 202, "survive_exact"),
                _guard(
                    "account.move.line", 203, "survive_allowed_delta"
                ),
            ],
        ),
    ],
)
def test_entry_reversal_guard_graphs_accept_controlled_line_deltas(
    method, action_targets, guard_records
):
    _contract, plan, _current, arguments = _case(
        method,
        action_targets=action_targets,
        guard_records=guard_records,
    )

    guarded = _validate(plan, arguments)

    assert guarded.guard_outcomes == tuple(
        (
            item["model"],
            item["record_id"],
            item["expected_outcome"],
        )
        for item in sorted(
            guard_records,
            key=lambda value: (value["model"], value["record_id"]),
        )
    )


def test_output_is_frozen_canonical_and_detached_from_caller_data():
    _contract, plan, current, arguments = _case(
        "cancel_and_unreconcile_payment_v1",
        action_targets=[
            _target("account.payment", 103),
            _target("account.payment", 101),
        ],
        guard_records=[
            _guard("account.move.line", 204, "absent"),
            _guard("account.move", 202, "survive_allowed_delta"),
        ],
    )

    guarded = _validate(plan, arguments)
    current[("account.payment", 101)]["record_state"] = "cancel"
    plan["action_targets"][0]["record_state"] = "cancel"

    assert guarded.action_identities == (
        ("account.payment", 101),
        ("account.payment", 103),
    )
    assert guarded.guard_identities == (
        ("account.move", 202),
        ("account.move.line", 204),
    )
    assert guarded.actions[0].record_state == "posted"
    assert guarded.guards[0].record_state == "posted"
    with pytest.raises(FrozenInstanceError):
        guarded.environment = "production"
    with pytest.raises(FrozenInstanceError):
        guarded.actions[0].role = "guard"


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ("production", "restricted to test and sandbox"),
        ("development", "restricted to test and sandbox"),
        ("Sandbox", "restricted to test and sandbox"),
        (" sandbox", "environment is invalid"),
    ],
)
def test_environment_fail_closed_matrix(environment, message):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_customer_invoice_v1"
    )
    arguments["environment"] = environment

    with pytest.raises(RecoveryPlanExecutionGuardError, match=message):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    "origin_capability_id",
    ["acct.move.draft_cancel.v1", "acct.recovery.execute.v1"],
)
def test_terminal_capabilities_cannot_execute_follow_on_recovery(
    origin_capability_id,
):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_customer_invoice_v1"
    )
    arguments["origin_capability_id"] = origin_capability_id

    with pytest.raises(
        RecoveryPlanExecutionGuardError,
        match="terminal capability has no executable recovery",
    ):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "origin_capability_id",
            "acct.invoice.customer_create.v1",
            "does not match an executable origin contract",
        ),
        (
            "origin_operation_id",
            "another-origin",
            "origin operation mismatch",
        ),
        (
            "expected_plan_digest",
            "b" * 64,
            "plan digest mismatch",
        ),
        (
            "company_id",
            8,
            "not uniquely company-bound",
        ),
        (
            "module_graph_digest",
            "b" * 64,
            "parameters digest does not bind",
        ),
    ],
)
def test_external_execution_bindings_cannot_drift(field, replacement, message):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_vendor_bill_v1"
    )
    arguments[field] = replacement

    with pytest.raises(RecoveryPlanExecutionGuardError, match=message):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("expected_plan_digest", "A" * 64),
        ("module_graph_digest", "short"),
        ("company_id", True),
        ("company_id", 0),
        ("origin_operation_id", ""),
        ("origin_capability_id", "acct.BAD.v1"),
    ],
)
def test_external_execution_bindings_reject_noncanonical_values(
    field, replacement
):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_refund_v1"
    )
    arguments[field] = replacement

    with pytest.raises(RecoveryPlanExecutionGuardError):
        _validate(plan, arguments)


def test_plain_available_v2_plan_and_expected_digest_are_both_required():
    _contract, plan, _current, arguments = _case(
        "reverse_the_reversal_v1"
    )
    with pytest.raises(
        RecoveryPlanExecutionGuardError, match="plain object"
    ):
        _validate(MappingProxyType(plan), arguments)

    arguments["expected_plan_digest"] = plan["parameters_digest"]
    with pytest.raises(
        RecoveryPlanExecutionGuardError, match="plan digest mismatch"
    ):
        _validate(plan, arguments)


def test_historical_v1_and_nonavailable_v2_plans_are_not_executable():
    _contract, _plan, _current, arguments = _case(
        "reverse_the_reversal_v1"
    )
    historical = create_recovery_plan(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="reverse_the_reversal_v1",
        requires_approval=True,
        target_records=[_target("account.move", 101)],
        parameters={"company_id": COMPANY_ID},
    )
    arguments["expected_plan_digest"] = historical["plan_digest"]
    with pytest.raises(
        RecoveryPlanExecutionGuardError, match="valid available V2 plan"
    ):
        _validate(historical, arguments)

    contract = RECOVERY_ACTION_CONTRACTS["reverse_the_reversal_v1"]
    nonavailable = create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="manual_escalation",
        method=contract.method,
        requires_approval=False,
        action_targets=[],
        guard_records=[
            _guard("account.move.line", 201, "manual_review")
        ],
        oracle_id="manual",
        parameters={"company_id": COMPANY_ID},
    )
    arguments["expected_plan_digest"] = nonavailable["plan_digest"]
    arguments["current_record_references"] = {}
    with pytest.raises(
        RecoveryPlanExecutionGuardError, match="valid available V2 plan"
    ):
        _validate(nonavailable, arguments)


@pytest.mark.parametrize(
    "method",
    [
        "cancel_pristine_v3_draft_customer_invoice_v1",
        "reverse_posted_vendor_bill_v1",
        "cancel_and_unreconcile_payment_v1",
        "post_compensating_bank_statement_v1",
        "undo_reconciliation_and_reverse_writeoff_v1",
        "cancel_asset_and_reverse_schedule_v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "reverse_deferred_source_and_schedule_v1",
        "reverse_posted_period_adjustment_v1",
        "reverse_the_reversal_v1",
    ],
)
@pytest.mark.parametrize(
    "parameter_tamper",
    [
        "company",
        "origin",
        "module_graph",
        "method",
        "action_identity",
        "guard_identity",
        "oracle",
        "extra",
    ],
)
def test_parameters_digest_must_bind_the_exact_canonical_identity_graph(
    method, parameter_tamper
):
    contract, original, _current, arguments = _case(method)
    parameters = _parameters(
        origin_operation_id=ORIGIN_OPERATION_ID,
        module_graph_digest=MODULE_GRAPH_DIGEST,
        method=method,
        action_targets=original["action_targets"],
        guard_records=original["guard_records"],
        oracle_id=contract.oracle_id,
    )
    if parameter_tamper == "company":
        parameters["company_id"] = 8
    elif parameter_tamper == "origin":
        parameters["origin_operation_id"] = "another-origin"
    elif parameter_tamper == "module_graph":
        parameters["module_graph_digest"] = "b" * 64
    elif parameter_tamper == "method":
        parameters["method"] = "forged_recovery_v1"
    elif parameter_tamper == "action_identity":
        parameters["action_targets"][0]["record_id"] += 1
    elif parameter_tamper == "guard_identity":
        parameters["guard_records"][0]["record_id"] += 1
    elif parameter_tamper == "oracle":
        parameters["oracle_id"] = "forged_recovery_exact_v1"
    else:
        parameters["unapproved"] = True
    plan = create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=original["action_targets"],
        guard_records=original["guard_records"],
        oracle_id=contract.oracle_id,
        parameters=parameters,
    )
    arguments["expected_plan_digest"] = plan["plan_digest"]
    arguments["current_record_references"] = index_recovery_guard_graph(plan)

    with pytest.raises(
        RecoveryPlanExecutionGuardError,
        match="parameters digest does not bind",
    ):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "missing or unexpected identities"),
        ("extra", "missing or unexpected identities"),
        ("key_payload_mismatch", "key differs from its payload"),
        ("fingerprint", "differs from its approved reference"),
        ("state", "differs from its approved reference"),
        ("company", "company mismatch"),
        ("role", "reference fields are invalid"),
        ("model", "key differs from its payload"),
        ("outcome", "differs from its approved reference"),
        ("missing_outcome", "reference fields are invalid"),
        ("extra_field", "reference fields are invalid"),
        ("duplicate_payload", "key differs from its payload"),
    ],
)
def test_current_record_reference_tamper_matrix(mutation, message):
    _contract, plan, current, arguments = _case(
        "cancel_and_unreconcile_payment_v1",
        guard_records=[
            _guard(
                "account.partial.reconcile",
                201,
                "absent",
            )
        ],
    )
    current = copy.deepcopy(current)
    action_key = next(
        key for key, value in current.items() if value["role"] == "action"
    )
    guard_key = next(
        key for key, value in current.items() if value["role"] == "guard"
    )
    if mutation == "missing":
        current.pop(guard_key)
    elif mutation == "extra":
        current[("account.move", 999)] = {
            **_target("account.move", 999),
            "role": "action",
        }
    elif mutation == "key_payload_mismatch":
        current[(action_key[0], 999)] = current.pop(action_key)
    elif mutation == "fingerprint":
        current[action_key]["record_fingerprint"] = "f" * 64
    elif mutation == "state":
        current[action_key]["record_state"] = "cancel"
    elif mutation == "company":
        current[action_key]["company_id"] = 8
    elif mutation == "role":
        current[action_key]["role"] = "guard"
    elif mutation == "model":
        current[action_key]["model"] = "account.move"
    elif mutation == "outcome":
        current[guard_key]["expected_outcome"] = "survive_allowed_delta"
    elif mutation == "missing_outcome":
        current[guard_key].pop("expected_outcome")
    elif mutation == "extra_field":
        current[action_key]["unexpected"] = True
    else:
        current[(action_key[0], 999)] = dict(current[action_key])
    arguments["current_record_references"] = current

    with pytest.raises(RecoveryPlanExecutionGuardError, match=message):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    "invalid_mapping",
    [
        [],
        {("account.move", True): {}},
        {("Account.move", 1): {}},
        {("account.move", 0): {}},
        {"account.move:1": {}},
    ],
)
def test_current_record_reference_mapping_shape_is_strict(invalid_mapping):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_customer_invoice_v1"
    )
    arguments["current_record_references"] = invalid_mapping

    with pytest.raises(RecoveryPlanExecutionGuardError):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    ("graph_tamper", "message"),
    [
        ("action_model", "action model is outside"),
        ("guard_model", "guard model is outside"),
        ("guard_outcome", "guard outcome is outside"),
    ],
)
def test_contract_model_and_outcome_closures_are_enforced(
    graph_tamper, message
):
    method = "reverse_posted_customer_invoice_v1"
    contract = RECOVERY_ACTION_CONTRACTS[method]
    actions = [_target("account.move", 101)]
    guards = [_guard("account.move.line", 201, "survive_allowed_delta")]
    if graph_tamper == "action_model":
        actions[0] = _target("account.tax", 101)
    elif graph_tamper == "guard_model":
        guards[0] = _guard(
            "account.partial.reconcile", 201, "survive_allowed_delta"
        )
    else:
        guards[0]["expected_outcome"] = "absent"
    parameters = _parameters(
        origin_operation_id=ORIGIN_OPERATION_ID,
        module_graph_digest=MODULE_GRAPH_DIGEST,
        method=method,
        action_targets=actions,
        guard_records=guards,
        oracle_id=contract.oracle_id,
    )
    plan = create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=actions,
        guard_records=guards,
        oracle_id=contract.oracle_id,
        parameters=parameters,
    )
    arguments = {
        "origin_capability_id": contract.origin_capability_id,
        "origin_operation_id": ORIGIN_OPERATION_ID,
        "expected_plan_digest": plan["plan_digest"],
        "environment": "test",
        "company_id": COMPANY_ID,
        "module_graph_digest": MODULE_GRAPH_DIGEST,
        "current_record_references": index_recovery_guard_graph(plan),
    }

    with pytest.raises(RecoveryPlanExecutionGuardError, match=message):
        _validate(plan, arguments)


def _rehash_invalid_plan(plan: dict) -> None:
    plan["guard_graph_digest"] = hashlib.sha256(
        canonical_json(
            {
                "action_targets": plan["action_targets"],
                "guard_records": plan["guard_records"],
                "oracle_id": plan["oracle_id"],
            }
        )
    ).hexdigest()
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    plan["plan_digest"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()


@pytest.mark.parametrize("graph_tamper", ["duplicate_action", "overlap"])
def test_plan_duplicate_and_overlap_are_rejected_even_when_rehashed(
    graph_tamper,
):
    _contract, plan, _current, arguments = _case(
        "reverse_posted_customer_invoice_v1"
    )
    plan = copy.deepcopy(plan)
    if graph_tamper == "duplicate_action":
        plan["action_targets"].append(dict(plan["action_targets"][0]))
    else:
        action = dict(plan["action_targets"][0])
        plan["guard_records"] = [
            {**action, "expected_outcome": "survive_allowed_delta"}
        ]
    _rehash_invalid_plan(plan)
    arguments["expected_plan_digest"] = plan["plan_digest"]

    with pytest.raises(
        RecoveryPlanExecutionGuardError, match="valid available V2 plan"
    ):
        _validate(plan, arguments)


@pytest.mark.parametrize(
    ("method", "oracle"),
    [
        (
            "reverse_posted_customer_invoice_v1",
            "reverse_posted_vendor_bill_exact_v1",
        ),
        (
            "reverse_posted_vendor_bill_v1",
            "reverse_posted_customer_invoice_exact_v1",
        ),
        ("unregistered_recovery_v1", "unregistered_recovery_exact_v1"),
    ],
)
def test_method_oracle_contract_crossing_is_rejected(method, oracle):
    source_method = "reverse_posted_customer_invoice_v1"
    source_contract, source_plan, _current, arguments = _case(source_method)
    parameters = _parameters(
        origin_operation_id=ORIGIN_OPERATION_ID,
        module_graph_digest=MODULE_GRAPH_DIGEST,
        method=method,
        action_targets=source_plan["action_targets"],
        guard_records=source_plan["guard_records"],
        oracle_id=oracle,
    )
    plan = create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=source_plan["action_targets"],
        guard_records=source_plan["guard_records"],
        oracle_id=oracle,
        parameters=parameters,
    )
    arguments.update(
        {
            "origin_capability_id": source_contract.origin_capability_id,
            "expected_plan_digest": plan["plan_digest"],
            "current_record_references": index_recovery_guard_graph(plan),
        }
    )

    with pytest.raises(
        RecoveryPlanExecutionGuardError,
        match="does not match an executable origin contract",
    ):
        _validate(plan, arguments)
