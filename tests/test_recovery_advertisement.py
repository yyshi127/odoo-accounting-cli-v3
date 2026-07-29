from types import SimpleNamespace
import hashlib

import pytest

from odoo_accounting_cli_v3.odoo.module_graph import (
    build_trusted_module_graph,
)
from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    OdooWriteBootstrapError,
    _execution_evidence,
)
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)


MODULE_GRAPH = build_trusted_module_graph(
    [{"name": "account", "latest_version": "19.0.test"}]
)
DRAFT_METHODS = {
    "cancel_pristine_v3_draft_customer_invoice_v1",
    "cancel_pristine_v3_draft_vendor_bill_v1",
}
GENERIC_CONTRACTS = tuple(
    contract
    for method, contract in RECOVERY_ACTION_CONTRACTS.items()
    if method not in DRAFT_METHODS
)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def snapshot(model: str, record_id: int) -> dict:
    values = {"company_id": 7}
    return {
        "model": model,
        "record_id": record_id,
        "company_id": 7,
        "state": "posted",
        "values": values,
        "values_digest": digest(values),
    }


def raw_for(contract, *, environment="test", outcome=None):
    action_model = sorted(contract.action_models)[0]
    guard_model = sorted(contract.guard_models)[0]
    action = snapshot(action_model, 1001)
    guard = snapshot(guard_model, 1002)
    if outcome is None:
        outcome = sorted(contract.allowed_guard_outcomes)[0]
    parameters = {"company_id": 7, "posting_mode": "post"}
    operation = SimpleNamespace(
        operation_id=f"origin:{contract.method}",
        capability_id=contract.origin_capability_id,
        company_id=7,
        environment=environment,
        parameters=parameters,
    )
    raw = {
        "capability_id": operation.capability_id,
        "company_id": 7,
        "parameters_digest": digest(parameters),
        "module_graph": MODULE_GRAPH.evidence,
        "before": [],
        "after": [action, guard],
        "records": [
            {"model": action_model, "record_id": 1001},
            {"model": guard_model, "record_id": 1002},
        ],
        "recovery": {
            "status": "available",
            "method": contract.method,
            "targets": [{"model": action_model, "record_id": 1001}],
            "guards": [
                {
                    "model": guard_model,
                    "record_id": 1002,
                    "expected_outcome": outcome,
                }
            ],
            "oracle_id": contract.oracle_id,
        },
    }
    return operation, raw


@pytest.mark.parametrize(
    "contract",
    GENERIC_CONTRACTS,
    ids=lambda contract: contract.method,
)
def test_each_generic_recovery_contract_becomes_an_available_v2_plan(contract):
    operation, raw = raw_for(contract)

    evidence = _execution_evidence(operation, raw)

    plan = evidence["recovery_plan"]
    assert plan["status"] == "available"
    assert plan["method"] == contract.method
    assert plan["oracle_id"] == contract.oracle_id
    assert plan["action_targets"][0]["model"] in contract.action_models
    assert plan["guard_records"][0]["model"] in contract.guard_models
    assert (
        plan["guard_records"][0]["expected_outcome"]
        in contract.allowed_guard_outcomes
    )
    assert evidence["recovery_parameters"]["module_graph_digest"] == (
        MODULE_GRAPH.digest
    )


@pytest.mark.parametrize(
    "contract",
    GENERIC_CONTRACTS,
    ids=lambda contract: contract.method,
)
def test_each_generic_recovery_contract_is_rejected_in_production(contract):
    operation, raw = raw_for(contract, environment="production")

    with pytest.raises(OdooWriteBootstrapError, match="environment"):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    "contract",
    GENERIC_CONTRACTS,
    ids=lambda contract: contract.method,
)
def test_each_generic_recovery_contract_rejects_an_outcome_outside_contract(
    contract,
):
    invalid = next(
        outcome
        for outcome in (
            "survive_exact",
            "survive_allowed_delta",
            "absent",
            "manual_review",
        )
        if outcome not in contract.allowed_guard_outcomes
    )
    operation, raw = raw_for(contract, outcome=invalid)

    with pytest.raises(OdooWriteBootstrapError, match="guard identity"):
        _execution_evidence(operation, raw)
