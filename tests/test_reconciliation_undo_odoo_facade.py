from __future__ import annotations

from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo import write_handlers as write_handlers_module
from odoo_accounting_cli_v3.odoo.recovery_verifier import (
    RecoveryVerificationError,
)
from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    EXCLUSIVE_BEFORE_LOCK_CAPABILITIES,
    OdooWriteBootstrapError,
    _resource_lock_digests,
    _trusted_recovery_plan as bootstrap_trusted_plan,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlerError,
    OdooWriteHandlers,
)
from odoo_accounting_cli_v3.odoo.write_precheck import (
    OdooWritePrecheckError,
    _trusted_recovery_plan as precheck_trusted_plan,
)
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan_v2


CAPABILITY_ID = "acct.reconciliation.undo.v1"
METHOD = "undo_reconciliation_and_reverse_writeoff_v1"
ORACLE = "undo_reconciliation_and_reverse_writeoff_exact_v1"
ORIGIN_OPERATION_ID = "operation-reconciliation-origin"
COMPANY_ID = 7
MODULE_GRAPH_DIGEST = "b" * 64


def _reference(
    model: str,
    record_id: int,
    *,
    company_id: int = COMPANY_ID,
    expected_outcome: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "record_state": "posted",
        "record_fingerprint": f"{record_id:064x}",
    }
    if expected_outcome is not None:
        value["expected_outcome"] = expected_outcome
    return value


def _plan(
    *,
    method: str = METHOD,
    oracle: str = ORACLE,
    company_id: int = COMPANY_ID,
) -> dict[str, object]:
    actions = [
        _reference("account.partial.reconcile", 31, company_id=company_id),
    ]
    guards = [
        _reference(
            "account.move.line",
            41,
            company_id=company_id,
            expected_outcome="survive_allowed_delta",
        ),
    ]
    parameters = {
        "company_id": company_id,
        "origin_operation_id": ORIGIN_OPERATION_ID,
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
        origin_operation_id=ORIGIN_OPERATION_ID,
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
        "origin_operation_id": ORIGIN_OPERATION_ID,
        "expected_origin_revision": 8,
        "expected_origin_final_receipt_body_digest": "c" * 64,
        "expected_recovery_plan_digest": plan["plan_digest"],
        "recovery_date": "2026-07-29",
        "reason": "Approved receipt-bound reconciliation undo",
        "idempotency_key": "undo-reconciliation-1",
    }


def test_reconciliation_undo_boundaries_accept_only_the_exact_company_plan():
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

    wrong_contract = _plan(
        method="reverse_the_reversal_v1",
        oracle="reverse_the_reversal_exact_v1",
    )
    wrong_parameters = _parameters(wrong_contract)
    with pytest.raises(
        OdooWritePrecheckError, match="exact reconciliation undo plan"
    ):
        precheck_trusted_plan(
            wrong_contract,
            capability_id=CAPABILITY_ID,
            parameters=wrong_parameters,
            company_id=COMPANY_ID,
        )
    with pytest.raises(
        OdooWriteBootstrapError, match="exact reconciliation undo plan"
    ):
        bootstrap_trusted_plan(
            wrong_contract,
            SimpleNamespace(
                capability_id=CAPABILITY_ID,
                parameters=wrong_parameters,
                company_id=COMPANY_ID,
            ),
            context,
        )

    foreign_company_plan = _plan(company_id=COMPANY_ID + 1)
    foreign_parameters = _parameters(foreign_company_plan)
    with pytest.raises(
        OdooWritePrecheckError, match="outside the bound operation"
    ):
        precheck_trusted_plan(
            foreign_company_plan,
            capability_id=CAPABILITY_ID,
            parameters=foreign_parameters,
            company_id=COMPANY_ID,
        )
    with pytest.raises(
        OdooWriteBootstrapError, match="not uniquely company-bound"
    ):
        bootstrap_trusted_plan(
            foreign_company_plan,
            SimpleNamespace(
                capability_id=CAPABILITY_ID,
                parameters=foreign_parameters,
                company_id=COMPANY_ID,
            ),
            context,
        )


def test_reconciliation_undo_uses_graph_and_exclusive_before_locks():
    plan = _plan()
    locks = _resource_lock_digests(
        CAPABILITY_ID,
        COMPANY_ID,
        _parameters(plan),
        plan,
    )

    assert CAPABILITY_ID in EXCLUSIVE_BEFORE_LOCK_CAPABILITIES
    assert len(locks) == 2
    assert locks == sorted(set(locks))
    assert (
        OdooWriteHandlers.dispatch_name(CAPABILITY_ID, "precheck")
        == "precheck_reconciliation_undo"
    )
    assert (
        OdooWriteHandlers.dispatch_name(CAPABILITY_ID, "verify")
        == "verify_reconciliation_undo"
    )


def _facade_handler(plan: dict[str, object]) -> OdooWriteHandlers:
    handler = object.__new__(OdooWriteHandlers)
    handler.context = SimpleNamespace(
        trusted_recovery_plan=plan,
        module_graph=SimpleNamespace(digest=MODULE_GRAPH_DIGEST),
    )
    return handler


def test_reconciliation_undo_executes_exact_oracle_before_return(monkeypatch):
    plan = _plan()
    parameters = _parameters(plan)
    handler = _facade_handler(plan)
    company = SimpleNamespace(id=COMPANY_ID)
    tombstones = frozenset({("account.partial.reconcile", 31)})
    result = (
        [("account.move.line", SimpleNamespace(id=41))],
        {"status": "not_applicable"},
        tombstones,
    )
    handler.execute_recovery = lambda *_args: result
    before = {("account.move.line", 41): {"id": 41}}
    handler.trusted_before_values = lambda *_args: before
    observed: list[dict[str, object]] = []

    def exact_oracle(_handler, method, **kwargs):
        observed.append({"method": method, **kwargs})
        return ("exact_reconciliation_undo_verified",)

    monkeypatch.setattr(
        write_handlers_module, "verify_recovery_action", exact_oracle
    )

    assert handler.execute_reconciliation_undo(
        parameters, company, {"before": []}
    ) == result
    assert len(observed) == 1
    assert observed[0]["method"] == METHOD
    assert observed[0]["plan"] == plan
    assert observed[0]["before_values"] == before
    assert observed[0]["tombstone_keys"] == tombstones


def test_reconciliation_undo_exact_oracle_failure_aborts_execution(monkeypatch):
    plan = _plan()
    parameters = _parameters(plan)
    handler = _facade_handler(plan)
    company = SimpleNamespace(id=COMPANY_ID)
    handler.execute_recovery = lambda *_args: (
        [("account.move.line", SimpleNamespace(id=41))],
        {"status": "not_applicable"},
        frozenset({("account.partial.reconcile", 31)}),
    )
    handler.trusted_before_values = lambda *_args: {
        ("account.move.line", 41): {"id": 41}
    }

    def reject_exact_oracle(*_args, **_kwargs):
        raise RecoveryVerificationError("exact delta mismatch")

    monkeypatch.setattr(
        write_handlers_module,
        "verify_recovery_action",
        reject_exact_oracle,
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match="fresh recovery verification failed closed",
    ):
        handler.execute_reconciliation_undo(
            parameters, company, {"before": []}
        )


def test_reconciliation_undo_handler_rejects_a_different_recovery_contract():
    plan = _plan(
        method="reverse_the_reversal_v1",
        oracle="reverse_the_reversal_exact_v1",
    )
    handler = _facade_handler(plan)

    with pytest.raises(
        OdooWriteHandlerError,
        match="not bound to this reconciliation undo",
    ):
        handler._reconciliation_undo_plan(
            _parameters(plan), SimpleNamespace(id=COMPANY_ID)
        )
