from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

import pytest

from odoo_accounting_cli_v3.operations import (
    State,
    canonical_json,
    sign_execution_result,
)
from odoo_accounting_cli_v3.persistence import (
    IdempotencyConflict,
    OperationNotFound,
    SQLitePersistence,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan_v2,
)
from odoo_accounting_cli_v3.write_service import (
    BackendEvidence,
    WriteServiceError,
)

from test_write_service import (
    EXECUTION_SECRET,
    NOW,
    TEST_MODULE_GRAPH,
    Backend,
    _accept,
    _approval,
    _begin,
    _clone_service,
    _context,
    service,
)


IMPORT_CAPABILITY = "acct.bank.statement_import.v1"
COMPENSATE_CAPABILITY = "acct.bank.statement_compensate.v1"
METHOD = "post_compensating_bank_statement_v1"
ORACLE = "post_compensating_bank_statement_exact_v1"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _bank_parameters(suffix: str) -> dict[str, object]:
    return {
        "company_id": 7,
        "journal_id": 9,
        "statement_date": "2026-07-16",
        "currency_id": 12,
        "external_reference": f"BANK-{suffix}",
        "source_digest": "a" * 64,
        "source_filename": f"{suffix}.csv",
        "opening_balance": "1000.00",
        "closing_balance": "1125.50",
        "lines": [
            {
                "external_transaction_id": f"BANK-{suffix}-1",
                "transaction_date": "2026-07-16",
                "value_date": "2026-07-16",
                "direction": "credit",
                "amount": "125.50",
                "foreign_currency_id": None,
                "foreign_amount": None,
                "summary": "Receipt",
                "partner_id": 101,
                "source_line_digest": "b" * 64,
            }
        ],
        "idempotency_key": f"bank-{suffix}",
    }


def _record(snapshot: dict[str, object], *, guard: bool = False):
    value = {
        "model": snapshot["model"],
        "record_id": snapshot["record_id"],
        "company_id": 7,
        "record_state": snapshot["record_state"],
        "record_fingerprint": _digest(snapshot),
    }
    if guard:
        value["expected_outcome"] = "survive_exact"
    return value


def _bank_execution_evidence(operation) -> dict[str, object]:
    identities = (
        (
            "account.bank.statement",
            701,
            "complete",
            {
                "company_id": 7,
                "journal_id": 9,
                "currency_id": 12,
                "odoo_cli_v3_source_digest": "a" * 64,
                "balance_start": "1000.00",
                "balance_end_real": "1125.50",
            },
        ),
        (
            "account.bank.statement.line",
            702,
            "posted",
            {
                "company_id": 7,
                "journal_id": 9,
                "currency_id": 12,
                "statement_id": 701,
                "move_id": 703,
                "amount": "125.50",
            },
        ),
        (
            "account.move",
            703,
            "posted",
            {"company_id": 7, "journal_id": 9, "state": "posted"},
        ),
        (
            "account.move.line",
            704,
            "posted",
            {"company_id": 7, "move_id": 703, "balance": "125.50"},
        ),
    )
    before = [
        create_record_snapshot(
            model=model,
            record_id=record_id,
            exists=False,
            record_state="absent",
            values={},
        )
        for model, record_id, _state, _values in identities
    ]
    after = [
        create_record_snapshot(
            model=model,
            record_id=record_id,
            exists=True,
            record_state=state,
            values=values,
        )
        for model, record_id, state, values in identities
    ]
    action = _record(after[0])
    guards = [_record(snapshot, guard=True) for snapshot in after[1:]]
    recovery_parameters = {
        "company_id": 7,
        "origin_operation_id": operation.operation_id,
        "module_graph_digest": TEST_MODULE_GRAPH.digest,
        "method": METHOD,
        "action_targets": [
            {"model": "account.bank.statement", "record_id": 701}
        ],
        "guard_records": [
            {
                "model": guard["model"],
                "record_id": guard["record_id"],
            }
            for guard in guards
        ],
        "oracle_id": ORACLE,
    }
    plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=METHOD,
        requires_approval=True,
        action_targets=[action],
        guard_records=guards,
        oracle_id=ORACLE,
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": [
            action,
            *[
                {
                    key: guard[key]
                    for key in (
                        "model",
                        "record_id",
                        "company_id",
                        "record_state",
                        "record_fingerprint",
                    )
                }
                for guard in guards
            ],
        ],
        "difference": create_difference(
            before=before,
            after=after,
            changed_fields=[
                "amount",
                "balance",
                "balance_end_real",
                "balance_start",
                "company_id",
                "currency_id",
                "journal_id",
                "move_id",
                "odoo_cli_v3_source_digest",
                "state",
                "statement_id",
            ],
        ),
        "recovery_plan": plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class BankBackend(Backend):
    def execute(
        self,
        context,
        capability,
        operation,
        approval,
        registry_digest,
        release_digest,
    ):
        if operation.capability_id != IMPORT_CAPABILITY:
            return super().execute(
                context,
                capability,
                operation,
                approval,
                registry_digest,
                release_digest,
            )
        self.calls.append("execute")
        evidence = _bank_execution_evidence(operation)
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


def _compensation_execution_evidence(
    operation, *, succeeded: bool = True
) -> dict[str, object]:
    recovery_parameters = {"operation_id": operation.operation_id}
    if not succeeded:
        return {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "succeeded": False,
            "odoo_records": [],
            "difference": create_difference(
                before=[],
                after=[],
                changed_fields=[],
            ),
            "recovery_plan": create_recovery_plan_v2(
                origin_operation_id=operation.operation_id,
                recovery_capability_id="acct.recovery.execute.v1",
                status="manual_escalation",
                method=(
                    "inspect_failed_receipt_bound_bank_statement_compensation"
                ),
                requires_approval=True,
                action_targets=[],
                guard_records=[],
                oracle_id="manual_escalation",
                parameters=recovery_parameters,
            ),
            "recovery_parameters": recovery_parameters,
            "module_graph": None,
            "failure_checks": [
                "execution_rejected_before_verified_effect"
            ],
        }
    origin = create_record_snapshot(
        model="account.bank.statement",
        record_id=701,
        exists=True,
        record_state="complete",
        values={
            "company_id": 7,
            "journal_id": 9,
            "currency_id": 12,
            "odoo_cli_v3_source_digest": "a" * 64,
            "balance_start": "1000.00",
            "balance_end_real": "1125.50",
        },
    )
    absent = create_record_snapshot(
        model="account.bank.statement",
        record_id=801,
        exists=False,
        record_state="absent",
        values={},
    )
    compensation = create_record_snapshot(
        model="account.bank.statement",
        record_id=801,
        exists=True,
        record_state="complete",
        values={
            "company_id": 7,
            "journal_id": 9,
            "currency_id": 12,
            "balance_start": "1125.50",
            "balance_end_real": "1000.00",
            "compensates_statement_id": 701,
            "reason": operation.parameters["reason"],
        },
    )
    recovery_plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="manual_escalation",
        method="inspect_failed_receipt_bound_bank_statement_compensation",
        requires_approval=True,
        action_targets=[],
        guard_records=[],
        oracle_id="manual_escalation",
        parameters=recovery_parameters,
    )
    records = [_record(origin), _record(compensation)]
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": records,
        "difference": create_difference(
            before=[origin, absent],
            after=[origin, compensation],
            changed_fields=[
                "balance_end_real",
                "balance_start",
                "company_id",
                "compensates_statement_id",
                "currency_id",
                "journal_id",
                "reason",
            ],
        ),
        "recovery_plan": recovery_plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class CompensationBackend(BankBackend):
    def execute(
        self,
        context,
        capability,
        operation,
        approval,
        registry_digest,
        release_digest,
    ):
        if operation.capability_id != COMPENSATE_CAPABILITY:
            return super().execute(
                context,
                capability,
                operation,
                approval,
                registry_digest,
                release_digest,
            )
        self.calls.append("execute")
        evidence = _compensation_execution_evidence(
            operation, succeeded=self.execution_succeeds
        )
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=self.execution_succeeds,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


def _complete_origin(gateway, *, suffix: str):
    parameters = _bank_parameters(suffix)
    prepared = gateway.prepare(
        _context(
            parameters=parameters,
            token_id=f"token-bank-{suffix}-prepare",
            capability_id=IMPORT_CAPABILITY,
        ),
        operation_id=f"op-bank-{suffix}",
        request_id=f"request-bank-{suffix}",
        capability_id=IMPORT_CAPABILITY,
        parameters=parameters,
    )
    gateway.preview(
        _context(
            parameters=parameters,
            token_id=f"token-bank-{suffix}-preview",
            capability_id=IMPORT_CAPABILITY,
        ),
        prepared.operation_id,
    )
    awaiting = gateway.status(
        _context(parameters=parameters, capability_id=IMPORT_CAPABILITY),
        prepared.operation_id,
    )
    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id=f"token-bank-{suffix}-execute",
            capability_id=IMPORT_CAPABILITY,
        ),
        _approval(awaiting, f"approval-bank-{suffix}"),
        reconciliation_only=False,
    )
    return (
        gateway.status(
            _context(parameters=parameters, capability_id=IMPORT_CAPABILITY),
            prepared.operation_id,
        ),
        output,
    )


def _compensation_parameters(origin, output, receipt):
    return {
        "company_id": 7,
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "expected_origin_final_receipt_body_digest": receipt.body_digest,
        "expected_recovery_plan_digest": output["recovery_plan"][
            "plan_digest"
        ],
        "expected_statement_id": 701,
        "expected_journal_id": 9,
        "expected_currency_id": 12,
        "expected_source_digest": "a" * 64,
        "compensation_date": "2026-07-17",
        "reason": "Compensate the exact complete imported statement",
        "idempotency_key": f"compensate-{origin.operation_id}",
    }


def _prepare(gateway, parameters, *, suffix: str):
    return gateway.prepare(
        _context(
            parameters=parameters,
            token_id=f"token-compensate-{suffix}",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        operation_id=f"op-compensate-{suffix}",
        request_id=f"request-compensate-{suffix}",
        capability_id=COMPENSATE_CAPABILITY,
        parameters=parameters,
    )


@pytest.fixture
def bank_case(service):
    original, _backend, store = service
    backend = BankBackend()
    gateway = _clone_service(original, backend, store)
    origin, output = _complete_origin(gateway, suffix="origin")
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(origin, output, receipt)
    return gateway, backend, store, origin, output, receipt, parameters


def test_compensation_binding_is_restart_safe_and_one_per_origin(bank_case):
    gateway, backend, store, origin, output, receipt, parameters = bank_case
    compensation = _prepare(gateway, parameters, suffix="primary")
    binding = store.get_bank_statement_compensation_operation_binding(
        compensation.operation_id
    )

    assert binding.origin_operation_id == origin.operation_id
    assert binding.origin_operation_revision == origin.revision
    assert binding.origin_final_receipt_id == receipt.receipt_id
    assert (
        binding.compensation_operation_id == compensation.operation_id
    )
    assert binding.plan_digest == output["recovery_plan"]["plan_digest"]
    assert (
        binding.audit_event.event_type
        == "bank.statement.compensation.binding.created"
    )
    assert gateway.trusted_recovery_plan(
        _context(parameters=parameters, capability_id=COMPENSATE_CAPABILITY),
        compensation,
    ) == output["recovery_plan"]

    retry = _prepare(
        gateway, copy.deepcopy(parameters), suffix="different-request-id"
    )
    assert retry == compensation
    assert sum(
        event.event_type
        == "bank.statement.compensation.binding.created"
        for event in store.audit_events()
    ) == 1

    restarted_store = SQLitePersistence(store.path)
    restarted = _clone_service(gateway, backend, restarted_store)
    assert (
        restarted_store.get_bank_statement_compensation_operation_binding(
            compensation.operation_id
        )
        == binding
    )
    assert restarted.trusted_recovery_plan(
        _context(parameters=parameters, capability_id=COMPENSATE_CAPABILITY),
        restarted_store.get_operation(compensation.operation_id),
    ) == output["recovery_plan"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("expected_statement_id", 999, "recovery plan binding changed"),
        ("expected_journal_id", 99, "statement binding changed"),
        ("expected_currency_id", 99, "statement binding changed"),
        ("expected_source_digest", "c" * 64, "statement binding changed"),
        (
            "expected_origin_final_receipt_body_digest",
            "d" * 64,
            "final receipt digest changed",
        ),
    ),
)
def test_compensation_rejects_tampered_origin_bindings(
    bank_case, field, value, message
):
    gateway, _backend, _store, _origin, _output, _receipt, parameters = (
        bank_case
    )
    changed = copy.deepcopy(parameters)
    changed[field] = value
    with pytest.raises(WriteServiceError, match=message):
        _prepare(gateway, changed, suffix=f"tamper-{field}")


def test_same_origin_rejects_different_compensation_content(bank_case):
    gateway, _backend, _store, _origin, _output, _receipt, parameters = (
        bank_case
    )
    _prepare(gateway, parameters, suffix="bound")
    changed = copy.deepcopy(parameters)
    changed["reason"] = "A different compensating business reason"
    with pytest.raises(
        IdempotencyConflict, match="different request content"
    ):
        _prepare(gateway, changed, suffix="changed")


def test_binding_disappearance_after_approval_stops_before_execute(
    bank_case,
    monkeypatch: pytest.MonkeyPatch,
):
    gateway, backend, store, _origin, _output, _receipt, parameters = (
        bank_case
    )
    compensation = _prepare(gateway, parameters, suffix="toctou")
    gateway.preview(
        _context(
            parameters=parameters,
            token_id="token-compensate-toctou-preview",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        compensation.operation_id,
    )
    awaiting = store.get_operation(compensation.operation_id)
    original_get = (
        store.get_bank_statement_compensation_operation_binding
    )
    checks = 0

    def disappear(operation_id: str):
        nonlocal checks
        checks += 1
        if checks >= 3:
            raise OperationNotFound(
                "bank statement compensation binding does not exist"
            )
        return original_get(operation_id)

    monkeypatch.setattr(
        store,
        "get_bank_statement_compensation_operation_binding",
        disappear,
    )
    calls_before = list(backend.calls)
    with pytest.raises(WriteServiceError, match="no durable origin binding"):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id="token-compensate-toctou-execute",
                capability_id=COMPENSATE_CAPABILITY,
            ),
            _approval(awaiting, "approval-compensate-toctou"),
            reconciliation_only=False,
        )

    assert checks == 3
    assert store.get_operation(compensation.operation_id).state is (
        State.APPROVED
    )
    assert backend.calls == [*calls_before, "precheck"]
    assert "execute" not in backend.calls[len(calls_before) :]


def _awaiting_compensation(gateway, store, parameters, *, suffix: str):
    compensation = _prepare(gateway, parameters, suffix=suffix)
    gateway.preview(
        _context(
            parameters=parameters,
            token_id=f"token-{suffix}-preview",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        compensation.operation_id,
    )
    return store.get_operation(compensation.operation_id)


def test_complete_compensation_is_verified_finalized_and_replay_safe(
    service,
):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix="complete-origin"
    )
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix="complete"
    )
    approval = _approval(awaiting, "approval-compensation-complete")
    calls_before = list(backend.calls)

    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-compensation-complete-execute",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == State.COMPLETED.value
    assert output["verification"]["passed"] is True
    assert output["database_finalization"]
    assert backend.calls[len(calls_before) :].count("execute") == 1
    assert backend.calls[len(calls_before) :].count("verify") == 1
    compensation = store.get_operation(awaiting.operation_id)
    assert compensation.state is State.COMPLETED
    receipts = store.get_final_write_receipts(compensation.operation_id)
    assert len(receipts) == 1
    assert receipts[0].body["receipt_details"][
        "database_finalization"
    ]
    assert gateway.trusted_recovery_plan(
        _context(parameters=parameters, capability_id=COMPENSATE_CAPABILITY),
        compensation,
    ) == origin_output["recovery_plan"]
    assert store.get_operation(origin.operation_id).state is State.COMPLETED

    exact_retry = _prepare(
        gateway, copy.deepcopy(parameters), suffix="terminal-retry"
    )
    assert exact_retry == compensation
    replay_calls = list(backend.calls)
    assert gateway.result(
        _context(parameters=parameters, capability_id=COMPENSATE_CAPABILITY),
        compensation.operation_id,
    ) == output
    assert gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-compensation-terminal-replay",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        approval,
        reconciliation_only=True,
    ) == output
    assert backend.calls == replay_calls


def test_response_loss_replay_does_not_repeat_compensation_write(service):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix="response-loss-origin"
    )
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix="response-loss"
    )
    approval = _approval(awaiting, "approval-compensation-response-loss")
    calls_before = list(backend.calls)
    original._test_effect_finalizer.lose_first_response = True

    with pytest.raises(
        WriteServiceError, match="database effect finalization failed"
    ):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id="token-compensation-response-loss-first",
                capability_id=COMPENSATE_CAPABILITY,
            ),
            approval,
            reconciliation_only=False,
        )
    assert store.get_operation(awaiting.operation_id).state is State.VERIFYING
    assert backend.calls[len(calls_before) :].count("execute") == 1
    assert backend.calls[len(calls_before) :].count("verify") == 1

    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-compensation-response-loss-replay",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        approval,
        reconciliation_only=True,
    )
    assert output["operation_state"] == State.COMPLETED.value
    assert backend.calls[len(calls_before) :].count("execute") == 1
    # Verification is a read-only fresh readback and is intentionally repeated
    # after the finalizer response is lost; the compensating write is not.
    assert backend.calls[len(calls_before) :].count("verify") == 2


def test_failed_compensation_verification_never_reports_completed(service):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix="verify-fail-origin"
    )
    backend.verification_passes = False
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix="verify-fail"
    )

    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-compensation-verify-fail-execute",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        _approval(awaiting, "approval-compensation-verify-fail"),
        reconciliation_only=False,
    )

    assert output["operation_state"] == State.FAILED.value
    assert output["verification"]["passed"] is False
    assert output["database_finalization"] is None
    assert store.get_operation(awaiting.operation_id).state is State.FAILED
    assert store.get_operation(origin.operation_id).state is State.COMPLETED


def test_failed_compensation_execution_has_receipt_and_no_verification(
    service,
):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix="execute-fail-origin"
    )
    backend.execution_succeeds = False
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix="execute-fail"
    )
    calls_before = list(backend.calls)

    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-compensation-execute-fail",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        _approval(awaiting, "approval-compensation-execute-fail"),
        reconciliation_only=False,
    )

    assert output["operation_state"] == State.FAILED.value
    assert output["verification"]["passed"] is False
    assert (
        output["verification"]["method"]
        == "execution_failure_readback"
    )
    assert output["database_finalization"] is None
    assert backend.calls[len(calls_before) :].count("execute") == 1
    assert backend.calls[len(calls_before) :].count("verify") == 0
    failed = store.get_operation(awaiting.operation_id)
    assert failed.state is State.FAILED
    receipts = store.get_final_write_receipts(failed.operation_id)
    assert len(receipts) == 1
    assert receipts[0].terminal_state == State.FAILED.value
    assert store.get_operation(origin.operation_id).state is State.COMPLETED


def _tamper_binding(store, operation_id: str, mode: str, monkeypatch):
    original_get = (
        store.get_bank_statement_compensation_operation_binding
    )

    def tampered(requested_operation_id: str):
        if mode == "missing":
            raise OperationNotFound(
                "bank statement compensation binding does not exist"
            )
        return replace(
            original_get(requested_operation_id),
            plan_digest="f" * 64,
        )

    monkeypatch.setattr(
        store,
        "get_bank_statement_compensation_operation_binding",
        tampered,
    )


@pytest.mark.parametrize("mode", ("missing", "drift"))
def test_executing_replay_revalidates_compensation_binding(
    bank_case, monkeypatch: pytest.MonkeyPatch, mode: str
):
    gateway, backend, store, _origin, _output, _receipt, parameters = (
        bank_case
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix=f"executing-{mode}"
    )
    approval = _approval(
        awaiting, f"approval-compensation-executing-{mode}"
    )
    approved = _accept(store, approval)
    executing = _begin(store, approval, approved)
    assert executing.state is State.EXECUTING
    calls_before = list(backend.calls)
    _tamper_binding(store, executing.operation_id, mode, monkeypatch)

    with pytest.raises(WriteServiceError, match="origin binding|differs"):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id=f"token-compensation-executing-{mode}",
                capability_id=COMPENSATE_CAPABILITY,
            ),
            approval,
            reconciliation_only=False,
        )
    assert backend.calls == calls_before


@pytest.mark.parametrize("mode", ("missing", "drift"))
def test_verifying_replay_revalidates_compensation_binding(
    service, monkeypatch: pytest.MonkeyPatch, mode: str
):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix=f"verifying-{mode}-origin"
    )
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix=f"verifying-{mode}"
    )
    approval = _approval(
        awaiting, f"approval-compensation-verifying-{mode}"
    )
    original._test_effect_finalizer.lose_first_response = True
    with pytest.raises(WriteServiceError):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id=f"token-compensation-verifying-first-{mode}",
                capability_id=COMPENSATE_CAPABILITY,
            ),
            approval,
            reconciliation_only=False,
        )
    assert store.get_operation(awaiting.operation_id).state is State.VERIFYING
    calls_before = list(backend.calls)
    _tamper_binding(store, awaiting.operation_id, mode, monkeypatch)

    with pytest.raises(WriteServiceError, match="origin binding|differs"):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id=f"token-compensation-verifying-replay-{mode}",
                capability_id=COMPENSATE_CAPABILITY,
            ),
            approval,
            reconciliation_only=True,
        )
    assert backend.calls == calls_before


@pytest.mark.parametrize("mode", ("missing", "drift"))
def test_terminal_result_revalidates_compensation_binding(
    service, monkeypatch: pytest.MonkeyPatch, mode: str
):
    original, _backend, store = service
    backend = CompensationBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output = _complete_origin(
        gateway, suffix=f"terminal-{mode}-origin"
    )
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _compensation_parameters(
        origin, origin_output, receipt
    )
    awaiting = _awaiting_compensation(
        gateway, store, parameters, suffix=f"terminal-{mode}"
    )
    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id=f"token-compensation-terminal-first-{mode}",
            capability_id=COMPENSATE_CAPABILITY,
        ),
        _approval(awaiting, f"approval-compensation-terminal-{mode}"),
        reconciliation_only=False,
    )
    assert output["operation_state"] == State.COMPLETED.value
    calls_before = list(backend.calls)
    _tamper_binding(store, awaiting.operation_id, mode, monkeypatch)

    with pytest.raises(WriteServiceError, match="origin binding|differs"):
        gateway.result(
            _context(
                parameters=parameters,
                capability_id=COMPENSATE_CAPABILITY,
            ),
            awaiting.operation_id,
        )
    assert backend.calls == calls_before
