from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

import pytest

from odoo_accounting_cli_v3.operations import (
    State,
    canonical_json,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.odoo.module_graph import build_trusted_module_graph
from odoo_accounting_cli_v3.operation_diagnostics import (
    OperationDiagnosticsError,
)
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.recovery_evidence import (
    validate_origin_recovery_completion_evidence,
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
    VERIFICATION_SECRET,
    Backend,
    _approval,
    _clone_service,
    _context,
    _incident_recovery_request,
    _install_incident_recovery_auth,
    _invoice_parameters,
    _prepare_and_preview,
    _verification_evidence,
    service,
)


MODULE_GRAPH = build_trusted_module_graph(
    [{"name": "account", "latest_version": "19.0.test"}]
)
RECOVERY_METHOD = "cancel_pristine_v3_draft_customer_invoice_v1"
RECOVERY_ORACLE = "cancel_pristine_v3_draft_customer_invoice_exact_v1"


def _digest(value) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _record(snapshot, company_id: int) -> dict[str, object]:
    return {
        "model": snapshot["model"],
        "record_id": snapshot["record_id"],
        "company_id": company_id,
        "record_state": snapshot["record_state"],
        "record_fingerprint": _digest(snapshot),
    }


def _origin_execution_evidence(operation) -> dict[str, object]:
    move_before = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_type": "out_invoice",
            "source": "pre-operation",
            "state": "draft",
        },
    )
    line_before = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_id": 501,
            "parent_state": "draft",
            "source": "pre-operation",
        },
    )
    move_after = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_type": "out_invoice",
            "source": "operation",
            "state": "draft",
        },
    )
    line_after = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_id": 501,
            "parent_state": "draft",
            "source": "operation",
        },
    )
    action = _record(move_after, operation.company_id)
    guard = {
        **_record(line_after, operation.company_id),
        "expected_outcome": "survive_allowed_delta",
    }
    recovery_parameters = {
        "company_id": operation.company_id,
        "origin_operation_id": operation.operation_id,
        "module_graph_digest": MODULE_GRAPH.digest,
        "method": RECOVERY_METHOD,
        "action_targets": [{"model": "account.move", "record_id": 501}],
        "guard_records": [
            {"model": "account.move.line", "record_id": 502}
        ],
        "oracle_id": RECOVERY_ORACLE,
    }
    plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=RECOVERY_METHOD,
        requires_approval=True,
        action_targets=[action],
        guard_records=[guard],
        oracle_id=RECOVERY_ORACLE,
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": [action, {key: guard[key] for key in action}],
        "difference": create_difference(
            before=[move_before, line_before],
            after=[move_after, line_after],
            changed_fields=[
                "company_id",
                "move_id",
                "move_type",
                "parent_state",
                "source",
                "state",
            ],
        ),
        "recovery_plan": plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


def _recovery_execution_evidence(operation) -> dict[str, object]:
    move_before = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_type": "out_invoice",
            "state": "draft",
        },
    )
    line_before = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=True,
        record_state="draft",
        values={
            "company_id": operation.company_id,
            "move_id": 501,
            "parent_state": "draft",
        },
    )
    move_after = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=True,
        record_state="cancel",
        values={
            "company_id": operation.company_id,
            "move_type": "out_invoice",
            "state": "cancel",
        },
    )
    line_after = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=True,
        record_state="cancel",
        values={
            "company_id": operation.company_id,
            "move_id": 501,
            "parent_state": "cancel",
        },
    )
    records = [
        _record(move_after, operation.company_id),
        _record(line_after, operation.company_id),
    ]
    recovery_parameters = {
        "origin_operation_id": operation.parameters["origin_operation_id"]
    }
    terminal_plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="not_applicable",
        method="not_applicable_recovery_execution_is_terminal_v1",
        requires_approval=False,
        action_targets=[],
        guard_records=[],
        oracle_id="not_applicable",
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": records,
        "difference": create_difference(
            before=[move_before, line_before],
            after=[move_after, line_after],
            changed_fields=["parent_state", "state"],
        ),
        "recovery_plan": terminal_plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class IncidentBackend(Backend):
    def execute(
        self,
        _context_value,
        capability,
        operation,
        _approval_value,
        _registry_digest,
        _release_digest,
    ) -> BackendEvidence:
        evidence = (
            _recovery_execution_evidence(operation)
            if capability.id == "acct.recovery.execute.v1"
            else _origin_execution_evidence(operation)
        )
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

    def verify(
        self,
        _context_value,
        capability,
        operation,
        execution_evidence,
        _registry_digest,
        _release_digest,
    ) -> BackendEvidence:
        passed = capability.id == "acct.recovery.execute.v1"
        evidence = _verification_evidence(
            operation,
            execution_evidence,
            passed=passed,
        )
        evidence["method"] = capability.data["verification"]["method"]
        result = sign_verification_result(
            operation=operation,
            issuer="odoo-write-verifier",
            key_id="verification-v1",
            succeeded=passed,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


def _prepare_incident(gateway, store):
    backend = IncidentBackend()
    gateway._write_executor = backend.execute
    gateway._verification_executor = backend.verify
    parameters = {**_invoice_parameters(), "posting_mode": "draft"}
    awaiting = _prepare_and_preview(gateway, parameters=parameters)
    failed_output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-completion-origin-execute",
        ),
        _approval(awaiting, "approval-completion-origin"),
        reconciliation_only=False,
    )
    origin = store.get_operation(awaiting.operation_id)
    assert failed_output["operation_state"] == State.FAILED.value
    assert origin.state == State.FAILED

    request = _incident_recovery_request(origin, suffix="completion")
    context = _install_incident_recovery_auth(gateway, origin, request)
    prepared = gateway.prepare_recovery(
        context("token-completion-prepare"),
        **request,
    )
    recovery = prepared["operation"]
    gateway.preview(
        context("token-completion-preview"),
        recovery.operation_id,
    )
    awaiting_recovery = store.get_operation(recovery.operation_id)
    assert awaiting_recovery.state == State.AWAITING_APPROVAL
    return origin, awaiting_recovery, context


def _complete_incident(gateway, store):
    origin, awaiting, context = _prepare_incident(gateway, store)
    output = gateway.approve_execute(
        context("token-completion-execute"),
        _approval(awaiting, "approval-completion-recovery"),
        reconciliation_only=False,
    )
    return origin, store.get_operation(awaiting.operation_id), context, output


def test_successful_recovery_completes_origin_with_trusted_evidence_and_replays(
    service,
) -> None:
    gateway, _unused_backend, store = service
    failed_origin, recovery, context, output = _complete_incident(
        gateway,
        store,
    )
    origin = store.get_operation(failed_origin.operation_id)

    assert output["operation_state"] == State.COMPLETED.value
    assert recovery.state == State.COMPLETED
    assert origin.state == State.RECOVERED
    assert origin.revision == failed_origin.revision + 2

    recovery_records = store.get_recovery_records(origin.operation_id)
    assert len(recovery_records) == 1
    assert recovery_records[0].plan_digest == recovery.parameters[
        "expected_recovery_plan_digest"
    ]
    assert recovery_records[0].plan["plan_digest"] == recovery_records[0].plan_digest

    origin_results = store.get_trusted_result_records(origin.operation_id)
    assert [record.kind for record in origin_results] == [
        "execution",
        "verification",
        "recovery",
    ]
    completion_record = origin_results[-1]
    completion = completion_record.evidence
    expected = gateway._rebuild_origin_recovery_completion_evidence(
        recovery_operation=recovery,
    )
    assert validate_origin_recovery_completion_evidence(
        completion,
        expected=expected,
    ) == expected

    recovered_receipts = [
        receipt
        for receipt in store.get_final_write_receipts(origin.operation_id)
        if receipt.terminal_state == State.RECOVERED.value
    ]
    assert len(recovered_receipts) == 1
    assert recovered_receipts[0].body["evidence"] == completion
    assert recovered_receipts[0].body["receipt_details"] == {
        "operation_id": origin.operation_id,
        "operation_state": State.RECOVERED.value,
        "recovery_completion": completion,
        "recovery_completion_digest": completion_record.evidence_digest,
    }
    diagnostics = gateway.operation_diagnostics(
        context("token-completion-diagnostics"),
        company_id=origin.company_id,
        operation_id=origin.operation_id,
    )
    assert diagnostics["operation"]["state"] == State.RECOVERED.value
    assert diagnostics["operation"]["business_succeeded"] is False
    assert (
        diagnostics["verification"]["trusted_terminal_result_verified"]
        is False
    )
    assert diagnostics["recovery"]["lifecycle_status"] == "recovered_verified"
    assert diagnostics["recovery"]["completion_evidence_digest"] == (
        completion_record.evidence_digest
    )
    assert diagnostics["recovery"]["completion_receipt_id"] == (
        recovered_receipts[0].receipt_id
    )
    assert diagnostics["recovery"]["completion_receipt_body_digest"] == (
        recovered_receipts[0].body_digest
    )

    counts = (
        len(store.get_recovery_records(origin.operation_id)),
        len(store.get_trusted_result_records(origin.operation_id)),
        len(store.get_final_write_receipts(origin.operation_id)),
    )
    replay = gateway.result(
        context("token-completion-result-replay"),
        recovery.operation_id,
    )
    assert replay == output
    assert store.get_operation(origin.operation_id) == origin
    assert counts == (
        len(store.get_recovery_records(origin.operation_id)),
        len(store.get_trusted_result_records(origin.operation_id)),
        len(store.get_final_write_receipts(origin.operation_id)),
    )

    restarted_store = SQLitePersistence(store.path)
    restarted = _clone_service(
        gateway,
        IncidentBackend(),
        restarted_store,
    )
    restarted_output = restarted.result(
        context("token-completion-restart-replay"),
        recovery.operation_id,
    )
    assert restarted_output == output
    assert restarted_store.get_operation(origin.operation_id) == origin


def test_response_loss_after_recovery_receipt_resumes_origin_completion(
    service,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway, _unused_backend, store = service
    failed_origin, awaiting, context = _prepare_incident(gateway, store)
    original = gateway._complete_incident_origin_recovery

    def lose_response(**_kwargs):
        raise WriteServiceError(
            "simulated response loss before origin recovery completion"
        )

    monkeypatch.setattr(
        gateway,
        "_complete_incident_origin_recovery",
        lose_response,
    )
    with pytest.raises(WriteServiceError, match="simulated response loss"):
        gateway.approve_execute(
            context("token-completion-loss-execute"),
            _approval(awaiting, "approval-completion-loss"),
            reconciliation_only=False,
        )

    assert store.get_operation(awaiting.operation_id).state == State.COMPLETED
    assert store.get_operation(failed_origin.operation_id).state == State.FAILED

    monkeypatch.setattr(
        gateway,
        "_complete_incident_origin_recovery",
        original,
    )
    output = gateway.result(
        context("token-completion-loss-replay"),
        awaiting.operation_id,
    )
    assert output["operation_state"] == State.COMPLETED.value
    assert store.get_operation(failed_origin.operation_id).state == State.RECOVERED


def test_recovered_origin_replay_rejects_completion_evidence_tampering(
    service,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway, _unused_backend, store = service
    origin, recovery, context, _output = _complete_incident(gateway, store)
    durable = store.get_trusted_result_records(origin.operation_id)
    forged_evidence = copy.deepcopy(durable[-1].evidence)
    forged_evidence["odoo_readback_digest"] = "f" * 64
    forged = replace(
        durable[-1],
        evidence_json=canonical_json(forged_evidence).decode("utf-8"),
    )
    original = store.get_trusted_result_records

    def forged_results(operation_id):
        if operation_id == origin.operation_id:
            return (*durable[:-1], forged)
        return original(operation_id)

    monkeypatch.setattr(store, "get_trusted_result_records", forged_results)
    with pytest.raises(
        WriteServiceError,
        match="recovery completion evidence",
    ):
        gateway.result(
            context("token-completion-tamper-replay"),
            recovery.operation_id,
        )
    with pytest.raises(
        WriteServiceError,
        match="recovery completion evidence",
    ):
        gateway.operation_diagnostics(
            context("token-completion-tamper-diagnostics"),
            company_id=origin.company_id,
            operation_id=origin.operation_id,
        )


def test_recovered_diagnostics_selects_successful_attempt_from_multiple_bindings(
    service,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway, _unused_backend, store = service
    failed_origin, recovery, context, _output = _complete_incident(
        gateway,
        store,
    )
    origin = store.get_operation(failed_origin.operation_id)
    binding = store.get_recovery_operation_binding(recovery.operation_id)
    prior_recovery_id = "op-prior-failed-recovery"
    prior_event = replace(
        binding.audit_event,
        event_id="recovery-binding-op-prior-failed-recovery",
        operation_id=prior_recovery_id,
        payload={
            **binding.audit_event.payload,
            "recovery_operation_id": prior_recovery_id,
        },
    )
    prior_binding = replace(
        binding,
        binding_id=prior_event.event_id,
        recovery_operation_id=prior_recovery_id,
        audit_event=prior_event,
    )
    durable_events = store.audit_events()
    durable_binding_reader = store.get_recovery_operation_binding

    monkeypatch.setattr(
        store,
        "audit_events",
        lambda: (*durable_events, prior_event),
    )
    monkeypatch.setattr(
        store,
        "get_recovery_operation_binding",
        lambda operation_id: (
            prior_binding
            if operation_id == prior_recovery_id
            else durable_binding_reader(operation_id)
        ),
    )

    diagnostics = gateway.operation_diagnostics(
        context("token-completion-multiple-bindings"),
        company_id=origin.company_id,
        operation_id=origin.operation_id,
    )

    assert diagnostics["recovery"]["lifecycle_status"] == "recovered_verified"
    assert diagnostics["recovery"]["bound_operation_ids"] == sorted(
        [prior_recovery_id, recovery.operation_id]
    )
    assert diagnostics["recovery"]["completion_evidence_digest"] == (
        store.get_trusted_result_records(origin.operation_id)[-1].evidence_digest
    )


def test_recovered_diagnostics_rejects_receipt_pointing_to_unbound_attempt(
    service,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway, _unused_backend, store = service
    failed_origin, _recovery, context, _output = _complete_incident(
        gateway,
        store,
    )
    origin = store.get_operation(failed_origin.operation_id)
    durable_receipts = store.get_final_write_receipts(origin.operation_id)
    recovered_receipt = next(
        receipt
        for receipt in durable_receipts
        if receipt.terminal_state == State.RECOVERED.value
    )
    forged_body = copy.deepcopy(recovered_receipt.body)
    forged_body["receipt_details"]["recovery_completion"][
        "recovery_operation"
    ]["operation_id"] = "op-unbound-recovery"
    forged_receipt = replace(
        recovered_receipt,
        body_json=canonical_json(forged_body).decode("utf-8"),
    )
    durable_receipt_reader = store.get_final_write_receipts

    monkeypatch.setattr(
        store,
        "get_final_write_receipts",
        lambda operation_id: (
            tuple(
                forged_receipt if receipt == recovered_receipt else receipt
                for receipt in durable_receipts
            )
            if operation_id == origin.operation_id
            else durable_receipt_reader(operation_id)
        ),
    )

    with pytest.raises(
        OperationDiagnosticsError,
        match="unbound recovery operation",
    ):
        gateway.operation_diagnostics(
            context("token-completion-unbound-receipt"),
            company_id=origin.company_id,
            operation_id=origin.operation_id,
        )
