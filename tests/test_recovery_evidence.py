from __future__ import annotations

import copy
import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
    trusted_result_envelope_digest,
)
from odoo_accounting_cli_v3.operations import (
    EXECUTION_RESULT_PURPOSE,
    RESULT_SIGNATURE_VERSION,
    VERIFICATION_RESULT_PURPOSE,
    Operation,
    ResultKind,
    State,
    TrustedResult,
    canonical_json,
)
from odoo_accounting_cli_v3.recovery_evidence import (
    ORIGIN_RECOVERY_COMPLETION_PURPOSE,
    ORIGIN_RECOVERY_COMPLETION_VERSION,
    OriginRecoveryCompletionError,
    OriginRecoveryCompletionEvidence,
    create_origin_recovery_completion_evidence,
    origin_recovery_completion_evidence_digest,
    validate_origin_recovery_completion_evidence,
)


NOW = datetime(2026, 7, 29, 8, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
DATABASE_UUID = "11111111-2222-4333-8444-555555555555"
GUARD_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _terminal_operation(
    *,
    operation_id: str,
    request_id: str,
    capability_id: str,
    parameters: dict[str, Any],
    state: State,
    execution_digest: str,
    verification_digest: str,
) -> Operation:
    prepared = Operation.prepare(
        operation_id=operation_id,
        request_id=request_id,
        capability_id=capability_id,
        parameters=parameters,
        principal="pi-agent:test-user",
        user_id=41,
        company_id=7,
        idempotency_key=f"idem:{operation_id}",
        odoo_instance_id="odoo-test",
        database_name="odoo_v3_test",
        database_uuid=DATABASE_UUID,
        environment="test",
        registry_digest=SHA_A,
        release_digest=SHA_B,
    )
    terminal = replace(
        prepared,
        precheck_digest=SHA_C,
        state=state,
        revision=6,
        approval_signature=SHA_D,
        approval_nonce_digest=SHA_E,
        approval_issued_at=NOW - timedelta(minutes=2),
        approval_expires_at=NOW + timedelta(minutes=8),
        approval_revision=2,
        approver_user_id=52,
        execution_result_digest=execution_digest,
        verification_result_digest=verification_digest,
    )
    terminal.assert_integrity()
    return terminal


def _result(
    operation: Operation,
    *,
    kind: ResultKind,
    revision: int,
    evidence: dict[str, Any],
    prior_evidence_digest: str | None,
    issued_at: datetime,
) -> TrustedResult:
    return TrustedResult(
        kind=kind,
        operation_id=operation.operation_id,
        request_id=operation.request_id,
        operation_digest=operation.digest,
        operation_state_digest=SHA_F,
        operation_revision=revision,
        company_id=operation.company_id,
        issuer="odoo-write-backend",
        key_id="write-result-key",
        succeeded=True,
        evidence_digest=_digest(evidence),
        prior_evidence_digest=prior_evidence_digest,
        issued_at=issued_at,
        signature_version=RESULT_SIGNATURE_VERSION,
        signature_purpose=(
            EXECUTION_RESULT_PURPOSE
            if kind == ResultKind.EXECUTION
            else VERIFICATION_RESULT_PURPOSE
        ),
        signature=SHA_A if kind == ResultKind.EXECUTION else SHA_B,
    )


def _result_id(result: TrustedResult) -> str:
    return "trusted-result:" + _digest(result.payload())


def _receipt_id(
    operation: Operation,
    *,
    result_id: str,
    body_digest: str,
) -> str:
    return "final-write-receipt:" + _digest(
        {
            "body_digest": body_digest,
            "operation_id": operation.operation_id,
            "operation_revision": operation.revision,
            "result_id": result_id,
        }
    )


def _valid_inputs() -> dict[str, Any]:
    plan_digest = _digest(
        {
            "origin_operation_id": "origin-op",
            "method": "account.move.reverse.v1",
        }
    )
    origin = _terminal_operation(
        operation_id="origin-op",
        request_id="origin-request",
        capability_id="acct.invoice.customer.create.v1",
        parameters={"company_id": 7, "amount": "100.00"},
        state=State.FAILED,
        execution_digest=SHA_D,
        verification_digest=SHA_E,
    )
    recovery = _terminal_operation(
        operation_id="recovery-op",
        request_id="recovery-request",
        capability_id="acct.recovery.execute.v1",
        parameters={
            "company_id": 7,
            "origin_operation_id": origin.operation_id,
            "expected_recovery_plan_digest": plan_digest,
        },
        state=State.COMPLETED,
        execution_digest=SHA_A,
        verification_digest=SHA_B,
    )
    records = [
        {
            "model": "account.move",
            "record_id": 901,
            "company_id": 7,
            "record_state": "posted",
            "record_fingerprint": SHA_C,
        }
    ]
    execution_evidence = {
        "operation_id": recovery.operation_id,
        "capability_id": recovery.capability_id,
        "succeeded": True,
        "odoo_records": records,
        "difference": {"before": ["origin"], "after": ["reversal"]},
        "recovery_plan": {"status": "not_applicable"},
        "recovery_parameters": {},
        "module_graph": {"digest": SHA_D},
        "failure_checks": [],
    }
    fresh_snapshots = [
        {
            "model": "account.move",
            "record_id": 901,
            "exists": True,
            "record_state": "posted",
            "values_digest": SHA_E,
            "values_json": "{}",
        }
    ]
    readback = {
        "company_id": recovery.company_id,
        "records": records,
        "fresh_snapshots": fresh_snapshots,
        "fresh_snapshots_digest": _digest(fresh_snapshots),
        "request_parameters_digest": _digest(recovery.parameters),
        "control_anchor": {"state": "verified"},
    }
    verification_evidence = {
        "operation_id": recovery.operation_id,
        "capability_id": recovery.capability_id,
        "passed": True,
        "method": "recovery_compensation_readback",
        "checks": ["record_exists", "compensation_balances"],
        "verified_at": (NOW - timedelta(seconds=1)).isoformat(),
        "readback": readback,
    }
    recovery = replace(
        recovery,
        execution_result_digest=_digest(execution_evidence),
        verification_result_digest=_digest(verification_evidence),
    )
    recovery.assert_integrity()
    execution_result = _result(
        recovery,
        kind=ResultKind.EXECUTION,
        revision=recovery.revision - 2,
        evidence=execution_evidence,
        prior_evidence_digest=None,
        issued_at=NOW - timedelta(seconds=3),
    )
    verification_result = _result(
        recovery,
        kind=ResultKind.VERIFICATION,
        revision=recovery.revision - 1,
        evidence=verification_evidence,
        prior_evidence_digest=execution_result.evidence_digest,
        issued_at=NOW - timedelta(seconds=1),
    )
    intent = EffectFinalizationIntent(
        database_name=recovery.database_name,
        database_uuid=recovery.database_uuid,
        operation_id=origin.operation_id,
        operation_digest=origin.digest,
        execution_result_digest=SHA_D,
        resolution_operation_id=recovery.operation_id,
        resolution_operation_digest=recovery.digest,
        resolution_execution_result_digest=trusted_result_envelope_digest(
            execution_result,
            recovery,
        ),
        resolution_result_digest=trusted_result_envelope_digest(
            verification_result,
            recovery,
        ),
        resolution_kind="recovered",
    )
    finalization_request = EffectFinalizationRequest.from_intent(
        intent,
        verified_at=NOW - timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=58),
    )
    attestation = create_effect_attestation(
        finalization_request,
        key_id="effect-key",
        secret=b"e" * 32,
    )
    finalization = EffectFinalizationReceipt(
        request_digest=finalization_request.request_digest,
        intent_digest=intent.intent_digest,
        attestation_id=attestation.attestation_id,
        attestation_digest=attestation.attestation_digest,
        attestation_key_id="effect-key",
        guard_installation_id=GUARD_UUID,
        database_oid=16384,
        database_uuid=DATABASE_UUID,
        operation_id=origin.operation_id,
        resolution_operation_id=recovery.operation_id,
        resolution_kind="recovered",
        resolved_anchor_count=2,
        remaining_unresolved_count=0,
        guard_epoch=4,
        proof_verified_at=NOW - timedelta(seconds=2),
        proof_expires_at=NOW + timedelta(seconds=58),
        finalized_at=NOW,
        finalized_txid="271828",
        replayed=False,
    ).evidence
    audit_event_id = "operation.completed:" + SHA_C
    audit_event_hash = SHA_D
    verification_result_id = _result_id(verification_result)
    receipt_details = {
        "operation_id": recovery.operation_id,
        "operation_state": State.COMPLETED.value,
        "odoo_records": records,
        "difference": execution_evidence["difference"],
        "verification": {
            "method": verification_evidence["method"],
            "passed": True,
            "checks": verification_evidence["checks"],
            "evidence_digest": verification_result.evidence_digest,
            "verified_at": verification_evidence["verified_at"],
        },
        "database_finalization": finalization,
        "recovery_plan": execution_evidence["recovery_plan"],
        "capability_channel": "staged",
    }
    final_receipt_body = {
        "audit_event_hash": audit_event_hash,
        "audit_event_id": audit_event_id,
        "audit_sequence": 19,
        "capability_id": recovery.capability_id,
        "company_id": recovery.company_id,
        "database_name": recovery.database_name,
        "database_uuid": recovery.database_uuid,
        "environment": recovery.environment,
        "evidence": verification_evidence,
        "evidence_digest": verification_result.evidence_digest,
        "odoo_instance_id": recovery.odoo_instance_id,
        "operation_digest": recovery.digest,
        "operation_id": recovery.operation_id,
        "operation_revision": recovery.revision,
        "precheck_digest": recovery.precheck_digest,
        "principal": recovery.principal,
        "protocol_version": recovery.protocol_version,
        "receipt_details": receipt_details,
        "registry_digest": recovery.registry_digest,
        "release_digest": recovery.release_digest,
        "request_id": recovery.request_id,
        "result_id": verification_result_id,
        "result_kind": ResultKind.VERIFICATION.value,
        "result_record_hash": SHA_F,
        "result_succeeded": True,
        "schema_version": 4,
        "terminal_state": State.COMPLETED.value,
        "user_id": recovery.user_id,
    }
    body_digest = _digest(final_receipt_body)
    return {
        "origin_operation": origin,
        "recovery_operation": recovery,
        "recovery_plan_digest": plan_digest,
        "recovery_execution_result": execution_result,
        "recovery_execution_evidence": execution_evidence,
        "recovery_verification_result": verification_result,
        "recovery_verification_evidence": verification_evidence,
        "recovery_final_receipt_id": _receipt_id(
            recovery,
            result_id=verification_result_id,
            body_digest=body_digest,
        ),
        "recovery_final_receipt_body": final_receipt_body,
        "recovery_final_receipt_body_digest": body_digest,
        "terminal_audit_event_id": audit_event_id,
        "terminal_audit_event_hash": audit_event_hash,
        "database_finalization": finalization,
    }


def _create() -> OriginRecoveryCompletionEvidence:
    return create_origin_recovery_completion_evidence(**_valid_inputs())


def _at(document: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    target = document
    for key in path:
        target = target[key]
    return target


def test_create_is_deterministic_immutable_and_detached() -> None:
    first = _create()
    second = _create()

    assert first == second
    assert first.protocol_version == ORIGIN_RECOVERY_COMPLETION_VERSION
    assert first.purpose == ORIGIN_RECOVERY_COMPLETION_PURPOSE
    assert first.origin_operation.state == "failed"
    assert first.recovery_operation.state == "completed"
    assert first.recovery_operation.capability_id == "acct.recovery.execute.v1"
    assert origin_recovery_completion_evidence_digest(first) == _digest(
        first.to_dict()
    )
    with pytest.raises(FrozenInstanceError):
        first.recovery_plan_digest = SHA_A  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        first.origin_operation.operation_id = "changed"  # type: ignore[misc]

    detached = first.to_dict()
    detached["origin_operation"]["operation_id"] = "changed"
    assert first.origin_operation.operation_id == "origin-op"


def test_validate_rebuilds_exact_evidence() -> None:
    expected = _create()
    actual = validate_origin_recovery_completion_evidence(
        expected.to_dict(),
        expected=expected,
    )
    assert actual == expected


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "unexpected"),
        (("origin_operation",), "unexpected"),
        (("recovery_operation",), "unexpected"),
        (("execution_result",), "unexpected"),
        (("verification_result",), "unexpected"),
        (("recovery_final_receipt",), "unexpected"),
    ],
)
def test_validate_rejects_extra_fields(
    path: tuple[str, ...],
    field: str,
) -> None:
    expected = _create()
    document = expected.to_dict()
    _at(document, path)[field] = "not allowed"
    with pytest.raises(OriginRecoveryCompletionError, match="fields"):
        validate_origin_recovery_completion_evidence(document, expected=expected)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "purpose"),
        (("origin_operation",), "operation_id"),
        (("recovery_operation",), "operation_digest"),
        (("execution_result",), "envelope_digest"),
        (("verification_result",), "evidence_digest"),
        (("recovery_final_receipt",), "body_digest"),
    ],
)
def test_validate_rejects_missing_fields(
    path: tuple[str, ...],
    field: str,
) -> None:
    expected = _create()
    document = expected.to_dict()
    del _at(document, path)[field]
    with pytest.raises(OriginRecoveryCompletionError, match="fields"):
        validate_origin_recovery_completion_evidence(document, expected=expected)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("protocol_version",), 2),
        (("purpose",), "wrong"),
        (("origin_operation", "state"), "completed"),
        (("recovery_operation", "state"), "failed"),
        (("recovery_operation", "capability_id"), "acct.move.reverse.v1"),
        (("recovery_operation", "company_id"), 8),
        (("execution_result", "kind"), "verification"),
        (("execution_result", "operation_id"), "origin-op"),
        (("execution_result", "operation_revision"), 5),
        (("verification_result", "kind"), "execution"),
        (("verification_result", "operation_id"), "origin-op"),
        (("verification_result", "operation_revision"), 4),
        (("recovery_final_receipt", "result_id"), "trusted-result:" + SHA_A),
        (("recovery_final_receipt", "evidence_digest"), SHA_C),
        (("recovery_plan_digest",), SHA_F),
        (("database_finalization_digest",), SHA_F),
        (("odoo_records_digest",), SHA_F),
        (("odoo_readback_digest",), SHA_F),
    ],
)
def test_validate_rejects_tampering(
    path: tuple[str, ...],
    replacement: Any,
) -> None:
    expected = _create()
    document = expected.to_dict()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(OriginRecoveryCompletionError):
        validate_origin_recovery_completion_evidence(document, expected=expected)


def test_validate_rejects_a_different_expected_source_set() -> None:
    actual = _create()
    kwargs = _valid_inputs()
    kwargs["recovery_final_receipt_body"] = copy.deepcopy(
        kwargs["recovery_final_receipt_body"]
    )
    kwargs["terminal_audit_event_hash"] = SHA_E
    kwargs["recovery_final_receipt_body"]["audit_event_hash"] = SHA_E
    kwargs["recovery_final_receipt_body_digest"] = _digest(
        kwargs["recovery_final_receipt_body"]
    )
    kwargs["recovery_final_receipt_id"] = _receipt_id(
        kwargs["recovery_operation"],
        result_id=kwargs["recovery_final_receipt_body"]["result_id"],
        body_digest=kwargs["recovery_final_receipt_body_digest"],
    )
    different = create_origin_recovery_completion_evidence(**kwargs)

    with pytest.raises(OriginRecoveryCompletionError, match="expected"):
        validate_origin_recovery_completion_evidence(
            actual.to_dict(),
            expected=different,
        )


@pytest.mark.parametrize(
    ("field", "mutation", "message"),
    [
        (
            "origin_operation",
            lambda value: replace(value, state=State.COMPLETED),
            "origin operation",
        ),
        (
            "recovery_operation",
            lambda value: replace(value, state=State.FAILED),
            "recovery operation",
        ),
        (
            "recovery_operation",
            lambda value: replace(value, capability_id="acct.move.reverse.v1"),
            "immutable content",
        ),
        (
            "recovery_operation",
            lambda value: replace(value, company_id=8),
            "immutable content",
        ),
        (
            "recovery_plan_digest",
            lambda _value: "not-a-digest",
            "plan",
        ),
        (
            "recovery_execution_result",
            lambda value: replace(value, succeeded=False),
            "execution result",
        ),
        (
            "recovery_execution_result",
            lambda value: replace(value, kind=ResultKind.VERIFICATION),
            "execution result",
        ),
        (
            "recovery_verification_result",
            lambda value: replace(value, succeeded=False),
            "verification result",
        ),
        (
            "recovery_verification_result",
            lambda value: replace(value, prior_evidence_digest=SHA_F),
            "verification result",
        ),
        (
            "recovery_execution_evidence",
            lambda value: {**value, "unexpected": True},
            "execution evidence fields",
        ),
        (
            "recovery_verification_evidence",
            lambda value: {**value, "unexpected": True},
            "verification evidence fields",
        ),
        (
            "recovery_final_receipt_body_digest",
            lambda _value: SHA_F,
            "receipt body digest",
        ),
        (
            "recovery_final_receipt_id",
            lambda _value: "final-write-receipt:" + SHA_F,
            "receipt ID",
        ),
        (
            "terminal_audit_event_hash",
            lambda _value: SHA_F,
            "audit",
        ),
    ],
)
def test_create_rejects_invalid_source_bindings(
    field: str,
    mutation: Any,
    message: str,
) -> None:
    kwargs = _valid_inputs()
    kwargs[field] = mutation(kwargs[field])
    with pytest.raises(OriginRecoveryCompletionError, match=message):
        create_origin_recovery_completion_evidence(**kwargs)


def test_create_rejects_recovery_parameters_not_bound_to_origin() -> None:
    kwargs = _valid_inputs()
    recovery = kwargs["recovery_operation"]
    parameters = {
        **recovery.parameters,
        "origin_operation_id": "different-origin",
    }
    kwargs["recovery_operation"] = Operation.prepare(
        operation_id=recovery.operation_id,
        request_id=recovery.request_id,
        capability_id=recovery.capability_id,
        parameters=parameters,
        principal=recovery.principal,
        user_id=recovery.user_id,
        company_id=recovery.company_id,
        idempotency_key=recovery.idempotency_key,
        odoo_instance_id=recovery.odoo_instance_id,
        database_name=recovery.database_name,
        database_uuid=recovery.database_uuid,
        environment=recovery.environment,
        registry_digest=recovery.registry_digest,
        release_digest=recovery.release_digest,
    )
    kwargs["recovery_operation"] = replace(
        kwargs["recovery_operation"],
        precheck_digest=recovery.precheck_digest,
        state=recovery.state,
        revision=recovery.revision,
        approval_signature=recovery.approval_signature,
        approval_nonce_digest=recovery.approval_nonce_digest,
        approval_issued_at=recovery.approval_issued_at,
        approval_expires_at=recovery.approval_expires_at,
        approval_revision=recovery.approval_revision,
        approver_user_id=recovery.approver_user_id,
        execution_result_digest=recovery.execution_result_digest,
        verification_result_digest=recovery.verification_result_digest,
    )
    with pytest.raises(OriginRecoveryCompletionError, match="parameters"):
        create_origin_recovery_completion_evidence(**kwargs)


def test_create_rejects_result_evidence_digest_mismatch() -> None:
    kwargs = _valid_inputs()
    kwargs["recovery_execution_evidence"] = copy.deepcopy(
        kwargs["recovery_execution_evidence"]
    )
    kwargs["recovery_execution_evidence"]["difference"]["after"] = ["tampered"]
    with pytest.raises(OriginRecoveryCompletionError, match="evidence digest"):
        create_origin_recovery_completion_evidence(**kwargs)


def test_create_rejects_readback_records_different_from_execution() -> None:
    kwargs = _valid_inputs()
    kwargs["recovery_verification_evidence"] = copy.deepcopy(
        kwargs["recovery_verification_evidence"]
    )
    kwargs["recovery_verification_evidence"]["readback"]["records"][0][
        "record_id"
    ] = 902
    changed = kwargs["recovery_verification_evidence"]
    kwargs["recovery_verification_result"] = replace(
        kwargs["recovery_verification_result"],
        evidence_digest=_digest(changed),
    )
    with pytest.raises(OriginRecoveryCompletionError, match="readback"):
        create_origin_recovery_completion_evidence(**kwargs)


def test_create_rejects_fresh_snapshot_digest_mismatch() -> None:
    kwargs = _valid_inputs()
    kwargs["recovery_verification_evidence"] = copy.deepcopy(
        kwargs["recovery_verification_evidence"]
    )
    kwargs["recovery_verification_evidence"]["readback"][
        "fresh_snapshots_digest"
    ] = SHA_F
    changed = kwargs["recovery_verification_evidence"]
    kwargs["recovery_verification_result"] = replace(
        kwargs["recovery_verification_result"],
        evidence_digest=_digest(changed),
    )
    with pytest.raises(OriginRecoveryCompletionError, match="fresh snapshots"):
        create_origin_recovery_completion_evidence(**kwargs)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("operation_id", "different", "receipt body"),
        ("result_id", "trusted-result:" + SHA_F, "receipt body"),
        ("result_succeeded", False, "receipt body"),
        ("audit_event_hash", SHA_F, "audit"),
        ("evidence_digest", SHA_F, "receipt body"),
    ],
)
def test_create_rejects_final_receipt_body_tampering(
    field: str,
    replacement: Any,
    message: str,
) -> None:
    kwargs = _valid_inputs()
    body = copy.deepcopy(kwargs["recovery_final_receipt_body"])
    body[field] = replacement
    kwargs["recovery_final_receipt_body"] = body
    kwargs["recovery_final_receipt_body_digest"] = _digest(body)
    kwargs["recovery_final_receipt_id"] = _receipt_id(
        kwargs["recovery_operation"],
        result_id=body["result_id"],
        body_digest=kwargs["recovery_final_receipt_body_digest"],
    )
    with pytest.raises(OriginRecoveryCompletionError, match=message):
        create_origin_recovery_completion_evidence(**kwargs)


def test_create_rejects_final_receipt_extra_field() -> None:
    kwargs = _valid_inputs()
    body = copy.deepcopy(kwargs["recovery_final_receipt_body"])
    body["unexpected"] = True
    kwargs["recovery_final_receipt_body"] = body
    kwargs["recovery_final_receipt_body_digest"] = _digest(body)
    with pytest.raises(OriginRecoveryCompletionError, match="receipt body fields"):
        create_origin_recovery_completion_evidence(**kwargs)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("operation_id", "different-origin", "finalization"),
        ("resolution_operation_id", "different-recovery", "finalization"),
        ("resolution_kind", "verified", "finalization"),
        ("remaining_unresolved_count", 1, "unresolved"),
    ],
)
def test_create_rejects_database_finalization_tampering(
    field: str,
    replacement: Any,
    message: str,
) -> None:
    kwargs = _valid_inputs()
    finalization = copy.deepcopy(kwargs["database_finalization"])
    finalization[field] = replacement
    stable = {key: value for key, value in finalization.items() if key != "receipt_digest"}
    finalization["receipt_digest"] = _digest(stable)
    kwargs["database_finalization"] = finalization
    body = copy.deepcopy(kwargs["recovery_final_receipt_body"])
    body["receipt_details"]["database_finalization"] = finalization
    kwargs["recovery_final_receipt_body"] = body
    kwargs["recovery_final_receipt_body_digest"] = _digest(body)
    kwargs["recovery_final_receipt_id"] = _receipt_id(
        kwargs["recovery_operation"],
        result_id=body["result_id"],
        body_digest=kwargs["recovery_final_receipt_body_digest"],
    )
    with pytest.raises(OriginRecoveryCompletionError, match=message):
        create_origin_recovery_completion_evidence(**kwargs)


def test_digest_rejects_mutable_or_unvalidated_input() -> None:
    with pytest.raises(OriginRecoveryCompletionError, match="validated"):
        origin_recovery_completion_evidence_digest({})  # type: ignore[arg-type]
