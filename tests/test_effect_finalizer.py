from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationError,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
    validate_effect_finalization_evidence,
    validate_effect_finalization_evidence_shape,
    verify_effect_attestation,
)
from odoo_accounting_cli_v3.operations import canonical_json


NOW = datetime(2026, 7, 18, 15, 0, tzinfo=timezone.utc)
SECRET = b"effect-finalizer-secret-material-32-bytes"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"


def _request() -> EffectFinalizationRequest:
    return EffectFinalizationRequest(
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        operation_id="op-finalize-1",
        operation_digest="1" * 64,
        execution_result_digest="2" * 64,
        resolution_operation_id="op-finalize-1",
        resolution_operation_digest="1" * 64,
        resolution_execution_result_digest="2" * 64,
        resolution_result_digest="3" * 64,
        resolution_kind="verified",
        verified_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _database_receipt(attestation, *, replayed: bool) -> dict[str, object]:
    return {
        "receipt_attestation_id": attestation.attestation_id,
        "receipt_guard_installation_id": INSTALLATION_ID,
        "receipt_database_oid": 16384,
        "receipt_database_uuid": DATABASE_UUID,
        "resolved_operation_id": "op-finalize-1",
        "receipt_resolution_operation_id": "op-finalize-1",
        "applied_resolution_kind": "verified",
        "resolved_anchor_count": 1,
        "remaining_unresolved_count": 0,
        "guard_epoch": 0,
        "receipt_attestation_digest": attestation.attestation_digest,
        "finalized_at": "2026-07-18T15:00:01Z",
        "finalized_txid": "9123",
        "replayed": replayed,
    }


def _validate_evidence(value, request: EffectFinalizationRequest):
    return validate_effect_finalization_evidence(
        value,
        intent=request.intent,
        expected_attestation_key_id="effect-finalizer-v1",
        expected_guard_installation_id=INSTALLATION_ID,
        expected_database_oid=16384,
    )


def test_effect_attestation_is_deterministic_content_bound_and_hmac_verified():
    request = _request()

    first = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    second = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )

    assert first == second
    verify_effect_attestation(
        first,
        request=request,
        expected_key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    with pytest.raises(EffectFinalizationError, match="binding"):
        verify_effect_attestation(
            first,
            request=replace(request, resolution_result_digest="4" * 64),
            expected_key_id="effect-finalizer-v1",
            secret=SECRET,
        )


def test_database_receipt_is_strictly_bound_and_replay_has_one_stable_digest():
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )

    first = EffectFinalizationReceipt.from_database_mapping(
        _database_receipt(attestation, replayed=False),
        request=request,
        attestation=attestation,
    )
    replay = EffectFinalizationReceipt.from_database_mapping(
        _database_receipt(attestation, replayed=True),
        request=request,
        attestation=attestation,
    )

    assert first.replayed is False
    assert replay.replayed is True
    assert first.evidence == replay.evidence
    assert first.receipt_digest == replay.receipt_digest
    assert first.evidence["receipt_digest"] == first.receipt_digest
    assert first.evidence["resolved_anchor_count"] == 1
    assert first.evidence["intent_digest"] == request.intent.intent_digest
    assert first.evidence["proof_verified_at"] == "2026-07-18T15:00:00Z"
    assert first.evidence["proof_expires_at"] == "2026-07-18T15:05:00Z"
    assert _validate_evidence(first.evidence, request) == first.evidence
    assert validate_effect_finalization_evidence_shape(first.evidence) == (
        first.evidence
    )


def test_database_receipt_normalizes_real_driver_uuid_and_datetime_types():
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    mapping = _database_receipt(attestation, replayed=False)
    mapping["receipt_attestation_id"] = uuid.UUID(attestation.attestation_id)
    mapping["receipt_guard_installation_id"] = uuid.UUID(INSTALLATION_ID)
    mapping["receipt_database_uuid"] = uuid.UUID(DATABASE_UUID)
    mapping["finalized_at"] = NOW + timedelta(seconds=1)

    receipt = EffectFinalizationReceipt.from_database_mapping(
        mapping,
        request=request,
        attestation=attestation,
    )

    assert receipt.attestation_id == attestation.attestation_id
    assert receipt.guard_installation_id == INSTALLATION_ID
    assert receipt.database_uuid == DATABASE_UUID
    assert receipt.evidence["finalized_at"] == "2026-07-18T15:00:01Z"


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("receipt_database_uuid", "33333333-3333-4333-8333-333333333333"),
        ("resolved_operation_id", "op-other"),
        ("receipt_attestation_digest", "f" * 64),
        ("resolved_anchor_count", 2),
    ),
)
def test_database_receipt_rejects_wrong_database_operation_proof_or_count(
    field: str,
    replacement: object,
):
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    mapping = _database_receipt(attestation, replayed=False)
    mapping[field] = replacement

    with pytest.raises(EffectFinalizationError, match="receipt"):
        EffectFinalizationReceipt.from_database_mapping(
            mapping,
            request=request,
            attestation=attestation,
        )


def test_finalization_request_rejects_noncanonical_identity_and_proof_window():
    request = _request()

    with pytest.raises(EffectFinalizationError, match="database"):
        replace(request, database_uuid="not-a-uuid")
    with pytest.raises(EffectFinalizationError, match="proof window"):
        replace(request, expires_at=NOW + timedelta(minutes=5, microseconds=1))
    with pytest.raises(EffectFinalizationError, match="verified resolution"):
        replace(request, resolution_operation_id="op-other")


def test_recovered_request_requires_a_distinct_resolution_operation():
    request = _request()

    with pytest.raises(EffectFinalizationError, match="distinct operation"):
        replace(request, resolution_kind="recovered")


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("receipt_database_oid", True),
        ("resolved_anchor_count", 1.0),
        ("remaining_unresolved_count", 0.0),
        ("guard_epoch", 0.0),
        ("finalized_txid", "09123"),
    ),
)
def test_database_receipt_rejects_type_confusion_and_noncanonical_txid(
    field: str,
    replacement: object,
):
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    mapping = _database_receipt(attestation, replayed=False)
    mapping[field] = replacement

    with pytest.raises(EffectFinalizationError, match="receipt"):
        EffectFinalizationReceipt.from_database_mapping(
            mapping,
            request=request,
            attestation=attestation,
        )


def test_persisted_evidence_rejects_bool_protocol_float_count_and_offset_time():
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    receipt = EffectFinalizationReceipt.from_database_mapping(
        _database_receipt(attestation, replayed=False),
        request=request,
        attestation=attestation,
    )

    for field, replacement in (
        ("protocol_version", True),
        ("resolved_anchor_count", 1.0),
        ("finalized_at", "2026-07-18T23:00:01+08:00"),
    ):
        evidence = {**receipt.evidence, field: replacement}
        if field != "protocol_version":
            # A forged self-digest must not make a non-canonical representation valid.
            stable = {
                key: value
                for key, value in evidence.items()
                if key != "receipt_digest"
            }
            evidence["receipt_digest"] = hashlib.sha256(
                canonical_json(stable)
            ).hexdigest()
        with pytest.raises(EffectFinalizationError, match="evidence"):
            _validate_evidence(evidence, request)


def test_persisted_evidence_is_bound_to_full_intent_and_pinned_finalizer_identity():
    request = _request()
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=SECRET,
    )
    receipt = EffectFinalizationReceipt.from_database_mapping(
        _database_receipt(attestation, replayed=False),
        request=request,
        attestation=attestation,
    )

    changed = replace(request.intent, resolution_result_digest="4" * 64)
    for kwargs in (
        {"intent": changed},
        {"expected_attestation_key_id": "effect-finalizer-v2"},
        {
            "expected_guard_installation_id": (
                "33333333-3333-4333-8333-333333333333"
            )
        },
        {"expected_database_oid": 16385},
    ):
        expected = {
            "intent": request.intent,
            "expected_attestation_key_id": "effect-finalizer-v1",
            "expected_guard_installation_id": INSTALLATION_ID,
            "expected_database_oid": 16384,
            **kwargs,
        }
        with pytest.raises(EffectFinalizationError, match="evidence"):
            validate_effect_finalization_evidence(receipt.evidence, **expected)
