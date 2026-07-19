from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationReceipt,
)
from odoo_accounting_cli_v3.effect_finalizer_service import (
    EffectFinalizationAttemptExpired,
    EffectFinalizationIntent,
    EffectFinalizerAttemptJournal,
    EffectFinalizerService,
    EffectFinalizerServiceError,
    effect_finalization_intent_from_mapping,
)


NOW = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
SECRET = b"finalizer-service-secret-material-32-bytes"


def _intent() -> EffectFinalizationIntent:
    return EffectFinalizationIntent(
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        operation_id="op-finalize-1",
        operation_digest="0" * 64,
        execution_result_digest="1" * 64,
        resolution_operation_id="op-finalize-1",
        resolution_operation_digest="0" * 64,
        resolution_execution_result_digest="1" * 64,
        resolution_result_digest="3" * 64,
        resolution_kind="verified",
    )


def _receipt(request, attestation, *, replayed: bool) -> EffectFinalizationReceipt:
    return EffectFinalizationReceipt.from_database_mapping(
        {
            "receipt_attestation_id": attestation.attestation_id,
            "receipt_guard_installation_id": INSTALLATION_ID,
            "receipt_database_oid": 16384,
            "receipt_database_uuid": DATABASE_UUID,
            "resolved_operation_id": request.operation_id,
            "receipt_resolution_operation_id": request.resolution_operation_id,
            "applied_resolution_kind": request.resolution_kind,
            "resolved_anchor_count": 1,
            "remaining_unresolved_count": 0,
            "guard_epoch": 0,
            "receipt_attestation_digest": attestation.attestation_digest,
            "finalized_at": "2026-07-19T02:00:01Z",
            "finalized_txid": "9123",
            "replayed": replayed,
        },
        request=request,
        attestation=attestation,
    )


def test_intent_is_time_free_strict_and_content_bound() -> None:
    intent = _intent()

    assert "verified_at" not in intent.payload()
    assert "expires_at" not in intent.payload()
    assert effect_finalization_intent_from_mapping(intent.payload()) == intent
    assert len(intent.intent_digest) == 64
    assert replace(intent, resolution_result_digest="4" * 64).intent_digest != intent.intent_digest

    invalid = intent.payload()
    invalid["unexpected"] = True
    with pytest.raises(EffectFinalizerServiceError, match="fields"):
        effect_finalization_intent_from_mapping(invalid)


def test_service_persists_attempt_before_database_and_replays_after_response_loss(
    tmp_path,
) -> None:
    journal = EffectFinalizerAttemptJournal(
        tmp_path / "attempts.sqlite3", require_posix_owner=False
    )
    observations = []

    def database_finalize(request, attestation):
        attempts = journal.attempts_for(_intent().intent_digest)
        observations.append((request, attestation, attempts))
        assert len(attempts) == 1
        assert attempts[0].request == request
        assert attempts[0].attestation == attestation
        return _receipt(request, attestation, replayed=len(observations) > 1)

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: NOW,
        proof_ttl_seconds=120,
    )

    first = service.finalize(_intent())
    replay = service.finalize(_intent())

    assert len(observations) == 2
    assert observations[0][0] == observations[1][0]
    assert observations[0][1] == observations[1][1]
    assert first.evidence == replay.evidence
    assert journal.attempts_for(_intent().intent_digest)[0].receipt_evidence == first.evidence


def test_committed_journal_outcome_replays_at_a_later_time_without_rewriting_timestamp(
    tmp_path,
) -> None:
    clock = [NOW]
    journal = EffectFinalizerAttemptJournal(
        tmp_path / "attempts.sqlite3", require_posix_owner=False
    )

    def database_finalize(request, attestation):
        return _receipt(request, attestation, replayed=clock[0] != NOW)

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: clock[0],
        proof_ttl_seconds=120,
    )
    first = service.finalize(_intent())
    clock[0] = NOW + timedelta(minutes=4)

    replay = service.finalize(_intent())

    assert replay.evidence == first.evidence
    assert len(journal.attempts_for(_intent().intent_digest)) == 1


def test_expired_uncommitted_attempt_is_probed_then_superseded_by_fresh_attempt(
    tmp_path,
) -> None:
    clock = [NOW]
    journal = EffectFinalizerAttemptJournal(
        tmp_path / "attempts.sqlite3", require_posix_owner=False
    )
    calls = []

    def database_finalize(request, attestation):
        calls.append((request, attestation))
        if len(calls) == 1:
            raise RuntimeError("response lost")
        if len(calls) == 2:
            raise EffectFinalizationAttemptExpired("not committed")
        return _receipt(request, attestation, replayed=False)

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: clock[0],
        proof_ttl_seconds=60,
    )

    with pytest.raises(RuntimeError, match="response lost"):
        service.finalize(_intent())
    first_request = calls[0][0]
    clock[0] = NOW + timedelta(minutes=2)

    receipt = service.finalize(_intent())

    assert calls[1][0] == first_request
    assert calls[2][0] != first_request
    assert calls[2][0].verified_at == clock[0]
    attempts = journal.attempts_for(_intent().intent_digest)
    assert len(attempts) == 2
    assert attempts[0].expired_uncommitted_at == clock[0]
    assert attempts[1].receipt_evidence == receipt.evidence


def test_nonexpired_database_failure_never_mints_a_second_attempt(tmp_path) -> None:
    journal = EffectFinalizerAttemptJournal(
        tmp_path / "attempts.sqlite3", require_posix_owner=False
    )

    def database_finalize(_request, _attestation):
        raise RuntimeError("database unavailable")

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: NOW,
        proof_ttl_seconds=120,
    )

    for _ in range(2):
        with pytest.raises(RuntimeError, match="database unavailable"):
            service.finalize(_intent())

    assert len(journal.attempts_for(_intent().intent_digest)) == 1


def test_repeated_expiry_is_bounded_to_one_refresh_per_call(tmp_path) -> None:
    clock = [NOW + timedelta(minutes=10)]
    journal = EffectFinalizerAttemptJournal(
        tmp_path / "attempts.sqlite3", require_posix_owner=False
    )
    calls = []

    def database_finalize(request, _attestation):
        calls.append(request)
        raise EffectFinalizationAttemptExpired("not committed")

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: clock[0],
        proof_ttl_seconds=60,
    )

    # Move the clock past each newly-created proof before the DB result is
    # interpreted, modeling a persistently slower DB attempt.
    def expiring_database_finalize(request, attestation):
        clock[0] = request.expires_at
        return database_finalize(request, attestation)

    service._database_finalize = expiring_database_finalize
    with pytest.raises(EffectFinalizerServiceError, match="refresh limit"):
        service.finalize(_intent())

    assert len(calls) == 2
    assert len(journal.attempts_for(_intent().intent_digest)) == 2


def test_service_reverifies_journal_attestation_hmac_before_database_retry(
    tmp_path,
) -> None:
    path = tmp_path / "attempts.sqlite3"
    journal = EffectFinalizerAttemptJournal(path, require_posix_owner=False)
    calls = []

    def database_finalize(_request, _attestation):
        calls.append(True)
        raise RuntimeError("response lost")

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id="effect-finalizer-v1",
        secret=SECRET,
        now=lambda: NOW,
        proof_ttl_seconds=120,
    )
    with pytest.raises(RuntimeError, match="response lost"):
        service.finalize(_intent())

    connection = sqlite3.connect(path)
    raw = connection.execute(
        "SELECT attestation_json FROM finalization_attempt"
    ).fetchone()[0]
    tampered = json.loads(raw)
    tampered["attestation_digest"] = "0" * 64
    connection.execute(
        "UPDATE finalization_attempt SET attestation_json = ?",
        (json.dumps(tampered, sort_keys=True, separators=(",", ":")),),
    )
    connection.commit()
    connection.close()

    with pytest.raises(EffectFinalizerServiceError, match="attestation"):
        service.finalize(_intent())
    assert len(calls) == 1
