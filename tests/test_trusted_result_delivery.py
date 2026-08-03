from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from odoo_accounting_cli_v3.auth import authentication_request_digest
from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
)
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    canonical_json,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.persistence import (
    GENESIS_HASH,
    PersistenceIntegrityError,
    SQLitePersistence,
    _VERIFIED_READ_RESULT_COLUMNS,
    _audit_hash,
    _verified_read_result_record_hash,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.trusted_authority import TrustedSession
from odoo_accounting_cli_v3.trusted_broker import (
    TrustedBroker,
    TrustedBrokerError,
    TrustedDeliveredResult,
)
from odoo_accounting_cli_v3.trusted_result_delivery import (
    ResultDeliveryRoute,
    TrustedResultDeliveryError,
    TrustedResultDeliveryResolver,
)
from odoo_accounting_cli_v3.write_receipts import (
    RESULT_BODY_FIELDS,
    WriteReceiptError,
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    verify_write_audit_receipt,
)


NOW = datetime(2026, 8, 3, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
CURRENT_RELEASE = "1" * 64
CURRENT_REGISTRY = "2" * 64
OLD_RELEASE = "3" * 64
OLD_REGISTRY = "4" * 64
READ_KEY_ID = "read-receipt-key-v1"
READ_SECRET = b"read-receipt-secret-material-32-bytes"
APPROVAL_KEY_ID = "approval-key-v1"
APPROVAL_SECRET = b"approval-secret-material-32-bytes!"
EXECUTION_KEY_ID = "execution-key-v1"
EXECUTION_SECRET = b"execution-secret-material-32-bytes"
VERIFICATION_KEY_ID = "verification-key-v1"
VERIFICATION_SECRET = b"verification-secret-material-32bytes"
WRITE_KEY_ID = "historical-write-key-v1"
OLD_WRITE_SECRET = b"historical-write-secret-material-32b"
CURRENT_WRITE_SECRET = b"current-write-secret-material-32-byte"
CAPABILITY_ID = "acct.invoice.customer_create.v1"
READ_CAPABILITY_ID = "acct.gl.trial_balance.v1"


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _session(**overrides: Any) -> TrustedSession:
    values: dict[str, Any] = {
        "session_id": "trusted-session-result-delivery-1",
        "principal": "pi:user-42",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": DATABASE_UUID,
        "user_id": 42,
        "company_id": 7,
        "allowed_company_ids": frozenset({7}),
        "environment": "sandbox",
        "release_digest": CURRENT_RELEASE,
        "registry_digest": CURRENT_REGISTRY,
        "issued_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(minutes=30),
    }
    values.update(overrides)
    return TrustedSession(**values)


def _read_store(path: Path) -> SQLitePersistence:
    return SQLitePersistence(
        path,
        receipt_key_id=READ_KEY_ID,
        receipt_secret=READ_SECRET,
        enable_verified_read_results=True,
    )


def _persist_read(
    path: Path,
    *,
    capability_id: str = READ_CAPABILITY_ID,
    receipt_id: str = "read-result-receipt-1",
) -> tuple[SQLitePersistence, dict[str, Any], dict[str, Any], dict[str, Any]]:
    store = _read_store(path)
    parameters = {"company_id": 7, "date_to": "2026-08-03"}
    result = {"lines": [], "page": {"total_count": 0}}
    receipt = create_read_receipt(
        receipt_id=receipt_id,
        capability_id=capability_id,
        parameters=parameters,
        result_body=result,
        auth_token_id=f"auth-{receipt_id}",
        principal="pi:user-42",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        company_id=7,
        user_id=42,
        registry_digest=CURRENT_REGISTRY,
        release_digest=CURRENT_RELEASE,
        environment="sandbox",
        capability_channel="staged",
        record_count=0,
        observed_at=NOW - timedelta(seconds=1),
        key_id=READ_KEY_ID,
        secret=READ_SECRET,
    )
    store.record_verified_read(
        receipt=receipt,
        capability_id=capability_id,
        parameters=parameters,
        result_body=result,
        auth_token_id=f"auth-{receipt_id}",
        principal="pi:user-42",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        company_id=7,
        user_id=42,
        registry_digest=CURRENT_REGISTRY,
        release_digest=CURRENT_RELEASE,
        environment="sandbox",
        capability_channel="staged",
        expected_record_count=0,
        now=NOW,
    )
    locator = {
        "action": "read",
        "business_succeeded": True,
        "capability_id": capability_id,
        "operation_id": None,
        "receipt_id": receipt_id,
        "result_digest": receipt["result_digest"],
        "status": "verified_success",
    }
    return store, result, receipt, locator


def _resolver(
    *,
    read_store: SQLitePersistence,
    write_store: SQLitePersistence,
    routes: dict[tuple[str, str], ResultDeliveryRoute] | None = None,
    route_calls: list[tuple[str, str]] | None = None,
) -> TrustedResultDeliveryResolver:
    def resolve_route(
        release_digest: str, registry_digest: str
    ) -> ResultDeliveryRoute | None:
        if route_calls is not None:
            route_calls.append((release_digest, registry_digest))
        return (routes or {}).get((release_digest, registry_digest))

    return TrustedResultDeliveryResolver(
        current_release_digest=CURRENT_RELEASE,
        current_registry_digest=CURRENT_REGISTRY,
        read_store=read_store,
        write_store=write_store,
        route_resolver=resolve_route,
        clock=lambda: NOW,
    )


def _copy_delivered(
    delivered: TrustedDeliveredResult,
    *,
    result_type: type[TrustedDeliveredResult] = TrustedDeliveredResult,
    business_result: dict[str, Any] | None = None,
    audit_receipt: dict[str, Any] | None = None,
) -> TrustedDeliveredResult:
    return result_type(
        action=delivered.action,
        capability_id=delivered.capability_id,
        operation_id=delivered.operation_id,
        receipt_id=delivered.receipt_id,
        result_digest=delivered.result_digest,
        principal=delivered.principal,
        user_id=delivered.user_id,
        company_id=delivered.company_id,
        odoo_instance_id=delivered.odoo_instance_id,
        database_name=delivered.database_name,
        database_uuid=delivered.database_uuid,
        environment=delivered.environment,
        executed_release_digest=delivered.executed_release_digest,
        executed_registry_digest=delivered.executed_registry_digest,
        business_result=(
            delivered.business_result
            if business_result is None
            else business_result
        ),
        audit_receipt=(
            delivered.audit_receipt
            if audit_receipt is None
            else audit_receipt
        ),
    )


class _DeliveryBrokerStub:
    def __init__(self, delivered: TrustedDeliveredResult) -> None:
        self._result_delivery_resolver = lambda _locator, _session: delivered
        self._current_release_digest = CURRENT_RELEASE
        self._current_registry_digest = CURRENT_REGISTRY

    @staticmethod
    def _deadline(
        _deadline_monotonic: float | None,
        *,
        action: str,
        post_submit: bool = False,
    ) -> None:
        del action, post_submit

    @staticmethod
    def _error(
        _action: str,
        error: TrustedBrokerError,
        *,
        authority_verified: bool = False,
    ) -> TrustedBrokerError:
        del authority_verified
        return error


def _broker_delivery_result(
    delivered: TrustedDeliveredResult,
    locator: dict[str, Any],
    session: TrustedSession,
) -> Any:
    return TrustedBroker._dispatch_result_delivery(
        _DeliveryBrokerStub(delivered),  # type: ignore[arg-type]
        locator=locator,
        trusted_session=session,
        deadline_monotonic=None,
    )


def _snapshot(*, state: str) -> dict[str, Any]:
    return create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state=state,
        values={
            "amount_total": "125.50",
            "name": "INV/2026/0001",
            "state": state,
        },
    )


def _database_finalization(
    operation: Operation,
    *,
    execution_digest: str,
    verification_digest: str,
) -> dict[str, Any]:
    intent = EffectFinalizationIntent(
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        execution_result_digest=execution_digest,
        resolution_operation_id=operation.operation_id,
        resolution_operation_digest=operation.digest,
        resolution_execution_result_digest=execution_digest,
        resolution_result_digest=verification_digest,
        resolution_kind="verified",
    )
    request = EffectFinalizationRequest.from_intent(
        intent,
        verified_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=b"effect-finalizer-secret-material-32-bytes",
    )
    return EffectFinalizationReceipt.from_database_mapping(
        {
            "receipt_attestation_id": attestation.attestation_id,
            "receipt_guard_installation_id": (
                "22222222-2222-4222-8222-222222222222"
            ),
            "receipt_database_oid": 16384,
            "receipt_database_uuid": operation.database_uuid,
            "resolved_operation_id": operation.operation_id,
            "receipt_resolution_operation_id": operation.operation_id,
            "applied_resolution_kind": "verified",
            "resolved_anchor_count": 1,
            "remaining_unresolved_count": 0,
            "guard_epoch": 0,
            "receipt_attestation_digest": attestation.attestation_digest,
            "finalized_at": _utc(NOW + timedelta(seconds=1)),
            "finalized_txid": "9123",
            "replayed": False,
        },
        request=request,
        attestation=attestation,
    ).evidence


def _write_result_body(
    operation: Operation,
    *,
    execution_digest: str,
    verification_digest: str,
) -> dict[str, Any]:
    before = _snapshot(state="draft")
    after = _snapshot(state="posted")
    difference = create_difference(
        before=[before], after=[after], changed_fields=["state"]
    )
    recovery_plan = create_recovery_plan(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="reverse_move",
        requires_approval=True,
        target_records=[
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": operation.company_id,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        parameters={"company_id": operation.company_id, "move_id": 880},
    )
    return {
        "operation_id": operation.operation_id,
        "operation_state": State.COMPLETED.value,
        "odoo_records": [
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": operation.company_id,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        "difference": difference,
        "verification": {
            "method": "read_back_move",
            "passed": True,
            "checks": ["record_exists", "company_matches", "state_matches"],
            "evidence_digest": verification_digest,
            "verified_at": _utc(NOW),
        },
        "database_finalization": _database_finalization(
            operation,
            execution_digest=execution_digest,
            verification_digest=verification_digest,
        ),
        "recovery_plan": recovery_plan,
    }


def _persist_completed_write(
    path: Path,
) -> tuple[SQLitePersistence, Any, dict[str, Any], dict[str, Any]]:
    store = SQLitePersistence(path)
    operation = Operation.prepare(
        operation_id="operation-result-delivery-1",
        request_id="request-result-delivery-1",
        capability_id=CAPABILITY_ID,
        parameters={
            "company_id": 7,
            "amount": "125.50",
            "idempotency_key": "write-result-delivery-1",
        },
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="write-result-delivery-1",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    store.get_or_create_operation(operation, scope="result-delivery")
    precheck_evidence = {
        "acl_allowed": True,
        "company_id": operation.company_id,
        "odoo_checked": True,
        "operation_digest": operation.digest,
        "user_id": operation.user_id,
    }
    prechecked = store.record_precheck(
        operation_id=operation.operation_id,
        evidence=precheck_evidence,
        occurred_at=NOW - timedelta(minutes=5),
        expected_revision=0,
    ).operation
    awaiting = prechecked.transition(
        State.AWAITING_APPROVAL, expected_revision=prechecked.revision
    )
    awaiting = store.cas_update_operation(
        awaiting,
        expected_revision=prechecked.revision,
        occurred_at=NOW - timedelta(minutes=4),
    )
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="result-delivery-approval-nonce",
        issued_at=NOW - timedelta(minutes=3),
        expires_at=NOW + timedelta(minutes=10),
        approval_ttl_seconds=900,
        key_id=APPROVAL_KEY_ID,
        secret=APPROVAL_SECRET,
    )
    approved = store.accept_approval(
        approval,
        now=NOW - timedelta(minutes=2),
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=awaiting.revision,
    ).operation
    executing = store.begin_execution(
        approval,
        now=NOW - timedelta(minutes=1),
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=approved.revision,
    ).operation
    execution_evidence = {"model": "account.move", "record_id": 880}
    execution = sign_execution_result(
        operation=executing,
        issuer="odoo-executor",
        key_id=EXECUTION_KEY_ID,
        succeeded=True,
        evidence_digest=_digest(execution_evidence),
        issued_at=NOW,
        secret=EXECUTION_SECRET,
    )
    verifying = store.record_execution_result(
        execution,
        evidence=execution_evidence,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id=EXECUTION_KEY_ID,
        allowed_issuers=frozenset({"odoo-executor"}),
        expected_revision=executing.revision,
    ).operation
    verification_evidence = {
        "checks": ["record_exists", "company_matches", "state_matches"],
        "passed": True,
        "record_id": 880,
    }
    verification_digest = _digest(verification_evidence)
    verification = sign_verification_result(
        operation=verifying,
        issuer="odoo-verifier",
        key_id=VERIFICATION_KEY_ID,
        succeeded=True,
        evidence_digest=verification_digest,
        issued_at=NOW,
        secret=VERIFICATION_SECRET,
    )
    completed = store.complete_operation(
        verification,
        evidence=verification_evidence,
        now=NOW,
        secret=VERIFICATION_SECRET,
        expected_key_id=VERIFICATION_KEY_ID,
        allowed_issuers=frozenset({"odoo-verifier"}),
        expected_revision=verifying.revision,
        receipt_factory=lambda terminal: {
            **_write_result_body(
                terminal,
                execution_digest=execution.evidence_digest,
                verification_digest=verification_digest,
            ),
            "capability_channel": "staged",
        },
    ).operation
    material = store.get_terminal_write_delivery(completed.operation_id)
    details = material.final_receipt.body["receipt_details"]
    result_body = {field: details[field] for field in RESULT_BODY_FIELDS}
    receipt_id = "write-" + hashlib.sha256(
        canonical_json(
            {
                "audit_event_id": material.audit_event.event_id,
                "audit_head": material.audit_event.event_hash,
                "operation_id": completed.operation_id,
                "result": result_body,
            }
        )
    ).hexdigest()
    locator = {
        "action": "operation.result",
        "business_succeeded": True,
        "capability_id": completed.capability_id,
        "operation_id": completed.operation_id,
        "receipt_id": receipt_id,
        "result_digest": _digest(result_body),
        "status": "verified_success",
    }
    return store, material, result_body, locator


def test_verified_read_delivery_uses_signed_consumed_hash_bound_evidence(
    tmp_path: Path,
) -> None:
    read_store, result, receipt, locator = _persist_read(tmp_path / "read.db")
    route_calls: list[tuple[str, str]] = []
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
        route_calls=route_calls,
    )

    delivered = resolver(locator, _session())
    retained = read_store.get_verified_read_result(receipt["id"])

    assert delivered.business_result == result
    assert delivered.audit_receipt == receipt
    assert delivered.result_digest == _digest(result)
    assert delivered.executed_release_digest == CURRENT_RELEASE
    assert delivered.executed_registry_digest == CURRENT_REGISTRY
    assert retained.record_hash == _verified_read_result_record_hash(
        {
            field: (
                getattr(retained, field)
                if field != "observed_at"
                else retained.observed_at.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
            )
            for field in _VERIFIED_READ_RESULT_COLUMNS[:-1]
        }
    )
    with sqlite3.connect(read_store.path) as connection:
        consumed = connection.execute(
            "SELECT request_digest, observed_at FROM consumed_receipts "
            "WHERE receipt_id = ?",
            (receipt["id"],),
        ).fetchone()
    assert consumed == (
        receipt["request_digest"],
        (NOW - timedelta(seconds=1))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
    )
    assert route_calls == []


@pytest.mark.parametrize(
    "session",
    [
        _session(principal="pi:user-43"),
        _session(company_id=8, allowed_company_ids=frozenset({8})),
        _session(database_uuid="22222222-2222-4222-8222-222222222222"),
    ],
)
def test_verified_read_delivery_rejects_session_binding_changes(
    tmp_path: Path, session: TrustedSession
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(TrustedResultDeliveryError, match="binding differs"):
        resolver(locator, session)


@pytest.mark.parametrize(
    "override",
    [
        {"capability_id": "acct.gl.general_ledger.v1"},
        {"result_digest": "f" * 64},
    ],
)
def test_verified_read_delivery_rejects_locator_tampering(
    tmp_path: Path, override: dict[str, Any]
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(TrustedResultDeliveryError, match="binding differs"):
        resolver({**locator, **override}, _session())


def test_verified_read_delivery_rejects_record_hash_tampering(
    tmp_path: Path,
) -> None:
    read_store, _, receipt, locator = _persist_read(tmp_path / "read.db")
    with sqlite3.connect(read_store.path) as connection:
        connection.execute("DROP TRIGGER verified_read_results_no_update")
        connection.execute(
            "UPDATE verified_read_results SET principal = ? WHERE receipt_id = ?",
            ("pi:attacker", receipt["id"]),
        )
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(PersistenceIntegrityError, match="hash mismatch"):
        resolver(locator, _session())


def test_verified_read_delivery_rejects_missing_consumption_binding(
    tmp_path: Path,
) -> None:
    read_store, _, receipt, locator = _persist_read(tmp_path / "read.db")
    with sqlite3.connect(read_store.path) as connection:
        connection.execute(
            "DELETE FROM consumed_receipts WHERE receipt_id = ?",
            (receipt["id"],),
        )
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(PersistenceIntegrityError, match="binding is invalid"):
        resolver(locator, _session())


def test_verified_read_delivery_rejects_invalid_signature_even_if_unkeyed_hashes_match(
    tmp_path: Path,
) -> None:
    read_store, _, receipt, locator = _persist_read(tmp_path / "read.db")
    with sqlite3.connect(read_store.path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("DROP TRIGGER verified_read_results_no_update")
        connection.execute("DROP TRIGGER audit_events_no_update")
        read_row = connection.execute(
            f"SELECT {', '.join(_VERIFIED_READ_RESULT_COLUMNS)} "
            "FROM verified_read_results WHERE receipt_id = ?",
            (receipt["id"],),
        ).fetchone()
        event = connection.execute(
            "SELECT * FROM audit_events WHERE event_id = ?",
            (f"read:{receipt['id']}",),
        ).fetchone()
        assert read_row is not None and event is not None
        forged_receipt = json.loads(read_row["receipt_json"])
        forged_receipt["signature"] = (
            "e" * 64 if forged_receipt["signature"] != "e" * 64 else "f" * 64
        )
        forged_receipt_json = canonical_json(forged_receipt).decode("utf-8")
        read_payload = {
            field: (
                forged_receipt_json
                if field == "receipt_json"
                else read_row[field]
            )
            for field in _VERIFIED_READ_RESULT_COLUMNS[:-1]
        }
        audit_payload = json.loads(event["payload_json"])
        audit_payload["receipt"] = forged_receipt
        audit_payload_json = canonical_json(audit_payload).decode("utf-8")
        event_hash = _audit_hash(
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_type=event["event_type"],
            operation_id=event["operation_id"],
            occurred_at=event["occurred_at"],
            payload_json=audit_payload_json,
            previous_hash=GENESIS_HASH,
        )
        connection.execute(
            "UPDATE verified_read_results SET receipt_json = ?, record_hash = ? "
            "WHERE receipt_id = ?",
            (
                forged_receipt_json,
                _verified_read_result_record_hash(read_payload),
                receipt["id"],
            ),
        )
        connection.execute(
            "UPDATE audit_events SET payload_json = ?, event_hash = ? "
            "WHERE event_id = ?",
            (audit_payload_json, event_hash, event["event_id"]),
        )
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(PersistenceIntegrityError, match="receipt rejected"):
        resolver(locator, _session())


def test_diagnostic_receipt_cannot_be_relabelled_as_verified_read_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_store, _, _, locator = _persist_read(
        tmp_path / "read.db",
        capability_id="acct.diagnostics.operation_read.v1",
        receipt_id="diagnostic-read-receipt-1",
    )
    read_calls = 0

    def forbidden_read(_receipt_id: str):
        nonlocal read_calls
        read_calls += 1
        raise AssertionError("diagnostic locator reached retained read evidence")

    monkeypatch.setattr(read_store, "get_verified_read_result", forbidden_read)
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(TrustedResultDeliveryError, match="locator is invalid"):
        resolver(locator, _session())
    assert locator["action"] == "read"
    assert locator["status"] == "verified_success"
    assert read_calls == 0


def test_verified_read_delivery_rejects_oversized_resolver_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_store, _, receipt, locator = _persist_read(tmp_path / "read.db")
    retained = read_store.get_verified_read_result(receipt["id"])
    oversized_result = {
        "blob": "界" * 90_000,
        "page": {"total_count": 0},
    }
    oversized_receipt = create_read_receipt(
        receipt_id=receipt["id"],
        capability_id=READ_CAPABILITY_ID,
        parameters=retained.parameters,
        result_body=oversized_result,
        auth_token_id=retained.auth_token_id,
        principal=retained.principal,
        odoo_instance_id=retained.odoo_instance_id,
        database_name=retained.database_name,
        database_uuid=retained.database_uuid,
        company_id=retained.company_id,
        user_id=retained.user_id,
        registry_digest=retained.executed_registry_digest,
        release_digest=retained.executed_release_digest,
        environment=retained.environment,
        capability_channel=retained.capability_channel,
        record_count=0,
        observed_at=retained.observed_at,
        key_id=READ_KEY_ID,
        secret=READ_SECRET,
    )
    forged = replace(
        retained,
        result_body_json=canonical_json(oversized_result).decode("utf-8"),
        receipt_json=canonical_json(oversized_receipt).decode("utf-8"),
        result_digest=oversized_receipt["result_digest"],
    )
    monkeypatch.setattr(
        read_store, "get_verified_read_result", lambda _receipt_id: forged
    )
    resolver = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )

    with pytest.raises(TrustedBrokerError) as rejected:
        resolver(
            {**locator, "result_digest": oversized_receipt["result_digest"]},
            _session(),
        )
    assert rejected.value.code == "broker_result_delivery_rejected"


def test_trusted_result_deep_copies_nested_caller_owned_documents(
    tmp_path: Path,
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    delivered = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )(locator, _session())
    source_result = json.loads(canonical_json(delivered.business_result))
    source_receipt = json.loads(canonical_json(delivered.audit_receipt))

    detached = _copy_delivered(
        delivered,
        business_result=source_result,
        audit_receipt=source_receipt,
    )
    source_result["page"]["total_count"] = 99
    source_receipt["company_id"] = 8

    assert detached.business_result["page"]["total_count"] == 0
    assert detached.audit_receipt["company_id"] == 7


@pytest.mark.parametrize("mutation", ["nested_result", "receipt_signature"])
def test_broker_rejects_any_post_construction_nested_mutation(
    tmp_path: Path, mutation: str
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    session = _session()
    delivered = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )(locator, session)
    if mutation == "nested_result":
        delivered.business_result["page"]["total_count"] = 1
    else:
        current = delivered.audit_receipt["signature"]
        delivered.audit_receipt["signature"] = (
            "e" * 64 if current != "e" * 64 else "f" * 64
        )

    rejected = _broker_delivery_result(delivered, locator, session)

    assert isinstance(rejected, TrustedBrokerError)
    assert rejected.code == "broker_result_delivery_rejected"


def test_broker_rejects_trusted_result_subclasses(
    tmp_path: Path,
) -> None:
    class ForgedDeliveredResult(TrustedDeliveredResult):
        pass

    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    session = _session()
    delivered = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )(locator, session)
    forged = _copy_delivered(
        delivered, result_type=ForgedDeliveredResult
    )

    rejected = _broker_delivery_result(forged, locator, session)

    assert isinstance(rejected, TrustedBrokerError)
    assert rejected.code == "broker_result_delivery_rejected"


def test_trusted_result_rejects_deep_json_without_recursion_escape(
    tmp_path: Path,
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    delivered = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )(locator, _session())
    deep: dict[str, Any] = {}
    cursor = deep
    for _ in range(40):
        child: dict[str, Any] = {}
        cursor["child"] = child
        cursor = child

    with pytest.raises(TrustedBrokerError) as rejected:
        _copy_delivered(
            delivered,
            business_result={
                "deep": deep,
                "lines": [],
                "page": {"total_count": 0},
            },
        )
    assert rejected.value.code == "broker_result_delivery_rejected"


@pytest.mark.parametrize(
    "bad_value",
    [
        {"bad": [0] * 10_001, "page": {"total_count": 0}},
        {"界" * 86: True, "page": {"total_count": 0}},
        {"bad": "界" * 90_000, "page": {"total_count": 0}},
        {1: "non-string-key", "page": {"total_count": 0}},
        {"": "empty-key", "page": {"total_count": 0}},
        {"bad": "\ud800", "page": {"total_count": 0}},
    ],
)
def test_trusted_result_rejects_unsafe_json_shape_and_utf8_boundaries(
    tmp_path: Path, bad_value: dict[Any, Any]
) -> None:
    read_store, _, _, locator = _persist_read(tmp_path / "read.db")
    delivered = _resolver(
        read_store=read_store,
        write_store=SQLitePersistence(tmp_path / "write.db"),
    )(locator, _session())

    with pytest.raises(TrustedBrokerError) as rejected:
        _copy_delivered(delivered, business_result=bad_value)
    assert rejected.value.code == "broker_result_delivery_rejected"


def test_completed_write_delivery_uses_its_historical_route_secret(
    tmp_path: Path,
) -> None:
    write_store, material, result_body, locator = _persist_completed_write(
        tmp_path / "write.db"
    )
    route = ResultDeliveryRoute(
        release_digest=OLD_RELEASE,
        registry_digest=OLD_REGISTRY,
        capability_channel="staged",
        write_receipt_key_id=WRITE_KEY_ID,
        write_receipt_secret=OLD_WRITE_SECRET,
    )
    route_calls: list[tuple[str, str]] = []
    resolver = _resolver(
        read_store=_read_store(tmp_path / "read.db"),
        write_store=write_store,
        routes={(OLD_RELEASE, OLD_REGISTRY): route},
        route_calls=route_calls,
    )

    delivered = resolver(locator, _session())
    operation = material.operation
    approval = material.approval_record
    verification_arguments = {
        "request_id": operation.request_id,
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "principal": operation.principal,
        "odoo_instance_id": operation.odoo_instance_id,
        "database_name": operation.database_name,
        "database_uuid": operation.database_uuid,
        "user_id": operation.user_id,
        "approver_user_id": approval.approver_user_id,
        "company_id": operation.company_id,
        "environment": operation.environment,
        "capability_channel": route.capability_channel,
        "request_digest": authentication_request_digest(
            operation.capability_id, operation.parameters
        ),
        "operation_digest": operation.digest,
        "approval_digest": approval.approval_signature,
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
        "audit_head": material.audit_event.event_hash,
        "result_body": result_body,
        "now": NOW,
        "expected_signing_key_id": WRITE_KEY_ID,
    }

    verify_write_audit_receipt(
        delivered.audit_receipt,
        secret=OLD_WRITE_SECRET,
        **verification_arguments,
    )
    with pytest.raises(WriteReceiptError, match="signature mismatch"):
        verify_write_audit_receipt(
            delivered.audit_receipt,
            secret=CURRENT_WRITE_SECRET,
            **verification_arguments,
        )
    assert delivered.business_result == result_body
    assert delivered.executed_release_digest == OLD_RELEASE
    assert delivered.executed_registry_digest == OLD_REGISTRY
    assert route_calls == [(OLD_RELEASE, OLD_REGISTRY)]


@pytest.mark.parametrize(
    "override",
    [
        {"capability_id": "acct.bill.vendor_create.v1"},
        {"receipt_id": "write-forged-receipt"},
        {"result_digest": "f" * 64},
    ],
)
def test_completed_write_delivery_rejects_locator_tampering(
    tmp_path: Path, override: dict[str, Any]
) -> None:
    write_store, _, _, locator = _persist_completed_write(tmp_path / "write.db")
    resolver = _resolver(
        read_store=_read_store(tmp_path / "read.db"),
        write_store=write_store,
        routes={
            (OLD_RELEASE, OLD_REGISTRY): ResultDeliveryRoute(
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
                capability_channel="staged",
                write_receipt_key_id=WRITE_KEY_ID,
                write_receipt_secret=OLD_WRITE_SECRET,
            )
        },
    )

    with pytest.raises(TrustedResultDeliveryError):
        resolver({**locator, **override}, _session())


@pytest.mark.parametrize("terminal_state", [State.FAILED, State.RECOVERED])
def test_failed_and_recovered_writes_are_not_delivered_as_verified_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: State,
) -> None:
    write_store, material, _, locator = _persist_completed_write(
        tmp_path / "write.db"
    )
    forged_material = replace(
        material,
        operation=replace(material.operation, state=terminal_state),
    )
    original = SQLitePersistence.get_terminal_write_delivery

    def load_material(store: SQLitePersistence, operation_id: str):
        if store is write_store:
            assert operation_id == locator["operation_id"]
            return forged_material
        return original(store, operation_id)

    monkeypatch.setattr(
        SQLitePersistence, "get_terminal_write_delivery", load_material
    )
    route_calls: list[tuple[str, str]] = []
    resolver = _resolver(
        read_store=_read_store(tmp_path / "read.db"),
        write_store=write_store,
        routes={},
        route_calls=route_calls,
    )

    with pytest.raises(
        TrustedResultDeliveryError, match="not a verified success"
    ):
        resolver(locator, _session())
    assert route_calls == []


def test_completed_write_delivery_rejects_cross_company_session(
    tmp_path: Path,
) -> None:
    write_store, _, _, locator = _persist_completed_write(tmp_path / "write.db")
    resolver = _resolver(
        read_store=_read_store(tmp_path / "read.db"),
        write_store=write_store,
        routes={
            (OLD_RELEASE, OLD_REGISTRY): ResultDeliveryRoute(
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
                capability_channel="staged",
                write_receipt_key_id=WRITE_KEY_ID,
                write_receipt_secret=OLD_WRITE_SECRET,
            )
        },
    )

    with pytest.raises(TrustedResultDeliveryError, match="binding differs"):
        resolver(
            locator,
            _session(company_id=8, allowed_company_ids=frozenset({8})),
        )
