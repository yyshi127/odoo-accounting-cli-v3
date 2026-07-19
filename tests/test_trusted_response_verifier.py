from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.auth import (
    authentication_request_digest,
    context_payload,
    write_action_request_digest,
)
from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
)
from odoo_accounting_cli_v3.gateway import (
    AUTH_SIGNATURE_PURPOSE,
    AUTH_SIGNATURE_VERSION,
    WRITE_AUTH_SIGNATURE_PURPOSE,
    WRITE_AUTH_SIGNATURE_VERSION,
    RequestContext,
)
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    canonical_json,
    record_precheck,
    sign_approval,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.trusted_response_verifier import (
    ReleaseReceiptVerificationConfig,
    ResponseVerifierConfigurationError,
    build_release_response_verifier,
    build_release_response_verifier_resolver,
)
from odoo_accounting_cli_v3.write_protocol import (
    approval_to_mapping,
    operation_to_mapping,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    create_write_audit_receipt,
)


NOW = datetime(2026, 7, 15, 4, 0, tzinfo=timezone.utc)
RELEASE = "d" * 64
REGISTRY = "c" * 64
OLD_RELEASE = "b" * 64
OLD_REGISTRY = "a" * 64
READ_SECRET = b"read-receipt-verifier-secret-32-bytes"
WRITE_SECRET = b"write-receipt-verifier-secret-32-bytes"
APPROVAL_SECRET = b"approval-verifier-secret-material-32"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
EFFECT_SECRET = b"effect-finalizer-verifier-secret-32-bytes"


def config(
    *,
    release: str = RELEASE,
    registry: str = REGISTRY,
    read_key: str = "read-receipt-v2",
    read_secret: bytes = READ_SECRET,
    write_key: str = "write-receipt-v1",
    write_secret: bytes = WRITE_SECRET,
) -> ReleaseReceiptVerificationConfig:
    return ReleaseReceiptVerificationConfig(
        release_digest=release,
        registry_digest=registry,
        capability_channel="staged",
        read_receipt_key_id=read_key,
        read_receipt_secret=read_secret,
        write_receipt_key_id=write_key,
        write_receipt_secret=write_secret,
    )


def context_mapping(
    action: str,
    unsigned: dict,
    *,
    token: str = "auth-token-1",
    principal: str = "pi:xiaojing",
    company_id: int = 7,
) -> dict:
    if action == "read":
        request_digest = authentication_request_digest(
            unsigned["capability_id"], unsigned["parameters"]
        )
        version = AUTH_SIGNATURE_VERSION
        purpose = AUTH_SIGNATURE_PURPOSE
    else:
        request_digest = write_action_request_digest(action, unsigned)
        version = WRITE_AUTH_SIGNATURE_VERSION
        purpose = WRITE_AUTH_SIGNATURE_PURPOSE
    context = RequestContext(
        audience="odoo-accounting-cli-v3",
        auth_token_id=token,
        auth_issued_at=NOW - timedelta(minutes=1),
        auth_expires_at=NOW + timedelta(minutes=4),
        auth_signature_version=version,
        auth_signature_purpose=purpose,
        auth_key_id="request-auth-v2",
        auth_request_digest=request_digest,
        auth_signature="f" * 64,
        principal=principal,
        odoo_instance_id="odoo19-tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=42,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
    )
    return {**context_payload(context), "auth_signature": context.auth_signature}


def read_exchange(
    *,
    route: ReleaseReceiptVerificationConfig | None = None,
) -> tuple[dict, dict]:
    route = route or config()
    capability_id = "acct.ar.open_items.read.v1"
    parameters = {
        "as_of_date": "2026-07-15",
        "company_id": 7,
        "limit": 50,
        "offset": 0,
    }
    unsigned = {"capability_id": capability_id, "parameters": parameters}
    request = {
        "context": context_mapping("read", unsigned),
        **unsigned,
    }
    body = {
        "items": [{"move_id": 101, "residual": "25.00"}],
        "page": {"count": 1, "total_count": 1},
    }
    receipt = create_read_receipt(
        receipt_id="read-receipt-1",
        capability_id=capability_id,
        parameters=parameters,
        result_body=body,
        auth_token_id=request["context"]["auth_token_id"],
        principal=request["context"]["principal"],
        odoo_instance_id=request["context"]["odoo_instance_id"],
        database_name=request["context"]["database_name"],
        database_uuid=request["context"]["database_uuid"],
        company_id=request["context"]["company_id"],
        user_id=request["context"]["user_id"],
        registry_digest=route.registry_digest,
        release_digest=route.release_digest,
        environment=request["context"]["environment"],
        capability_channel=route.capability_channel,
        record_count=1,
        observed_at=NOW - timedelta(seconds=1),
        key_id=route.read_receipt_key_id,
        secret=route.read_receipt_secret,
    )
    response = {
        "command": "read",
        "data": {
            "capability_id": capability_id,
            "release_identity": {
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "manifest_sha256": route.release_digest,
                "package_sha256": "9" * 64,
                "registry_digest": route.registry_digest,
                "release": "2026.07.15-test",
                "verified": True,
                "version": "3.0.0",
            },
            "result": {**body, "receipt": receipt},
            "runtime": {
                "instance_id": request["context"]["odoo_instance_id"],
                "environment": request["context"]["environment"],
                "capability_channel": route.capability_channel,
                "database_name": request["context"]["database_name"],
                "database_uuid": request["context"]["database_uuid"],
            },
        },
        "ok": True,
    }
    return request, response


def prepared_operation(
    operation_id: str = "op-1",
    *,
    release: str = RELEASE,
    registry: str = REGISTRY,
    capability_id: str = "acct.invoice.customer_create.v1",
    parameters: dict | None = None,
    request_id: str | None = None,
) -> Operation:
    values = parameters or {
        "company_id": 7,
        "currency_id": 12,
        "idempotency_key": f"idem-{operation_id}",
        "invoice_date": "2026-07-15",
    }
    return Operation.prepare(
        operation_id=operation_id,
        request_id=request_id or f"request-{operation_id}",
        capability_id=capability_id,
        parameters=values,
        principal="pi:xiaojing",
        user_id=42,
        company_id=7,
        idempotency_key=values["idempotency_key"],
        odoo_instance_id="odoo19-tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=registry,
        release_digest=release,
    )


def awaiting_operation(
    operation_id: str = "op-1",
    *,
    release: str = RELEASE,
    registry: str = REGISTRY,
    precheck: dict | None = None,
) -> tuple[Operation, dict]:
    evidence = precheck or {
        "checks": ["acl", "company", "period"],
        "company_id": 7,
        "passed": True,
    }
    operation = prepared_operation(
        operation_id, release=release, registry=registry
    )
    operation = record_precheck(
        operation,
        precheck_digest=hashlib.sha256(canonical_json(evidence)).hexdigest(),
        expected_revision=operation.revision,
    )
    return (
        operation.transition(
            State.AWAITING_APPROVAL, expected_revision=operation.revision
        ),
        evidence,
    )


def terminal_operation(
    operation_id: str = "op-1",
    *,
    release: str = RELEASE,
    registry: str = REGISTRY,
) -> tuple[Operation, object]:
    awaiting, _precheck = awaiting_operation(
        operation_id, release=release, registry=registry
    )
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce=f"nonce-{operation_id}",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=9),
        approval_ttl_seconds=900,
        key_id="approval-v3",
        secret=APPROVAL_SECRET,
    )
    terminal = replace(
        awaiting,
        state=State.COMPLETED,
        revision=6,
        approval_signature=approval.signature,
        approval_nonce_digest=hashlib.sha256(
            approval.nonce.encode("utf-8")
        ).hexdigest(),
        approval_issued_at=approval.issued_at,
        approval_expires_at=approval.expires_at,
        approval_revision=approval.operation_revision,
        approver_user_id=approval.approver_user_id,
        execution_result_digest="e" * 64,
        verification_result_digest="f" * 64,
    )
    terminal.assert_integrity()
    return terminal, approval


def result_body(operation: Operation) -> dict:
    before = create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state="draft",
        values={"state": "draft", "amount_total": "125.50"},
    )
    after = create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state="posted",
        values={"state": "posted", "amount_total": "125.50"},
    )
    plan = create_recovery_plan(
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
        "operation_state": operation.state.value,
        "odoo_records": [
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": operation.company_id,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        "difference": create_difference(
            before=[before], after=[after], changed_fields=["state"]
        ),
        "verification": {
            "method": "read_back_move",
            "passed": True,
            "checks": ["record_exists", "company_matches"],
            "evidence_digest": "7" * 64,
            "verified_at": "2026-07-15T04:00:00Z",
        },
        "database_finalization": database_finalization(operation),
        "recovery_plan": plan,
    }


def database_finalization(operation: Operation) -> dict:
    intent = EffectFinalizationIntent(
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        execution_result_digest="5" * 64,
        resolution_operation_id=operation.operation_id,
        resolution_operation_digest=operation.digest,
        resolution_execution_result_digest="5" * 64,
        resolution_result_digest="7" * 64,
        resolution_kind="verified",
    )
    request = EffectFinalizationRequest.from_intent(
        intent,
        verified_at=NOW - timedelta(seconds=2),
        expires_at=NOW + timedelta(minutes=3),
    )
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=EFFECT_SECRET,
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
            "finalized_at": "2026-07-15T04:00:00Z",
            "finalized_txid": "9123",
            "replayed": False,
        },
        request=request,
        attestation=attestation,
    ).evidence


def terminal_exchange(
    operation: Operation,
    approval,
    *,
    action: str = "operation.approve_execute",
    route: ReleaseReceiptVerificationConfig | None = None,
) -> tuple[dict, dict]:
    route = route or config(
        release=operation.release_digest, registry=operation.registry_digest
    )
    unsigned = {"operation_id": operation.operation_id}
    if action == "operation.approve_execute":
        unsigned["approval"] = approval_to_mapping(approval)
        unsigned["reconciliation_only"] = False
    request = {"context": context_mapping(action, unsigned), **unsigned}
    body = result_body(operation)
    receipt = create_write_audit_receipt(
        receipt_id=f"receipt-{operation.operation_id}",
        request_id=operation.request_id,
        operation_id=operation.operation_id,
        capability_id=operation.capability_id,
        principal=operation.principal,
        odoo_instance_id=operation.odoo_instance_id,
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        user_id=operation.user_id,
        approver_user_id=operation.approver_user_id,
        company_id=operation.company_id,
        environment=operation.environment,
        capability_channel=route.capability_channel,
        request_digest=authentication_request_digest(
            operation.capability_id, operation.parameters
        ),
        operation_digest=operation.digest,
        approval_digest=operation.approval_signature,
        registry_digest=operation.registry_digest,
        release_digest=operation.release_digest,
        audit_head="8" * 64,
        result_body=body,
        issued_at=NOW - timedelta(seconds=1),
        signing_key_id=route.write_receipt_key_id,
        secret=route.write_receipt_secret,
    )
    response = {
        "business_succeeded": True,
        "command": action,
        "data": {**body, "audit_receipt": receipt},
        "ok": True,
    }
    return request, response


def verifier(route, operations, *, clock=lambda: NOW):
    return build_release_response_verifier(
        route,
        operation_resolver=lambda operation_id: operations.get(operation_id),
        utc_clock=clock,
    ).verify


def operation_response(operation: Operation, *, next_action: str) -> dict:
    return {
        "operation_id": operation.operation_id,
        "operation_state": operation.state.value,
        "capability_id": operation.capability_id,
        "operation_revision": operation.revision,
        "operation_digest": operation.digest,
        "operation": operation_to_mapping(operation),
        "result_available": operation.state
        in {State.COMPLETED, State.FAILED, State.RECOVERED},
        "next_action": next_action,
    }


def test_read_response_requires_real_hmac_and_complete_runtime_binding():
    route = config()
    request, response = read_exchange(route=route)
    verify = verifier(route, {})

    assert verify("read", response, request) is True

    fake = copy.deepcopy(response)
    fake["data"]["result"]["receipt"]["signature"] = "0" * 64
    assert verify("read", fake, request) is False

    tampered_result = copy.deepcopy(response)
    tampered_result["data"]["result"]["items"][0]["residual"] = "999.00"
    assert verify("read", tampered_result, request) is False

    tampered_runtime = copy.deepcopy(response)
    tampered_runtime["data"]["runtime"]["database_name"] = "other_db"
    assert verify("read", tampered_runtime, request) is False

    wrong_count = copy.deepcopy(response)
    wrong_count["data"]["result"]["page"]["total_count"] = 2
    assert verify("read", wrong_count, request) is False

    cross_company = copy.deepcopy(request)
    cross_company["context"]["company_id"] = 8
    cross_company["context"]["allowed_company_ids"] = [8]
    assert verify("read", response, cross_company) is False


@pytest.mark.parametrize(
    "route",
    (
        config(read_key="wrong-key"),
        config(read_secret=b"x" * 32),
    ),
)
def test_read_response_rejects_wrong_receipt_key_or_secret(route):
    request, response = read_exchange()
    assert verifier(route, {})("read", response, request) is False


def test_read_broker_check_is_repeatable_without_second_business_consumption(
    monkeypatch,
):
    import odoo_accounting_cli_v3.trusted_response_verifier as module

    route = config()
    request, response = read_exchange(route=route)
    original = module.verify_read_receipt
    callbacks = []

    def observe(*args, **kwargs):
        callbacks.append(kwargs["consume_receipt"])
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "verify_read_receipt", observe)
    verify = verifier(route, {})

    assert verify("read", response, request) is True
    assert verify("read", response, request) is True
    assert len(callbacks) == 2
    assert callbacks[0]("receipt", "0" * 64, NOW, NOW) is True


@pytest.mark.parametrize(
    "action", ("operation.approve_execute", "operation.result")
)
def test_terminal_write_response_requires_real_operation_bound_hmac(action):
    route = config()
    operation, approval = terminal_operation()
    request, response = terminal_exchange(
        operation, approval, action=action, route=route
    )

    assert verifier(route, {operation.operation_id: operation})(
        action, response, request
    ) is True


@pytest.mark.parametrize(
    "route",
    (
        config(write_key="wrong-key"),
        config(write_secret=b"z" * 32),
    ),
)
def test_terminal_write_rejects_wrong_key_or_secret(route):
    operation, approval = terminal_operation()
    request, response = terminal_exchange(operation, approval)
    assert verifier(route, {operation.operation_id: operation})(
        "operation.approve_execute", response, request
    ) is False


def test_terminal_write_rejects_fake_signature_tamper_and_cross_operation():
    route = config()
    operation, approval = terminal_operation("op-1")
    other, other_approval = terminal_operation("op-2")
    request, response = terminal_exchange(operation, approval)
    verify = verifier(
        route, {operation.operation_id: operation, other.operation_id: other}
    )

    fake = copy.deepcopy(response)
    fake["data"]["audit_receipt"]["signature"] = "a" * 64
    assert verify("operation.approve_execute", fake, request) is False

    tampered = copy.deepcopy(response)
    tampered["data"]["odoo_records"][0]["record_state"] = "cancelled"
    assert verify("operation.approve_execute", tampered, request) is False

    tampered_audit = copy.deepcopy(response)
    tampered_audit["data"]["audit_receipt"]["audit_head"] = "9" * 64
    assert verify("operation.approve_execute", tampered_audit, request) is False

    cross_request, _other_response = terminal_exchange(other, other_approval)
    assert verify("operation.approve_execute", response, cross_request) is False

    approval_swap = copy.deepcopy(request)
    approval_swap["approval"] = approval_to_mapping(other_approval)
    unsigned = {key: value for key, value in approval_swap.items() if key != "context"}
    approval_swap["context"] = context_mapping(
        "operation.approve_execute", unsigned
    )
    assert verify("operation.approve_execute", response, approval_swap) is False


def test_historical_route_uses_only_its_own_receipt_credentials():
    current = config()
    historical = config(
        release=OLD_RELEASE,
        registry=OLD_REGISTRY,
        read_key="old-read-key",
        read_secret=b"old-read-receipt-secret-material-32",
        write_key="old-write-key",
        write_secret=b"old-write-receipt-secret-material-32",
    )
    operation, approval = terminal_operation(
        "old-op", release=OLD_RELEASE, registry=OLD_REGISTRY
    )
    request, response = terminal_exchange(
        operation, approval, route=historical
    )
    operations = {operation.operation_id: operation}
    resolve = build_release_response_verifier_resolver(
        (current, historical),
        operation_resolver=lambda operation_id: operations.get(operation_id),
        utc_clock=lambda: NOW,
    )

    old_verifier = resolve(OLD_RELEASE, OLD_REGISTRY)
    current_verifier = resolve(RELEASE, REGISTRY)
    assert old_verifier is not None
    assert current_verifier is not None
    assert old_verifier.verify(
        "operation.approve_execute", response, request
    ) is True
    assert current_verifier.verify(
        "operation.approve_execute", response, request
    ) is False
    assert resolve(OLD_RELEASE, REGISTRY) is None


def test_known_nonterminal_actions_require_exact_route_context_and_operation():
    route = config()
    prepared = prepared_operation()
    operations = {prepared.operation_id: prepared}
    verify = verifier(route, operations)

    prepare_unsigned = {
        "operation_id": prepared.operation_id,
        "request_id": prepared.request_id,
        "capability_id": prepared.capability_id,
        "parameters": prepared.parameters,
    }
    prepare_request = {
        "context": context_mapping("operation.prepare", prepare_unsigned),
        **prepare_unsigned,
    }
    prepare_response = {
        "command": "operation.prepare",
        "data": operation_response(
            prepared, next_action="operation.preview"
        ),
        "ok": True,
    }
    assert verify("operation.prepare", prepare_response, prepare_request) is True

    status_unsigned = {"operation_id": prepared.operation_id}
    status_request = {
        "context": context_mapping("operation.status", status_unsigned),
        **status_unsigned,
    }
    status_response = {
        "command": "operation.status",
        "data": operation_response(
            prepared, next_action="operation.preview"
        ),
        "ok": True,
    }
    assert verify("operation.status", status_response, status_request) is True

    cross_company = copy.deepcopy(status_request)
    cross_company["context"]["company_id"] = 8
    assert verify("operation.status", status_response, cross_company) is False

    wrong_route_operation = prepared_operation(
        prepared.operation_id,
        release=OLD_RELEASE,
        registry=OLD_REGISTRY,
        parameters=prepared.parameters,
        request_id=prepared.request_id,
    )
    operations[prepared.operation_id] = wrong_route_operation
    assert verify("operation.status", status_response, status_request) is False
    assert verify("operation.unknown", status_response, status_request) is False


def test_prepare_lost_response_accepts_only_the_original_idempotent_operation():
    route = config(release=OLD_RELEASE, registry=OLD_REGISTRY)
    original = prepared_operation(
        "original-op", release=OLD_RELEASE, registry=OLD_REGISTRY
    )
    requested_id = "new-retry-op"
    operations = {original.operation_id: original}
    unsigned = {
        "operation_id": requested_id,
        "request_id": "new-retry-request",
        "capability_id": original.capability_id,
        "parameters": original.parameters,
    }
    request = {
        "context": context_mapping("operation.prepare", unsigned),
        **unsigned,
    }
    response = {
        "command": "operation.prepare",
        "data": operation_response(original, next_action="operation.preview"),
        "ok": True,
    }
    verify = verifier(route, operations)

    assert verify("operation.prepare", response, request) is True

    operations[requested_id] = prepared_operation(
        requested_id,
        release=OLD_RELEASE,
        registry=OLD_REGISTRY,
        parameters=original.parameters,
        request_id=unsigned["request_id"],
    )
    assert verify("operation.prepare", response, request) is False


def test_preview_binds_precheck_content_and_durable_identity():
    route = config()
    operation, precheck = awaiting_operation()
    operations = {operation.operation_id: operation}
    unsigned = {"operation_id": operation.operation_id}
    request = {
        "context": context_mapping("operation.preview", unsigned),
        **unsigned,
    }
    response = {
        "command": "operation.preview",
        "data": {
            "operation_id": operation.operation_id,
            "operation_state": operation.state.value,
            "capability_id": operation.capability_id,
            "business_description": "Create and post a customer invoice",
            "parameters": operation.parameters,
            "operation_digest": operation.digest,
            "precheck": precheck,
            "precheck_identity": {
                "operation_id": operation.operation_id,
                "precheck_digest": operation.precheck_digest,
                "registry_digest": operation.registry_digest,
                "release_digest": operation.release_digest,
            },
            "precheck_digest": operation.precheck_digest,
            "risk_level": "high",
            "approval": {"required": True},
            "recovery": {"method": "reverse_move"},
        },
        "ok": True,
    }
    verify = verifier(route, operations)

    assert verify("operation.preview", response, request) is True
    response["data"]["precheck"]["company_id"] = 8
    assert verify("operation.preview", response, request) is False


def test_recovery_prepare_binds_origin_revision_plan_and_new_operation():
    route = config()
    origin, _approval = terminal_operation("origin-op")
    plan_digest = "6" * 64
    recovery_parameters = {
        "company_id": 7,
        "expected_recovery_plan_digest": plan_digest,
        "idempotency_key": "recovery-idem-1",
        "origin_operation_id": origin.operation_id,
        "reason": "Correct duplicate posting",
        "recovery_date": "2026-07-15",
    }
    recovery = prepared_operation(
        "recovery-op",
        capability_id="acct.recovery.execute.v1",
        parameters=recovery_parameters,
        request_id="recovery-request-1",
    )
    operations = {
        origin.operation_id: origin,
        recovery.operation_id: recovery,
    }
    unsigned = {
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "recovery_operation_id": recovery.operation_id,
        "request_id": recovery.request_id,
        "recovery_date": recovery_parameters["recovery_date"],
        "reason": recovery_parameters["reason"],
        "idempotency_key": recovery_parameters["idempotency_key"],
    }
    request = {
        "context": context_mapping("operation.recover", unsigned),
        **unsigned,
    }
    data = {
        **operation_response(recovery, next_action="operation.preview"),
        "origin_operation_id": origin.operation_id,
        "origin_operation_revision": origin.revision,
        "recovery_plan_digest": plan_digest,
    }
    response = {"command": "operation.recover", "data": data, "ok": True}
    verify = verifier(route, operations)

    assert verify("operation.recover", response, request) is True
    response["data"]["recovery_plan_digest"] = "5" * 64
    assert verify("operation.recover", response, request) is False


def test_factory_rejects_weak_dependencies_and_never_leaks_secrets():
    secret = b"highly-sensitive-verifier-secret-32"
    with pytest.raises(ResponseVerifierConfigurationError):
        config(read_secret=b"short")
    with pytest.raises(ResponseVerifierConfigurationError):
        config(read_key="bad key")
    with pytest.raises(ResponseVerifierConfigurationError):
        build_release_response_verifier(
            config(), operation_resolver=None, utc_clock=lambda: NOW
        )

    safe = config(read_secret=secret)
    assert secret.decode() not in repr(safe)

    request, response = read_exchange(route=safe)
    bad_clock = verifier(safe, {}, clock=lambda: datetime(2026, 7, 15))
    assert bad_clock("read", response, request) is False

    def broken_resolver(_operation_id):
        raise RuntimeError(secret.decode())

    operation, approval = terminal_operation()
    write_request, write_response = terminal_exchange(operation, approval)
    bound = build_release_response_verifier(
        safe,
        operation_resolver=broken_resolver,
        utc_clock=lambda: NOW,
    )
    assert bound.verify(
        "operation.approve_execute", write_response, write_request
    ) is False
    assert secret.decode() not in repr(bound.verify)
