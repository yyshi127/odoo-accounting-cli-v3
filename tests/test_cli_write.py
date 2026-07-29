from __future__ import annotations

import hashlib
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import pytest
from click.testing import CliRunner

from odoo_accounting_cli_v3.cli import main
from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
)
from odoo_accounting_cli_v3.operations import Approval, canonical_json
from odoo_accounting_cli_v3.write_protocol import approval_to_mapping


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
EFFECT_SECRET = b"cli-effect-finalizer-secret-material-32-bytes"


def _completed_result(
    operation_id: str = "op-1",
    *,
    recovered_origin_operation_id: str | None = None,
) -> dict[str, Any]:
    resolved_operation_id = recovered_origin_operation_id or operation_id
    resolution_kind = (
        "recovered" if recovered_origin_operation_id is not None else "verified"
    )
    intent = EffectFinalizationIntent(
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        operation_id=resolved_operation_id,
        operation_digest="4" * 64 if recovered_origin_operation_id else "1" * 64,
        execution_result_digest="5" * 64 if recovered_origin_operation_id else "2" * 64,
        resolution_operation_id=operation_id,
        resolution_operation_digest="1" * 64,
        resolution_execution_result_digest="2" * 64,
        resolution_result_digest="3" * 64,
        resolution_kind=resolution_kind,
    )
    request = EffectFinalizationRequest.from_intent(
        intent,
        verified_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    attestation = create_effect_attestation(
        request,
        key_id="effect-finalizer-v1",
        secret=EFFECT_SECRET,
    )
    finalization = EffectFinalizationReceipt.from_database_mapping(
        {
            "receipt_attestation_id": attestation.attestation_id,
            "receipt_guard_installation_id": (
                "22222222-2222-4222-8222-222222222222"
            ),
            "receipt_database_oid": 16384,
            "receipt_database_uuid": intent.database_uuid,
            "resolved_operation_id": resolved_operation_id,
            "receipt_resolution_operation_id": operation_id,
            "applied_resolution_kind": resolution_kind,
            "resolved_anchor_count": 2 if recovered_origin_operation_id else 1,
            "remaining_unresolved_count": 0 if recovered_origin_operation_id else 3,
            "guard_epoch": 0,
            "receipt_attestation_digest": attestation.attestation_digest,
            "finalized_at": "2026-07-15T08:00:01Z",
            "finalized_txid": "9123",
            "replayed": False,
        },
        request=request,
        attestation=attestation,
    ).evidence
    return {
        "operation_id": operation_id,
        "operation_state": "completed",
        "verification": {"passed": True},
        "database_finalization": finalization,
        "audit_receipt": {
            "approval_digest": "6" * 64,
            "approver_user_id": 99,
            "audit_head": "7" * 64,
            "capability_channel": "staged",
            "capability_id": "acct.bill.vendor_create.v1",
            "company_id": 7,
            "database_name": intent.database_name,
            "database_uuid": intent.database_uuid,
            "environment": "sandbox",
            "issued_at": "2026-07-15T08:00:02Z",
            "odoo_instance_id": "odoo19@sandbox",
            "operation_digest": "8" * 64,
            "operation_id": operation_id,
            "principal": "pi:user-42",
            "receipt_id": "write-receipt-1",
            "registry_digest": "9" * 64,
            "release_digest": "a" * 64,
            "request_digest": "b" * 64,
            "request_id": "req-1",
            "result_digest": "c" * 64,
            "signature": "d" * 64,
            "signature_purpose": "write_audit_receipt_v1",
            "signature_version": 1,
            "signing_key_id": "write-receipt-v1",
            "user_id": 42,
            "verification_evidence_digest": "e" * 64,
        },
    }


def _context() -> dict[str, Any]:
    return {
        "allowed_company_ids": [7],
        "audience": "odoo-accounting-cli-v3",
        "auth_expires_at": "2026-07-15T08:05:00Z",
        "auth_issued_at": "2026-07-15T08:00:00Z",
        "auth_key_id": "write-auth-v2",
        "auth_request_digest": "a" * 64,
        "auth_signature": "b" * 64,
        "auth_signature_purpose": "write_action_context_v2",
        "auth_signature_version": 2,
        "auth_token_id": "write-token-1",
        "company_id": 7,
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "odoo_instance_id": "odoo19@sandbox",
        "principal": "pi:user-42",
        "user_id": 42,
    }


def _approval() -> dict[str, Any]:
    return approval_to_mapping(
        Approval(
            operation_id="op-1",
            request_id="req-1",
            operation_digest="c" * 64,
            precheck_digest="d" * 64,
            user_id=42,
            company_id=7,
            operation_revision=2,
            approver_user_id=99,
            nonce="approval-nonce-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            signature_version=3,
            signature_purpose="approval_v3",
            key_id="approval-v3",
            signature="e" * 64,
        )
    )


def _request(action: str) -> dict[str, Any]:
    context = _context()
    if action == "operation.prepare":
        return {
            "context": context,
            "operation_id": "op-1",
            "request_id": "req-1",
            "capability_id": "acct.bill.vendor_create.v1",
            "parameters": {
                "company_id": 7,
                "accounting_date": "2026-07-15",
                "currency_id": 12,
                "idempotency_key": "bill-1",
                "lines": [{"name": "完整参数不会被 CLI 丢弃", "price_unit": "8.80"}],
                "partner_id": 901,
            },
        }
    if action == "operation.approve_execute":
        return {
            "context": context,
            "operation_id": "op-1",
            "approval": _approval(),
            "reconciliation_only": False,
        }
    if action == "operation.recover":
        return {
            "context": context,
            "origin_operation_id": "op-origin",
            "expected_origin_revision": 6,
            "recovery_operation_id": "op-recovery",
            "request_id": "req-recovery",
            "recovery_date": "2026-07-16",
            "reason": "Reverse the verified origin operation",
            "idempotency_key": "recover-origin-1",
        }
    if action == "operation.diagnostics":
        return {
            "context": context,
            "company_id": 7,
            "operation_id": "op-1",
        }
    return {"context": context, "operation_id": "op-1"}


def _install_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
    function: Callable[[str, Any], dict[str, Any]],
) -> None:
    module = types.ModuleType("odoo_accounting_cli_v3.write_app")
    module.execute_write_action = function  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)


def _invoke(action: str, request: dict[str, Any], *, command: str | None = None):
    cli_name = command or action.removeprefix("operation.").replace("_", "-")
    return CliRunner().invoke(
        main,
        ["operation", cli_name, "--request-json", json.dumps(request, ensure_ascii=False)],
    )


@pytest.mark.parametrize(
    "action",
    [
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
        "operation.status",
        "operation.result",
        "operation.diagnostics",
        "operation.recover",
    ],
)
def test_six_pi_actions_parse_exact_request_and_dispatch(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    observed: list[tuple[str, Any]] = []

    def dispatch(received_action: str, parsed: Any) -> dict[str, Any]:
        observed.append((received_action, parsed))
        if received_action in {"operation.approve_execute", "operation.result"}:
            return _completed_result()
        return {"accepted_action": received_action}

    _install_dispatcher(monkeypatch, dispatch)
    request = _request(action)

    result = _invoke(action, request)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    expected_command = action
    assert payload["command"] == expected_command
    assert payload["ok"] is True
    assert observed[0][0] == action
    assert observed[0][1].action == action
    assert observed[0][1].payload == {key: value for key, value in request.items() if key != "context"}
    if action in {"operation.approve_execute", "operation.result"}:
        assert payload["business_succeeded"] is True
    else:
        assert set(payload) == {"command", "data", "ok"}


def test_verify_is_read_only_result_alias_and_keeps_result_auth_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []

    def dispatch(action: str, parsed: Any) -> dict[str, Any]:
        observed.append((action, parsed.action))
        return _completed_result()

    _install_dispatcher(monkeypatch, dispatch)

    result = _invoke("operation.result", _request("operation.result"), command="verify")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert observed == [("operation.result", "operation.result")]
    assert payload["command"] == "operation.verify"
    assert payload["business_succeeded"] is True


def test_failed_business_result_is_not_reported_as_business_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        return {
            "operation_id": "op-1",
            "operation_state": "failed",
            "verification": {"passed": False},
        }

    _install_dispatcher(monkeypatch, dispatch)

    result = _invoke("operation.result", _request("operation.result"))

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "business_succeeded": False,
        "command": "operation.result",
        "data": {
            "operation_id": "op-1",
            "operation_state": "failed",
            "verification": {"passed": False},
        },
        "ok": True,
    }


@pytest.mark.parametrize(
    "mutation",
    ("missing", "wrong_operation", "wrong_database"),
)
def test_cli_never_reports_success_without_operation_bound_database_receipt(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        result = _completed_result()
        if mutation == "missing":
            result.pop("database_finalization")
        elif mutation == "wrong_operation":
            result["database_finalization"]["operation_id"] = "op-other"
        else:
            result["audit_receipt"]["database_uuid"] = (
                "33333333-3333-4333-8333-333333333333"
            )
        return result

    _install_dispatcher(monkeypatch, dispatch)
    response = _invoke("operation.result", _request("operation.result"))

    assert response.exit_code == 0, response.output
    assert json.loads(response.stdout)["business_succeeded"] is False


def test_cli_never_reports_success_with_thin_audit_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        result = _completed_result()
        result["audit_receipt"] = {
            "database_uuid": "11111111-1111-4111-8111-111111111111"
        }
        return result

    _install_dispatcher(monkeypatch, dispatch)
    response = _invoke("operation.result", _request("operation.result"))

    assert response.exit_code == 0, response.output
    assert json.loads(response.stdout)["business_succeeded"] is False


def test_cli_accepts_recovered_result_only_with_two_anchor_database_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        return _completed_result(
            "op-1", recovered_origin_operation_id="op-failed-origin"
        )

    _install_dispatcher(monkeypatch, dispatch)
    response = _invoke("operation.result", _request("operation.result"))

    assert response.exit_code == 0, response.output
    payload = json.loads(response.stdout)
    assert payload["business_succeeded"] is True
    assert payload["data"]["operation_state"] == "completed"
    finalization = payload["data"]["database_finalization"]
    assert {
        key: finalization[key]
        for key in (
            "operation_id",
            "resolution_operation_id",
            "resolved_anchor_count",
            "remaining_unresolved_count",
        )
    } == {
        "operation_id": "op-failed-origin",
        "resolution_operation_id": "op-1",
        "resolved_anchor_count": 2,
        "remaining_unresolved_count": 0,
    }


@pytest.mark.parametrize(
    "field,value",
    (
        ("operation_id", "op-1"),
        ("resolution_operation_id", "op-other-recovery"),
        ("resolved_anchor_count", 1),
    ),
)
def test_cli_rejects_misbound_recovered_database_receipt(
    monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        result = _completed_result(
            "op-1", recovered_origin_operation_id="op-failed-origin"
        )
        finalization = result["database_finalization"]
        finalization[field] = value
        finalization["receipt_digest"] = hashlib.sha256(
            canonical_json(
                {
                    key: item
                    for key, item in finalization.items()
                    if key != "receipt_digest"
                }
            )
        ).hexdigest()
        return result

    _install_dispatcher(monkeypatch, dispatch)
    response = _invoke("operation.result", _request("operation.result"))

    assert response.exit_code == 0, response.output
    assert json.loads(response.stdout)["business_succeeded"] is False


@pytest.mark.parametrize(
    "raw,code",
    [
        ("", "request_required"),
        ('{"context":{},"operation_id":"op-1","operation_id":"op-2"}', "invalid_json"),
        ('{"context":{},"operation_id":NaN}', "invalid_json"),
    ],
)
def test_missing_duplicate_and_non_finite_json_are_rejected_exactly(
    raw: str, code: str
) -> None:
    result = CliRunner().invoke(
        main, ["operation", "status", "--request-json", raw]
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert payload["error"] == {
        "code": code,
        "message": (
            "A non-empty JSON request object is required."
            if code == "request_required"
            else "The request is not valid JSON."
        ),
        "odoo_effect": "none",
        "retryable": False,
    }


def test_extra_or_missing_action_fields_fail_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    _install_dispatcher(monkeypatch, dispatch)
    request = _request("operation.status")

    for invalid in (
        {**request, "runtime_config": "C:/secret/runtime.json"},
        {"context": request["context"]},
    ):
        result = _invoke("operation.status", invalid)
        assert result.exit_code == 2
        payload = json.loads(result.stderr)
        assert payload["error"]["code"] == "invalid_request"
        assert payload["error"]["odoo_effect"] == "none"
    assert called is False


def test_pi_operation_commands_do_not_expose_runtime_or_secret_options() -> None:
    result = CliRunner().invoke(main, ["operation", "approve-execute", "--help"])

    assert result.exit_code == 0
    assert "--request-json" in result.stdout
    for forbidden in ("runtime-config", "timeout", "secret", "key-id"):
        assert forbidden not in result.stdout.lower()


def test_structured_dispatch_error_preserves_stable_safe_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BackendRejected(Exception):
        code = "approval_expired"
        message = "The signed approval expired before execution."
        retryable = True
        odoo_effect = "none"
        operation_id = "op-1"
        state = "approved"
        exit_code = 7

    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        raise BackendRejected()

    _install_dispatcher(monkeypatch, dispatch)

    result = _invoke("operation.approve_execute", _request("operation.approve_execute"))

    assert result.exit_code == 7
    assert json.loads(result.stderr) == {
        "command": "operation.approve_execute",
        "error": {
            "code": "approval_expired",
            "message": "The signed approval expired before execution.",
            "odoo_effect": "none",
            "operation_id": "op-1",
            "retryable": True,
            "state": "approved",
        },
        "ok": False,
    }


def test_unexpected_approve_execute_failure_reports_unknown_odoo_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def dispatch(_action: str, _parsed: Any) -> dict[str, Any]:
        raise RuntimeError("must not leak backend details")

    _install_dispatcher(monkeypatch, dispatch)

    result = _invoke("operation.approve_execute", _request("operation.approve_execute"))

    assert result.exit_code == 3
    payload = json.loads(result.stderr)
    assert payload["error"] == {
        "code": "write_action_failed",
        "message": "The durable write action did not return a trusted result.",
        "odoo_effect": "unknown",
        "operation_id": "op-1",
        "retryable": False,
    }
