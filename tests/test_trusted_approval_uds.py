from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

import odoo_accounting_cli_v3.trusted_approval_uds as approval_uds
from odoo_accounting_cli_v3.monotonic_deadline import (
    current_monotonic_deadline,
    monotonic_deadline_scope,
)
from odoo_accounting_cli_v3.trusted_authority import ApprovalDecision
from odoo_accounting_cli_v3.trusted_broker import TrustedBrokerError


SESSION_HANDLE = "opaque-session-handle-0123456789abcdef"
APPROVER_HANDLE = "opaque-approver-handle-0123456789abc"
OPERATION_ID = "operation-123"
CHALLENGE_ID = "challenge-123"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"


def test_request_handlers_are_non_daemon_and_joined_on_server_close() -> None:
    source = inspect.getsource(approval_uds)
    assert "daemon_threads = False" in source
    assert "block_on_close = True" in source
    assert "self.broker_invoker.wait_for_drain()" in source



def _view(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "capability_id": "account.move.post",
        "challenge_id": CHALLENGE_ID,
        "company_id": 7,
        "expires_at": "2026-07-15T08:05:00+00:00",
        "issued_at": "2026-07-15T08:00:00+00:00",
        "operation_digest": "4" * 64,
        "operation_id": OPERATION_ID,
        "precheck_digest": "5" * 64,
        "requester_user_id": 42,
        "state": "pending",
    }
    value.update(overrides)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _inspection(
    *,
    preview_line_count: int = 0,
    preview_memo_bytes: int = 0,
) -> dict[str, Any]:
    parameters = {
        "company_id": 7,
        "currency_id": 12,
        "idempotency_key": "invoice-101-20260715",
        "invoice_date": "2026-07-15",
        "partner_id": 101,
    }
    preview_lines = [
        {
            "amount": "1.00",
            "date": "2026-07-15",
            "memo": f"line-{index:03d}-" + ("x" * preview_memo_bytes),
        }
        for index in range(preview_line_count)
    ]
    if preview_lines:
        parameters["lines"] = preview_lines
    parameters_digest = _digest(parameters)
    operation_digest = _digest(
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "company_id": 7,
            "database_name": "odoo_v3_sandbox",
            "database_uuid": DATABASE_UUID,
            "environment": "sandbox",
            "idempotency_key": "invoice-101-20260715",
            "odoo_instance_id": "odoo19@tokyo2",
            "parameters": parameters,
            "principal": "pi:user-42",
            "registry_digest": "2" * 64,
            "release_digest": "1" * 64,
            "user_id": 42,
        }
    )
    evidence = {
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "parameters_digest": parameters_digest,
        "passed": True,
        "checks": ["accounting_dependencies", "tax_preview"],
        "handler_details": {
            "dependencies": [
                {
                    "display_name": "Customer 101",
                    "model": "res.partner",
                    "record_id": 101,
                }
            ],
            "financial_preview": {
                "amount_tax": "10.00",
                "amount_total": "110.00",
                "amount_untaxed": "100.00",
                **({"lines": preview_lines} if preview_lines else {}),
            },
        },
        "runtime_binding": {
            "capability_channel": "staged",
            "database_name": "odoo_v3_sandbox",
            "database_uuid": DATABASE_UUID,
            "environment": "sandbox",
            "odoo_instance_id": "odoo19@tokyo2",
            "user_id": 42,
        },
        "registry_digest": "2" * 64,
        "release_digest": "1" * 64,
    }
    evidence_digest = _digest(evidence)
    operation = {
        "operation_id": OPERATION_ID,
        "request_id": "request-123",
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": parameters,
        "parameters_digest": parameters_digest,
        "principal": "pi:user-42",
        "user_id": 42,
        "company_id": 7,
        "idempotency_key": "invoice-101-20260715",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": DATABASE_UUID,
        "environment": "sandbox",
        "registry_digest": "2" * 64,
        "release_digest": "1" * 64,
        "operation_digest": operation_digest,
        "precheck_digest": evidence_digest,
        "state": "awaiting_approval",
        "revision": 2,
        "protocol_version": 4,
    }
    binding_digest = _digest(
        {
            "company_id": operation["company_id"],
            "database_name": operation["database_name"],
            "database_uuid": operation["database_uuid"],
            "environment": operation["environment"],
            "odoo_instance_id": operation["odoo_instance_id"],
            "operation_digest": operation_digest,
            "operation_id": OPERATION_ID,
            "operation_revision": 2,
            "precheck_digest": evidence_digest,
            "principal": operation["principal"],
            "request_id": operation["request_id"],
            "user_id": operation["user_id"],
        }
    )
    challenge = {
        "challenge_id": CHALLENGE_ID,
        "binding_digest": binding_digest,
        "issued_at": "2026-07-15T08:00:00+00:00",
        "expires_at": "2026-07-15T08:02:00+00:00",
        "ttl_seconds": 120,
        "state": "pending",
        "version": 0,
    }
    summary = {
        "binding_digest": binding_digest,
        "capability_id": operation["capability_id"],
        "challenge_id": CHALLENGE_ID,
        "company_id": 7,
        "operation_digest": operation_digest,
        "operation_id": OPERATION_ID,
        "parameters_digest": parameters_digest,
        "precheck_digest": evidence_digest,
        "requester_principal": "pi:user-42",
        "requester_user_id": 42,
    }
    core = {
        "schema_version": 1,
        "challenge": challenge,
        "operation": operation,
        "summary": summary,
    }
    preview = {**core, "preview_digest": _digest(core)}
    precheck = {
        "operation_id": OPERATION_ID,
        "request_id": operation["request_id"],
        "operation_digest": operation_digest,
        "operation_revision": 2,
        "source_operation_revision": 0,
        "principal": "pi:user-42",
        "user_id": 42,
        "company_id": 7,
        "evidence_digest": evidence_digest,
        "occurred_at": "2026-07-15T08:00:00+00:00",
        "evidence": evidence,
    }
    unsigned = {**preview, "precheck": precheck}
    return {**unsigned, "inspection_digest": _digest(unsigned)}


class StubBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.request_result: Any = _view()
        self.decide_result: Any = _view(state="approved")
        self.inspect_result: Any = _inspection()
        self.request_error: Exception | None = None
        self.decide_error: Exception | None = None
        self.inspect_error: Exception | None = None

    def request_approval(
        self,
        *,
        session_handle: str,
        operation_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]:
        details: dict[str, Any] = {
            "session_handle": session_handle,
            "operation_id": operation_id,
        }
        if (peer_uid, peer_gid, peer_pid) != (None, None, None):
            details.update(
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
            )
        self.calls.append(
            (
                "request_approval",
                details,
            )
        )
        if self.request_error is not None:
            raise self.request_error
        return self.request_result

    def decide_approval(
        self,
        *,
        session_handle: str,
        challenge_id: str,
        decision: ApprovalDecision,
        reason: str | None = None,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]:
        details = {
            "session_handle": session_handle,
            "challenge_id": challenge_id,
            "decision": decision,
            "reason": reason,
        }
        if (peer_uid, peer_gid, peer_pid) != (None, None, None):
            details.update(
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
            )
        self.calls.append(
            (
                "decide_approval",
                details,
            )
        )
        if self.decide_error is not None:
            raise self.decide_error
        return self.decide_result

    def inspect_approval(
        self,
        *,
        session_handle: str,
        challenge_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]:
        details: dict[str, Any] = {
            "session_handle": session_handle,
            "challenge_id": challenge_id,
        }
        if (peer_uid, peer_gid, peer_pid) != (None, None, None):
            details.update(
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
            )
        self.calls.append(("inspect_approval", details))
        if self.inspect_error is not None:
            raise self.inspect_error
        return self.inspect_result


def _config(**overrides: Any) -> approval_uds.TrustedApprovalUdsConfig:
    values: dict[str, Any] = {
        "socket_path": "/run/odoo-v3/trusted-approval.sock",
        "odoo_client_uid": 1101,
        "pi_bridge_uid": 1201,
        "socket_group_gid": 1101,
    }
    values.update(overrides)
    return approval_uds.TrustedApprovalUdsConfig(**values)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _request_payload(**overrides: Any) -> dict[str, Any]:
    value = {"session_handle": SESSION_HANDLE, "operation_id": OPERATION_ID}
    value.update(overrides)
    return value


def _decide_payload(**overrides: Any) -> dict[str, Any]:
    value = {
        "session_handle": APPROVER_HANDLE,
        "challenge_id": CHALLENGE_ID,
        "decision": "approve",
        "reason": None,
    }
    value.update(overrides)
    return value


def _inspect_payload(**overrides: Any) -> dict[str, Any]:
    value = {
        "session_handle": APPROVER_HANDLE,
        "challenge_id": CHALLENGE_ID,
    }
    value.update(overrides)
    return value


def test_config_separates_odoo_client_from_pi_bridge_and_bounds_transport() -> None:
    config = _config()
    assert config.odoo_client_uid == 1101
    assert config.pi_bridge_uid == 1201
    assert config.max_body_bytes == 8192
    assert config.max_response_bytes == 1024 * 1024

    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="different UID"):
        _config(pi_bridge_uid=1101)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="unprivileged"):
        _config(pi_bridge_uid=0)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="unprivileged"):
        _config(odoo_client_uid=0)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="body limit"):
        _config(max_body_bytes=1)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="response limit"):
        _config(max_response_bytes=128)
    assert _config(max_response_bytes=4 * 1024 * 1024).max_response_bytes == (
        4 * 1024 * 1024
    )
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="response limit"):
        _config(max_response_bytes=(4 * 1024 * 1024) + 1)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="header byte"):
        _config(max_header_bytes=128)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="timeout"):
        _config(request_timeout_seconds=0)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="in-flight"):
        _config(max_inflight_broker_calls=0)


def test_peer_uid_is_authentication_and_pid_gid_are_diagnostic_only() -> None:
    config = _config()
    same_uid_different_process = approval_uds._PeerCredentials(
        pid=999_999, uid=1101, gid=9999
    )
    pi = approval_uds._PeerCredentials(pid=1, uid=1201, gid=1101)

    assert approval_uds._peer_is_allowed(same_uid_different_process, config) is True
    assert approval_uds._peer_is_allowed(pi, config) is False
    assert "cannot distinguish" in approval_uds.SAME_UID_THREAT.lower()
    assert "different unix uid" in approval_uds.SAME_UID_THREAT.lower()


def test_peer_credentials_use_linux_so_peercred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    option = 0x7FFE
    monkeypatch.setattr(approval_uds.socket, "SO_PEERCRED", option, raising=False)
    calls: list[tuple[int, int, int]] = []

    class FakeConnection:
        def getsockopt(self, level: int, name: int, length: int) -> bytes:
            calls.append((level, name, length))
            return struct.pack(
                approval_uds._PEER_CREDENTIAL_FORMAT, 123, 1101, 1102
            )

    peer = approval_uds._peer_credentials(FakeConnection())  # type: ignore[arg-type]
    assert peer == approval_uds._PeerCredentials(pid=123, uid=1101, gid=1102)
    assert calls == [
        (socket.SOL_SOCKET, option, approval_uds._PEER_CREDENTIAL_SIZE)
    ]


def test_decode_accepts_only_exact_business_request_fields() -> None:
    request = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH,
        _json_bytes(_request_payload()),
    )
    assert request.session_handle == SESSION_HANDLE
    assert request.operation_id == OPERATION_ID
    assert request.challenge_id is None
    assert request.decision is None
    assert request.reason is None
    assert SESSION_HANDLE not in repr(request)

    decision = approval_uds._decode_call(
        approval_uds.APPROVAL_DECIDE_PATH,
        _json_bytes(_decide_payload(decision="deny", reason="Missing evidence")),
    )
    assert decision.session_handle == APPROVER_HANDLE
    assert decision.challenge_id == CHALLENGE_ID
    assert decision.decision is ApprovalDecision.DENY
    assert decision.reason == "Missing evidence"

    inspection = approval_uds._decode_call(
        approval_uds.APPROVAL_INSPECT_PATH,
        _json_bytes(_inspect_payload()),
    )
    assert inspection.action == "approval.inspect"
    assert inspection.session_handle == APPROVER_HANDLE
    assert inspection.challenge_id == CHALLENGE_ID
    assert inspection.operation_id is None
    assert inspection.decision is None
    assert inspection.reason is None

    for forbidden in (
        {"user_id": 42},
        {"company_id": 7},
        {"release_digest": "a" * 64},
        {"registry_digest": "b" * 64},
        {"runtime": {"database": "prod"}},
        {"odoo_instance_id": "prod"},
        {"peer_uid": 1101},
        {"peer_gid": 1101},
        {"peer_pid": 123},
    ):
        with pytest.raises(
            approval_uds.TrustedApprovalUdsError,
            match="exact approval request fields",
        ):
            approval_uds._decode_call(
                approval_uds.APPROVAL_REQUEST_PATH,
                _json_bytes(_request_payload(**forbidden)),
            )

    for forbidden in (
        {"user_id": 84},
        {"company_id": 7},
        {"approval": {"signature": "attacker"}},
        {"release_digest": "a" * 64},
        {"deadline_monotonic": time.monotonic() + 10},
        {"peer_uid": 1101},
    ):
        with pytest.raises(
            approval_uds.TrustedApprovalUdsError,
            match="exact approval request fields",
        ):
            approval_uds._decode_call(
                approval_uds.APPROVAL_INSPECT_PATH,
                _json_bytes(_inspect_payload(**forbidden)),
            )


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (approval_uds.APPROVAL_REQUEST_PATH, b"[]"),
        (
            approval_uds.APPROVAL_REQUEST_PATH,
            b'{"session_handle":"' + SESSION_HANDLE.encode() + b'",'
            b'"operation_id":"one","operation_id":"two"}',
        ),
        (approval_uds.APPROVAL_REQUEST_PATH, b'{"operation_id":NaN}'),
        (approval_uds.APPROVAL_REQUEST_PATH, b"\xff"),
        (
            approval_uds.APPROVAL_REQUEST_PATH,
            _json_bytes(_request_payload(session_handle="short")),
        ),
        (
            approval_uds.APPROVAL_REQUEST_PATH,
            _json_bytes(_request_payload(operation_id="invalid/id")),
        ),
        (
            approval_uds.APPROVAL_DECIDE_PATH,
            _json_bytes(_decide_payload(decision="APPROVE")),
        ),
        (
            approval_uds.APPROVAL_DECIDE_PATH,
            _json_bytes(_decide_payload(decision="approve", reason="not allowed")),
        ),
        (
            approval_uds.APPROVAL_DECIDE_PATH,
            _json_bytes(_decide_payload(decision="deny", reason=None)),
        ),
        (
            approval_uds.APPROVAL_DECIDE_PATH,
            _json_bytes(_decide_payload(decision="deny", reason=" padded ")),
        ),
    ],
)
def test_decode_rejects_non_strict_or_invalid_business_requests(
    path: str, body: bytes
) -> None:
    with pytest.raises(approval_uds.TrustedApprovalUdsError):
        approval_uds._decode_call(path, body)


def test_invoke_calls_only_exact_broker_approval_interfaces() -> None:
    broker = StubBroker()
    request = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    assert approval_uds._invoke_broker(broker, request) == _view()

    decision = approval_uds._decode_call(
        approval_uds.APPROVAL_DECIDE_PATH,
        _json_bytes(_decide_payload(decision="deny", reason="Missing evidence")),
    )
    broker.decide_result = _view(state="denied")
    assert approval_uds._invoke_broker(broker, decision) == _view(state="denied")
    inspection = approval_uds._decode_call(
        approval_uds.APPROVAL_INSPECT_PATH,
        _json_bytes(_inspect_payload()),
    )
    assert approval_uds._invoke_broker(broker, inspection) == _inspection()
    assert broker.calls == [
        (
            "request_approval",
            {"session_handle": SESSION_HANDLE, "operation_id": OPERATION_ID},
        ),
        (
            "decide_approval",
            {
                "session_handle": APPROVER_HANDLE,
                "challenge_id": CHALLENGE_ID,
                "decision": ApprovalDecision.DENY,
                "reason": "Missing evidence",
            },
        ),
        (
            "inspect_approval",
            {
                "session_handle": APPROVER_HANDLE,
                "challenge_id": CHALLENGE_ID,
            },
        ),
    ]


def test_transport_peer_credentials_are_forwarded_only_as_observed_metadata() -> None:
    broker = StubBroker()
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    peer = approval_uds._PeerCredentials(pid=4321, uid=1101, gid=1102)

    assert approval_uds._invoke_broker(broker, call, peer=peer) == _view()
    assert broker.calls == [
        (
            "request_approval",
            {
                "session_handle": SESSION_HANDLE,
                "operation_id": OPERATION_ID,
                "peer_uid": 1101,
                "peer_gid": 1102,
                "peer_pid": 4321,
            },
        )
    ]

    invalid_peer = approval_uds._PeerCredentials(pid=0, uid=1101, gid=1102)
    with pytest.raises(
        approval_uds.TrustedApprovalUdsError,
        match="trusted approval broker rejected request",
    ):
        approval_uds._invoke_broker(broker, call, peer=invalid_peer)


def test_inspect_forwards_peer_metadata_and_never_supplies_caller_deadline() -> None:
    broker = StubBroker()
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_INSPECT_PATH,
        _json_bytes(_inspect_payload()),
    )
    peer = approval_uds._PeerCredentials(pid=4321, uid=1101, gid=1102)

    assert approval_uds._invoke_broker(broker, call, peer=peer) == _inspection()
    assert broker.calls == [
        (
            "inspect_approval",
            {
                "session_handle": APPROVER_HANDLE,
                "challenge_id": CHALLENGE_ID,
                "peer_uid": 1101,
                "peer_gid": 1102,
                "peer_pid": 4321,
            },
        )
    ]
    assert "deadline_monotonic" not in broker.calls[0][1]


def test_inspection_schema_is_rebuilt_verified_serializable_and_detached() -> None:
    raw = _inspection()

    sanitized = approval_uds._sanitize_inspection(raw)

    assert sanitized == raw
    assert json.loads(_canonical(sanitized)) == sanitized
    assert set(sanitized) == {
        "schema_version",
        "challenge",
        "operation",
        "summary",
        "preview_digest",
        "precheck",
        "inspection_digest",
    }
    assert sanitized["precheck"]["evidence"]["handler_details"][
        "financial_preview"
    ]["amount_total"] == "110.00"
    raw["operation"]["parameters"]["partner_id"] = 999
    raw["precheck"]["evidence"]["handler_details"]["dependencies"][0][
        "display_name"
    ] = "tampered"
    assert sanitized["operation"]["parameters"]["partner_id"] == 101
    assert sanitized["precheck"]["evidence"]["handler_details"]["dependencies"][
        0
    ]["display_name"] == "Customer 101"


def _transport_digest(value: dict[str, Any], *, exclude: str) -> str:
    return _digest({key: child for key, child in value.items() if key != exclude})


def test_inspection_rejects_any_schema_binding_evidence_or_authority_drift() -> None:
    forged: list[dict[str, Any]] = []

    extra = _inspection()
    extra["signature"] = "secret-signature"
    forged.append(extra)

    nested_authority = _inspection()
    nested_authority["precheck"]["evidence"]["approval"] = {
        "signature": "secret-signature"
    }
    nested_authority["inspection_digest"] = _transport_digest(
        nested_authority, exclude="inspection_digest"
    )
    forged.append(nested_authority)

    parameter_drift = _inspection()
    parameter_drift["operation"]["parameters"]["partner_id"] = 999
    parameter_drift["inspection_digest"] = _transport_digest(
        parameter_drift, exclude="inspection_digest"
    )
    forged.append(parameter_drift)

    source_revision_drift = _inspection()
    source_revision_drift["precheck"]["source_operation_revision"] = 1
    source_revision_drift["inspection_digest"] = _transport_digest(
        source_revision_drift, exclude="inspection_digest"
    )
    forged.append(source_revision_drift)

    future_evidence = _inspection()
    future_evidence["precheck"]["occurred_at"] = "2026-07-15T08:00:01+00:00"
    future_evidence["inspection_digest"] = _transport_digest(
        future_evidence, exclude="inspection_digest"
    )
    forged.append(future_evidence)

    evidence_drift = _inspection()
    evidence_drift["precheck"]["evidence"]["handler_details"][
        "financial_preview"
    ]["amount_total"] = "999.00"
    evidence_drift["inspection_digest"] = _transport_digest(
        evidence_drift, exclude="inspection_digest"
    )
    forged.append(evidence_drift)

    runtime_drift = _inspection()
    runtime_drift["precheck"]["evidence"]["runtime_binding"]["user_id"] = 999
    runtime_drift["inspection_digest"] = _transport_digest(
        runtime_drift, exclude="inspection_digest"
    )
    forged.append(runtime_drift)

    release_drift = _inspection()
    release_drift["precheck"]["evidence"]["release_digest"] = "f" * 64
    release_drift["inspection_digest"] = _transport_digest(
        release_drift, exclude="inspection_digest"
    )
    forged.append(release_drift)

    digest_drift = _inspection()
    digest_drift["inspection_digest"] = "f" * 64
    forged.append(digest_drift)

    for value in forged:
        with pytest.raises(
            approval_uds.TrustedApprovalUdsError,
            match="inspection",
        ) as captured:
            approval_uds._sanitize_inspection(value)
        assert "secret-signature" not in str(captured.value)


def test_inspect_response_must_bind_to_requested_challenge() -> None:
    broker = StubBroker()
    broker.inspect_result["challenge"]["challenge_id"] = "other-challenge"
    broker.inspect_result["summary"]["challenge_id"] = "other-challenge"
    broker.inspect_result["preview_digest"] = _digest(
        {
            key: child
            for key, child in broker.inspect_result.items()
            if key
            in {"schema_version", "challenge", "operation", "summary"}
        }
    )
    broker.inspect_result["inspection_digest"] = _transport_digest(
        broker.inspect_result, exclude="inspection_digest"
    )
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_INSPECT_PATH,
        _json_bytes(_inspect_payload()),
    )

    with pytest.raises(
        approval_uds.TrustedApprovalUdsError,
        match="trusted approval broker rejected request",
    ):
        approval_uds._invoke_broker(broker, call)


@pytest.mark.parametrize(
    ("action", "result"),
    [
        ("request", _view(operation_id="other-operation")),
        ("decide", _view(challenge_id="other-challenge", state="approved")),
        ("decide", _view(state="pending")),
        ("decide-deny", _view(state="approved")),
    ],
)
def test_broker_view_must_bind_to_exact_request_and_decision(
    action: str, result: dict[str, Any]
) -> None:
    broker = StubBroker()
    if action == "request":
        broker.request_result = result
        call = approval_uds._decode_call(
            approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
        )
    else:
        decision = "deny" if action == "decide-deny" else "approve"
        reason = "Missing evidence" if decision == "deny" else None
        broker.decide_result = result
        call = approval_uds._decode_call(
            approval_uds.APPROVAL_DECIDE_PATH,
            _json_bytes(_decide_payload(decision=decision, reason=reason)),
        )
    with pytest.raises(approval_uds.TrustedApprovalUdsError):
        approval_uds._invoke_broker(broker, call)


@pytest.mark.parametrize(
    "forged",
    [
        _view(approval_signature="secret-signature"),
        _view(approval={"signature": "secret-signature"}),
        _view(signature="secret-signature"),
        _view(state="executed"),
        _view(company_id=True),
        _view(requester_user_id=0),
        _view(operation_digest="A" * 64),
        _view(issued_at="2026-07-15T08:00:00Z"),
        _view(expires_at="2026-07-15T07:59:59+00:00"),
    ],
)
def test_forged_or_authority_bearing_broker_views_fail_closed(
    forged: dict[str, Any],
) -> None:
    broker = StubBroker()
    broker.request_result = forged
    request = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    with pytest.raises(
        approval_uds.TrustedApprovalUdsError,
        match="trusted approval broker rejected request",
    ) as captured:
        approval_uds._invoke_broker(broker, request)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "secret-signature" not in str(captured.value)


@pytest.mark.parametrize("failure", ["replayed", "expired", "unauthorized"])
def test_replay_expiry_and_authorization_failures_are_sanitized(failure: str) -> None:
    broker = StubBroker()
    secret = f"{failure}-{SESSION_HANDLE}"
    broker.request_error = TrustedBrokerError(secret, status_code=403)
    request = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    with pytest.raises(approval_uds.TrustedApprovalUdsError) as captured:
        approval_uds._invoke_broker(broker, request)
    assert str(captured.value) == "trusted approval broker rejected request"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert SESSION_HANDLE not in str(captured.value)


def test_inspect_failure_is_safe_and_still_forwards_peer_for_broker_audit() -> None:
    broker = StubBroker()
    broker.inspect_error = TrustedBrokerError(
        f"private-{APPROVER_HANDLE}-precheck-backend", status_code=503
    )
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_INSPECT_PATH,
        _json_bytes(_inspect_payload()),
    )
    peer = approval_uds._PeerCredentials(pid=4321, uid=1101, gid=1102)

    with pytest.raises(approval_uds.TrustedApprovalUdsError) as captured:
        approval_uds._invoke_broker(broker, call, peer=peer)

    assert str(captured.value) == "trusted approval broker rejected request"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert APPROVER_HANDLE not in str(captured.value)
    assert broker.calls == [
        (
            "inspect_approval",
            {
                "session_handle": APPROVER_HANDLE,
                "challenge_id": CHALLENGE_ID,
                "peer_uid": 1101,
                "peer_gid": 1102,
                "peer_pid": 4321,
            },
        )
    ]


def test_broker_adapter_contract_requires_inspect_method() -> None:
    broker = StubBroker()
    broker.inspect_approval = None  # type: ignore[method-assign]

    assert approval_uds._broker_contract_is_valid(broker) is False
    with pytest.raises(
        approval_uds.TrustedApprovalUdsError,
        match="trusted approval broker is invalid",
    ):
        approval_uds._BoundedBrokerInvoker(broker, max_inflight=1)


def test_broker_worker_explicitly_inherits_the_shortest_absolute_deadline() -> None:
    observed_deadlines: list[float | None] = []

    class DeadlineBroker(StubBroker):
        def request_approval(self, **kwargs: Any) -> dict[str, Any]:
            observed_deadlines.append(current_monotonic_deadline())
            return super().request_approval(**kwargs)

    broker = DeadlineBroker()
    invoker = approval_uds._BoundedBrokerInvoker(broker, max_inflight=1)
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    outer_deadline = time.monotonic() + 1

    with monotonic_deadline_scope(outer_deadline):
        result = invoker.invoke(call, deadline_monotonic=outer_deadline + 10)

    assert result.status == "ok"
    assert observed_deadlines == [outer_deadline]
    assert current_monotonic_deadline() is None


def test_hung_broker_is_time_bounded_and_consumes_only_one_bounded_slot() -> None:
    release = threading.Event()

    class BlockingBroker(StubBroker):
        def request_approval(
            self,
            *,
            session_handle: str,
            operation_id: str,
            peer_uid: int | None = None,
            peer_gid: int | None = None,
            peer_pid: int | None = None,
        ) -> dict[str, Any]:
            del peer_uid, peer_gid, peer_pid
            self.calls.append(
                (
                    "request_approval",
                    {"session_handle": session_handle, "operation_id": operation_id},
                )
            )
            release.wait()
            return self.request_result

    broker = BlockingBroker()
    invoker = approval_uds._BoundedBrokerInvoker(broker, max_inflight=1)
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )
    started = time.monotonic()
    first = invoker.invoke(call, deadline_monotonic=started + 0.05)
    elapsed = time.monotonic() - started
    second = invoker.invoke(call, deadline_monotonic=time.monotonic() + 1)
    release.set()
    invoker.wait_for_drain()

    assert first.status == "timeout"
    assert first.view is None
    assert elapsed < 0.5
    assert second.status == "unavailable"
    assert second.view is None
    assert len(broker.calls) == 1


def test_timed_out_broker_worker_is_non_daemon_and_drainable() -> None:
    release = threading.Event()

    class BlockingBroker(StubBroker):
        def request_approval(
            self,
            *,
            session_handle: str,
            operation_id: str,
            peer_uid: int | None = None,
            peer_gid: int | None = None,
            peer_pid: int | None = None,
        ) -> dict[str, Any]:
            del session_handle, operation_id, peer_uid, peer_gid, peer_pid
            release.wait()
            return self.request_result

    invoker = approval_uds._BoundedBrokerInvoker(
        BlockingBroker(), max_inflight=1
    )
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )

    result = invoker.invoke(
        call, deadline_monotonic=time.monotonic() + 0.05
    )
    workers = [
        thread
        for thread in threading.enumerate()
        if thread.name == "odoo-v3-approval-broker"
    ]
    drained = threading.Event()
    drain_thread = threading.Thread(
        target=lambda: (invoker.wait_for_drain(), drained.set()),
        name="approval-drain-test",
    )
    drain_thread.start()
    try:
        assert result.status == "timeout"
        assert len(workers) == 1
        assert workers[0].daemon is False
        assert not drained.wait(0.05)
    finally:
        release.set()
        drain_thread.join(timeout=1)
    assert drained.is_set()
    assert not drain_thread.is_alive()


def test_broker_call_does_not_start_if_deadline_expires_during_thread_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 99.0}

    class InlineThread:
        def __init__(self, *, target: Any, name: str, daemon: bool) -> None:
            del name, daemon
            self._target = target

        def start(self) -> None:
            clock["now"] = 101.0
            self._target()

    monkeypatch.setattr(approval_uds, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(approval_uds.threading, "Thread", InlineThread)
    broker = StubBroker()
    invoker = approval_uds._BoundedBrokerInvoker(broker, max_inflight=1)
    call = approval_uds._decode_call(
        approval_uds.APPROVAL_REQUEST_PATH, _json_bytes(_request_payload())
    )

    result = invoker.invoke(call, deadline_monotonic=100.0)

    assert result.status == "timeout"
    assert result.view is None
    assert broker.calls == []


def test_request_line_reader_bounds_preparse_resource_use() -> None:
    raw = io.BytesIO(b"POST /" + b"x" * 10_000 + b" HTTP/1.1\r\n")
    reader = approval_uds._RequestLineLimitedReader(raw, max_bytes=1024)

    request_line = reader.readline(65_537)

    assert len(request_line) == 1025
    assert raw.tell() == 1025


def test_safe_errors_and_access_logging_never_expose_handle_or_backend_detail(
    capfd: pytest.CaptureFixture[str],
) -> None:
    source = inspect.getsource(approval_uds)
    assert "UnixStreamServer" in source
    assert "TCPServer" not in source
    assert "SO_PEERCRED" in source
    approval_uds._ApprovalRequestHandler.log_message(
        object(), "%s %s", SESSION_HANDLE, "backend stack secret"
    )
    captured = capfd.readouterr()
    rendered = json.dumps(approval_uds._safe_error("approval_rejected"))
    assert SESSION_HANDLE not in captured.out + captured.err + rendered
    assert "backend stack secret" not in captured.out + captured.err + rendered


def _raw_request(
    *,
    path: str = approval_uds.APPROVAL_REQUEST_PATH,
    body: bytes | None = None,
    method: str = "POST",
    content_type: str = "application/json",
    extra_headers: list[tuple[str, str]] | None = None,
) -> bytes:
    body = _json_bytes(_request_payload()) if body is None else body
    headers = [
        ("Host", "odoo-approval-client"),
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Connection", "close"),
    ]
    headers.extend(extra_headers or [])
    rendered = "".join(f"{name}: {value}\r\n" for name, value in headers)
    return (
        f"{method} {path} HTTP/1.1\r\n{rendered}\r\n".encode("ascii") + body
    )


def _response(response: bytes) -> tuple[int, dict[str, str], dict[str, Any]]:
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        assert name.lower() not in headers
        headers[name.lower()] = value.strip()
    assert int(headers["content-length"]) == len(body)
    return status, headers, json.loads(body)


def _render_json_response(
    value: dict[str, Any], *, max_response_bytes: int
) -> tuple[int, dict[str, str], dict[str, Any]]:
    class CapturingHandler:
        def __init__(self) -> None:
            self._response_sent = False
            self.close_connection = False
            self.server = type(
                "Server",
                (),
                {"config": _config(max_response_bytes=max_response_bytes)},
            )()
            self.wfile = io.BytesIO()
            self.status_code = 0
            self.response_headers: dict[str, str] = {}

        def _cancel_io_timer(self) -> None:
            return None

        def send_response_only(self, status_code: int) -> None:
            self.status_code = status_code

        def send_header(self, name: str, value: str) -> None:
            self.response_headers[name.lower()] = value

        def end_headers(self) -> None:
            return None

    handler = CapturingHandler()
    approval_uds._ApprovalRequestHandler._send_json(handler, 200, value)  # type: ignore[arg-type]
    body = handler.wfile.getvalue()
    assert int(handler.response_headers["content-length"]) == len(body)
    return handler.status_code, handler.response_headers, json.loads(body)


def test_large_complete_inspection_fits_default_response_bound_and_overflow_fails_closed() -> None:
    inspection = approval_uds._sanitize_inspection(
        _inspection(preview_line_count=250, preview_memo_bytes=1200)
    )
    response = {"ok": True, "inspection": inspection}
    encoded = _json_bytes(response)
    assert 64 * 1024 < len(encoded) < 1024 * 1024

    status, headers, body = _render_json_response(
        response,
        max_response_bytes=1024 * 1024,
    )
    assert status == 200
    assert headers["cache-control"] == "no-store"
    assert body == response

    status, _, body = _render_json_response(
        response,
        max_response_bytes=len(encoded) - 1,
    )
    assert status == 500
    assert body == approval_uds._safe_error("approval_response_rejected")


def test_capacity_response_is_safe_deterministic_and_retryable() -> None:
    status, headers, body = _response(approval_uds._capacity_response())
    assert status == 503
    assert headers["connection"] == "close"
    assert headers["cache-control"] == "no-store"
    assert body == approval_uds._safe_error(
        "approval_broker_unavailable", retryable=True
    )
    assert body["error"]["retryable"] is True
    assert approval_uds._safe_error("approval_broker_rejected")["error"][
        "retryable"
    ] is False


@contextmanager
def _linux_server(
    broker: StubBroker,
    *,
    allowed_uid: int | None = None,
    request_timeout_seconds: float = 2.0,
    max_body_bytes: int = 8192,
    max_response_bytes: int = 1024 * 1024,
    max_inflight_broker_calls: int = 4,
) -> Iterator[approval_uds.TrustedApprovalUdsConfig]:
    if sys.platform != "linux" or approval_uds._TrustedUnixHTTPServer is None:
        pytest.skip("requires Linux Unix sockets and SO_PEERCRED")
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-approval-uds-", dir="/tmp"))
    root.chmod(0o700)
    path = root / "approval.sock"
    current_uid = os.getuid()
    if current_uid == 0:
        pytest.skip("real peer tests require an unprivileged Odoo client UID")
    effective_uid = current_uid if allowed_uid is None else allowed_uid
    pi_uid = current_uid + 1 if effective_uid == current_uid else current_uid
    if pi_uid == effective_uid:
        pi_uid += 1
    config = approval_uds.TrustedApprovalUdsConfig(
        socket_path=str(path),
        odoo_client_uid=effective_uid,
        pi_bridge_uid=pi_uid,
        socket_group_gid=os.getgid(),
        request_timeout_seconds=request_timeout_seconds,
        max_body_bytes=max_body_bytes,
        max_response_bytes=max_response_bytes,
        max_inflight_broker_calls=max_inflight_broker_calls,
    )
    server = approval_uds._TrustedUnixHTTPServer(
        config, broker, bind_and_activate=True
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        path.unlink(missing_ok=True)
        root.rmdir()


def _exchange(path: str, request: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(path)
        try:
            client.sendall(request)
        except (BrokenPipeError, ConnectionResetError):
            return b""
        chunks: list[bytes] = []
        while True:
            try:
                chunk = client.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        client.close()


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_fixed_routes_return_only_sanitized_views() -> None:
    broker = StubBroker()
    with _linux_server(broker) as config:
        requested = _exchange(config.socket_path, _raw_request())
        decided = _exchange(
            config.socket_path,
            _raw_request(
                path=approval_uds.APPROVAL_DECIDE_PATH,
                body=_json_bytes(_decide_payload()),
            ),
        )
        inspected = _exchange(
            config.socket_path,
            _raw_request(
                path=approval_uds.APPROVAL_INSPECT_PATH,
                body=_json_bytes(_inspect_payload()),
            ),
        )
    request_status, _, request_body = _response(requested)
    decide_status, _, decide_body = _response(decided)
    inspect_status, _, inspect_body = _response(inspected)
    assert request_status == decide_status == inspect_status == 200
    assert request_body == {"challenge": _view(), "ok": True}
    assert decide_body == {"decision": _view(state="approved"), "ok": True}
    assert inspect_body == {"inspection": _inspection(), "ok": True}
    rendered = requested + decided + inspected
    assert b"approval_signature" not in rendered
    assert b'"signature"' not in rendered
    assert broker.calls[0][1]["peer_uid"] == os.getuid()
    assert broker.calls[0][1]["peer_gid"] == os.getgid()
    assert broker.calls[0][1]["peer_pid"] == os.getpid()
    assert broker.calls[1][1]["peer_uid"] == os.getuid()
    assert broker.calls[1][1]["peer_gid"] == os.getgid()
    assert broker.calls[1][1]["peer_pid"] == os.getpid()
    assert broker.calls[2][1]["peer_uid"] == os.getuid()
    assert broker.calls[2][1]["peer_gid"] == os.getgid()
    assert broker.calls[2][1]["peer_pid"] == os.getpid()


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_rejects_wrong_uid_without_http_response() -> None:
    broker = StubBroker()
    wrong_uid = os.getuid() + 1
    with _linux_server(broker, allowed_uid=wrong_uid) as config:
        response = _exchange(config.socket_path, _raw_request())
    assert response == b""
    assert broker.calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (_raw_request(path="/v1/approval/request?company_id=7"), 404),
        (_raw_request(method="GET"), 405),
        (
            _raw_request(body=_json_bytes(_request_payload(company_id=7))),
            400,
        ),
        (
            _raw_request(
                path=approval_uds.APPROVAL_INSPECT_PATH,
                body=_json_bytes(
                    _inspect_payload(deadline_monotonic=time.monotonic() + 10)
                ),
            ),
            400,
        ),
        (_raw_request(content_type="application/json; charset=UTF-8"), 415),
        (_raw_request(extra_headers=[("Transfer-Encoding", "chunked")]), 400),
        (_raw_request(extra_headers=[("Content-Length", "2")]), 411),
        (_raw_request(extra_headers=[("X-Odoo-User", "42")]), 400),
        (_raw_request(path="/" + "x" * 5000), 431),
    ],
)
def test_real_linux_rejects_noncanonical_or_authority_bearing_requests(
    request_bytes: bytes, status: int
) -> None:
    broker = StubBroker()
    with _linux_server(broker) as config:
        response = _exchange(config.socket_path, request_bytes)
    assert _response(response)[0] == status
    assert broker.calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
@pytest.mark.parametrize("failure", ["replayed", "expired", "unauthorized"])
def test_real_linux_broker_failures_are_closed_and_sanitized(failure: str) -> None:
    broker = StubBroker()
    broker.request_error = TrustedBrokerError(
        f"{failure}-{SESSION_HANDLE}-backend-secret", status_code=403
    )
    with _linux_server(broker) as config:
        response = _exchange(config.socket_path, _raw_request())
    status, _, body = _response(response)
    assert status == 403
    assert body == approval_uds._safe_error("approval_broker_rejected")
    assert SESSION_HANDLE.encode() not in response
    assert b"backend-secret" not in response


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_response_limit_rejects_oversized_success() -> None:
    broker = StubBroker()
    broker.request_result = _view(
        capability_id="a" * 128,
        challenge_id="c" * 128,
    )
    with _linux_server(broker, max_response_bytes=512) as config:
        response = _exchange(config.socket_path, _raw_request())
    status, _, body = _response(response)
    assert status == 500
    assert body == approval_uds._safe_error("approval_response_rejected")


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_inspection_uses_same_response_limit() -> None:
    broker = StubBroker()
    with _linux_server(broker, max_response_bytes=512) as config:
        response = _exchange(
            config.socket_path,
            _raw_request(
                path=approval_uds.APPROVAL_INSPECT_PATH,
                body=_json_bytes(_inspect_payload()),
            ),
        )
    status, _, body = _response(response)
    assert status == 500
    assert body == approval_uds._safe_error("approval_response_rejected")


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_large_complete_inspection_succeeds_with_production_default() -> None:
    broker = StubBroker()
    broker.inspect_result = _inspection(
        preview_line_count=250,
        preview_memo_bytes=1200,
    )
    with _linux_server(broker, max_response_bytes=1024 * 1024) as config:
        response = _exchange(
            config.socket_path,
            _raw_request(
                path=approval_uds.APPROVAL_INSPECT_PATH,
                body=_json_bytes(_inspect_payload()),
            ),
        )
    status, _, body = _response(response)
    assert status == 200
    assert body == {"inspection": broker.inspect_result, "ok": True}


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_partial_body_hits_absolute_io_timeout() -> None:
    broker = StubBroker()
    with _linux_server(broker, request_timeout_seconds=0.1) as config:
        partial = _raw_request(body=_json_bytes(_request_payload()))
        header, body = partial.split(b"\r\n\r\n", 1)
        declared = header.replace(
            f"Content-Length: {len(body)}".encode("ascii"),
            f"Content-Length: {len(body) + 10}".encode("ascii"),
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2)
        try:
            client.connect(config.socket_path)
            client.sendall(declared + b"\r\n\r\n" + body)
            time.sleep(0.2)
            response = b""
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
        finally:
            client.close()
    assert response == b"" or _response(response)[0] == 408
    assert broker.calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_slow_connections_are_bounded_before_handler_thread_creation() -> None:
    broker = StubBroker()
    with _linux_server(
        broker,
        request_timeout_seconds=2,
        max_inflight_broker_calls=1,
    ) as config:
        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(2)
        try:
            slow.connect(config.socket_path)
            slow.sendall(b"POST ")
            time.sleep(0.05)
            response = _exchange(config.socket_path, _raw_request())
        finally:
            slow.close()
    status, _, body = _response(response)
    assert status == 503
    assert body == approval_uds._safe_error(
        "approval_broker_unavailable", retryable=True
    )
    assert broker.calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux approval UDS")
def test_real_linux_hung_broker_is_bounded() -> None:
    release = threading.Event()

    class BlockingBroker(StubBroker):
        def request_approval(
            self,
            *,
            session_handle: str,
            operation_id: str,
            peer_uid: int | None = None,
            peer_gid: int | None = None,
            peer_pid: int | None = None,
        ) -> dict[str, Any]:
            del peer_uid, peer_gid, peer_pid
            self.calls.append(
                (
                    "request_approval",
                    {"session_handle": session_handle, "operation_id": operation_id},
                )
            )
            release.wait()
            return self.request_result

    broker = BlockingBroker()
    try:
        with _linux_server(
            broker,
            request_timeout_seconds=0.1,
            max_inflight_broker_calls=1,
        ) as config:
            started = time.monotonic()
            response = _exchange(config.socket_path, _raw_request())
            elapsed = time.monotonic() - started
            unavailable = _exchange(config.socket_path, _raw_request())
            # A timed-out broker call remains bounded but is now deliberately
            # drained by server_close instead of being abandoned as a daemon.
            release.set()
    finally:
        release.set()
    status, _, body = _response(response)
    assert status == 504
    assert body == approval_uds._safe_error("approval_request_timeout")
    assert elapsed < 1
    unavailable_status, _, unavailable_body = _response(unavailable)
    assert unavailable_status == 503
    assert unavailable_body == approval_uds._safe_error(
        "approval_broker_unavailable", retryable=True
    )
    assert len(broker.calls) == 1


def test_production_factory_rejects_non_root_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(approval_uds, "_require_linux", lambda: None)
    monkeypatch.setattr(approval_uds.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(approval_uds.TrustedApprovalUdsError, match="requires root"):
        approval_uds.create_trusted_approval_uds_server(_config(), StubBroker())


def test_activated_factory_requires_non_root_and_adopts_root_owned_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from odoo_accounting_cli_v3 import systemd_activation

    adopted: list[dict[str, Any]] = []

    class FakeServer:
        def __init__(self, config: Any, broker: Any, *, bind_and_activate: bool) -> None:
            self.config = config
            self.broker = broker
            self.bind_and_activate = bind_and_activate
            self.closed = False

        def server_close(self) -> None:
            self.closed = True

    def fake_adopt(server: Any, descriptor: int, **kwargs: Any) -> None:
        adopted.append({"server": server, "descriptor": descriptor, **kwargs})

    monkeypatch.setattr(approval_uds, "_require_linux", lambda: None)
    monkeypatch.setattr(approval_uds, "_TrustedUnixHTTPServer", FakeServer)
    monkeypatch.setattr(approval_uds.os, "geteuid", lambda: 2301, raising=False)
    monkeypatch.setattr(
        systemd_activation, "adopt_activated_unix_server", fake_adopt
    )
    config = _config()

    server = approval_uds.create_trusted_approval_uds_server_from_fd(
        config, StubBroker(), 5
    )

    assert server.bind_and_activate is False
    assert adopted == [
        {
            "server": server,
            "descriptor": 5,
            "socket_path": config.socket_path,
            "expected_owner_uid": 0,
            "expected_group_gid": config.socket_group_gid,
            "expected_mode": config.socket_mode,
        }
    ]
    assert "create_trusted_approval_uds_server_from_fd" in approval_uds.__all__

    monkeypatch.setattr(approval_uds.os, "geteuid", lambda: 0, raising=False)
    with pytest.raises(
        approval_uds.TrustedApprovalUdsError,
        match="dedicated non-root",
    ):
        approval_uds.create_trusted_approval_uds_server_from_fd(
            config, StubBroker(), 5
        )


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="real root-owned Linux approval UDS factory",
)
def test_real_linux_root_factory_secures_and_cleans_socket() -> None:
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-approval-factory-", dir="/run"))
    root.chmod(0o750)
    path = root / "approval.sock"
    config = approval_uds.TrustedApprovalUdsConfig(
        socket_path=str(path),
        odoo_client_uid=65534,
        pi_bridge_uid=65533,
        socket_group_gid=os.getgid(),
    )
    server = None
    try:
        server = approval_uds.create_trusted_approval_uds_server(
            config, StubBroker()
        )
        metadata = path.lstat()
        assert stat.S_ISSOCK(metadata.st_mode)
        assert metadata.st_uid == 0
        assert metadata.st_gid == os.getgid()
        assert stat.S_IMODE(metadata.st_mode) == config.socket_mode
    finally:
        if server is not None:
            server.server_close()
        path.unlink(missing_ok=True)
        root.rmdir()
    assert not path.exists()
