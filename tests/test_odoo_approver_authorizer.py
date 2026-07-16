from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from odoo_accounting_cli_v3.auth import verify_request_context
from odoo_accounting_cli_v3.odoo.bootstrap import request_context_from_mapping
from odoo_accounting_cli_v3.odoo.runner import RuntimeConfig
from odoo_accounting_cli_v3.odoo_approver_authorizer import (
    OdooApproverAuthorizationError,
    OdooApproverAuthorizer,
    OdooApproverReleaseRuntime,
)
from odoo_accounting_cli_v3.operations import Operation, canonical_json
from odoo_accounting_cli_v3.trusted_authority import TrustedSession
from odoo_accounting_cli_v3.write_runtime import (
    WriteRoleConfig,
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
)


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE = "a" * 64
REGISTRY = "b" * 64
WRITE_AUTH_SECRET = b"release-a-write-auth-secret-material-01"
TOKEN = "c" * 64


def _session(
    *,
    user_id: int = 84,
    company_id: int = 7,
    database_name: str = "odoo_v3_sandbox",
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> TrustedSession:
    return TrustedSession(
        session_id="approver-session-1",
        principal=f"pi:user-{user_id}",
        odoo_instance_id="odoo19@sandbox",
        database_name=database_name,
        database_uuid=DATABASE_UUID,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
        release_digest=RELEASE,
        registry_digest=REGISTRY,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=expires_at,
    )


def _operation(
    *,
    user_id: int = 42,
    company_id: int = 7,
    database_name: str = "odoo_v3_sandbox",
    release_digest: str = RELEASE,
    registry_digest: str = REGISTRY,
) -> Operation:
    return Operation.prepare(
        operation_id="operation-1",
        request_id="request-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": company_id, "idempotency_key": "invoice-1"},
        principal=f"pi:user-{user_id}",
        user_id=user_id,
        company_id=company_id,
        idempotency_key="invoice-1",
        odoo_instance_id="odoo19@sandbox",
        database_name=database_name,
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=registry_digest,
        release_digest=release_digest,
    )


def _runtime(
    tmp_path: Path,
    *,
    instance_id: str = "odoo19@sandbox",
    database_name: str = "odoo_v3_sandbox",
) -> tuple[WriteRuntimeConfig, WriteRuntimeSecrets]:
    base = RuntimeConfig(
        instance_id=instance_id,
        environment="sandbox",
        capability_channel="staged",
        database_name=database_name,
        database_uuid=DATABASE_UUID,
        odoo_python=(tmp_path / "python").resolve(),
        odoo_python_sha256="1" * 64,
        odoo_bin=(tmp_path / "odoo-bin").resolve(),
        odoo_bin_sha256="2" * 64,
        odoo_config=(tmp_path / "odoo.conf").resolve(),
        odoo_config_sha256="3" * 64,
        release_root=(tmp_path / "release-a").resolve(),
        canonical_package_path=(tmp_path / "release-a.tar.gz").resolve(),
        canonical_package_sha256="4" * 64,
        auth_state_path=(tmp_path / "read-auth.sqlite3").resolve(),
        receipt_state_path=(tmp_path / "read-receipt.sqlite3").resolve(),
        auth_key_id="read-auth-v1",
        receipt_key_id="read-receipt-v1",
        auth_secret_path=(tmp_path / "read-auth.hmac").resolve(),
        receipt_secret_path=(tmp_path / "read-receipt.hmac").resolve(),
    )
    roles = {
        name: WriteRoleConfig(
            key_id=f"{name}-v1",
            secret_path=(tmp_path / f"{name}.hmac").resolve(),
            issuer=(
                f"{name}-issuer"
                if name in {"execution", "verification", "recovery"}
                else None
            ),
        )
        for name in (
            "write_auth",
            "approval",
            "execution",
            "verification",
            "recovery",
            "write_receipt",
        )
    }
    config = WriteRuntimeConfig(
        schema_version=1,
        write_execution_mode="sandbox_staged",
        base_runtime_config_path=(tmp_path / "read-runtime.json").resolve(),
        write_state_path=(tmp_path / "write-state.sqlite3").resolve(),
        base_runtime=base,
        config_fingerprint="f" * 64,
        _require_root_owner=False,
        **roles,
    )
    secrets = WriteRuntimeSecrets(
        write_auth=WRITE_AUTH_SECRET,
        approval=b"approval-secret-material-000000000001",
        execution=b"execution-secret-material-0000000001",
        verification=b"verification-secret-material-0000001",
        recovery=b"recovery-secret-material-000000000002",
        write_receipt=b"write-receipt-secret-material-000001",
    )
    return config, secrets


def _binding(
    tmp_path: Path,
    *,
    release_digest: str = RELEASE,
    registry_digest: str = REGISTRY,
    instance_id: str = "odoo19@sandbox",
    database_name: str = "odoo_v3_sandbox",
) -> OdooApproverReleaseRuntime:
    config, secrets = _runtime(
        tmp_path, instance_id=instance_id, database_name=database_name
    )
    return OdooApproverReleaseRuntime(
        release_digest=release_digest,
        registry_digest=registry_digest,
        config=config,
        secrets=secrets,
    )


def _runtime_binding(config: WriteRuntimeConfig) -> dict[str, Any]:
    base = config.base_runtime
    return {
        "odoo_instance_id": base.instance_id,
        "database_name": base.database_name,
        "database_uuid": base.database_uuid,
        "environment": base.environment,
        "capability_channel": base.capability_channel,
    }


def _result(
    request: dict[str, Any], binding: OdooApproverReleaseRuntime
) -> dict[str, Any]:
    return {
        "authorized": True,
        "approver_user_id": request["parameters"]["approver_user_id"],
        "company_id": request["parameters"]["company_id"],
        "capability_id": request["capability_id"],
        "runtime_binding": _runtime_binding(binding.config),
        "registry_digest": binding.registry_digest,
        "release_digest": binding.release_digest,
    }


def test_authorizer_signs_exact_short_lived_context_for_selected_release(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    calls: list[tuple[Any, ...]] = []

    def resolve(release_digest: str, registry_digest: str):
        calls.append(("resolve", release_digest, registry_digest))
        return binding

    def run(config, secrets, request, *, release_digest, timeout_seconds):
        calls.append(
            (
                "run",
                config,
                secrets,
                json.loads(canonical_json(request)),
                release_digest,
                timeout_seconds,
            )
        )
        return _result(request, binding)

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=resolve,
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
        context_ttl_seconds=60,
        timeout_seconds=4.5,
    )

    assert authorizer(_session(), _operation()) is True
    assert calls[0] == ("resolve", RELEASE, REGISTRY)
    _, config, secrets, request, release_digest, timeout_seconds = calls[1]
    assert config is binding.config
    assert secrets is binding.secrets
    assert release_digest == RELEASE
    assert timeout_seconds == 4.5
    assert set(request) == {"context", "capability_id", "parameters"}
    assert request["capability_id"] == _operation().capability_id
    assert request["parameters"] == {"approver_user_id": 84, "company_id": 7}

    context = request_context_from_mapping(request["context"])
    verify_request_context(
        context,
        now=NOW + timedelta(seconds=1),
        secret=WRITE_AUTH_SECRET,
        expected_key_id=binding.config.write_auth.key_id,
    )
    assert context.auth_token_id == f"odoo-approver-{TOKEN}"
    assert context.auth_issued_at == NOW
    assert context.auth_expires_at == NOW + timedelta(seconds=60)
    assert context.principal == "pi:user-84"
    assert context.user_id == 84
    assert context.company_id == 7
    assert context.allowed_company_ids == frozenset({7})
    assert context.auth_request_digest != _operation().digest
    assert WRITE_AUTH_SECRET not in canonical_json(request)
    assert WRITE_AUTH_SECRET.decode() not in repr(authorizer)
    assert WRITE_AUTH_SECRET.decode() not in repr(binding)


def test_authorizer_caps_context_at_trusted_session_expiry(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    captured: dict[str, Any] = {}

    def run(_config, _secrets, request, **_kwargs):
        captured.update(request)
        return _result(request, binding)

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: binding,
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
        context_ttl_seconds=120,
    )
    session = _session(expires_at=NOW + timedelta(seconds=20))

    assert authorizer(session, _operation()) is True
    context = request_context_from_mapping(captured["context"])
    assert context.auth_expires_at == session.expires_at


def test_literal_odoo_denial_returns_false(tmp_path: Path) -> None:
    binding = _binding(tmp_path)

    def run(_config, _secrets, request, **_kwargs):
        result = _result(request, binding)
        result["authorized"] = False
        return result

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: binding,
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
    )
    assert authorizer(_session(), _operation()) is False


@pytest.mark.parametrize(
    "session, operation",
    [
        (_session(user_id=42), _operation(user_id=42)),
        (_session(company_id=8), _operation(company_id=7)),
        (_session(database_name="other_sandbox"), _operation()),
    ],
)
def test_self_approval_and_tenant_or_company_drift_fail_before_runner(
    tmp_path: Path, session: TrustedSession, operation: Operation
) -> None:
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: _binding(tmp_path),
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
    )
    assert authorizer(session, operation) is False
    assert called is False


@pytest.mark.parametrize(
    "binding_kwargs",
    [
        {"release_digest": "d" * 64},
        {"registry_digest": "e" * 64},
        {"instance_id": "odoo19@other"},
        {"database_name": "other_sandbox"},
    ],
)
def test_resolved_release_and_runtime_must_match_operation_and_session(
    tmp_path: Path, binding_kwargs: dict[str, str]
) -> None:
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: _binding(tmp_path, **binding_kwargs),
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
    )
    with pytest.raises(OdooApproverAuthorizationError):
        authorizer(_session(), _operation())
    assert called is False


@pytest.mark.parametrize(
    "tamper",
    [
        "not_object",
        "extra_field",
        "authorized_integer",
        "approver",
        "company",
        "capability",
        "runtime",
        "registry",
        "release",
    ],
)
def test_untrusted_or_mismatched_runner_result_fails_closed(
    tmp_path: Path, tamper: str
) -> None:
    binding = _binding(tmp_path)

    def run(_config, _secrets, request, **_kwargs):
        if tamper == "not_object":
            return ["authorized"]
        result = _result(request, binding)
        if tamper == "extra_field":
            result["unexpected"] = True
        elif tamper == "authorized_integer":
            result["authorized"] = 1
        elif tamper == "approver":
            result["approver_user_id"] = 999
        elif tamper == "company":
            result["company_id"] = 8
        elif tamper == "capability":
            result["capability_id"] = "acct.bill.vendor_create.v1"
        elif tamper == "runtime":
            result["runtime_binding"] = {
                **result["runtime_binding"],
                "database_uuid": "22222222-2222-4222-8222-222222222222",
            }
        elif tamper == "registry":
            result["registry_digest"] = "e" * 64
        else:
            result["release_digest"] = "d" * 64
        return result

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: binding,
        runner=run,
        clock=lambda: NOW,
        token_factory=lambda: TOKEN,
    )
    with pytest.raises(OdooApproverAuthorizationError, match="authorization failed"):
        authorizer(_session(), _operation())


@pytest.mark.parametrize(
    "failure_at", ["resolver", "runner", "runner_typed", "clock", "token"]
)
def test_dependency_errors_and_timeouts_are_sanitized(
    tmp_path: Path, failure_at: str
) -> None:
    binding = _binding(tmp_path)
    secret_marker = WRITE_AUTH_SECRET.decode()

    def fail(*_args, **_kwargs):
        if failure_at == "runner_typed":
            raise OdooApproverAuthorizationError(
                f"forged adapter error containing {secret_marker}"
            )
        error = TimeoutError if failure_at == "runner" else RuntimeError
        raise error(f"private backend detail {secret_marker}")

    authorizer = OdooApproverAuthorizer(
        runtime_resolver=(fail if failure_at == "resolver" else lambda *_: binding),
        runner=(
            fail
            if failure_at in {"runner", "runner_typed"}
            else lambda *_a, **_k: {}
        ),
        clock=(fail if failure_at == "clock" else lambda: NOW),
        token_factory=(fail if failure_at == "token" else lambda: TOKEN),
    )

    with pytest.raises(OdooApproverAuthorizationError) as rejected:
        authorizer(_session(), _operation())
    assert str(rejected.value) == "Odoo approver authorization failed"
    assert rejected.value.__cause__ is None
    assert rejected.value.__context__ is None
    assert secret_marker not in str(rejected.value)
    assert secret_marker not in repr(rejected.value)


@pytest.mark.parametrize(
    "updates",
    [
        {"context_ttl_seconds": 0},
        {"context_ttl_seconds": 301},
        {"timeout_seconds": 0},
        {"timeout_seconds": 121},
    ],
)
def test_trusted_ttl_and_timeout_configuration_is_bounded(
    tmp_path: Path, updates: dict[str, Any]
) -> None:
    arguments = {
        "runtime_resolver": lambda *_: _binding(tmp_path),
        "runner": lambda *_a, **_k: {},
        "clock": lambda: NOW,
        "token_factory": lambda: TOKEN,
        **updates,
    }
    with pytest.raises(OdooApproverAuthorizationError):
        OdooApproverAuthorizer(**arguments)


def test_expired_session_and_invalid_trusted_token_fail_without_runner(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    expired = OdooApproverAuthorizer(
        runtime_resolver=lambda *_: binding,
        runner=run,
        clock=lambda: NOW + timedelta(minutes=10),
        token_factory=lambda: TOKEN,
    )
    with pytest.raises(OdooApproverAuthorizationError):
        expired(_session(), _operation())

    invalid_token = replace(expired, clock=lambda: NOW, token_factory=lambda: "caller")
    with pytest.raises(OdooApproverAuthorizationError):
        invalid_token(_session(), _operation())
    assert called is False
