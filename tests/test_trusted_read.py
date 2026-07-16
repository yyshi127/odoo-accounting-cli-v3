from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from odoo_accounting_cli_v3.auth import (
    authentication_request_digest,
    context_payload,
    verify_request_context,
)
from odoo_accounting_cli_v3.odoo.bootstrap import request_context_from_mapping
from odoo_accounting_cli_v3.odoo.runner import RuntimeConfig
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.registry import load_registry, registry_digest
from odoo_accounting_cli_v3.trusted_authority import TrustedSession
from odoo_accounting_cli_v3.trusted_broker import AuthorizedReadAction
from odoo_accounting_cli_v3.trusted_read import TrustedReadAdapter, TrustedReadError
from odoo_accounting_cli_v3.trusted_response_verifier import (
    ReleaseReceiptVerificationConfig,
    build_release_response_verifier,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
HANDLE = "opaque-session-handle-0123456789abcdef"
RELEASE_DIGEST = "a" * 64
AUTH_SECRET = b"trusted-read-auth-secret-material-0001"
RECEIPT_SECRET = b"trusted-read-receipt-secret-material-1"
OTHER_AUTH_SECRET = b"trusted-read-other-auth-secret-material"
WRITE_RECEIPT_SECRET = b"trusted-read-write-receipt-secret-material"
CAPABILITY_ID = "acct.registry.list.v1"


def _context_mapping(context) -> dict[str, Any]:
    return {**context_payload(context), "auth_signature": context.auth_signature}


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.runtime_path = (tmp_path / "runtime" / "read-runtime.json").resolve()
        self.runtime_path.parent.mkdir(parents=True)
        self.runtime_path.write_bytes(b'{"generation":1}')
        release_root = (tmp_path / "releases" / "v3-current").resolve()
        release_root.mkdir(parents=True)
        packages = (tmp_path / "packages").resolve()
        packages.mkdir()
        absolute = lambda name: (tmp_path / name).resolve()  # noqa: E731
        self.config = RuntimeConfig(
            instance_id="odoo19@test",
            environment="test",
            capability_channel="staged",
            database_name="odoo_v3_test",
            database_uuid="11111111-1111-4111-8111-111111111111",
            odoo_python=absolute("odoo-python"),
            odoo_python_sha256="1" * 64,
            odoo_bin=absolute("odoo-bin"),
            odoo_bin_sha256="2" * 64,
            odoo_config=absolute("odoo.conf"),
            odoo_config_sha256="3" * 64,
            release_root=release_root,
            canonical_package_path=(
                packages / "odoo-accounting-cli-v3-v3-current.tar.gz"
            ),
            canonical_package_sha256="4" * 64,
            auth_state_path=absolute("read-auth.sqlite3"),
            receipt_state_path=absolute("read-receipts.sqlite3"),
            auth_key_id="read-auth-v1",
            receipt_key_id="read-receipt-v1",
            auth_secret_path=absolute("read-auth.secret"),
            receipt_secret_path=absolute("read-receipt.secret"),
        )
        self.capabilities = load_registry(ROOT / "registry" / "capabilities.json")
        self.registry_digest = registry_digest(self.capabilities)
        self.identity = {
            "commit": "commit-1",
            "manifest_sha256": RELEASE_DIGEST,
            "package_sha256": self.config.canonical_package_sha256,
            "registry_digest": self.registry_digest,
            "release": self.config.release_root.name,
            "verified": True,
            "version": "0.1.0.dev8",
        }
        self.secrets = (AUTH_SECRET, RECEIPT_SECRET)
        self.session = TrustedSession(
            session_id="trusted-session-1",
            principal="pi:test-user-42",
            odoo_instance_id=self.config.instance_id,
            database_name=self.config.database_name,
            database_uuid=self.config.database_uuid,
            user_id=42,
            company_id=7,
            allowed_company_ids=frozenset({7, 8}),
            environment=self.config.environment,
            issued_at=NOW - timedelta(minutes=2),
            expires_at=NOW + timedelta(minutes=10),
        )
        self.sessions: dict[str, object] = {HANDLE: self.session}
        self.runner_calls: list[tuple[RuntimeConfig, dict[str, Any], str, float]] = []
        self.runner_error = False
        self.invalid_result = False
        self.wrong_receipt_route = False
        self.drift_runtime_during_runner = False
        self.clock_value = NOW
        self.token_number = 0
        self.adapter = self.build()

    def build(self, **overrides: Any) -> TrustedReadAdapter:
        def next_token() -> str:
            self.token_number += 1
            return f"internally-generated-read-token-{self.token_number}"

        arguments = {
            "runtime_config_path": self.runtime_path,
            "expected_release_digest": RELEASE_DIGEST,
            "expected_registry_digest": self.registry_digest,
            "session_resolver": lambda handle: self.sessions.get(handle),
            "clock": lambda: self.clock_value,
            "auth_token_resolver": lambda _session: next_token(),
            "config_loader": lambda _path: self.config,
            "secret_loader": lambda _config: self.secrets,
            "release_identity_loader": lambda _config: copy.deepcopy(self.identity),
            "registry_loader": lambda _config: self.capabilities,
            "runner": self.run,
        }
        arguments.update(overrides)
        return TrustedReadAdapter(**arguments)

    @staticmethod
    def business(company_id: int = 7) -> dict[str, Any]:
        return {"capability_id": CAPABILITY_ID, "parameters": {"company_id": company_id}}

    def authorize(self, business: dict[str, Any] | None = None) -> AuthorizedReadAction:
        return self.adapter.authorize(HANDLE, business or self.business())

    def full_request(self, authorized: AuthorizedReadAction) -> dict[str, Any]:
        return {
            "context": _context_mapping(authorized.context),
            **copy.deepcopy(authorized.request),
        }

    def run(
        self,
        config: RuntimeConfig,
        request: dict[str, Any],
        *,
        release_digest: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        self.runner_calls.append(
            (config, copy.deepcopy(request), release_digest, timeout_seconds)
        )
        if self.runner_error:
            raise RuntimeError("simulated Odoo runner failure")
        if self.invalid_result:
            return {"unexpected": True}
        context = request_context_from_mapping(request["context"])
        body = {"capabilities": [], "page": {"count": 0, "total_count": 0}}
        receipt = create_read_receipt(
            receipt_id=f"receipt-{len(self.runner_calls)}",
            capability_id=request["capability_id"],
            parameters=request["parameters"],
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=self.registry_digest,
            release_digest=RELEASE_DIGEST,
            environment=context.environment,
            capability_channel=config.capability_channel,
            record_count=0,
            observed_at=self.clock_value,
            key_id=config.receipt_key_id,
            secret=RECEIPT_SECRET,
        )
        if self.wrong_receipt_route:
            receipt["release_digest"] = "f" * 64
        if self.drift_runtime_during_runner:
            self.runtime_path.write_bytes(b'{"generation":2}')
        return {**body, "receipt": receipt}


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_authorizer_derives_all_identity_and_executor_returns_exact_broker_envelope(
    harness: Harness,
) -> None:
    business = harness.business()
    authorized = harness.authorize(business)

    assert isinstance(authorized, AuthorizedReadAction)
    assert authorized.request == business
    assert authorized.context.principal == harness.session.principal
    assert authorized.context.user_id == harness.session.user_id
    assert authorized.context.company_id == harness.session.company_id
    assert authorized.context.allowed_company_ids == harness.session.allowed_company_ids
    assert authorized.context.database_name == harness.session.database_name
    assert authorized.context.auth_token_id == "internally-generated-read-token-1"
    assert authorized.context.auth_expires_at == NOW + timedelta(minutes=5)
    assert authorized.context.auth_request_digest == authentication_request_digest(
        CAPABILITY_ID, business["parameters"]
    )
    assert verify_request_context(
        authorized.context,
        now=NOW,
        secret=AUTH_SECRET,
        expected_key_id=harness.config.auth_key_id,
    )

    full_request = harness.full_request(authorized)
    envelope = harness.adapter.execute(full_request)

    assert set(envelope) == {"command", "data", "ok"}
    assert envelope["command"] == "read"
    assert envelope["ok"] is True
    assert set(envelope["data"]) == {
        "capability_id",
        "release_identity",
        "result",
        "runtime",
    }
    assert envelope["data"]["capability_id"] == CAPABILITY_ID
    assert envelope["data"]["release_identity"] == harness.identity
    assert envelope["data"]["runtime"] == harness.config.runtime_identity
    assert envelope["data"]["result"]["receipt"]["release_digest"] == RELEASE_DIGEST
    assert envelope["data"]["result"]["receipt"]["registry_digest"] == (
        harness.registry_digest
    )
    assert len(harness.runner_calls) == 1
    called_config, called_request, called_release, called_timeout = (
        harness.runner_calls[0]
    )
    assert called_config == harness.config
    assert called_request == full_request
    assert called_release == RELEASE_DIGEST
    assert called_timeout == 30.0
    verifier = build_release_response_verifier(
        ReleaseReceiptVerificationConfig(
            release_digest=RELEASE_DIGEST,
            registry_digest=harness.registry_digest,
            capability_channel=harness.config.capability_channel,
            read_receipt_key_id=harness.config.receipt_key_id,
            read_receipt_secret=RECEIPT_SECRET,
            write_receipt_key_id="write-receipt-v1",
            write_receipt_secret=WRITE_RECEIPT_SECRET,
        ),
        operation_resolver=lambda _operation_id: None,
        utc_clock=lambda: NOW,
    )
    assert verifier.verify("read", envelope, full_request) is True


@pytest.mark.parametrize(
    "payload",
    [
        {
            "capability_id": CAPABILITY_ID,
            "parameters": {"company_id": 7},
            "context": {"principal": "caller-selected"},
        },
        {
            "capability_id": CAPABILITY_ID,
            "parameters": {"company_id": 7},
            "user_id": 1,
        },
    ],
)
def test_authorizer_rejects_caller_supplied_identity_fields(
    harness: Harness, payload: dict[str, Any]
) -> None:
    with pytest.raises(TrustedReadError) as rejected:
        harness.adapter.authorize(HANDLE, payload)

    assert rejected.value.code == "trusted_read_authorization_rejected"
    assert harness.runner_calls == []


@pytest.mark.parametrize("session_state", ["expired", "future", "forged"])
def test_authorizer_rejects_expired_future_or_untrusted_session_objects(
    harness: Harness, session_state: str
) -> None:
    if session_state == "expired":
        harness.sessions[HANDLE] = replace(
            harness.session,
            issued_at=NOW - timedelta(minutes=10),
            expires_at=NOW,
        )
    elif session_state == "future":
        harness.sessions[HANDLE] = replace(
            harness.session,
            issued_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    else:
        harness.sessions[HANDLE] = object()

    with pytest.raises(TrustedReadError) as rejected:
        harness.authorize()

    assert rejected.value.code == "trusted_read_authorization_rejected"
    assert harness.runner_calls == []


def test_cross_company_read_is_rejected_before_signing_or_runner(
    harness: Harness,
) -> None:
    with pytest.raises(TrustedReadError) as rejected:
        harness.authorize(harness.business(company_id=8))

    assert rejected.value.code == "trusted_read_authorization_rejected"
    assert harness.token_number == 0
    assert harness.runner_calls == []


@pytest.mark.parametrize(
    "session",
    [
        lambda value: replace(value, database_name="other_database"),
        lambda value: replace(value, odoo_instance_id="odoo19@other"),
        lambda value: replace(value, user_id=1),
    ],
)
def test_resolved_session_must_match_the_pinned_runtime(
    harness: Harness, session
) -> None:
    harness.sessions[HANDLE] = session(harness.session)

    with pytest.raises(TrustedReadError) as rejected:
        harness.authorize()

    assert rejected.value.code == "trusted_read_authorization_rejected"
    assert harness.runner_calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal", "pi:forged-user"),
        ("database_name", "other_database"),
        ("auth_token_id", "caller-selected-token"),
    ],
)
def test_executor_rejects_forged_signed_identity_without_calling_runner(
    harness: Harness, field: str, value: str
) -> None:
    full_request = harness.full_request(harness.authorize())
    full_request["context"][field] = value

    with pytest.raises(TrustedReadError) as rejected:
        harness.adapter.execute(full_request)

    assert rejected.value.code == "trusted_read_execution_rejected"
    assert harness.runner_calls == []


def test_executor_rejects_parameter_tamper_after_authorization(
    harness: Harness,
) -> None:
    full_request = harness.full_request(harness.authorize())
    full_request["parameters"]["company_id"] = 8

    with pytest.raises(TrustedReadError) as rejected:
        harness.adapter.execute(full_request)

    assert rejected.value.code == "trusted_read_execution_rejected"
    assert harness.runner_calls == []


def test_runtime_config_byte_drift_is_permanently_fail_closed(
    harness: Harness,
) -> None:
    harness.runtime_path.write_bytes(b'{"generation":2}')

    with pytest.raises(TrustedReadError) as rejected:
        harness.authorize()

    assert rejected.value.code == "trusted_read_configuration_rejected"
    assert harness.runner_calls == []


@pytest.mark.parametrize("drift", ["release", "registry", "secret"])
def test_release_registry_and_secret_drift_fail_before_runner(
    harness: Harness, drift: str
) -> None:
    full_request = harness.full_request(harness.authorize())
    if drift == "release":
        harness.identity["manifest_sha256"] = "e" * 64
    elif drift == "registry":
        harness.capabilities = harness.capabilities[:-1]
    else:
        harness.secrets = (OTHER_AUTH_SECRET, RECEIPT_SECRET)

    with pytest.raises(TrustedReadError) as rejected:
        harness.adapter.execute(full_request)

    assert rejected.value.code == "trusted_read_configuration_rejected"
    assert harness.runner_calls == []


def test_runner_error_and_invalid_or_cross_release_results_fail_closed(
    harness: Harness,
) -> None:
    full_request = harness.full_request(harness.authorize())

    harness.runner_error = True
    with pytest.raises(TrustedReadError) as unavailable:
        harness.adapter.execute(full_request)
    assert unavailable.value.code == "trusted_read_runner_failed"

    harness.runner_error = False
    harness.invalid_result = True
    with pytest.raises(TrustedReadError) as invalid:
        harness.adapter.execute(full_request)
    assert invalid.value.code == "trusted_read_runner_failed"

    harness.invalid_result = False
    harness.wrong_receipt_route = True
    with pytest.raises(TrustedReadError) as cross_release:
        harness.adapter.execute(full_request)
    assert cross_release.value.code == "trusted_read_runner_failed"


def test_runtime_drift_during_runner_never_returns_business_success(
    harness: Harness,
) -> None:
    full_request = harness.full_request(harness.authorize())
    harness.drift_runtime_during_runner = True

    with pytest.raises(TrustedReadError) as rejected:
        harness.adapter.execute(full_request)

    assert rejected.value.code == "trusted_read_configuration_rejected"
    assert len(harness.runner_calls) == 1


def test_constructor_rejects_route_identity_mismatch(tmp_path: Path) -> None:
    # Build one normal harness first, then use its injected, non-Odoo dependencies.
    normal = Harness(tmp_path)

    with pytest.raises(TrustedReadError) as rejected:
        normal.build(expected_release_digest="f" * 64)

    assert rejected.value.code == "trusted_read_configuration_rejected"
