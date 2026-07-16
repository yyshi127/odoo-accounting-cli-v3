from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

import odoo_accounting_cli_v3.verified_release as verified
from odoo_accounting_cli_v3.odoo.runner import RuntimeConfig
from odoo_accounting_cli_v3.operations import Operation
from odoo_accounting_cli_v3.registry import load_registry, registry_digest
from odoo_accounting_cli_v3.trusted_authority_bootstrap import (
    TrustedAuthorityRuntimeConfig,
)
from odoo_accounting_cli_v3.write_runtime import (
    WriteRoleConfig,
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
)


ROOT = Path(__file__).resolve().parents[1]
RELEASE = "a" * 64


def _runtime(tmp_path: Path) -> TrustedAuthorityRuntimeConfig:
    base = RuntimeConfig(
        instance_id="odoo19@sandbox",
        environment="sandbox",
        capability_channel="staged",
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        odoo_python=(tmp_path / "python").resolve(),
        odoo_python_sha256="1" * 64,
        odoo_bin=(tmp_path / "odoo-bin").resolve(),
        odoo_bin_sha256="2" * 64,
        odoo_config=(tmp_path / "odoo.conf").resolve(),
        odoo_config_sha256="3" * 64,
        release_root=(tmp_path / "release-a").resolve(),
        canonical_package_path=(tmp_path / "packages" / "release-a.tar.gz").resolve(),
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
            issuer=f"{name}-issuer" if name in {"execution", "verification", "recovery"} else None,
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
    write = WriteRuntimeConfig(
        schema_version=1,
        write_execution_mode="sandbox_staged",
        base_runtime_config_path=(tmp_path / "read-runtime.json").resolve(),
        write_state_path=(tmp_path / "write.sqlite3").resolve(),
        base_runtime=base,
        config_fingerprint="5" * 64,
        _require_root_owner=False,
        **roles,
    )
    return TrustedAuthorityRuntimeConfig(
        schema_version=1,
        config_path=(tmp_path / "authority.json").resolve(),
        write_runtime_config_path=(tmp_path / "write-runtime.json").resolve(),
        authority_state_path=(tmp_path / "authority.sqlite3").resolve(),
        sqlite_busy_timeout_ms=5_000,
        context_ttl_seconds=120,
        write_runtime=write,
        config_fingerprint="6" * 64,
        _require_root_owner=False,
    )


@pytest.fixture
def release_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    authority = _runtime(tmp_path)
    capabilities = load_registry(ROOT / "registry" / "capabilities.json")
    registry = registry_digest(capabilities)
    identity = {
        "commit": "commit-a",
        "manifest_sha256": RELEASE,
        "package_sha256": authority.write_runtime.base_runtime.canonical_package_sha256,
        "registry_digest": registry,
        "release": authority.write_runtime.base_runtime.release_root.name,
        "verified": True,
        "version": "0.1.0.dev9",
    }
    read_secrets = (b"read-auth-secret-material-00000000001", b"read-receipt-secret-material-0000001")
    write_secrets = WriteRuntimeSecrets(
        write_auth=b"write-auth-secret-material-000000001",
        approval=b"approval-secret-material-00000000002",
        execution=b"execution-secret-material-0000000002",
        verification=b"verification-secret-material-0000002",
        recovery=b"recovery-secret-material-00000000003",
        write_receipt=b"write-receipt-secret-material-000002",
    )
    monkeypatch.setattr(verified, "_validate_canonical_package_binding", lambda _config: None)
    monkeypatch.setattr("odoo_accounting_cli_v3.cli._load_release_identity", lambda *_args, **_kwargs: copy.deepcopy(identity))
    monkeypatch.setattr(verified, "load_registry", lambda _path: capabilities)
    monkeypatch.setattr(verified, "load_runtime_secrets", lambda _config: read_secrets)
    monkeypatch.setattr(verified, "load_write_runtime_secrets", lambda _config: write_secrets)
    return authority, registry, identity


def test_retained_release_bundle_binds_identity_registry_keys_and_approval_ttl(
    release_fixture,
) -> None:
    authority, registry, identity = release_fixture
    route = verified.load_verified_release_route(
        authority,
        expected_release_digest=RELEASE,
        expected_registry_digest=registry,
    )
    operation = Operation.prepare(
        operation_id="operation-1",
        request_id="request-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "idempotency_key": "invoice-1"},
        principal="odoo:user:42",
        user_id=42,
        company_id=7,
        idempotency_key="invoice-1",
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        environment="sandbox",
        registry_digest=registry,
        release_digest=RELEASE,
    )

    assert route.release_identity == identity
    assert route.approval_ttl_seconds(operation) == 900
    assert "secret-material" not in repr(route)


@pytest.mark.parametrize("drift", ["release", "registry", "package", "verified"])
def test_retained_release_route_rejects_every_identity_drift(
    release_fixture, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    authority, registry, identity = release_fixture
    changed = copy.deepcopy(identity)
    if drift == "release":
        changed["manifest_sha256"] = "b" * 64
    elif drift == "registry":
        changed["registry_digest"] = "c" * 64
    elif drift == "package":
        changed["package_sha256"] = "d" * 64
    else:
        changed["verified"] = False
    monkeypatch.setattr("odoo_accounting_cli_v3.cli._load_release_identity", lambda *_args, **_kwargs: changed)

    with pytest.raises(verified.VerifiedReleaseError):
        verified.load_verified_release_route(
            authority,
            expected_release_digest=RELEASE,
            expected_registry_digest=registry,
        )


def test_approval_ttl_has_no_root_or_request_fallback(release_fixture) -> None:
    authority, registry, _identity = release_fixture
    route = verified.load_verified_release_route(
        authority,
        expected_release_digest=RELEASE,
        expected_registry_digest=registry,
    )
    operation = Operation.prepare(
        operation_id="operation-2",
        request_id="request-2",
        capability_id="acct.gl.trial_balance.v1",
        parameters={"company_id": 7},
        principal="odoo:user:42",
        user_id=42,
        company_id=7,
        idempotency_key="read-not-write",
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        environment="sandbox",
        registry_digest=registry,
        release_digest=RELEASE,
    )

    with pytest.raises(verified.VerifiedReleaseError, match="approval policy"):
        route.approval_ttl_seconds(operation)


def test_executing_broker_source_must_be_the_current_verified_release(
    release_fixture,
) -> None:
    authority, registry, identity = release_fixture
    route = verified.load_verified_release_route(
        authority,
        expected_release_digest=RELEASE,
        expected_registry_digest=registry,
    )
    module_file = (
        authority.write_runtime.base_runtime.release_root
        / "src"
        / "odoo_accounting_cli_v3"
        / "trusted_broker_app.py"
    )
    module_file.parent.mkdir(parents=True)
    module_file.write_text("# manifest-verified broker source\n", encoding="utf-8")

    route.assert_executing_broker_source(
        module_file,
        package_version=identity["version"],
    )

    with pytest.raises(verified.VerifiedReleaseError, match="differs"):
        route.assert_executing_broker_source(
            module_file,
            package_version="0.1.0.dev8",
        )

    outside = module_file.parents[3] / "other" / "trusted_broker_app.py"
    outside.parent.mkdir()
    outside.write_text("# different broker source\n", encoding="utf-8")
    with pytest.raises(verified.VerifiedReleaseError, match="differs"):
        route.assert_executing_broker_source(
            outside,
            package_version=identity["version"],
        )
