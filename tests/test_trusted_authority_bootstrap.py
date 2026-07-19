from __future__ import annotations

import copy
import inspect
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

from odoo_accounting_cli_v3.effect_finalizer import EffectFinalizationIdentity
from odoo_accounting_cli_v3.effect_finalizer_runtime import (
    EffectFinalizerClientRuntime,
)
from odoo_accounting_cli_v3.operations import Operation, State, record_precheck
from odoo_accounting_cli_v3.trusted_authority import (
    ApprovalDecision,
    AuthorityError,
    TrustedSession,
)
from odoo_accounting_cli_v3.trusted_authority_bootstrap import (
    AUTHORITY_RUNTIME_CONFIG_FIELDS,
    AUTHORITY_RUNTIME_SCHEMA_VERSION,
    TrustedAuthorityBootstrapError,
    build_trusted_authority,
    load_trusted_authority_runtime_config,
)
from odoo_accounting_cli_v3.write_runtime import (
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRuntimeError,
)


NOW = datetime(2026, 7, 15, 9, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
WRITE_ROLES = (
    "write_auth",
    "approval",
    "execution",
    "verification",
    "recovery",
    "write_receipt",
)


def _effect_finalizer_runtime() -> EffectFinalizerClientRuntime:
    return EffectFinalizerClientRuntime(
        socket_path="/run/odoo-accounting-cli-v3/effect-finalizer.sock",
        socket_owner_uid=0,
        socket_group_gid=3204,
        socket_mode=0o660,
        finalizer_service_uid=3104,
        finalizer_service_gid=3104,
        finalizer_systemd_unit=(
            "odoo-accounting-cli-v3-effect-finalizer.service"
        ),
        finalization_identity=EffectFinalizationIdentity(
            attestation_key_id="effect-finalizer-v1",
            guard_installation_id="22222222-2222-4222-8222-222222222222",
            database_oid=16384,
        ),
        handoff_idle_timeout_seconds=115,
        request_io_timeout_seconds=10,
        max_request_bytes=16_384,
        max_response_bytes=32_768,
    )


def _effect_finalizer_document() -> dict[str, object]:
    runtime = _effect_finalizer_runtime()
    return {
        "socket_path": runtime.socket_path,
        "socket_owner_uid": runtime.socket_owner_uid,
        "socket_group_gid": runtime.socket_group_gid,
        "socket_mode": runtime.socket_mode,
        "finalizer_service_uid": runtime.finalizer_service_uid,
        "finalizer_service_gid": runtime.finalizer_service_gid,
        "finalizer_systemd_unit": runtime.finalizer_systemd_unit,
        "attestation_key_id": (
            runtime.finalization_identity.attestation_key_id
        ),
        "guard_installation_id": (
            runtime.finalization_identity.guard_installation_id
        ),
        "database_oid": runtime.finalization_identity.database_oid,
        "handoff_idle_timeout_seconds": runtime.handoff_idle_timeout_seconds,
        "request_io_timeout_seconds": runtime.request_io_timeout_seconds,
        "max_request_bytes": runtime.max_request_bytes,
        "max_response_bytes": runtime.max_response_bytes,
    }


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o640)


def _runtime_documents(
    tmp_path: Path,
) -> tuple[Path, dict[str, object], Path, dict[str, object], dict[str, bytes]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    secret_dir = tmp_path / "secrets"
    write_state_dir = tmp_path / "write-state"
    authority_state_dir = tmp_path / "authority-state"
    for directory, mode in (
        (secret_dir, 0o750),
        (write_state_dir, 0o700),
        (authority_state_dir, 0o700),
    ):
        directory.mkdir()
        if os.name == "posix":
            directory.chmod(mode)

    secret_values = {
        "base_auth": b"base-auth-bootstrap-secret-00000000001",
        "base_receipt": b"base-receipt-bootstrap-secret-000002",
        "write_auth": b"write-auth-bootstrap-secret-000000001",
        "approval": b"approval-bootstrap-secret-0000000002",
        "execution": b"execution-bootstrap-secret-00000001",
        "verification": b"verification-bootstrap-secret-000001",
        "recovery": b"recovery-bootstrap-secret-0000000002",
        "write_receipt": b"write-receipt-bootstrap-secret-00001",
    }
    secret_paths: dict[str, Path] = {}
    for name, value in secret_values.items():
        path = secret_dir / f"{name}.hmac"
        path.write_bytes(value)
        if os.name == "posix":
            path.chmod(0o640)
        secret_paths[name] = path

    base_path = tmp_path / "read-runtime.json"
    base_document: dict[str, object] = {
        "instance_id": "odoo19@sandbox",
        "environment": "sandbox",
        "capability_channel": "staged",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": DATABASE_UUID,
        "odoo_python": str(tmp_path / "python"),
        "odoo_python_sha256": "1" * 64,
        "odoo_bin": str(tmp_path / "odoo-bin"),
        "odoo_bin_sha256": "2" * 64,
        "odoo_config": str(tmp_path / "odoo.conf"),
        "odoo_config_sha256": "3" * 64,
        "release_root": str(tmp_path / "release"),
        "canonical_package_path": str(tmp_path / "package.tar.gz"),
        "canonical_package_sha256": "4" * 64,
        "auth_state_path": str(tmp_path / "read-auth.sqlite3"),
        "receipt_state_path": str(tmp_path / "read-receipt.sqlite3"),
        "auth_key_id": "base-read-auth-v1",
        "receipt_key_id": "base-read-receipt-v1",
        "auth_secret_path": str(secret_paths["base_auth"]),
        "receipt_secret_path": str(secret_paths["base_receipt"]),
    }
    _write_json(base_path, base_document)

    roles: dict[str, dict[str, object]] = {
        role: {
            "key_id": f"{role.replace('_', '-')}-v1",
            "secret_path": str(secret_paths[role]),
        }
        for role in WRITE_ROLES
    }
    roles["execution"]["issuer"] = "odoo-write-executor"
    roles["verification"]["issuer"] = "odoo-write-verifier"
    roles["recovery"]["issuer"] = "odoo-write-recovery"
    write_path = tmp_path / "write-runtime.json"
    write_document: dict[str, object] = {
        "schema_version": WRITE_RUNTIME_SCHEMA_VERSION,
        "write_execution_mode": "sandbox_staged",
        "base_runtime_config_path": str(base_path),
        "write_state_path": str(write_state_dir / "write.sqlite3"),
        "effect_finalizer": _effect_finalizer_document(),
        **roles,
    }
    _write_json(write_path, write_document)

    authority_path = tmp_path / "authority-runtime.json"
    authority_document: dict[str, object] = {
        "schema_version": AUTHORITY_RUNTIME_SCHEMA_VERSION,
        "write_runtime_config_path": str(write_path),
        "authority_state_path": str(authority_state_dir / "authority.sqlite3"),
        "sqlite_busy_timeout_ms": 5_000,
        "context_ttl_seconds": 120,
    }
    _write_json(authority_path, authority_document)
    return authority_path, authority_document, write_path, write_document, secret_values


def _operation() -> Operation:
    operation = Operation.prepare(
        operation_id="op-1",
        request_id="request-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "partner_id": 101},
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="invoice-2026-1",
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest="b" * 64,
        release_digest="c" * 64,
    )
    operation = record_precheck(
        operation, precheck_digest="d" * 64, expected_revision=0
    )
    return operation.transition(State.AWAITING_APPROVAL, expected_revision=1)


def _sessions(operation: Operation) -> dict[str, TrustedSession]:
    requester = TrustedSession(
        session_id="requester-session",
        principal=operation.principal,
        odoo_instance_id=operation.odoo_instance_id,
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        user_id=operation.user_id,
        company_id=operation.company_id,
        allowed_company_ids=frozenset({operation.company_id}),
        environment=operation.environment,
        release_digest=operation.release_digest,
        registry_digest=operation.registry_digest,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    return {
        "requester": requester,
        "approver": TrustedSession(
            **{
                **requester.__dict__,
                "session_id": "approver-session",
                "principal": "pi:user-84",
                "user_id": 84,
            }
        ),
    }


def _build(path: Path, operation: Operation, sessions: dict[str, TrustedSession]):
    return build_trusted_authority(
        path,
        require_root_owner=False,
        session_resolver=sessions.get,
        operation_resolver=lambda operation_id: (
            operation if operation_id == operation.operation_id else None
        ),
        approver_authorizer=lambda session, candidate: session.user_id == 84,
        approval_ttl_resolver=lambda candidate: 120,
        clock=lambda: NOW,
    )


def test_config_is_exact_secret_free_and_binds_existing_write_runtime(
    tmp_path: Path,
) -> None:
    path, document, _, _, secret_values = _runtime_documents(tmp_path)

    config = load_trusted_authority_runtime_config(
        path, require_root_owner=False
    )

    assert frozenset(document) == AUTHORITY_RUNTIME_CONFIG_FIELDS
    assert config.schema_version == AUTHORITY_RUNTIME_SCHEMA_VERSION
    assert config.authority_state_path == Path(document["authority_state_path"])
    assert config.sqlite_busy_timeout_ms == 5_000
    assert config.context_ttl_seconds == 120
    assert config.write_runtime.write_auth.key_id == "write-auth-v1"
    assert config.write_runtime.approval.key_id == "approval-v1"
    rendered = repr(config) + json.dumps(config.runtime_identity, sort_keys=True)
    assert "secret_path" not in json.dumps(config.runtime_identity)
    assert all(value.decode("ascii") not in rendered for value in secret_values.values())


def test_factory_persists_approval_across_restart_and_never_persists_keys(
    tmp_path: Path,
) -> None:
    path, document, _, _, secret_values = _runtime_documents(tmp_path)
    operation = _operation()
    sessions = _sessions(operation)
    first = _build(path, operation, sessions)

    challenge = first.authority.request_approval("requester", operation.operation_id)
    approved = first.authority.decide_approval(
        "approver", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    restarted = _build(path, operation, sessions)
    action = restarted.authority.issue_approved_execute(
        "requester", challenge.challenge_id
    )

    assert restarted.store is not first.store
    assert restarted.store.path == Path(document["authority_state_path"])
    assert restarted.store.get_challenge(challenge.challenge_id) == approved
    assert action.request["approval"]["operation_id"] == operation.operation_id
    persisted = restarted.store.path.read_bytes()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{restarted.store.path}{suffix}")
        if sidecar.exists():
            persisted += sidecar.read_bytes()
    assert all(value not in persisted for value in secret_values.values())


def test_two_factories_share_one_atomic_challenge_store(tmp_path: Path) -> None:
    path, _, _, _, _ = _runtime_documents(tmp_path)
    operation = _operation()
    sessions = _sessions(operation)
    left = _build(path, operation, sessions)
    right = _build(path, operation, sessions)
    barrier = Barrier(2)

    def request(runtime):
        barrier.wait()
        return runtime.authority.request_approval("requester", operation.operation_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = (
            future.result()
            for future in (pool.submit(request, left), pool.submit(request, right))
        )

    assert first == second
    assert len(left.store.challenges()) == 1
    assert [event.event_type for event in left.store.audit_events()].count(
        "approval.challenge_created"
    ) == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "schema_version"),
        ("write_runtime_config_path", "write-runtime.json", "absolute"),
        ("authority_state_path", "authority.sqlite3", "absolute"),
        ("sqlite_busy_timeout_ms", 0, "busy timeout"),
        ("sqlite_busy_timeout_ms", True, "busy timeout"),
        ("context_ttl_seconds", 0, "context TTL"),
        ("context_ttl_seconds", 301, "context TTL"),
    ],
)
def test_config_schema_and_bounds_fail_closed(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    path, document, _, _, _ = _runtime_documents(tmp_path)
    document[field] = value
    _write_json(path, document)

    with pytest.raises(TrustedAuthorityBootstrapError, match=message):
        load_trusted_authority_runtime_config(path, require_root_owner=False)


def test_extra_duplicate_and_state_colliding_fields_are_rejected(tmp_path: Path) -> None:
    path, document, _, write_document, _ = _runtime_documents(tmp_path)
    _write_json(path, {**document, "session_resolver": "caller-controlled"})
    with pytest.raises(TrustedAuthorityBootstrapError, match="fields"):
        load_trusted_authority_runtime_config(path, require_root_owner=False)

    _write_json(path, document)
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace(
            '"schema_version": 1',
            '"schema_version": 1, "schema_version": 1',
            1,
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        path.chmod(0o640)
    with pytest.raises(TrustedAuthorityBootstrapError, match="duplicate JSON key"):
        load_trusted_authority_runtime_config(path, require_root_owner=False)

    _write_json(path, document)
    document["authority_state_path"] = write_document["write_state_path"]
    _write_json(path, document)
    with pytest.raises(TrustedAuthorityBootstrapError, match="distinct"):
        load_trusted_authority_runtime_config(path, require_root_owner=False)


def test_state_hardlink_cannot_alias_an_existing_runtime_file(tmp_path: Path) -> None:
    path, document, _, write_document, _ = _runtime_documents(tmp_path)
    read_state = tmp_path / "read-auth.sqlite3"
    read_state.write_bytes(b"")
    authority_state = Path(document["authority_state_path"])
    try:
        os.link(read_state, authority_state)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    if os.name == "posix":
        read_state.chmod(0o600)

    with pytest.raises(TrustedAuthorityBootstrapError, match="inode.*distinct"):
        load_trusted_authority_runtime_config(path, require_root_owner=False)

    assert write_document["write_state_path"] != str(authority_state)


def test_disabled_write_runtime_keeps_status_authority_available(tmp_path: Path) -> None:
    path, _, write_path, write_document, _ = _runtime_documents(tmp_path)
    write_document["write_execution_mode"] = "disabled"
    _write_json(write_path, write_document)
    operation = _operation()

    runtime = _build(path, operation, _sessions(operation))
    authorized = runtime.authority.issue_write_action(
        "requester",
        "operation.status",
        {"operation_id": operation.operation_id},
    )
    assert authorized.context.company_id == operation.company_id
    assert authorized.request == {"operation_id": operation.operation_id}


def test_secret_loader_or_sqlite_failure_has_no_memory_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, document, _, _, _ = _runtime_documents(tmp_path)
    operation = _operation()
    sessions = _sessions(operation)

    def reject_secrets(config):
        raise WriteRuntimeError("injected secret failure")

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.trusted_authority_bootstrap.load_write_runtime_secrets",
        reject_secrets,
    )
    with pytest.raises(TrustedAuthorityBootstrapError, match="secrets rejected"):
        _build(path, operation, sessions)
    assert not Path(document["authority_state_path"]).exists()

    source = inspect.getsource(build_trusted_authority)
    assert "InMemoryApprovalChallengeStore" not in source


def test_corrupt_sqlite_schema_rejects_factory_restart(tmp_path: Path) -> None:
    path, document, _, _, _ = _runtime_documents(tmp_path)
    operation = _operation()
    sessions = _sessions(operation)
    _build(path, operation, sessions)
    state_path = Path(document["authority_state_path"])
    with sqlite3.connect(state_path) as connection:
        connection.execute("DROP TRIGGER authority_schema_meta_no_update")
        connection.execute(
            "UPDATE authority_schema_meta SET value='999' WHERE key='schema_version'"
        )
        connection.commit()

    with pytest.raises(TrustedAuthorityBootstrapError, match="state store rejected"):
        _build(path, operation, sessions)


def test_external_identity_and_policy_dependencies_are_required() -> None:
    required = {
        "session_resolver",
        "operation_resolver",
        "approver_authorizer",
        "approval_ttl_resolver",
        "clock",
    }
    signature = inspect.signature(build_trusted_authority)
    assert required.issubset(signature.parameters)
    assert all(signature.parameters[name].default is inspect.Parameter.empty for name in required)
    assert "session" not in AUTHORITY_RUNTIME_CONFIG_FIELDS
    assert "approver" not in AUTHORITY_RUNTIME_CONFIG_FIELDS
