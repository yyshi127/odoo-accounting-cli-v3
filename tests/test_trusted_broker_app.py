from __future__ import annotations

import copy
import ast
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import odoo_accounting_cli_v3.trusted_broker_app as broker_app
from odoo_accounting_cli_v3.effect_finalizer import EffectFinalizationIdentity
from odoo_accounting_cli_v3.effect_finalizer_runtime import (
    EffectFinalizerClientRuntime,
)
from odoo_accounting_cli_v3.trusted_broker_app import (
    TrustedBrokerRuntimeError,
    _assert_finalizer_socket_membership,
    _assert_loaded_topology,
    load_trusted_broker_runtime_config,
)
from odoo_accounting_cli_v3.historical_router import (
    HistoricalRoute,
    HistoricalRoutingManifest,
)
from odoo_accounting_cli_v3.odoo.runner import RuntimeConfig
from odoo_accounting_cli_v3.trusted_authority_bootstrap import (
    TrustedAuthorityRuntimeConfig,
)
from odoo_accounting_cli_v3.write_runtime import (
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRoleConfig,
    WriteRuntimeConfig,
)


CURRENT_RELEASE = "a" * 64
CURRENT_REGISTRY = "b" * 64
OLD_RELEASE = "c" * 64
OLD_REGISTRY = "d" * 64
EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "deployment"
    / "dev9"
    / "broker-runtime.example.json"
)


def _effect_finalizer_runtime() -> EffectFinalizerClientRuntime:
    return EffectFinalizerClientRuntime(
        socket_path="/run/odoo-accounting-cli-v3/effect-finalizer.sock",
        socket_owner_uid=0,
        socket_group_gid=1301,
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


def test_production_composition_injects_durable_precheck_resolver() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "odoo_accounting_cli_v3"
        / "trusted_broker_app.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    broker_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TrustedBroker"
    ]
    assert len(broker_calls) == 1
    keywords = {item.arg: item.value for item in broker_calls[0].keywords}
    resolver = keywords["precheck_resolver"]
    assert isinstance(resolver, ast.Attribute)
    assert isinstance(resolver.value, ast.Name)
    assert (resolver.value.id, resolver.attr) == (
        "operation_store",
        "get_precheck_record",
    )

    build = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "build_trusted_broker_runtime"
    )
    build_source = ast.get_source_segment(source, build)
    assert build_source is not None
    assert "enforce_source_release" in build_source
    assert "current_release.assert_executing_broker_source(" in build_source
    assert "package_version=__version__" in build_source
    assert "preconnect_effect_finalizer_socket(" in build_source

    router_calls = [
        node
        for node in ast.walk(build)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "HistoricalReleaseRouter"
    ]
    assert len(router_calls) == 1
    router_keywords = {item.arg for item in router_calls[0].keywords}
    assert "effect_finalizer_preconnector" in router_keywords

    persistence_calls = [
        node
        for node in ast.walk(build)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "SQLitePersistence"
    ]
    assert len(persistence_calls) == 2
    shared_call, current_receipt_call = sorted(
        persistence_calls, key=lambda node: node.lineno
    )
    assert ast.unparse(shared_call.args[0]) == "config.shared_write_state_path"
    assert {
        keyword.arg for keyword in shared_call.keywords
    } == {"busy_timeout_ms"}
    assert ast.unparse(current_receipt_call.args[0]) == (
        "current.base_runtime.receipt_state_path"
    )
    current_keywords = {
        keyword.arg: keyword.value for keyword in current_receipt_call.keywords
    }
    assert set(current_keywords) == {
        "busy_timeout_ms",
        "receipt_key_id",
        "receipt_secret",
        "enable_verified_read_results",
    }
    assert isinstance(
        current_keywords["enable_verified_read_results"], ast.Constant
    )
    assert current_keywords["enable_verified_read_results"].value is True

    write_app_source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "odoo_accounting_cli_v3"
        / "write_app.py"
    ).read_text(encoding="utf-8")
    assert "preconnect_effect_finalizer_socket" not in write_app_source


def _document(tmp_path: Path) -> dict[str, Any]:
    socket_root = "/run/odoo-accounting-cli-v3"
    return {
        "schema_version": 1,
        "broker_service_uid": 1301,
        "broker_service_gid": 1301,
        "current_release_digest": CURRENT_RELEASE,
        "current_registry_digest": CURRENT_REGISTRY,
        "historical_routing_manifest_path": str(
            (tmp_path / "historical-routes.json").resolve()
        ),
        "historical_routing_manifest_sha256": "1" * 64,
        "read_runtime_config_path": str((tmp_path / "read-runtime.json").resolve()),
        "read_runtime_config_sha256": "2" * 64,
        "shared_write_state_path": str((tmp_path / "write.sqlite3").resolve()),
        "trusted_session_state_path": str((tmp_path / "sessions.sqlite3").resolve()),
        "broker_audit_state_path": str((tmp_path / "broker-audit.sqlite3").resolve()),
        "sqlite_busy_timeout_ms": 1_000,
        "read_context_ttl_seconds": 120,
        "read_timeout_seconds": 90,
        "historical_timeout_seconds": 100,
        "historical_max_stdin_bytes": 262_144,
        "historical_max_stdout_bytes": 2 * 1024 * 1024,
        "historical_max_stderr_bytes": 65_536,
        "approver_context_ttl_seconds": 60,
        "approver_timeout_seconds": 20,
        "release_routes": [
            {
                "release_digest": CURRENT_RELEASE,
                "registry_digest": CURRENT_REGISTRY,
                "authority_runtime_config_path": str(
                    (tmp_path / "authority-current.json").resolve()
                ),
                "authority_runtime_config_sha256": "3" * 64,
            },
            {
                "release_digest": OLD_RELEASE,
                "registry_digest": OLD_REGISTRY,
                "authority_runtime_config_path": str(
                    (tmp_path / "authority-old.json").resolve()
                ),
                "authority_runtime_config_sha256": "4" * 64,
            },
        ],
        "pi_broker_uds": {
            "socket_path": f"{socket_root}/pi-broker.sock",
            "allowed_client_uid": 1201,
            "socket_group_gid": 2201,
            "socket_mode": 0o660,
            "max_body_bytes": 1024 * 1024,
            "max_response_bytes": 1024 * 1024,
            "max_header_bytes": 8192,
            "max_header_count": 16,
            "max_inflight_requests": 16,
            "request_timeout_seconds": 110,
        },
        "session_mint_uds": {
            "socket_path": f"{socket_root}/session-mint.sock",
            "odoo_issuer_uid": 1101,
            "pi_bridge_uid": 1201,
            "socket_group_gid": 2101,
            "session_ttl_seconds": 180,
            "session_max_uses": 32,
            "socket_mode": 0o660,
            "max_body_bytes": 8192,
            "max_response_bytes": 4096,
            "max_header_bytes": 4096,
            "max_header_count": 8,
            "max_inflight_requests": 4,
            "request_timeout_seconds": 5,
        },
        "trusted_approval_uds": {
            "socket_path": f"{socket_root}/trusted-approval.sock",
            "odoo_client_uid": 1101,
            "pi_bridge_uid": 1201,
            "socket_group_gid": 2101,
            "socket_mode": 0o660,
            "max_body_bytes": 8192,
            "max_response_bytes": 8192,
            "max_header_bytes": 4096,
            "max_header_count": 8,
            "max_inflight_broker_calls": 4,
            "request_timeout_seconds": 30,
        },
    }


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o640)


def _load(tmp_path: Path, value: dict[str, Any]):
    path = (tmp_path / "broker-runtime.json").resolve()
    _write(path, value)
    return load_trusted_broker_runtime_config(path, require_root_owner=False)


def test_deployment_example_is_the_complete_secret_free_root_schema(
    tmp_path: Path,
) -> None:
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    if os.name != "posix":
        for field in (
            "historical_routing_manifest_path",
            "read_runtime_config_path",
            "shared_write_state_path",
            "trusted_session_state_path",
            "broker_audit_state_path",
        ):
            value[field] = str((tmp_path / field).resolve())
        for index, route in enumerate(value["release_routes"]):
            route["authority_runtime_config_path"] = str(
                (tmp_path / f"authority-{index}.json").resolve()
            )
    config = _load(tmp_path, value)

    assert config.broker_service_uid == 3101
    assert config.pi_broker_uds.max_inflight_requests == 16
    assert config.session_mint_uds.max_inflight_requests == 4
    assert config.trusted_approval_uds.max_inflight_broker_calls == 4
    assert config.pi_broker_uds.socket_mode == 0o660
    assert "secret" not in EXAMPLE.read_text(encoding="utf-8").lower()


def test_exact_root_snapshot_binds_three_separate_uds_and_deadlines(
    tmp_path: Path,
) -> None:
    config = _load(tmp_path, _document(tmp_path))

    assert config.route_identities == (
        (CURRENT_RELEASE, CURRENT_REGISTRY),
        (OLD_RELEASE, OLD_REGISTRY),
    )
    assert config.pi_broker_uds.allowed_client_uid == 1201
    assert config.pi_broker_uds.max_inflight_requests == 16
    assert config.session_mint_uds.odoo_issuer_uid == 1101
    assert config.session_mint_uds.max_inflight_requests == 4
    assert config.session_mint_uds.current_release_digest == CURRENT_RELEASE
    assert config.session_mint_uds.current_registry_digest == CURRENT_REGISTRY
    assert config.trusted_approval_uds.odoo_client_uid == 1101
    assert config.trusted_approval_uds.max_inflight_broker_calls == 4
    assert config.broker_service_uid == 1301
    assert config.historical_timeout_seconds == 100
    assert config.config_fingerprint not in {CURRENT_RELEASE, CURRENT_REGISTRY}
    assert "secret" not in repr(config).lower()


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_field",
        "missing_current",
        "duplicate_release",
        "service_equals_pi",
        "service_equals_odoo",
        "pi_equals_odoo",
        "shared_socket_group",
        "duplicate_socket_path",
        "unsafe_socket_mode",
        "missing_pi_capacity",
        "missing_mint_capacity",
        "unsafe_pi_capacity",
        "unsafe_mint_capacity",
        "missing_approval_capacity",
        "unsafe_approval_capacity",
        "short_session_ttl",
        "read_deadline",
        "write_deadline",
        "approval_deadline",
        "state_path_alias",
    ],
)
def test_root_snapshot_rejects_unsafe_topology(
    tmp_path: Path, mutation: str
) -> None:
    value = _document(tmp_path)
    if mutation == "extra_field":
        value["fallback_release"] = CURRENT_RELEASE
    elif mutation == "missing_current":
        value["current_release_digest"] = "e" * 64
    elif mutation == "duplicate_release":
        value["release_routes"][1]["release_digest"] = CURRENT_RELEASE
    elif mutation == "service_equals_pi":
        value["broker_service_uid"] = 1201
    elif mutation == "service_equals_odoo":
        value["broker_service_uid"] = 1101
    elif mutation == "pi_equals_odoo":
        value["session_mint_uds"]["pi_bridge_uid"] = 1101
    elif mutation == "shared_socket_group":
        value["pi_broker_uds"]["socket_group_gid"] = 2101
    elif mutation == "duplicate_socket_path":
        value["trusted_approval_uds"]["socket_path"] = value["session_mint_uds"][
            "socket_path"
        ]
    elif mutation == "unsafe_socket_mode":
        value["pi_broker_uds"]["socket_mode"] = 0o640
    elif mutation == "missing_pi_capacity":
        del value["pi_broker_uds"]["max_inflight_requests"]
    elif mutation == "missing_mint_capacity":
        del value["session_mint_uds"]["max_inflight_requests"]
    elif mutation == "unsafe_pi_capacity":
        value["pi_broker_uds"]["max_inflight_requests"] = 33
    elif mutation == "unsafe_mint_capacity":
        value["session_mint_uds"]["max_inflight_requests"] = 0
    elif mutation == "missing_approval_capacity":
        del value["trusted_approval_uds"]["max_inflight_broker_calls"]
    elif mutation == "unsafe_approval_capacity":
        value["trusted_approval_uds"]["max_inflight_broker_calls"] = 33
    elif mutation == "short_session_ttl":
        value["session_mint_uds"]["session_ttl_seconds"] = 100
    elif mutation == "read_deadline":
        value["read_timeout_seconds"] = 106
    elif mutation == "write_deadline":
        value["historical_timeout_seconds"] = 106
    elif mutation == "approval_deadline":
        value["trusted_approval_uds"]["request_timeout_seconds"] = 20
    else:
        value["broker_audit_state_path"] = value["trusted_session_state_path"]

    with pytest.raises(TrustedBrokerRuntimeError):
        _load(tmp_path, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "sqlite_busy_cap",
        "mint_sqlite_budget",
        "read_sqlite_budget",
        "historical_sqlite_budget",
        "approval_route_scan_budget",
    ],
)
def test_root_snapshot_rejects_aggregate_deadline_inversions(
    tmp_path: Path, mutation: str
) -> None:
    value = _document(tmp_path)
    if mutation == "sqlite_busy_cap":
        value["sqlite_busy_timeout_ms"] = 1_001
    elif mutation == "mint_sqlite_budget":
        value["session_mint_uds"]["request_timeout_seconds"] = 1.9
    elif mutation == "read_sqlite_budget":
        value["read_timeout_seconds"] = 103
    elif mutation == "historical_sqlite_budget":
        value["historical_timeout_seconds"] = 103
    else:
        third = copy.deepcopy(value["release_routes"][1])
        third.update(
            {
                "release_digest": "e" * 64,
                "registry_digest": "f" * 64,
                "authority_runtime_config_path": str(
                    (tmp_path / "authority-third.json").resolve()
                ),
                "authority_runtime_config_sha256": "5" * 64,
            }
        )
        value["release_routes"].append(third)

    with pytest.raises(TrustedBrokerRuntimeError):
        _load(tmp_path, value)


def test_existing_state_hardlink_alias_is_rejected(tmp_path: Path) -> None:
    value = _document(tmp_path)
    session = Path(value["trusted_session_state_path"])
    audit = Path(value["broker_audit_state_path"])
    session.write_bytes(b"state")
    try:
        os.link(session, audit)
    except OSError:
        pytest.skip("local filesystem does not support hard links")

    with pytest.raises(TrustedBrokerRuntimeError, match="inode"):
        _load(tmp_path, value)


def test_root_snapshot_is_reloaded_without_mutating_prior_object(tmp_path: Path) -> None:
    value = _document(tmp_path)
    first = _load(tmp_path, value)
    changed = copy.deepcopy(value)
    changed["session_mint_uds"]["session_max_uses"] = 48
    second = _load(tmp_path, changed)

    assert first.session_mint_uds.session_max_uses == 32
    assert second.session_mint_uds.session_max_uses == 48
    assert first.config_fingerprint != second.config_fingerprint


def _authority(
    tmp_path: Path,
    *,
    name: str,
    base_runtime_path: Path,
    write_runtime_path: Path,
    authority_path: Path,
    shared_write_state: Path,
) -> TrustedAuthorityRuntimeConfig:
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
        release_root=(tmp_path / f"release-{name}").resolve(),
        canonical_package_path=(tmp_path / f"package-{name}.tar.gz").resolve(),
        canonical_package_sha256="4" * 64,
        auth_state_path=(tmp_path / f"read-auth-{name}.sqlite3").resolve(),
        receipt_state_path=(tmp_path / f"read-receipt-{name}.sqlite3").resolve(),
        auth_key_id=f"read-auth-{name}",
        receipt_key_id=f"read-receipt-{name}",
        auth_secret_path=(tmp_path / f"read-auth-{name}.hmac").resolve(),
        receipt_secret_path=(tmp_path / f"read-receipt-{name}.hmac").resolve(),
    )
    roles = {
        role: WriteRoleConfig(
            key_id=f"{role}-{name}",
            secret_path=(tmp_path / f"{role}-{name}.hmac").resolve(),
            issuer=(
                f"{role}-{name}-issuer"
                if role in {"execution", "verification", "recovery"}
                else None
            ),
        )
        for role in (
            "write_auth",
            "approval",
            "execution",
            "verification",
            "recovery",
            "write_receipt",
        )
    }
    write = WriteRuntimeConfig(
        schema_version=WRITE_RUNTIME_SCHEMA_VERSION,
        write_execution_mode="sandbox_staged",
        base_runtime_config_path=base_runtime_path,
        write_state_path=shared_write_state,
        effect_finalizer=_effect_finalizer_runtime(),
        base_runtime=base,
        config_fingerprint=("5" if name == "current" else "6") * 64,
        _require_root_owner=False,
        **roles,
    )
    return TrustedAuthorityRuntimeConfig(
        schema_version=1,
        config_path=authority_path,
        write_runtime_config_path=write_runtime_path,
        authority_state_path=(tmp_path / f"authority-{name}.sqlite3").resolve(),
        sqlite_busy_timeout_ms=1_000,
        context_ttl_seconds=120,
        write_runtime=write,
        config_fingerprint=("7" if name == "current" else "8") * 64,
        _require_root_owner=False,
    )


def _loaded_topology(tmp_path: Path):
    config = _load(tmp_path, _document(tmp_path))
    current_route, old_route = config.release_routes
    current_write_path = (tmp_path / "write-current.json").resolve()
    old_write_path = (tmp_path / "write-old.json").resolve()
    current = _authority(
        tmp_path,
        name="current",
        base_runtime_path=config.read_runtime_config_path,
        write_runtime_path=current_write_path,
        authority_path=current_route.authority_runtime_config_path,
        shared_write_state=config.shared_write_state_path,
    )
    old = _authority(
        tmp_path,
        name="old",
        base_runtime_path=(tmp_path / "read-old.json").resolve(),
        write_runtime_path=old_write_path,
        authority_path=old_route.authority_runtime_config_path,
        shared_write_state=config.shared_write_state_path,
    )
    manifest = HistoricalRoutingManifest(
        current_release_digest=CURRENT_RELEASE,
        routes={
            CURRENT_RELEASE: HistoricalRoute(
                release_digest=CURRENT_RELEASE,
                registry_digest=CURRENT_REGISTRY,
                executable_path=(tmp_path / "current-cli").resolve(),
                executable_sha256="9" * 64,
                runtime_config_path=current_write_path,
                runtime_config_sha256="a" * 64,
            ),
            OLD_RELEASE: HistoricalRoute(
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
                executable_path=(tmp_path / "old-cli").resolve(),
                executable_sha256="b" * 64,
                runtime_config_path=old_write_path,
                runtime_config_sha256="c" * 64,
            ),
        },
    )
    return config, manifest, current, old


def test_loaded_release_topology_accepts_one_tenant_shared_write_and_isolated_states(
    tmp_path: Path,
) -> None:
    config, manifest, current, old = _loaded_topology(tmp_path)
    _assert_loaded_topology(config, manifest, (current, old))


def test_loaded_release_topology_rejects_current_receipt_path_alias(
    tmp_path: Path,
) -> None:
    config, manifest, current, old = _loaded_topology(tmp_path)
    current = replace(
        current,
        write_runtime=replace(
            current.write_runtime,
            base_runtime=replace(
                current.write_runtime.base_runtime,
                receipt_state_path=config.shared_write_state_path,
            ),
        ),
    )

    with pytest.raises(TrustedBrokerRuntimeError, match="aliases .* by path"):
        _assert_loaded_topology(config, manifest, (current, old))


def test_loaded_release_topology_rejects_hardlinked_receipt_states(
    tmp_path: Path,
) -> None:
    config, manifest, current, old = _loaded_topology(tmp_path)
    current_receipt = current.write_runtime.base_runtime.receipt_state_path
    old_receipt = old.write_runtime.base_runtime.receipt_state_path
    current_receipt.write_bytes(b"current")
    os.link(current_receipt, old_receipt)

    with pytest.raises(TrustedBrokerRuntimeError, match="aliases .* by inode"):
        _assert_loaded_topology(config, manifest, (current, old))


def test_runtime_only_opts_current_receipt_store_into_verified_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, manifest, current_authority, old_authority = _loaded_topology(
        tmp_path
    )

    def release(authority, release_digest: str, registry_digest: str):
        return SimpleNamespace(
            release_digest=release_digest,
            registry_digest=registry_digest,
            authority_config=authority,
            write_runtime=authority.write_runtime,
            base_runtime=authority.write_runtime.base_runtime,
            read_receipt_secret=b"read-receipt-secret-material-32b",
            write_secrets=SimpleNamespace(
                write_receipt=b"write-receipt-secret-material-32"
            ),
            approval_ttl_seconds=lambda _capability_id: 120,
        )

    current = release(current_authority, CURRENT_RELEASE, CURRENT_REGISTRY)
    old = release(old_authority, OLD_RELEASE, OLD_REGISTRY)
    topology = SimpleNamespace(
        releases=(current, old),
        manifest=manifest,
    )
    authority_by_path = {
        item.config_path: item for item in (current_authority, old_authority)
    }

    class StopAfterPersistenceCalls(Exception):
        pass

    persistence_calls: list[tuple[Path, dict[str, Any]]] = []

    def persistence(path, **kwargs):
        persistence_calls.append((Path(path), kwargs))
        if len(persistence_calls) == 2:
            raise StopAfterPersistenceCalls
        return SimpleNamespace()

    def build_authority(path, **_kwargs):
        authority = authority_by_path[Path(path)]
        return SimpleNamespace(
            config=authority,
            authority=object(),
            store=SimpleNamespace(find_challenge=lambda _challenge_id: None),
        )

    monkeypatch.setattr(
        broker_app, "load_trusted_broker_runtime_config", lambda *_args, **_kwargs: config
    )
    monkeypatch.setattr(
        broker_app, "load_release_topology", lambda _config: topology
    )
    monkeypatch.setattr(broker_app, "SQLitePersistence", persistence)
    monkeypatch.setattr(
        broker_app,
        "SQLiteTrustedSessionStore",
        lambda *_args, **_kwargs: SimpleNamespace(resolve=lambda _handle: None),
    )
    monkeypatch.setattr(
        broker_app,
        "SQLiteBrokerAuditSink",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        broker_app,
        "OdooApproverAuthorizer",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        broker_app,
        "ReleaseAuthority",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )
    monkeypatch.setattr(
        broker_app, "build_trusted_authority", build_authority
    )
    monkeypatch.setattr(
        broker_app,
        "build_release_response_verifier_resolver",
        lambda *_args, **_kwargs: object(),
    )

    with pytest.raises(TrustedBrokerRuntimeError) as exc_info:
        broker_app.build_trusted_broker_runtime(
            tmp_path / "broker.json",
            require_root_owner=False,
            enforce_service_identity=False,
            enforce_source_release=False,
        )
    assert isinstance(exc_info.value.__cause__, StopAfterPersistenceCalls)
    assert persistence_calls == [
        (
            config.shared_write_state_path,
            {"busy_timeout_ms": config.sqlite_busy_timeout_ms},
        ),
        (
            current.base_runtime.receipt_state_path,
            {
                "busy_timeout_ms": config.sqlite_busy_timeout_ms,
                "receipt_key_id": current.base_runtime.receipt_key_id,
                "receipt_secret": current.read_receipt_secret,
                "enable_verified_read_results": True,
            },
        ),
    ]
    assert old.base_runtime.receipt_state_path not in {
        path for path, _kwargs in persistence_calls
    }


def test_broker_service_must_join_dedicated_finalizer_socket_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _manifest, current, _old = _loaded_topology(tmp_path)
    supplementary_runtime = replace(
        current.write_runtime,
        effect_finalizer=replace(
            current.write_runtime.effect_finalizer,
            socket_group_gid=3204,
        ),
    )
    topology = SimpleNamespace(
        releases=(SimpleNamespace(write_runtime=supplementary_runtime),)
    )
    monkeypatch.setattr(
        os, "getegid", lambda: config.broker_service_gid, raising=False
    )
    monkeypatch.setattr(
        os,
        "getgroups",
        lambda: [supplementary_runtime.effect_finalizer.socket_group_gid],
        raising=False,
    )
    _assert_finalizer_socket_membership(config, topology)

    monkeypatch.setattr(os, "getgroups", lambda: [])
    with pytest.raises(TrustedBrokerRuntimeError, match="not a member"):
        _assert_finalizer_socket_membership(config, topology)


@pytest.mark.parametrize(
    "drift",
    [
        "tenant",
        "write_state",
        "authority_state",
        "route_set",
        "read_path",
        "busy_timeout",
        "finalizer_cross_release",
        "finalizer_socket_path",
        "finalizer_socket_owner",
        "finalizer_socket_group",
        "finalizer_socket_mode",
        "finalizer_service_uid",
        "finalizer_service_gid",
        "finalizer_idle_timeout",
    ],
)
def test_loaded_release_topology_rejects_every_cross_release_drift(
    tmp_path: Path, drift: str
) -> None:
    config, manifest, current, old = _loaded_topology(tmp_path)
    if drift == "tenant":
        changed_base = replace(
            old.write_runtime.base_runtime,
            database_uuid="22222222-2222-4222-8222-222222222222",
        )
        old = replace(
            old,
            write_runtime=replace(old.write_runtime, base_runtime=changed_base),
        )
    elif drift == "write_state":
        old = replace(
            old,
            write_runtime=replace(
                old.write_runtime,
                write_state_path=(tmp_path / "other-write.sqlite3").resolve(),
            ),
        )
    elif drift == "authority_state":
        old = replace(old, authority_state_path=current.authority_state_path)
    elif drift == "route_set":
        manifest = HistoricalRoutingManifest(
            current_release_digest=CURRENT_RELEASE,
            routes={CURRENT_RELEASE: manifest.routes[CURRENT_RELEASE]},
        )
    elif drift == "read_path":
        current = replace(
            current,
            write_runtime=replace(
                current.write_runtime,
                base_runtime_config_path=(tmp_path / "wrong-read.json").resolve(),
            ),
        )
    elif drift == "busy_timeout":
        old = replace(old, sqlite_busy_timeout_ms=999)
    elif drift == "finalizer_cross_release":
        old = replace(
            old,
            write_runtime=replace(
                old.write_runtime,
                effect_finalizer=replace(
                    old.write_runtime.effect_finalizer,
                    max_response_bytes=16_384,
                ),
            ),
        )
    else:
        field, value = {
            "finalizer_socket_path": (
                "socket_path",
                config.pi_broker_uds.socket_path,
            ),
            "finalizer_socket_owner": ("socket_owner_uid", 3104),
            "finalizer_socket_group": (
                "socket_group_gid",
                config.pi_broker_uds.socket_group_gid,
            ),
            "finalizer_socket_mode": ("socket_mode", 0o640),
            "finalizer_service_uid": (
                "finalizer_service_uid",
                config.broker_service_uid,
            ),
            "finalizer_service_gid": (
                "finalizer_service_gid",
                config.broker_service_gid,
            ),
            "finalizer_idle_timeout": (
                "handoff_idle_timeout_seconds",
                104.0,
            ),
        }[drift]
        changed = replace(
            current.write_runtime.effect_finalizer,
            **{field: value},
        )
        current = replace(
            current,
            write_runtime=replace(
                current.write_runtime, effect_finalizer=changed
            ),
        )
        old = replace(
            old,
            write_runtime=replace(old.write_runtime, effect_finalizer=changed),
        )

    with pytest.raises(TrustedBrokerRuntimeError):
        _assert_loaded_topology(config, manifest, (current, old))
