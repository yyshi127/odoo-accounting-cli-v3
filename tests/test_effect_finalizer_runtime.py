from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.effect_finalizer_runtime import (
    EffectFinalizerRuntimeError,
    load_effect_finalizer_runtime_config,
    load_effect_finalizer_runtime_secrets,
)


DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"


def _document(tmp_path):
    dependency_manifest = tmp_path / "dependency-manifest.json"
    if dependency_manifest.exists():
        dependency_manifest.chmod(0o644)
    dependency_manifest.write_bytes(b'{"fixture":true}\n')
    dependency_manifest.chmod(0o444)
    secret = tmp_path / "finalizer.hmac"
    secret.write_bytes(b"finalizer-runtime-hmac-secret-at-least-32-bytes")
    secret.chmod(0o600)
    pgpass = tmp_path / "finalizer.pgpass"
    pgpass.write_text(
        "/var/run/postgresql:5432:odoo_sandbox:odoo_v3_finalizer:password\n",
        encoding="utf-8",
    )
    pgpass.chmod(0o600)
    return {
        "schema_version": 2,
        "service_uid": 3104,
        "service_gid": 3104,
        "database_name": "odoo_sandbox",
        "database_uuid": DATABASE_UUID,
        "database_user": "odoo_v3_finalizer",
        "database_host": "/var/run/postgresql",
        "database_port": 5432,
        "database_connect_timeout_seconds": 2,
        "dependency_manifest_path": str(dependency_manifest),
        "dependency_manifest_sha256": hashlib.sha256(
            dependency_manifest.read_bytes()
        ).hexdigest(),
        "pgpass_path": str(pgpass),
        "attestation_key_id": "effect-finalizer-v1",
        "expected_guard_installation_id": INSTALLATION_ID,
        "expected_database_oid": 16384,
        "attestation_secret_path": str(secret),
        "journal_path": str(tmp_path / "attempts.sqlite3"),
        "proof_ttl_seconds": 120,
        "statement_timeout_ms": 5000,
        "uds": {
            "socket_path": "/run/odoo-accounting-cli-v3/effect-finalizer.sock",
            "socket_owner_uid": 0,
            "socket_group_gid": 3204,
            "socket_mode": 432,
            "broker_service_uid": 3101,
            "broker_systemd_unit": "odoo-accounting-cli-v3-broker.service",
            "finalizer_systemd_unit": "odoo-accounting-cli-v3-effect-finalizer.service",
            "handoff_idle_timeout_seconds": 115,
            "request_io_timeout_seconds": 10,
            "max_request_bytes": 16384,
            "max_response_bytes": 32768,
            "max_inflight_requests": 4,
        },
    }


def _write(tmp_path, document):
    path = tmp_path / "effect-finalizer-runtime.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_runtime_is_strict_role_separated_and_exposes_only_secret_free_client_values(
    tmp_path,
) -> None:
    document = _document(tmp_path)
    config = load_effect_finalizer_runtime_config(
        _write(tmp_path, document), require_root_owner=False
    )

    assert config.service_uid == 3104
    assert config.uds.broker_service_uid == 3101
    assert config.database.database_user == "odoo_v3_finalizer"
    assert config.database.connect_timeout_seconds == 2
    assert config.client_runtime.finalizer_service_uid == 3104
    assert config.client_runtime.attestation_key_id == "effect-finalizer-v1"
    assert config.client_runtime.finalization_identity == config.finalization_identity
    assert config.client_runtime.finalization_identity.guard_installation_id == INSTALLATION_ID
    assert config.client_runtime.finalization_identity.database_oid == 16384
    assert config.database.expected_guard_installation_id == INSTALLATION_ID
    assert config.database.expected_database_oid == 16384
    assert config.dependency_manifest_path == Path(
        document["dependency_manifest_path"]
    )
    assert config.dependency_manifest_sha256 == document[
        "dependency_manifest_sha256"
    ]
    assert "secret" not in repr(config.client_runtime).lower()
    assert "pgpass" not in repr(config.client_runtime).lower()
    secrets = load_effect_finalizer_runtime_secrets(config)
    assert secrets.attestation_secret.startswith(b"finalizer-runtime")
    assert "finalizer-runtime" not in repr(secrets)


def test_runtime_rejects_same_broker_and_finalizer_uid_or_extra_fields(tmp_path) -> None:
    document = _document(tmp_path)
    document["service_uid"] = document["uds"]["broker_service_uid"]
    with pytest.raises(EffectFinalizerRuntimeError, match="distinct"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )

    document = _document(tmp_path)
    document["unexpected"] = True
    with pytest.raises(EffectFinalizerRuntimeError, match="fields"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )

    document = _document(tmp_path)
    document["pgpass_path"] = document["attestation_secret_path"]
    with pytest.raises(EffectFinalizerRuntimeError, match="paths must be distinct"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )


def test_runtime_rejects_schema_v1_and_removed_odoo_field(
    tmp_path,
) -> None:
    document = _document(tmp_path)
    document["schema_version"] = 1
    with pytest.raises(EffectFinalizerRuntimeError, match="schema version"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )

    document = _document(tmp_path)
    document["odoo_config_path"] = str(tmp_path / "odoo.conf")
    with pytest.raises(EffectFinalizerRuntimeError, match="fields"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )


def test_runtime_rejects_distinct_credential_paths_with_same_inode(
    tmp_path,
) -> None:
    document = _document(tmp_path)
    secret_path = Path(document["attestation_secret_path"])
    pgpass_path = Path(document["pgpass_path"])
    pgpass_path.unlink()
    try:
        os.link(secret_path, pgpass_path)
    except OSError:
        pytest.skip("hard links are unavailable")
    config = load_effect_finalizer_runtime_config(
        _write(tmp_path, document), require_root_owner=False
    )

    with pytest.raises(EffectFinalizerRuntimeError, match="inodes"):
        load_effect_finalizer_runtime_secrets(config)


def test_runtime_rejects_dependency_manifest_digest_drift(tmp_path) -> None:
    document = _document(tmp_path)
    document["dependency_manifest_sha256"] = "0" * 64

    with pytest.raises(EffectFinalizerRuntimeError, match="digest differs"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )

def test_runtime_rejects_duplicate_json_keys(tmp_path) -> None:
    document = _document(tmp_path)
    path = _write(tmp_path, document)
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw[:-1] + ', "schema_version": 2}', encoding="utf-8")

    with pytest.raises(EffectFinalizerRuntimeError, match="duplicate"):
        load_effect_finalizer_runtime_config(path, require_root_owner=False)


@pytest.mark.parametrize("connect_timeout", [True, 0, 1, 31, 1.5, "2"])
def test_runtime_rejects_invalid_database_connect_timeout(
    tmp_path, connect_timeout
) -> None:
    document = _document(tmp_path)
    document["database_connect_timeout_seconds"] = connect_timeout

    with pytest.raises(EffectFinalizerRuntimeError, match="database configuration"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )


@pytest.mark.parametrize("request_timeout", [8, 7.999])
def test_runtime_requires_strict_database_and_response_margin_before_io_deadline(
    tmp_path, request_timeout
) -> None:
    document = _document(tmp_path)
    # 2s connect + 5s statement + 1s response/commit margin must be < I/O timeout.
    document["uds"]["request_io_timeout_seconds"] = request_timeout

    with pytest.raises(EffectFinalizerRuntimeError, match="timeouts"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_guard_installation_id", "NOT-A-UUID"),
        ("expected_guard_installation_id", "22222222-2222-4222-8222-222222222222 "),
        ("expected_database_oid", 0),
        ("expected_database_oid", True),
        ("expected_database_oid", "16384"),
    ],
)
def test_runtime_rejects_invalid_pinned_finalization_identity(
    tmp_path, field, value
) -> None:
    document = _document(tmp_path)
    document[field] = value

    with pytest.raises(EffectFinalizerRuntimeError, match="identity"):
        load_effect_finalizer_runtime_config(
            _write(tmp_path, document), require_root_owner=False
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("socket_path", "run/finalizer.sock"),
        ("socket_mode", 0o666),
        ("finalizer_service_uid", 0),
        ("finalizer_service_gid", 0),
        ("finalizer_systemd_unit", "not-a-service"),
        ("finalization_identity", "untrusted"),
        ("handoff_idle_timeout_seconds", 89),
        ("request_io_timeout_seconds", 31),
        ("max_response_bytes", 100),
    ],
)
def test_secret_free_client_runtime_is_strict_when_built_independently(
    tmp_path, field, value
) -> None:
    document = _document(tmp_path)
    client_runtime = load_effect_finalizer_runtime_config(
        _write(tmp_path, document), require_root_owner=False
    ).client_runtime

    with pytest.raises(EffectFinalizerRuntimeError, match="client runtime|invalid"):
        replace(client_runtime, **{field: value})
