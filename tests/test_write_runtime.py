from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.write_runtime import (
    WRITE_CONFIG_FIELDS,
    WriteRuntimeError,
    load_write_runtime_config,
    load_write_runtime_secrets,
)


SHA256 = re.compile(r"^[0-9a-f]{64}$")
WRITE_ROLES = (
    "write_auth",
    "approval",
    "execution",
    "verification",
    "recovery",
    "write_receipt",
)


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o640)


def _make_runtime(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    secrets_dir = tmp_path / "secrets"
    state_dir = tmp_path / "write-state"
    secrets_dir.mkdir()
    state_dir.mkdir()
    if os.name == "posix":
        secrets_dir.chmod(0o750)
        state_dir.chmod(0o700)

    secret_values = {
        "base_auth": b"base-auth-secret-material-000000000001",
        "base_receipt": b"base-receipt-secret-material-00000002",
        "write_auth": b"write-auth-secret-material-0000000001",
        "approval": b"approval-secret-material-000000000002",
        "execution": b"execution-secret-material-00000000001",
        "verification": b"verification-secret-material-0000001",
        "recovery": b"recovery-secret-material-000000000002",
        "write_receipt": b"write-receipt-secret-material-000001",
    }
    secret_paths: dict[str, Path] = {}
    for name, value in secret_values.items():
        path = secrets_dir / f"{name}.hmac"
        path.write_bytes(value)
        if os.name == "posix":
            path.chmod(0o640)
        secret_paths[name] = path

    base_config_path = tmp_path / "read-runtime.json"
    base_document: dict[str, object] = {
        "instance_id": "odoo19@sandbox",
        "environment": "sandbox",
        "capability_channel": "staged",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
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
    _write_json(base_config_path, base_document)

    role_documents: dict[str, dict[str, object]] = {}
    for role in WRITE_ROLES:
        role_documents[role] = {
            "key_id": f"{role.replace('_', '-')}-v1",
            "secret_path": str(secret_paths[role]),
        }
    role_documents["execution"]["issuer"] = "odoo-write-executor"
    role_documents["verification"]["issuer"] = "odoo-write-verifier"
    role_documents["recovery"]["issuer"] = "odoo-write-recovery"

    write_document: dict[str, object] = {
        "schema_version": 1,
        "write_execution_mode": "sandbox_staged",
        "base_runtime_config_path": str(base_config_path),
        "write_state_path": str(state_dir / "write.sqlite3"),
        **role_documents,
    }
    write_config_path = tmp_path / "write-runtime.json"
    _write_json(write_config_path, write_document)
    return write_config_path, write_document, base_document


def _reload(path: Path, document: dict[str, object]) -> None:
    _write_json(path, document)


def test_valid_runtime_is_exact_fixed_and_does_not_leak_secrets(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)

    runtime = load_write_runtime_config(path, require_root_owner=False)
    secrets = load_write_runtime_secrets(runtime)

    assert WRITE_CONFIG_FIELDS == frozenset(document)
    assert runtime.schema_version == 1
    assert runtime.write_execution_mode == "sandbox_staged"
    assert runtime.base_runtime_config_path == Path(document["base_runtime_config_path"])
    assert runtime.write_state_path == Path(document["write_state_path"])
    assert runtime.base_runtime.runtime_identity == {
        "instance_id": base["instance_id"],
        "environment": base["environment"],
        "capability_channel": base["capability_channel"],
        "database_name": base["database_name"],
        "database_uuid": base["database_uuid"],
    }
    assert runtime.execution.issuer == "odoo-write-executor"
    assert runtime.verification.issuer == "odoo-write-verifier"
    assert runtime.recovery.issuer == "odoo-write-recovery"
    assert runtime.write_auth.issuer is None
    assert runtime.approval.issuer is None
    assert runtime.write_receipt.issuer is None
    assert secrets.write_auth == Path(
        document["write_auth"]["secret_path"]  # type: ignore[index]
    ).read_bytes()

    identity = runtime.runtime_identity
    assert set(identity) == {
        "instance_id",
        "environment",
        "capability_channel",
        "database_name",
        "database_uuid",
        "write_execution_mode",
        "write_runtime_schema_version",
        "write_runtime_config_sha256",
    }
    assert identity["write_runtime_config_sha256"] == runtime.config_fingerprint
    assert SHA256.fullmatch(runtime.config_fingerprint)

    rendered = repr(runtime) + repr(secrets) + json.dumps(identity, sort_keys=True)
    for role in WRITE_ROLES:
        secret = Path(document[role]["secret_path"]).read_bytes()  # type: ignore[index]
        assert secret.decode("ascii") not in rendered
    assert "secret_path" not in json.dumps(identity)


@pytest.mark.parametrize("field", tuple(sorted(WRITE_CONFIG_FIELDS)))
def test_top_level_fields_are_exact(tmp_path: Path, field: str) -> None:
    path, document, _ = _make_runtime(tmp_path)
    document.pop(field)
    _reload(path, document)

    with pytest.raises(WriteRuntimeError, match="fields are invalid"):
        load_write_runtime_config(path, require_root_owner=False)


def test_extra_and_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    _reload(path, {**document, "runtime_config_path_from_pi": "/tmp/attacker.json"})
    with pytest.raises(WriteRuntimeError, match="fields are invalid"):
        load_write_runtime_config(path, require_root_owner=False)

    raw = json.dumps(document, sort_keys=True)
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
    with pytest.raises(WriteRuntimeError, match="duplicate JSON key"):
        load_write_runtime_config(path, require_root_owner=False)


@pytest.mark.parametrize("value", [None, True, 1, "sandbox", "production"])
def test_write_execution_mode_is_closed_enum(tmp_path: Path, value: object) -> None:
    path, document, _ = _make_runtime(tmp_path)
    document["write_execution_mode"] = value
    _reload(path, document)

    with pytest.raises(WriteRuntimeError, match="write_execution_mode"):
        load_write_runtime_config(path, require_root_owner=False)


@pytest.mark.parametrize(
    ("mode", "channel"),
    [("disabled", "staged"), ("sandbox_staged", "staged"), ("enabled", "enabled")],
)
def test_each_write_execution_mode_is_accepted(
    tmp_path: Path, mode: str, channel: str
) -> None:
    path, document, base = _make_runtime(tmp_path)
    document["write_execution_mode"] = mode
    base["capability_channel"] = channel
    _write_json(Path(document["base_runtime_config_path"]), base)
    _reload(path, document)

    assert (
        load_write_runtime_config(path, require_root_owner=False).write_execution_mode
        == mode
    )


def test_write_mode_must_match_base_environment_and_capability_channel(
    tmp_path: Path,
) -> None:
    path, document, base = _make_runtime(tmp_path)
    base_path = Path(document["base_runtime_config_path"])

    base["environment"] = "test"
    _write_json(base_path, base)
    with pytest.raises(WriteRuntimeError, match="staged sandbox"):
        load_write_runtime_config(path, require_root_owner=False)

    path, document, base = _make_runtime(tmp_path / "enabled")
    document["write_execution_mode"] = "enabled"
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="enabled base runtime channel"):
        load_write_runtime_config(path, require_root_owner=False)


@pytest.mark.parametrize("role", WRITE_ROLES)
def test_each_role_has_exact_fields(tmp_path: Path, role: str) -> None:
    path, document, _ = _make_runtime(tmp_path)
    role_document = document[role]
    assert isinstance(role_document, dict)
    role_document["unexpected"] = "not-allowed"
    _reload(path, document)

    with pytest.raises(WriteRuntimeError, match=f"{role} fields are invalid"):
        load_write_runtime_config(path, require_root_owner=False)


def test_issuer_roles_require_distinct_nonempty_issuers(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    document["execution"]["issuer"] = document["verification"]["issuer"]  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="issuers must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)

    path, document, _ = _make_runtime(tmp_path / "second")
    document["execution"]["issuer"] = ""  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="execution.issuer"):
        load_write_runtime_config(path, require_root_owner=False)


def test_key_ids_are_distinct_across_write_and_base_read_roles(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)
    document["approval"]["key_id"] = document["write_auth"]["key_id"]  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="key IDs must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)

    path, document, _ = _make_runtime(tmp_path / "second")
    document["approval"]["key_id"] = base["auth_key_id"]  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="key IDs must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_secret_paths_are_distinct_across_write_and_base_read_roles(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)
    document["approval"]["secret_path"] = document["write_auth"]["secret_path"]  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="secret paths must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)

    path, document, second_base = _make_runtime(tmp_path / "second")
    document["approval"]["secret_path"] = second_base["auth_secret_path"]  # type: ignore[index]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="secret paths must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_secret_inodes_are_distinct_even_when_paths_differ(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    source = Path(document["write_auth"]["secret_path"])  # type: ignore[index]
    target = Path(document["approval"]["secret_path"])  # type: ignore[index]
    target.unlink()
    try:
        os.link(source, target)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(WriteRuntimeError, match="secret inodes must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_write_secret_inode_must_not_reuse_a_base_read_secret(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)
    source = Path(base["auth_secret_path"])
    target = Path(document["approval"]["secret_path"])  # type: ignore[index]
    target.unlink()
    try:
        os.link(source, target)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(WriteRuntimeError, match="secret inodes must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_secret_bytes_are_distinct_even_when_files_differ(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    source = Path(document["write_auth"]["secret_path"])  # type: ignore[index]
    target = Path(document["approval"]["secret_path"])  # type: ignore[index]
    target.write_bytes(source.read_bytes())
    if os.name == "posix":
        target.chmod(0o640)

    with pytest.raises(WriteRuntimeError, match="secret bytes must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_write_secret_bytes_must_not_reuse_a_base_read_secret(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)
    source = Path(base["receipt_secret_path"])
    target = Path(document["recovery"]["secret_path"])  # type: ignore[index]
    target.write_bytes(source.read_bytes())
    if os.name == "posix":
        target.chmod(0o640)

    with pytest.raises(WriteRuntimeError, match="secret bytes must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_secret_loader_revalidates_material_after_configuration_load(
    tmp_path: Path,
) -> None:
    path, document, _ = _make_runtime(tmp_path)
    runtime = load_write_runtime_config(path, require_root_owner=False)
    source = Path(document["write_auth"]["secret_path"])  # type: ignore[index]
    target = Path(document["write_receipt"]["secret_path"])  # type: ignore[index]
    target.write_bytes(source.read_bytes())
    if os.name == "posix":
        target.chmod(0o640)

    with pytest.raises(WriteRuntimeError, match="secret bytes must be distinct"):
        load_write_runtime_secrets(runtime)


def test_all_secrets_are_at_least_32_bytes(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    target = Path(document["recovery"]["secret_path"])  # type: ignore[index]
    target.write_bytes(b"too-short")
    if os.name == "posix":
        target.chmod(0o640)

    with pytest.raises(WriteRuntimeError, match="at least 32 bytes"):
        load_write_runtime_config(path, require_root_owner=False)


def test_fixed_paths_are_absolute_and_write_state_is_read_state_independent(
    tmp_path: Path,
) -> None:
    path, document, base = _make_runtime(tmp_path)
    document["base_runtime_config_path"] = "read-runtime.json"
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="base_runtime_config_path.*absolute"):
        load_write_runtime_config(path, require_root_owner=False)

    path, document, second_base = _make_runtime(tmp_path / "second")
    document["write_state_path"] = second_base["auth_state_path"]
    _reload(path, document)
    with pytest.raises(WriteRuntimeError, match="write state path must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_existing_write_state_inode_cannot_reuse_read_state(tmp_path: Path) -> None:
    path, document, base = _make_runtime(tmp_path)
    read_state = Path(base["auth_state_path"])
    write_state = Path(document["write_state_path"])
    read_state.write_bytes(b"")
    try:
        os.link(read_state, write_state)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    if os.name == "posix":
        read_state.chmod(0o600)

    with pytest.raises(WriteRuntimeError, match="write state inode must be distinct"):
        load_write_runtime_config(path, require_root_owner=False)


def test_config_and_secret_symlinks_are_rejected(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    config_link = tmp_path / "write-runtime-link.json"
    try:
        config_link.symlink_to(path)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(WriteRuntimeError, match="regular non-symlink"):
        load_write_runtime_config(config_link, require_root_owner=False)

    target = Path(document["approval"]["secret_path"])  # type: ignore[index]
    real = target.with_suffix(".real")
    target.rename(real)
    target.symlink_to(real)
    with pytest.raises(WriteRuntimeError, match="regular non-symlink"):
        load_write_runtime_config(path, require_root_owner=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_posix_modes_remain_enforced_when_root_owner_check_is_disabled(
    tmp_path: Path,
) -> None:
    path, document, _ = _make_runtime(tmp_path)
    secret = Path(document["approval"]["secret_path"])  # type: ignore[index]
    secret.chmod(0o660)
    with pytest.raises(WriteRuntimeError, match="POSIX mode"):
        load_write_runtime_config(path, require_root_owner=False)

    secret.chmod(0o640)
    state_parent = Path(document["write_state_path"]).parent
    state_parent.chmod(0o750)
    with pytest.raises(WriteRuntimeError, match="parent directory must be private"):
        load_write_runtime_config(path, require_root_owner=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_posix_secret_parent_cannot_be_group_writable(tmp_path: Path) -> None:
    path, document, _ = _make_runtime(tmp_path)
    secret_parent = Path(document["approval"]["secret_path"]).parent  # type: ignore[index]
    secret_parent.chmod(0o770)

    with pytest.raises(WriteRuntimeError, match="must not be group/world writable"):
        load_write_runtime_config(path, require_root_owner=False)


def test_configuration_fingerprint_binds_base_runtime_without_secret_material(
    tmp_path: Path,
) -> None:
    path, document, base = _make_runtime(tmp_path)
    first = load_write_runtime_config(path, require_root_owner=False)

    base_path = Path(document["base_runtime_config_path"])
    changed = copy.deepcopy(base)
    changed["database_uuid"] = "22222222-2222-4222-8222-222222222222"
    _write_json(base_path, changed)
    second = load_write_runtime_config(path, require_root_owner=False)

    assert first.config_fingerprint != second.config_fingerprint
    for role in WRITE_ROLES:
        secret = Path(document[role]["secret_path"]).read_bytes()  # type: ignore[index]
        assert secret.decode("ascii") not in first.config_fingerprint
        assert secret.decode("ascii") not in second.config_fingerprint
