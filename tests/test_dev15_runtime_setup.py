from __future__ import annotations

import errno
import importlib.util
import hashlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "deployment" / "dev15" / "runtime_setup.py"
SPEC = importlib.util.spec_from_file_location("dev15_runtime_setup", SCRIPT)
assert SPEC and SPEC.loader
runtime_setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime_setup
SPEC.loader.exec_module(runtime_setup)


def _write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _prepare_runtime_inputs(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    layout = runtime_setup.build_layout(root)
    layout.release_root.mkdir(parents=True)
    member = b"sealed release member\n"
    member_path = layout.release_root / "payload.txt"
    member_path.write_bytes(member)
    unsigned = {
        "schema_version": 1,
        "version": runtime_setup.VERSION,
        "commit": runtime_setup.COMMIT,
        "files": [
            {"path": "payload.txt", "sha256": _sha256(member), "size": len(member)}
        ],
    }
    manifest_sha256 = _sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    manifest = {**unsigned, "manifest_sha256": manifest_sha256}
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    package = b"canonical dev15 package"
    odoo_python = b"python"
    odoo_bin = b"odoo-bin"
    odoo_config = b"[options]\n"
    _write(layout.package, package)
    _write(layout.odoo_python, odoo_python)
    _write(layout.odoo_bin, odoo_bin)
    _write(layout.odoo_config, odoo_config)
    monkeypatch.setattr(runtime_setup, "MANIFEST_SHA256", manifest_sha256)
    monkeypatch.setattr(
        runtime_setup,
        "RELEASE_MANIFEST_RAW_SHA256",
        _sha256(manifest_path.read_bytes()),
    )
    monkeypatch.setattr(runtime_setup, "PACKAGE_SHA256", _sha256(package))
    monkeypatch.setattr(runtime_setup, "ODOO_PYTHON_SHA256", _sha256(odoo_python))
    monkeypatch.setattr(runtime_setup, "ODOO_BIN_SHA256", _sha256(odoo_bin))
    monkeypatch.setattr(runtime_setup, "ODOO_CONFIG_SHA256", _sha256(odoo_config))
    layout.trusted_artifact_parent.mkdir(parents=True, exist_ok=True)
    layout.trusted_artifact.write_text(
        json.dumps(
            {
                "commit": runtime_setup.COMMIT,
                "manifest_sha256": manifest_sha256,
                "package_sha256": _sha256(package),
                "release": runtime_setup.RELEASE_ID,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    if os.name == "posix":
        member_path.chmod(0o444)
        manifest_path.chmod(0o444)
        layout.package.chmod(0o444)
        layout.release_root.chmod(0o555)
        layout.trusted_artifact_parent.chmod(0o755)
        layout.trusted_artifact.chmod(0o444)


def _replace_sealed(path: Path, payload: bytes, *, sealed_mode: int = 0o444) -> None:
    if os.name == "posix":
        path.chmod(0o644)
    path.write_bytes(payload)
    if os.name == "posix":
        path.chmod(sealed_mode)


@pytest.fixture
def private_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    _prepare_runtime_inputs(tmp_path, monkeypatch)
    return tmp_path


def test_production_release_manifest_raw_digest_is_fixed() -> None:
    assert runtime_setup.RELEASE_MANIFEST_RAW_SHA256 == (
        "21b220ab3bea012201d3d8d06b3f12c4841c08d5a37afd416889729f47d8e3d6"
    )


def test_setup_publishes_exact_isolated_twenty_field_runtime(private_root: Path) -> None:
    result = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    layout = runtime_setup.build_layout(private_root)
    document = json.loads(result.config_path.read_text(encoding="utf-8"))

    assert len(document) == 20
    assert set(document) == runtime_setup.CONFIG_FIELDS
    assert document["environment"] == "test"
    assert document["capability_channel"] == "staged"
    assert document["database_name"] == "odoo_test"
    assert document["database_uuid"] == runtime_setup.DATABASE_UUID
    assert document["release_root"].endswith(runtime_setup.RELEASE_ID)
    assert document["auth_key_id"] != document["receipt_key_id"]
    assert Path(document["auth_state_path"]).parent == layout.auth_state_parent
    assert Path(document["receipt_state_path"]).parent == layout.receipt_state_parent
    assert layout.auth_state_parent != layout.receipt_state_parent
    assert "odoo-accounting-cli-v3/test/candidates" not in document["auth_state_path"]
    assert "odoo-accounting-cli-v3-dev15-candidates" in document["auth_state_path"]
    assert layout.auth_secret.read_bytes() != layout.receipt_secret.read_bytes()
    assert len(layout.auth_secret.read_bytes()) == 32
    assert len(layout.receipt_secret.read_bytes()) == 32
    assert layout.auth_secret.stat().st_nlink == 1
    assert layout.receipt_secret.stat().st_nlink == 1
    assert layout.config.stat().st_nlink == 1
    assert list(layout.child_home.iterdir()) == []
    assert not (private_root / "opt/odoo-accounting-cli-v3/current").exists()
    assert not (private_root / "etc/systemd").exists()
    assert not (
        private_root / "etc/odoo-accounting-cli-v3/runtime-test-dev8.json"
    ).exists()
    output = result.public_record()
    rendered = json.dumps(output)
    assert "auth.hmac" not in rendered and "receipt.hmac" not in rendered
    assert layout.auth_secret.read_bytes().hex() not in rendered


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_first_setup_rejects_noncanonical_existing_config_parent(
    private_root: Path,
) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.config_parent.mkdir(parents=True)
    layout.config_parent.chmod(0o750)

    with pytest.raises(runtime_setup.RuntimeSetupError, match="mode drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)

    assert not layout.config.exists()
    assert not layout.secret_root.exists()
    assert not layout.state_root.exists()


def test_release_member_tamper_is_rejected(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    _replace_sealed(layout.release_root / "payload.txt", b"tampered release member\n")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="release member mismatch"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_missing_trusted_artifact_anchor_is_rejected(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.trusted_artifact.unlink()
    with pytest.raises(runtime_setup.RuntimeSetupError, match="trusted artifact anchor"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "package_sha256": "0" * 64},
        lambda value: {**value, "unexpected": "field"},
    ],
)
def test_tampered_trusted_artifact_anchor_is_rejected(
    private_root: Path, mutation
) -> None:
    layout = runtime_setup.build_layout(private_root)
    document = json.loads(layout.trusted_artifact.read_text(encoding="utf-8"))
    _replace_sealed(
        layout.trusted_artifact,
        json.dumps(mutation(document), sort_keys=True).encode("utf-8"),
    )
    with pytest.raises(runtime_setup.RuntimeSetupError, match="not exact Dev15"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_trusted_artifact_anchor_hard_link_is_rejected(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    alias = layout.trusted_artifact.with_suffix(".alias")
    os.link(layout.trusted_artifact, alias)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="single-link"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_trusted_artifact_metadata_drift_is_rejected(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.trusted_artifact.chmod(0o644)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="metadata drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_trusted_artifact_parent_metadata_drift_is_rejected(
    private_root: Path,
) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.trusted_artifact_parent.chmod(0o775)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="mode drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_self_rehashed_forged_manifest_is_rejected_by_external_digest(
    private_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = runtime_setup.build_layout(private_root)
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["size"] += 1
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = _sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    _replace_sealed(manifest_path, json.dumps(manifest, sort_keys=True).encode("utf-8"))
    monkeypatch.setattr(
        runtime_setup,
        "RELEASE_MANIFEST_RAW_SHA256",
        _sha256(manifest_path.read_bytes()),
    )
    with pytest.raises(runtime_setup.RuntimeSetupError, match="not exact Dev15"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_manifest_unsigned_digest_is_recomputed(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["size"] += 1
    _replace_sealed(manifest_path, json.dumps(manifest, sort_keys=True).encode("utf-8"))
    monkeypatch.setattr(
        runtime_setup,
        "RELEASE_MANIFEST_RAW_SHA256",
        _sha256(manifest_path.read_bytes()),
    )
    with pytest.raises(runtime_setup.RuntimeSetupError, match="unsigned digest mismatch"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_release_manifest_raw_byte_drift_is_rejected(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _replace_sealed(
        manifest_path,
        json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
    )

    with pytest.raises(
        runtime_setup.RuntimeSetupError, match="manifest raw SHA-256 mismatch"
    ):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


@pytest.mark.parametrize(
    ("attribute", "label"),
    [
        ("odoo_python", "odoo_python"),
        ("odoo_bin", "odoo_bin"),
        ("odoo_config", "odoo_config"),
    ],
)
def test_odoo_dependency_digest_drift_is_rejected(
    private_root: Path, attribute: str, label: str
) -> None:
    layout = runtime_setup.build_layout(private_root)
    _replace_sealed(getattr(layout, attribute), b"drift")
    with pytest.raises(runtime_setup.RuntimeSetupError, match=rf"{label} digest drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_binary_secrets_preserve_trailing_newline_and_nul_exactly(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = bytes(range(31)) + b"\x0a"
    receipt = bytes(range(1, 32)) + b"\x00"
    monkeypatch.setattr(runtime_setup, "_new_secret_pair", lambda: (auth, receipt))

    first = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    layout = runtime_setup.build_layout(private_root)
    assert layout.auth_secret.read_bytes() == auth
    assert layout.receipt_secret.read_bytes() == receipt
    assert layout.auth_secret.stat().st_size == 32
    assert layout.receipt_secret.stat().st_size == 32

    # The idempotent path re-opens both files through the stable descriptor gate.
    second = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    assert first.config_path == second.config_path
    assert second.already_exists is True

    with layout.auth_secret.open("ab") as stream:
        stream.write(b"\x00")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="secret has drifted"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_matching_setup_is_idempotent_but_drift_is_rejected(private_root: Path) -> None:
    first = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    second = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    assert first.config_path == second.config_path
    assert second.already_exists is True

    document = json.loads(first.config_path.read_text(encoding="utf-8"))
    document["database_name"] = "other"
    first.config_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_existing_config_hard_link_and_secret_symlink_are_rejected(
    private_root: Path,
) -> None:
    result = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    layout = runtime_setup.build_layout(private_root)
    alias = result.config_path.with_suffix(".alias")
    os.link(result.config_path, alias)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="link-count drift"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    alias.unlink()

    original = layout.auth_secret.read_bytes()
    layout.auth_secret.unlink()
    target = layout.secret_root / "outside-auth"
    target.write_bytes(original)
    try:
        layout.auth_secret.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not permitted")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="unsafe regular file"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)


def test_symlink_and_unsafe_parent_are_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not permitted")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="unsafe directory"):
        runtime_setup.setup_candidate_runtime(root=linked, test_mode=True)


def test_existing_partial_candidate_is_never_overwritten(private_root: Path) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.secret_root.mkdir(parents=True)
    sentinel = layout.secret_root / "operator-file"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(runtime_setup.RuntimeSetupError, match="partial candidate"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not layout.config.exists()
    assert not layout.state_root.exists()


def test_empty_existing_child_home_is_accepted_but_content_is_not(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    layout.child_home.mkdir(parents=True, mode=0o700)
    if os.name == "posix":
        layout.child_home.chmod(0o700)
    runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)

    # A fresh candidate root with a non-empty fixed HOME must fail closed.
    other = private_root.parent / "other-private-root"
    other.mkdir(mode=0o700)
    if os.name == "posix":
        other.chmod(0o700)
    _prepare_runtime_inputs(other, monkeypatch)
    other_layout = runtime_setup.build_layout(other)
    other_layout.child_home.mkdir(parents=True, mode=0o700)
    if os.name == "posix":
        other_layout.child_home.chmod(0o700)
    (other_layout.child_home / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="not empty"):
        runtime_setup.setup_candidate_runtime(root=other, test_mode=True)


def test_config_is_published_last_and_failure_cleans_only_transaction_objects(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    original = runtime_setup._publish_file

    def fail_config(path, payload, **kwargs):
        if path == layout.config:
            raise runtime_setup.RuntimeSetupError("injected config failure")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(runtime_setup, "_publish_file", fail_config)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="injected"):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    assert not layout.config.exists()
    assert not layout.secret_root.exists()
    assert not layout.state_root.exists()
    assert not layout.child_home.exists()
    assert layout.release_root.exists()
    assert layout.package.exists()


def test_staging_unlink_failure_cannot_report_runtime_success(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    original_unlink = Path.unlink

    def fail_staging_unlink(path: Path, *args, **kwargs) -> None:
        if path.name.endswith(".staging"):
            raise OSError("injected staging unlink failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_staging_unlink)
    with pytest.raises(
        runtime_setup.RuntimeSetupError, match="cannot be removed durably"
    ):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)

    assert not layout.config.exists()
    assert not layout.auth_secret.exists()
    stages = list(layout.secret_root.glob(".*.staging"))
    assert len(stages) == 1
    assert stages[0].stat().st_nlink == 1


def test_staging_directory_fsync_failure_cannot_report_runtime_success(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    original_fsync = runtime_setup._fsync_directory
    secret_root_calls = 0

    def fail_cleanup_fsync(path: Path) -> None:
        nonlocal secret_root_calls
        if path == layout.secret_root:
            secret_root_calls += 1
            if secret_root_calls == 2:
                raise OSError("injected staging directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(runtime_setup, "_fsync_directory", fail_cleanup_fsync)
    with pytest.raises(
        runtime_setup.RuntimeSetupError, match="cannot be removed durably"
    ):
        runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)

    assert secret_root_calls >= 3
    assert not layout.config.exists()
    assert not layout.secret_root.exists()
    assert not layout.state_root.exists()


def test_flock_timeout_is_finite_and_deterministic() -> None:
    now = [10.0]
    attempts = []
    pauses = []

    def busy(descriptor: int) -> None:
        attempts.append(descriptor)
        raise BlockingIOError(errno.EAGAIN, "busy")

    def pause(seconds: float) -> None:
        pauses.append(seconds)
        now[0] += seconds

    with pytest.raises(runtime_setup.RuntimeSetupError, match="timed out"):
        runtime_setup._acquire_posix_flock(
            37,
            timeout_seconds=0.12,
            poll_seconds=0.05,
            acquire=busy,
            monotonic=lambda: now[0],
            sleep=pause,
        )
    assert attempts == [37, 37, 37, 37]
    assert pauses == pytest.approx([0.05, 0.05, 0.02])
    assert now[0] == pytest.approx(10.12)


def test_runtime_is_rechecked_after_lock_wait(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = runtime_setup.build_layout(private_root)
    expected = runtime_setup.SetupResult(
        layout.config, layout.child_home, already_exists=True
    )
    checks = iter((None, expected))
    monkeypatch.setattr(
        runtime_setup,
        "_existing_runtime",
        lambda *args, **kwargs: next(checks),
    )
    monkeypatch.setattr(
        runtime_setup,
        "_open_runtime_lock",
        lambda *args, **kwargs: (37, False, (1, 2)),
    )
    monkeypatch.setattr(
        runtime_setup,
        "_close_runtime_lock",
        lambda *args, **kwargs: None,
    )

    result = runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)

    assert result is expected


@pytest.mark.skipif(os.name != "posix", reason="real POSIX descriptor contract")
def test_lock_descriptor_is_closed_when_acquisition_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "candidate.lock"
    observed = []

    def timeout(descriptor: int) -> None:
        observed.append(descriptor)
        raise runtime_setup.RuntimeSetupError("timed out waiting for lock")

    monkeypatch.setattr(runtime_setup, "_acquire_posix_flock", timeout)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="timed out"):
        runtime_setup._open_runtime_lock(lock, test_mode=True)

    assert len(observed) == 1
    with pytest.raises(OSError):
        os.fstat(observed[0])


@pytest.mark.skipif(os.name != "posix", reason="real POSIX flock concurrency")
def test_two_concurrent_setups_converge_on_one_runtime(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime_setup, "RUNTIME_LOCK_TIMEOUT_SECONDS", 5.0)
    layout = runtime_setup.build_layout(private_root)
    original_open_lock = runtime_setup._open_runtime_lock
    original_publish = runtime_setup._publish_file
    call_guard = threading.Lock()
    lock_calls = 0
    first_has_lock = threading.Event()
    second_attempted_lock = threading.Event()

    def tracked_open_lock(*args, **kwargs):
        nonlocal lock_calls
        with call_guard:
            lock_calls += 1
            number = lock_calls
        if number == 2:
            second_attempted_lock.set()
        result = original_open_lock(*args, **kwargs)
        if number == 1:
            first_has_lock.set()
        return result

    def coordinated_publish(path, payload, **kwargs):
        if path == layout.config:
            assert second_attempted_lock.wait(timeout=5)
        return original_publish(path, payload, **kwargs)

    monkeypatch.setattr(runtime_setup, "_open_runtime_lock", tracked_open_lock)
    monkeypatch.setattr(runtime_setup, "_publish_file", coordinated_publish)
    results = []
    failures = []

    def run_setup() -> None:
        try:
            results.append(
                runtime_setup.setup_candidate_runtime(
                    root=private_root, test_mode=True
                )
            )
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=run_setup)
    first.start()
    assert first_has_lock.wait(timeout=5)
    second = threading.Thread(target=run_setup)
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)

    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert len(results) == 2
    assert sorted(result.already_exists for result in results) == [False, True]
    assert len(list(layout.secret_root.iterdir())) == 2
    assert layout.config.exists()


def test_mkdir_identity_swap_does_not_remove_preexisting_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "root-owned-parent"
    parent.mkdir()
    target = parent / "candidate"
    sentinel = parent / "sentinel"
    sentinel.mkdir()
    sentinel_identity = runtime_setup._identity(sentinel)
    stolen = parent / "stolen-created-object"
    original = runtime_setup._set_metadata

    def swap_before_metadata(path, **kwargs):
        if path == target:
            path.rename(stolen)
            sentinel.rename(path)
        return original(path, **kwargs)

    monkeypatch.setattr(runtime_setup, "_set_metadata", swap_before_metadata)
    transaction = runtime_setup._Transaction()
    with pytest.raises(runtime_setup.RuntimeSetupError, match="identity changed"):
        runtime_setup._mkdir_exact(
            target,
            uid=0,
            gid=0,
            mode=0o700,
            test_mode=True,
            transaction=transaction,
        )
    transaction.rollback()
    assert target.exists()
    assert runtime_setup._identity(target) == sentinel_identity
    if stolen.exists():
        stolen.rmdir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_state_container_is_not_service_writable(private_root: Path) -> None:
    runtime_setup.setup_candidate_runtime(root=private_root, test_mode=True)
    layout = runtime_setup.build_layout(private_root)
    assert layout.state_root.stat().st_mode & 0o777 == 0o710
    assert layout.state_root.parent.stat().st_mode & 0o022 == 0
    assert layout.auth_state_parent.stat().st_mode & 0o777 == 0o700
    assert layout.receipt_state_parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX root gate")
def test_production_mode_requires_effective_root(monkeypatch: pytest.MonkeyPatch) -> None:
    layout = runtime_setup.build_layout(Path("/"))
    assert layout.config == Path(
        "/etc/odoo-accounting-cli-v3/candidates/runtime-test-dev15-c4616386f921.json"
    )
    assert layout.child_home == Path("/var/lib/odoo-accounting-cli-v3-broker")
    assert layout.release_root == Path(
        "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev15-c4616386f921"
    )
    assert layout.trusted_artifact == Path(
        "/opt/odoo-accounting-cli-v3/trusted-artifacts/"
        "0.1.0.dev15-c4616386f921.json"
    )
    monkeypatch.setattr(runtime_setup.os, "geteuid", lambda: 1000)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="must run as root"):
        runtime_setup._service_identity(False)
