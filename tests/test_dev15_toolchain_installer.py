from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = PROJECT_ROOT / "deployment" / "dev15" / "install_toolchain.py"


def _load_installer():
    name = "odoo_v3_dev15_toolchain_installer_contract"
    spec = importlib.util.spec_from_file_location(name, INSTALLER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture(scope="module")
def installer():
    return _load_installer()


def _source_fixture(
    installer,
    root: Path,
    *,
    readme: bytes = b"Dev15 exact read toolchain fixture.\n",
) -> Path:
    source = root / "upload"
    source.mkdir(parents=True, mode=0o700)
    payloads = {
        "README.md": readme,
        "check_toolchain.py": b"#!/usr/bin/env python3\nprint('checked')\n",
        "install_toolchain.py": INSTALLER_PATH.read_bytes(),
        "runtime_setup.py": b"#!/usr/bin/env python3\nprint('runtime')\n",
        "sign_read.py": b"#!/usr/bin/env python3\nprint('sign')\n",
        "run_multicurrency_read.py": b"#!/usr/bin/env python3\nprint('read')\n",
        "multicurrency_sql_oracle.py": b"#!/usr/bin/env python3\nprint('oracle')\n",
        "verify_evidence.py": b"#!/usr/bin/env python3\nprint('verify')\n",
        "read_plan.json": b'{"schema_version":1}\n',
    }
    assert set(payloads) == installer.EXPECTED_FILES - {installer.MANIFEST_NAME}
    manifest = {
        "application": installer.APPLICATION,
        "control_files": [
            {
                "name": name,
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "size": len(payloads[name]),
            }
            for name in installer.CONTROL_FILES
        ],
        "files": [
            {
                "name": name,
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "size": len(payloads[name]),
            }
            for name in installer.MANIFEST_FILES
        ],
        "schema_version": 2,
        "toolchain_version": installer.TOOLCHAIN_VERSION,
    }
    payloads[installer.MANIFEST_NAME] = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    for name, payload in payloads.items():
        path = source / name
        path.write_bytes(payload)
        path.chmod(0o444)
    source.chmod(0o700)
    return source


def _manifest_sha256(installer, source: Path) -> str:
    return hashlib.sha256((source / installer.MANIFEST_NAME).read_bytes()).hexdigest()


def _target(installer, install_root: Path) -> Path:
    return install_root / installer.TARGET_RELATIVE


def _stages(installer, install_root: Path) -> list[Path]:
    parent = install_root / "toolchains"
    if not parent.exists():
        return []
    return sorted(parent.glob(".install-toolchain-*"))


def test_installs_exact_immutable_tree_and_is_idempotent(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"

    manifest_sha256 = _manifest_sha256(installer, source)
    first = installer._install_for_test(source, install_root, manifest_sha256)
    second = installer._install_for_test(source, install_root, manifest_sha256)

    assert first["already_installed"] is False
    assert second["already_installed"] is True
    assert first["toolchain_version"] == installer.TOOLCHAIN_VERSION
    assert first["toolchain_manifest_sha256"] == manifest_sha256
    target = _target(installer, install_root)
    target_metadata = target.lstat()
    if os.name == "posix":
        assert stat.S_IMODE(target_metadata.st_mode) == 0o555
    assert {item.name for item in target.iterdir()} == installer.EXPECTED_FILES
    for path in target.iterdir():
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert metadata.st_nlink == 1
        assert stat.S_IMODE(metadata.st_mode) == 0o444
        assert metadata.st_uid == target_metadata.st_uid
        assert metadata.st_gid == target_metadata.st_gid
    assert _stages(installer, install_root) == []


def test_rejects_payload_tampering(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    manifest_sha256 = _manifest_sha256(installer, source)
    path = source / "runtime_setup.py"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"# tampered\n")
    path.chmod(0o444)

    with pytest.raises(installer.ToolchainInstallError, match="mismatch"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_manifest_identity_tampering(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    path = source / installer.MANIFEST_NAME
    document = json.loads(path.read_text("utf-8"))
    document["toolchain_version"] = "0.1.0.dev15-read-toolchain.tampered"
    path.chmod(0o600)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)
    manifest_sha256 = _manifest_sha256(installer, source)

    with pytest.raises(installer.ToolchainInstallError, match="version mismatch"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_manifest_control_file_order_drift(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    path = source / installer.MANIFEST_NAME
    document = json.loads(path.read_text("utf-8"))
    document["control_files"].reverse()
    path.chmod(0o600)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)
    manifest_sha256 = _manifest_sha256(installer, source)

    with pytest.raises(installer.ToolchainInstallError, match="control_files order"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_manifest_not_matching_independently_approved_raw_sha256(
    installer, tmp_path: Path
):
    approved_source = _source_fixture(installer, tmp_path / "approved")
    approved_sha256 = _manifest_sha256(installer, approved_source)
    different_source = _source_fixture(
        installer,
        tmp_path / "different",
        readme=b"Different README under the same toolchain version.\n",
    )

    with pytest.raises(
        installer.ToolchainInstallError, match="manifest raw SHA-256 mismatch"
    ):
        installer._install_for_test(
            different_source, tmp_path / "installed", approved_sha256
        )


def test_manifest_binds_readme_control_file(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    approved_sha256 = _manifest_sha256(installer, source)
    readme = source / "README.md"
    readme.chmod(0o600)
    payload = readme.read_bytes()
    readme.write_bytes(b"X" + payload[1:])
    readme.chmod(0o444)

    with pytest.raises(
        installer.ToolchainInstallError, match="file SHA-256 mismatch: README.md"
    ):
        installer._install_for_test(
            source, tmp_path / "installed", approved_sha256
        )


def test_same_version_different_approved_manifest_cannot_replace_target(
    installer, tmp_path: Path
):
    original = _source_fixture(installer, tmp_path / "original")
    different = _source_fixture(
        installer,
        tmp_path / "different",
        readme=b"Different independently hashed README.\n",
    )
    original_sha256 = _manifest_sha256(installer, original)
    different_sha256 = _manifest_sha256(installer, different)
    assert original_sha256 != different_sha256
    install_root = tmp_path / "installed"
    installer._install_for_test(original, install_root, original_sha256)

    with pytest.raises(installer.ToolchainInstallError, match="content mismatch"):
        installer._install_for_test(different, install_root, different_sha256)

    assert (
        _target(installer, install_root) / "TOOLCHAIN-MANIFEST.json"
    ).read_bytes() == (original / "TOOLCHAIN-MANIFEST.json").read_bytes()


def test_idempotence_rejects_installed_content_drift(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)
    installer._install_for_test(source, install_root, manifest_sha256)
    installed = _target(installer, install_root) / "runtime_setup.py"
    installed.chmod(0o600)
    payload = installed.read_bytes()
    installed.write_bytes(b"X" + payload[1:])
    installed.chmod(0o444)

    with pytest.raises(installer.ToolchainInstallError, match="content mismatch"):
        installer._install_for_test(source, install_root, manifest_sha256)


def test_rejects_symlinked_source_member(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    manifest_sha256 = _manifest_sha256(installer, source)
    member = source / "runtime_setup.py"
    member.chmod(0o600)
    member.unlink()
    try:
        member.symlink_to(source / "sign_read.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable to this test user")

    with pytest.raises(installer.ToolchainInstallError, match="not regular"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_hardlinked_source_member(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    manifest_sha256 = _manifest_sha256(installer, source)
    original = source / "runtime_setup.py"
    extra_link = tmp_path / "second-link"
    try:
        os.link(original, extra_link)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    with pytest.raises(installer.ToolchainInstallError, match="one link"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_rejects_source_member_not_exactly_mode_0444(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    manifest_sha256 = _manifest_sha256(installer, source)
    member = source / "runtime_setup.py"
    member.chmod(0o400)

    with pytest.raises(installer.ToolchainInstallError, match="file mode mismatch"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_unexpected_source_member(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    manifest_sha256 = _manifest_sha256(installer, source)
    extra = source / "unreviewed.py"
    extra.write_bytes(b"print('unexpected')\n")
    extra.chmod(0o444)

    with pytest.raises(installer.ToolchainInstallError, match="unexpected.*file set"):
        installer._install_for_test(source, tmp_path / "installed", manifest_sha256)


def test_rejects_partial_existing_target_without_overwrite(installer, tmp_path: Path):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)
    toolchains = install_root / "toolchains"
    toolchains.mkdir(parents=True, mode=0o700)
    target = _target(installer, install_root)
    target.mkdir(mode=0o700)
    sentinel = target / "do-not-delete"
    sentinel.write_bytes(b"existing\n")
    sentinel.chmod(0o444)
    target.chmod(0o555)

    with pytest.raises(installer.ToolchainInstallError, match="partial"):
        installer._install_for_test(source, install_root, manifest_sha256)

    assert sentinel.read_bytes() == b"existing\n"
    assert _stages(installer, install_root) == []


def test_failure_removes_only_the_invocation_owned_stage(
    installer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)

    def fail_publication(stage: Path, target: Path, *, test_mode: bool) -> bool:
        assert test_mode is True
        displaced = stage.with_name(stage.name + "-owned-displaced")
        stage.rename(displaced)
        stage.mkdir(mode=0o700)
        sentinel = stage / "foreign-sentinel"
        sentinel.write_bytes(b"foreign inode\n")
        raise installer.ToolchainInstallError("injected publication failure")

    monkeypatch.setattr(installer, "_publish_noreplace", fail_publication)
    with pytest.raises(installer.ToolchainInstallError, match="injected"):
        installer._install_for_test(source, install_root, manifest_sha256)

    toolchains = install_root / "toolchains"
    foreign = next(
        path
        for path in toolchains.glob(".install-toolchain-*")
        if not path.name.endswith("-owned-displaced")
    )
    assert (foreign / "foreign-sentinel").read_bytes() == b"foreign inode\n"
    displaced = next(toolchains.glob(".install-toolchain-*-owned-displaced"))
    assert {path.name for path in displaced.iterdir()} == installer.EXPECTED_FILES


def test_normal_publication_failure_rolls_back_owned_stage(
    installer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)
    fsynced: list[Path] = []
    original_fsync = installer._fsync_directory

    def record_fsync(path: Path, *, test_mode: bool) -> None:
        fsynced.append(path)
        original_fsync(path, test_mode=test_mode)

    def fail_publication(stage: Path, target: Path, *, test_mode: bool) -> bool:
        raise installer.ToolchainInstallError("injected normal failure")

    monkeypatch.setattr(installer, "_fsync_directory", record_fsync)
    monkeypatch.setattr(installer, "_publish_noreplace", fail_publication)
    with pytest.raises(installer.ToolchainInstallError, match="normal failure"):
        installer._install_for_test(source, install_root, manifest_sha256)

    assert _stages(installer, install_root) == []
    assert not _target(installer, install_root).exists()
    assert fsynced[-1] == install_root / "toolchains"


def test_losing_publication_fsyncs_owned_stage_cleanup(
    installer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = _source_fixture(installer, tmp_path)
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)
    fsynced: list[Path] = []
    original_fsync = installer._fsync_directory

    def record_fsync(path: Path, *, test_mode: bool) -> None:
        fsynced.append(path)
        original_fsync(path, test_mode=test_mode)

    def publish_competing_target(
        stage: Path, target: Path, *, test_mode: bool
    ) -> bool:
        assert test_mode is True
        target.mkdir(mode=0o700)
        for source_file in stage.iterdir():
            target_file = target / source_file.name
            target_file.write_bytes(source_file.read_bytes())
            target_file.chmod(0o444)
        target.chmod(0o555)
        return False

    monkeypatch.setattr(installer, "_fsync_directory", record_fsync)
    monkeypatch.setattr(
        installer, "_publish_noreplace", publish_competing_target
    )
    result = installer._install_for_test(source, install_root, manifest_sha256)

    assert result["already_installed"] is True
    assert _stages(installer, install_root) == []
    assert fsynced[-1] == install_root / "toolchains"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_production_layout_requires_canonical_0755_application_root(
    installer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tmp_path.chmod(0o755)
    install_root = tmp_path / "odoo-accounting-cli-v3"
    layout = installer._Layout(
        install_root, os.getuid(), os.getgid(), False
    )
    monkeypatch.setattr(installer, "_set_owner", lambda path, layout: None)

    try:
        installer._ensure_layout(layout)
        assert stat.S_IMODE(install_root.stat().st_mode) == 0o755
        install_root.chmod(0o555)
        with pytest.raises(
            installer.ToolchainInstallError,
            match="managed directory mode mismatch",
        ):
            installer._ensure_layout(layout)
    finally:
        if layout.toolchains.exists():
            layout.toolchains.chmod(0o755)
        if install_root.exists():
            install_root.chmod(0o755)


def test_install_fsyncs_created_layout_and_sealed_stage(
    installer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = _source_fixture(installer, tmp_path / "source")
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)
    fsynced: list[Path] = []

    def record_fsync(path: Path, *, test_mode: bool) -> None:
        assert test_mode is True
        fsynced.append(path)

    monkeypatch.setattr(installer, "_fsync_directory", record_fsync)
    installer._install_for_test(source, install_root, manifest_sha256)

    toolchains = install_root / "toolchains"
    stages = [path for path in fsynced if path.name.startswith(".install-toolchain-")]
    assert install_root.parent in fsynced
    assert fsynced.count(install_root) >= 2
    assert fsynced.count(toolchains) >= 2
    assert len(stages) == 2


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux renameat2 is required"
)
def test_production_rename_noreplace_never_overwrites(installer, tmp_path: Path):
    occupied_source = tmp_path / "occupied-source"
    occupied_target = tmp_path / "occupied-target"
    occupied_source.mkdir()
    occupied_target.mkdir()
    sentinel = occupied_target / "sentinel"
    sentinel.write_bytes(b"do not replace\n")

    assert (
        installer._publish_noreplace(
            occupied_source, occupied_target, test_mode=False
        )
        is False
    )
    assert occupied_source.is_dir()
    assert sentinel.read_bytes() == b"do not replace\n"

    fresh_source = tmp_path / "fresh-source"
    fresh_target = tmp_path / "fresh-target"
    fresh_source.mkdir()
    assert installer._publish_noreplace(fresh_source, fresh_target, test_mode=False)
    assert not fresh_source.exists()
    assert fresh_target.is_dir()


@pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="full production install requires Linux root",
)
def test_full_production_install_is_immutable_and_idempotent(
    installer, tmp_path: Path
):
    tmp_path.chmod(0o755)
    source = _source_fixture(installer, tmp_path / "source")
    install_root = tmp_path / "installed"
    manifest_sha256 = _manifest_sha256(installer, source)

    first = installer._install(
        source,
        install_root=install_root,
        owner_uid=0,
        owner_gid=0,
        test_mode=False,
        expected_manifest_sha256=manifest_sha256,
    )
    second = installer._install(
        source,
        install_root=install_root,
        owner_uid=0,
        owner_gid=0,
        test_mode=False,
        expected_manifest_sha256=manifest_sha256,
    )

    target = _target(installer, install_root)
    assert first["already_installed"] is False
    assert second["already_installed"] is True
    assert stat.S_IMODE(install_root.stat().st_mode) == 0o755
    assert stat.S_IMODE((install_root / "toolchains").stat().st_mode) == 0o555
    assert stat.S_IMODE(target.stat().st_mode) == 0o555
    assert _stages(installer, install_root) == []
    assert {path.name for path in target.iterdir()} == installer.EXPECTED_FILES
    for path in target.iterdir():
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o444
        assert metadata.st_uid == 0 and metadata.st_gid == 0
        assert metadata.st_nlink == 1


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux production gate is required"
)
def test_production_main_rejects_non_root(
    installer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(installer.os, "geteuid", lambda: 1000)

    with pytest.raises(SystemExit, match="must run as root"):
        installer.main([str(tmp_path), "0" * 64])
