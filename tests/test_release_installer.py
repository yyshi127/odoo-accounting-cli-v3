from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = PROJECT_ROOT / "deployment" / "install-release.py"


def _load_installer():
    name = "odoo_v3_release_installer_contract"
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


def _manifest(files: dict[str, bytes], version: str, commit: str) -> dict:
    document = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            for name, payload in sorted(files.items())
        ],
    }
    document["manifest_sha256"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return document


def _fixture_files(
    *,
    verifier_payload: bytes | None = None,
    broker_payload: bytes | None = None,
) -> dict[str, bytes]:
    return {
        "VERSION": b"1.2.3.dev4\n",
        "bin/odoo-accounting-cli-v3": b"#!/bin/sh\nexit 0\n",
        "bin/odoo-accounting-cli-v3-broker": broker_payload
        if broker_payload is not None
        else (
            b"#!/bin/sh\nprintf '%s\\n' "
            b"'usage: odoo-accounting-cli-v3-broker --config ABSOLUTE_PATH'\n"
        ),
        "deployment/install-release.py": INSTALLER_PATH.read_bytes(),
        "deployment/dev9/run-private-mount-gate.sh": b"#!/bin/sh\nexit 70\n",
        "src/odoo_accounting_cli_v3/__init__.py": (
            PROJECT_ROOT / "src/odoo_accounting_cli_v3/__init__.py"
        ).read_bytes(),
        "src/odoo_accounting_cli_v3/release.py": (
            PROJECT_ROOT / "src/odoo_accounting_cli_v3/release.py"
        ).read_bytes(),
        "tools/verify_release.py": verifier_payload
        if verifier_payload is not None
        else (PROJECT_ROOT / "tools/verify_release.py").read_bytes(),
    }


def _build_archive(
    installer,
    directory: Path,
    *,
    verifier_payload: bytes | None = None,
    broker_payload: bytes | None = None,
    mutate_member=None,
    extra_members: tuple[tarfile.TarInfo, ...] = (),
):
    version = "1.2.3.dev4"
    commit = "a" * 40
    release = f"{version}-{commit[:12]}"
    files = _fixture_files(
        verifier_payload=verifier_payload,
        broker_payload=broker_payload,
    )
    manifest = _manifest(files, version, commit)
    manifest_payload = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    archive_path = directory / f"odoo-accounting-cli-v3-{release}.tar.gz"
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(
                mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT
            ) as archive:
                for name, payload in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    info.mode = 0o755 if name in installer.EXECUTABLE_MEMBERS else 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    if mutate_member is not None:
                        mutate_member(info)
                    archive.addfile(info, io.BytesIO(payload))
                info = tarfile.TarInfo("RELEASE-MANIFEST.json")
                info.size = len(manifest_payload)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(manifest_payload))
                for extra in extra_members:
                    archive.addfile(extra, io.BytesIO(b"x" * extra.size))
    archive_path.chmod(0o600)
    expected = installer.ExpectedIdentity(
        version=version,
        commit=commit,
        release=release,
        package_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        manifest_sha256=manifest["manifest_sha256"],
    )
    return archive_path.resolve(), expected


def _linux_non_root() -> bool:
    return sys.platform == "linux" and os.geteuid() != 0


def _linux_root() -> bool:
    return sys.platform == "linux" and os.geteuid() == 0


def test_expected_release_is_bound_to_version_and_full_commit(installer):
    identity = installer.ExpectedIdentity(
        version="1.2.3",
        commit="a" * 40,
        release="1.2.3-" + "b" * 12,
        package_sha256="c" * 64,
        manifest_sha256="d" * 64,
    )
    with pytest.raises(installer.InstallError, match="release must equal"):
        identity.validate()


def test_archive_filename_is_bound_before_any_installation(installer):
    identity = installer.ExpectedIdentity(
        version="1.2.3",
        commit="a" * 40,
        release="1.2.3-" + "a" * 12,
        package_sha256="c" * 64,
        manifest_sha256="d" * 64,
    )
    with pytest.raises(installer.InstallError, match="filename"):
        installer.install(Path("/tmp/wrong-name.tar.gz"), identity)


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX installer metadata contract")
def test_running_installer_must_match_the_target_manifest(installer, tmp_path):
    metadata = INSTALLER_PATH.stat()
    plan = installer.ArchivePlan(
        manifest={
            "files": [
                {
                    "path": "deployment/install-release.py",
                    "sha256": "0" * 64,
                    "size": metadata.st_size,
                }
            ]
        },
        members=(),
    )
    layout = installer.InstallLayout(
        tmp_path, metadata.st_uid, metadata.st_gid, True
    )
    with pytest.raises(installer.InstallError, match="target release manifest"):
        installer._validate_running_installer(plan, layout)


def test_installer_and_runbook_fix_the_side_load_only_boundary(installer):
    source = INSTALLER_PATH.read_text("utf-8")
    deployment = (PROJECT_ROOT / "docs/DEPLOYMENT.md").read_text("utf-8")
    assert 'Path("/opt/odoo-accounting-cli-v3")' in source
    assert "systemctl" not in source
    assert "--expected-package-sha256" in source
    assert "--expected-manifest-sha256" in source
    assert "--expected-version" in source
    assert "--expected-commit" in source
    assert "--expected-release" in source
    assert "deployment/install-release.py" in deployment
    assert "does not create or\nchange `current`" in deployment


def test_json_and_manifest_schema_are_strict(installer):
    with pytest.raises(installer.InstallError, match="non-finite"):
        installer._load_json(b'{"value":NaN}', label="test")
    expected = installer.ExpectedIdentity(
        version="1.2.3",
        commit="a" * 40,
        release="1.2.3-" + "a" * 12,
        package_sha256="b" * 64,
        manifest_sha256="c" * 64,
    )
    with pytest.raises(installer.InstallError, match="schema"):
        installer._validate_manifest(
            {
                "schema_version": True,
                "version": expected.version,
                "commit": expected.commit,
                "files": [],
                "manifest_sha256": expected.manifest_sha256,
            },
            expected,
        )


def test_root_prefix_is_available_only_in_explicit_test_mode(
    installer, monkeypatch, tmp_path
):
    monkeypatch.setattr(installer.sys, "platform", "linux")
    with pytest.raises(installer.InstallError, match="forbidden"):
        installer._layout(test_mode=False, root_prefix=tmp_path)
    with pytest.raises(installer.InstallError, match="requires an absolute"):
        installer._layout(test_mode=True, root_prefix=None)
    child = tmp_path / "child"
    child.mkdir()
    with pytest.raises(installer.InstallError, match="canonical physical path"):
        installer._layout(test_mode=True, root_prefix=child / "..")
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(installer.os, "getegid", lambda: 0, raising=False)
    with pytest.raises(installer.InstallError, match="non-root identity"):
        installer._layout(test_mode=True, root_prefix=tmp_path.resolve())


@pytest.mark.skipif(not _linux_root(), reason="real production privilege-drop contract")
def test_production_candidate_runner_drops_to_nobody(installer, tmp_path):
    import pwd

    nobody = pwd.getpwnam("nobody")
    layout = installer.InstallLayout(tmp_path, 0, 0, False)
    installer._run_candidate_command(
        ["/usr/bin/id", "-u"],
        root=tmp_path,
        layout=layout,
        expected_stdout=f"{nobody.pw_uid}\n".encode(),
        label="production identity probe",
    )


@pytest.mark.parametrize("mutation", ("owner", "mode", "symlink"))
def test_archive_member_owner_mode_and_type_fail_closed(
    installer, tmp_path, mutation
):
    def mutate(info: tarfile.TarInfo) -> None:
        if info.name != "bin/odoo-accounting-cli-v3":
            return
        if mutation == "owner":
            info.uid = 1000
        elif mutation == "mode":
            info.mode = 0o775
        else:
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            info.size = 0

    archive, expected = _build_archive(
        installer, tmp_path, mutate_member=mutate
    )
    with pytest.raises(installer.InstallError):
        installer.inspect_archive(archive, expected)


def test_archive_traversal_and_external_manifest_mismatch_are_rejected(
    installer, tmp_path
):
    extra = tarfile.TarInfo("../escape")
    extra.size = 1
    extra.mode = 0o644
    extra.uid = extra.gid = 0
    extra.uname = extra.gname = "root"
    archive, expected = _build_archive(
        installer, tmp_path, extra_members=(extra,)
    )
    with pytest.raises(installer.InstallError, match="unsafe archive path"):
        installer.inspect_archive(archive, expected)

    clean_directory = tmp_path / "clean"
    clean_directory.mkdir()
    clean, clean_expected = _build_archive(installer, clean_directory)
    wrong = installer.ExpectedIdentity(
        version=clean_expected.version,
        commit=clean_expected.commit,
        release=clean_expected.release,
        package_sha256=clean_expected.package_sha256,
        manifest_sha256="0" * 64,
    )
    with pytest.raises(installer.InstallError, match="external identity"):
        installer.inspect_archive(clean, wrong)


def test_archive_duplicate_member_is_rejected(installer, tmp_path):
    duplicate = tarfile.TarInfo("VERSION")
    duplicate.size = 1
    duplicate.mode = 0o644
    duplicate.uid = duplicate.gid = 0
    duplicate.uname = duplicate.gname = "root"
    archive, expected = _build_archive(
        installer, tmp_path, extra_members=(duplicate,)
    )
    with pytest.raises(installer.InstallError, match="duplicate archive member"):
        installer.inspect_archive(archive, expected)


def test_oversized_member_is_rejected_before_tar_scans_its_payload(
    installer, monkeypatch
):
    oversized = tarfile.TarInfo("oversized.bin")
    oversized.size = installer.MAX_RELEASE_FILE_BYTES + 1
    oversized.mode = 0o644
    oversized.uid = oversized.gid = 0
    oversized.uname = oversized.gname = "root"

    class HeaderOnlyArchive:
        calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def next(self):
            self.calls += 1
            if self.calls == 1:
                return oversized
            raise AssertionError("installer scanned beyond an oversized member header")

    archive = HeaderOnlyArchive()
    monkeypatch.setattr(installer.tarfile, "open", lambda *_args, **_kwargs: archive)
    expected = installer.ExpectedIdentity(
        version="1.2.3",
        commit="a" * 40,
        release="1.2.3-" + "a" * 12,
        package_sha256="b" * 64,
        manifest_sha256="c" * 64,
    )

    with pytest.raises(installer.InstallError, match="file size limit exceeded"):
        installer.inspect_archive(Path("unused.tar.gz"), expected)
    assert archive.calls == 1


def test_archive_expansion_and_filesystem_allocation_are_bounded(
    installer, monkeypatch, tmp_path
):
    archive, expected = _build_archive(installer, tmp_path)
    monkeypatch.setattr(installer, "MAX_RELEASE_TREE_ENTRIES", 1)
    with pytest.raises(installer.InstallError, match="too many filesystem entries"):
        installer.inspect_archive(archive, expected)

    regular = tarfile.TarInfo("nested/payload.bin")
    regular.size = 4097
    directory = tarfile.TarInfo("nested")
    directory.type = tarfile.DIRTYPE
    directory.size = 0
    plan = installer.ArchivePlan(manifest={}, members=(regular, directory))
    monkeypatch.setattr(
        installer.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_frsize=4096, f_bsize=4096),
        raising=False,
    )

    assert installer._release_allocation_budget(plan, tmp_path) == 24_576


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_side_load_is_immutable_exact_and_idempotent(installer, tmp_path):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(installer, tmp_path)

    first = installer.install(
        archive, expected, test_mode=True, root_prefix=tmp_path
    )
    second = installer.install(
        archive, expected, test_mode=True, root_prefix=tmp_path
    )

    assert first["already_installed"] is False
    assert second["already_installed"] is True
    root = tmp_path / "opt/odoo-accounting-cli-v3"
    package = root / "packages" / expected.package_name
    release = root / "releases" / expected.release
    anchor = root / "trusted-artifacts" / f"{expected.release}.json"
    assert hashlib.sha256(package.read_bytes()).hexdigest() == expected.package_sha256
    assert json.loads(anchor.read_text("utf-8")) == expected.anchor
    for path in [release, *release.rglob("*")]:
        metadata = path.lstat()
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_gid == os.getegid()
        if path.is_dir():
            assert stat.S_IMODE(metadata.st_mode) == 0o555
        else:
            relative = path.relative_to(release).as_posix()
            expected_mode = (
                0o555 if relative in installer.EXECUTABLE_MEMBERS else 0o444
            )
            assert stat.S_IMODE(metadata.st_mode) == expected_mode
            assert metadata.st_nlink == 1
    assert stat.S_IMODE(package.stat().st_mode) == 0o444
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o444
    assert package.stat().st_nlink == anchor.stat().st_nlink == 1
    assert not os.path.lexists(root / "current")
    assert not (tmp_path / "etc").exists()
    assert not (tmp_path / "var").exists()


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_failure_cleans_only_own_staging_and_keeps_foreign_evidence(
    installer, tmp_path
):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(installer, tmp_path)
    layout = installer._layout(test_mode=True, root_prefix=tmp_path)
    installer._prepare_layout(layout)
    foreign = layout.releases / ".install-foreign.staging"
    foreign.mkdir(mode=0o700)
    marker = foreign / "evidence"
    marker.write_text("keep", encoding="utf-8")
    wrong = installer.ExpectedIdentity(
        version=expected.version,
        commit=expected.commit,
        release=expected.release,
        package_sha256="0" * 64,
        manifest_sha256=expected.manifest_sha256,
    )

    with pytest.raises(installer.InstallError, match="SHA-256"):
        installer.install(archive, wrong, test_mode=True, root_prefix=tmp_path)

    assert marker.read_text("utf-8") == "keep"
    for parent in (layout.packages, layout.releases, layout.anchors):
        remaining = list(parent.glob(".install-*"))
        assert remaining == ([foreign] if parent == layout.releases else [])
    assert not (layout.packages / expected.package_name).exists()
    assert not (layout.releases / expected.release).exists()
    assert not (layout.anchors / f"{expected.release}.json").exists()


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_partial_or_changed_existing_release_is_rejected_without_repair(
    installer, tmp_path
):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(installer, tmp_path)
    installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)
    root = tmp_path / "opt/odoo-accounting-cli-v3"
    package = root / "packages" / expected.package_name
    release = root / "releases" / expected.release
    anchor = root / "trusted-artifacts" / f"{expected.release}.json"
    package_digest = hashlib.sha256(package.read_bytes()).hexdigest()
    release_inode = release.stat().st_ino
    anchor.unlink()

    with pytest.raises(installer.InstallError, match="partial existing release"):
        installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)

    assert hashlib.sha256(package.read_bytes()).hexdigest() == package_digest
    assert release.stat().st_ino == release_inode
    assert not anchor.exists()

    anchor.write_text(
        json.dumps(expected.anchor, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    anchor.chmod(0o444)
    package.chmod(0o640)
    with pytest.raises(installer.InstallError, match="metadata mismatch"):
        installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)
    assert stat.S_IMODE(package.stat().st_mode) == 0o640


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_candidate_verifier_cannot_write_to_sealed_release(installer, tmp_path):
    tmp_path.chmod(0o700)
    verifier = b"""from pathlib import Path
import sys
Path(sys.argv[1], 'verifier-mutation').write_text('bad', encoding='utf-8')
raise SystemExit(1)
"""
    archive, expected = _build_archive(
        installer, tmp_path, verifier_payload=verifier
    )

    with pytest.raises(installer.InstallError, match="verify_release rejected"):
        installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)

    root = tmp_path / "opt/odoo-accounting-cli-v3"
    assert not (root / "packages" / expected.package_name).exists()
    assert not (root / "releases" / expected.release).exists()
    assert not (root / "trusted-artifacts" / f"{expected.release}.json").exists()
    for parent in (root / "packages", root / "releases", root / "trusted-artifacts"):
        assert not list(parent.glob(".install-*"))


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_broken_broker_launcher_is_rejected_before_publication(installer, tmp_path):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(
        installer,
        tmp_path,
        broker_payload=b"#!/bin/sh\nexit 0\n",
    )

    with pytest.raises(installer.InstallError, match="frozen broker launcher"):
        installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)

    root = tmp_path / "opt/odoo-accounting-cli-v3"
    assert not (root / "packages" / expected.package_name).exists()
    assert not (root / "releases" / expected.release).exists()
    assert not (root / "trusted-artifacts" / f"{expected.release}.json").exists()


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_candidate_timeout_kills_the_process_group_and_cleans_staging(
    installer, tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(
        installer,
        tmp_path,
        verifier_payload=b"import time\ntime.sleep(10)\n",
    )
    monkeypatch.setattr(installer, "CHILD_TIMEOUT_SECONDS", 0.1)

    with pytest.raises(installer.InstallError, match="execution deadline"):
        installer.install(archive, expected, test_mode=True, root_prefix=tmp_path)

    root = tmp_path / "opt/odoo-accounting-cli-v3"
    for parent in (root / "packages", root / "releases", root / "trusted-artifacts"):
        assert not list(parent.glob(".install-*"))


@pytest.mark.skipif(not _linux_non_root(), reason="real non-root Linux install contract")
def test_concurrent_installers_serialize_to_one_install_and_one_exact_retry(
    installer, tmp_path
):
    tmp_path.chmod(0o700)
    archive, expected = _build_archive(installer, tmp_path)
    command = [
        sys.executable,
        str(INSTALLER_PATH),
        "--test-mode",
        "--root-prefix",
        str(tmp_path),
        "--archive",
        str(archive),
        "--expected-package-sha256",
        expected.package_sha256,
        "--expected-manifest-sha256",
        expected.manifest_sha256,
        "--expected-version",
        expected.version,
        "--expected-commit",
        expected.commit,
        "--expected-release",
        expected.release,
    ]
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    results = [process.communicate(timeout=30) for process in processes]
    assert [process.returncode for process in processes] == [0, 0]
    assert [stderr for _stdout, stderr in results] == ["", ""]
    documents = [json.loads(stdout) for stdout, _stderr in results]
    assert sorted(document["already_installed"] for document in documents) == [
        False,
        True,
    ]
