from __future__ import annotations

import contextlib
import errno
import importlib.util
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "publish_read_evidence.py"
SPEC = importlib.util.spec_from_file_location("dev29_publish_read_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
publisher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publisher
SPEC.loader.exec_module(publisher)
TRACE_SCRIPT = ROOT / "deployment" / "dev29" / "runtime_open_trace.py"
TRACE_SPEC = importlib.util.spec_from_file_location(
    "dev29_publish_runtime_open_trace_contract", TRACE_SCRIPT
)
assert TRACE_SPEC is not None and TRACE_SPEC.loader is not None
runtime_trace = importlib.util.module_from_spec(TRACE_SPEC)
sys.modules[TRACE_SPEC.name] = runtime_trace
TRACE_SPEC.loader.exec_module(runtime_trace)
LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="publisher is a Linux-only production gate"
)
STAGE_FILES = {
    "validation-report.json",
    "cleanup-receipt.json",
    "verifier-child.json",
    "verifier-process-control.json",
    "verifier-runtime-trace.json",
    "prepublication-guard.json",
    "supervisor-bootstrap.json",
}
LDCONFIG_SHA256 = "a" * 64
RUNTIME_INDEX_SHA256 = "8" * 64
STRACE_SHA256 = "9" * 64


def _durable_anchor_document(
    *, evidence: Path, release_identity: dict[str, object], bundle_sha256: str
) -> dict[str, object]:
    publisher_script_execution = {
        "schema_version": 1,
        "method": "inherited-pinned-script-fd-v1",
        "path": "/opt/odoo-accounting-cli-v3/releases/release/deployment/dev29/publish_read_evidence.py",
        "sha256": "7" * 64,
        "size": 1,
        "device": 1,
        "inode": 2,
        "argv_fixed_fd_verified": True,
        "fd_closed_before_children": True,
        "all_checks_passed": True,
    }
    report = {
        "release_identity": release_identity,
        "bundle_manifest_sha256": bundle_sha256,
        "closure_verification": {"verified": True},
        "all_checks_passed": True,
        "production_promotion_allowed": False,
    }
    outer_unit = {
        "unit": "odoo-accounting-cli-v3-dev29-proof.service",
        "systemctl": {
            "path": str(publisher.SYSTEMCTL),
            "sha256": "6" * 64,
            "size": 1,
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        },
        "properties": {
            field: f"value-{field}" for field in publisher.SYSTEMD_UNIT_FIELDS
        },
        "proc": {
            "argv": ["publisher"],
            "argv_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(["publisher"])
            ).hexdigest(),
            "cgroup": "/system.slice/proof.service",
        },
        "wrapper": {"verified": True},
        "worker": {"verified": True},
        "launcher_lease": {"verified": True},
    }
    publication_unit = {
        "unit": outer_unit["unit"],
        "systemctl": outer_unit["systemctl"],
        "properties": outer_unit["properties"],
        "properties_sha256": publisher.hashlib.sha256(
            publisher.canonical_json(outer_unit["properties"])
        ).hexdigest(),
        "proc": outer_unit["proc"],
        "wrapper": outer_unit["wrapper"],
        "worker": outer_unit["worker"],
        "launcher_lease": outer_unit["launcher_lease"],
        "outer_unit": outer_unit,
        "outer_unit_sha256": publisher.hashlib.sha256(
            publisher.canonical_json(outer_unit)
        ).hexdigest(),
        "systemctl_execution": {"all_checks_passed": True},
        "all_checks_passed": True,
    }
    frozen = {
        "path": str(evidence),
        "bundle_manifest_sha256": bundle_sha256,
        "outer_unit": outer_unit,
        "runtime_open_trace_private": {"verified": True},
        "publication_outer_unit_reverification": publication_unit,
    }
    hashed_documents = {
        "validation_report": report,
        "cleanup_receipt": {"clean": True},
        "verifier_child": {"verified": True},
        "verifier_process_control": {"verified": True},
        "verifier_runtime_trace": {"verified": True},
        "prepublication_guard": {"verified": True},
        "supervisor_bootstrap": {
            "files": {"ldconfig": {"sha256": LDCONFIG_SHA256}}
        },
    }
    document: dict[str, object] = {
        "schema_version": 1,
        "anchor_type": "odoo-accounting-cli-v3.dev29.read-suite-verification",
        "bundle_path": str(evidence),
        "bundle_manifest_sha256": bundle_sha256,
        "release_identity": release_identity,
        "closure_identity": {"verified": True},
        **hashed_documents,
        "publisher_cgroup": {"verified": True},
        "final_publication": {
            "mode": "initial",
            "publisher_pid": 123,
            "publisher_cgroup": {"verified": True},
            "unit": outer_unit["unit"],
            "systemctl": publication_unit["systemctl"],
            "properties": publication_unit["properties"],
            "properties_sha256": publication_unit["properties_sha256"],
            "proc": publication_unit["proc"],
            "outer_unit": outer_unit,
            "outer_unit_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(outer_unit)
            ).hexdigest(),
            "systemctl_execution": publication_unit["systemctl_execution"],
            "publisher_script_execution": publisher_script_execution,
            "resumed_pending_sha256": None,
            "staging_documents_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(hashed_documents)
            ).hexdigest(),
            "all_checks_passed": True,
        },
        "frozen_evidence_identity": frozen,
        "verifier_runtime_trace_reverification": {
            "raw_trace_independently_reparsed_by_publisher": True,
            "production_promotion_allowed": False,
        },
        "cleanup_completed_before_anchor": True,
        "production_promotion_allowed": False,
    }
    for field, value in hashed_documents.items():
        document[f"{field}_sha256"] = publisher.hashlib.sha256(
            publisher.canonical_json(value)
        ).hexdigest()
    return document


def _portable_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        publisher,
        "_anchor_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )

    def rename_noreplace(source: Path, destination: Path) -> None:
        if destination.exists():
            raise FileExistsError(destination)
        os.replace(source, destination)

    monkeypatch.setattr(publisher, "_rename_noreplace", rename_noreplace)
    monkeypatch.setattr(publisher, "_fsync_directory", lambda _path: None)
    if sys.platform != "linux":
        monkeypatch.setattr(
            publisher,
            "_anchor_readonly_modes",
            lambda **_kwargs: frozenset({0o400, 0o444, 0o600, 0o666}),
        )
        monkeypatch.setattr(
            publisher,
            "stable_read",
            lambda path, **_kwargs: Path(path).read_bytes(),
        )
        monkeypatch.setattr(
            publisher,
            "_read_and_fsync_pending",
            lambda path, **_kwargs: Path(path).read_bytes(),
        )


def test_release_member_mode_policy_matches_the_builder_whitelist() -> None:
    expected = frozenset(
        {
            "bin/odoo-accounting-cli-v3",
            "bin/odoo-accounting-cli-v3-broker",
            "bin/odoo-accounting-cli-v3-effect-finalizer",
            "deployment/dev9/run-private-mount-gate.sh",
        }
    )
    assert publisher.EXECUTABLE_RELEASE_MEMBERS == expected
    assert all(
        publisher._expected_release_member_mode(name) == 0o555
        for name in expected
    )
    assert publisher._expected_release_member_mode("VERSION") == 0o444
    assert publisher._expected_release_member_mode(str(publisher.TRACE_RELATIVE)) == 0o444


@pytest.mark.parametrize("schema_version", [True, 1.0, "1"])
def test_publisher_script_execution_rejects_non_integer_schema_version(
    schema_version: object,
) -> None:
    proof = {
        "schema_version": schema_version,
        "method": "inherited-pinned-script-fd-v1",
        "path": "/sealed/publish_read_evidence.py",
        "sha256": "a" * 64,
        "size": 1,
        "device": 1,
        "inode": 1,
        "argv_fixed_fd_verified": True,
        "fd_closed_before_children": True,
        "all_checks_passed": True,
    }
    with pytest.raises(publisher.PublishError, match="execution proof is invalid"):
        publisher._validate_publisher_script_execution(proof)


def _disable_trace_reverification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        publisher,
        "_reverify_private_runtime_trace_sidecar",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(
        publisher,
        "_validate_verifier_runtime_trace",
        lambda *_args, **_kwargs: {"verified": True},
    )


@pytest.mark.parametrize("field", ["st_mode", "st_uid", "st_gid"])
def test_stable_read_rejects_security_metadata_drift_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    target = tmp_path / "sealed.json"
    target.write_bytes(b'{"sealed":true}\n')
    real_fstat = publisher.os.fstat
    calls = 0

    class DriftedStat:
        def __init__(self, original: os.stat_result) -> None:
            self._original = original

        def __getattr__(self, name: str) -> object:
            value = getattr(self._original, name)
            if name != field:
                return value
            if name == "st_mode":
                return value ^ 0o100
            return value + 1

    def fstat_spy(descriptor: int) -> os.stat_result | DriftedStat:
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        return DriftedStat(current) if calls == 2 else current

    monkeypatch.setattr(publisher.os, "fstat", fstat_spy)
    with pytest.raises(publisher.PublishError, match="changed during read"):
        publisher.stable_read(target, label="sealed test member")
    assert calls == 2


def test_sealed_policy_directory_rechecks_root_0555_and_exact_file_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "INDEX.json").write_bytes(b"{}\n")
    policy.chmod(0o555)
    safety_checks: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        publisher,
        "_safe_root_chain",
        lambda path, *, final_mode: safety_checks.append((path, final_mode)),
    )
    identity = publisher._sealed_directory_identity(
        policy,
        label="test policy directory",
        expected_mode=0o555,
        enforce_root=True,
        expected_names={"INDEX.json"},
    )
    metadata = policy.lstat()
    assert identity[0][3:6] == (
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
    )
    assert identity[1] == ("INDEX.json",)
    assert safety_checks == [(policy, 0o555), (policy, 0o555)]
    (policy / "unexpected.json").write_bytes(b"{}\n")
    with pytest.raises(publisher.PublishError, match="file set is not exact"):
        publisher._sealed_directory_identity(
            policy,
            label="test policy directory",
            expected_mode=0o555,
            enforce_root=True,
            expected_names={"INDEX.json"},
        )


def test_sealed_release_tree_identity_covers_nested_exact_files_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = tmp_path / "release"
    nested = release / "deployment" / "dev29"
    nested.mkdir(parents=True)
    (release / "RELEASE-MANIFEST.json").write_bytes(b"{}\n")
    runtime = nested / "runtime_open_trace.py"
    runtime.write_bytes(b"pass\n")
    for directory in (release, release / "deployment", nested):
        directory.chmod(0o555)
    for member in (release / "RELEASE-MANIFEST.json", runtime):
        member.chmod(0o444)
    safety_checks: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        publisher,
        "_safe_root_chain",
        lambda path, *, final_mode: safety_checks.append((path, final_mode)),
    )
    before = publisher._sealed_release_tree_identity(release, enforce_root=True)
    after = publisher._sealed_release_tree_identity(release, enforce_root=True)
    assert before == after
    assert {name for name, _identity in before[1]} == {
        "RELEASE-MANIFEST.json",
        "deployment/dev29/runtime_open_trace.py",
    }
    assert safety_checks.count((release, 0o555)) == 8
    assert safety_checks.count((release / "deployment", 0o555)) == 8
    assert safety_checks.count((nested, 0o555)) == 8
    runtime_metadata = runtime.stat()
    os.utime(
        runtime,
        ns=(runtime_metadata.st_atime_ns, runtime_metadata.st_mtime_ns + 1_000_000),
    )
    assert publisher._sealed_release_tree_identity(
        release, enforce_root=True
    ) != before


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires root-owned POSIX release metadata",
)
def test_sealed_release_tree_rejects_mode_drift_in_both_directions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = tmp_path / "release"
    bin_dir = release / "bin"
    bin_dir.mkdir(parents=True)
    manifest = release / "RELEASE-MANIFEST.json"
    version = release / "VERSION"
    launcher = bin_dir / "odoo-accounting-cli-v3"
    manifest.write_bytes(b"{}\n")
    version.write_bytes(b"0.1.0.dev29\n")
    launcher.write_bytes(b"#!/bin/sh\n")
    for directory in (release, bin_dir):
        directory.chmod(0o555)
    for member in (manifest, version):
        member.chmod(0o444)
    launcher.chmod(0o555)
    monkeypatch.setattr(
        publisher, "_safe_root_chain", lambda *_args, **_kwargs: None
    )

    publisher._sealed_release_tree_identity(release, enforce_root=True)

    version.chmod(0o555)
    with pytest.raises(publisher.PublishError, match="member is unsafe"):
        publisher._sealed_release_tree_identity(release, enforce_root=True)
    version.chmod(0o444)

    launcher.chmod(0o444)
    with pytest.raises(publisher.PublishError, match="member is unsafe"):
        publisher._sealed_release_tree_identity(release, enforce_root=True)


def test_release_manifest_parser_accepts_build_format_but_rejects_unsafe_json() -> None:
    document = {
        "schema_version": 1,
        "version": "0.1.0.dev29",
        "commit": "a" * 40,
        "files": [],
        "manifest_sha256": "b" * 64,
    }
    build_payload = (
        publisher.json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    assert publisher._parse_release_manifest_json(build_payload) == document
    for invalid in (
        b'{"files":[],"files":[]}\n',
        b'{"value":NaN}\n',
        b'{"value":Infinity}\n',
        b'\xff\n',
    ):
        with pytest.raises(publisher.PublishError):
            publisher._parse_release_manifest_json(invalid)


def test_atomic_publish_is_idempotent_and_conflict_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _portable_atomic(monkeypatch)
    anchor = tmp_path / "evidence.json"
    payload = b'{"ok":true}\n'
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    assert anchor.read_bytes() == payload
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    with pytest.raises(publisher.PublishError, match="conflicts"):
        publisher._atomic_publish_no_replace(
            anchor, b'{"ok":false}\n', enforce_root=False
        )
    assert anchor.read_bytes() == payload


@pytest.mark.parametrize("failure", ["zero", "enospc", "file_fsync"])
def test_precommit_failures_publish_no_final_and_remove_partial_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    _portable_atomic(monkeypatch)
    anchor = tmp_path / "evidence.json"
    payload = b"x" * 4096
    if failure == "zero":
        monkeypatch.setattr(publisher.os, "write", lambda *_args: 0)
        expected = publisher.PublishError
    elif failure == "enospc":
        real_write = publisher.os.write
        calls = 0

        def partial_then_full(_descriptor: int, value: memoryview) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(_descriptor, value[:17])
            raise OSError(errno.ENOSPC, "full")

        monkeypatch.setattr(publisher.os, "write", partial_then_full)
        expected = OSError
    else:
        real_fsync = publisher.os.fsync
        calls = 0

        def fail_first(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EIO, "fsync")
            real_fsync(descriptor)

        monkeypatch.setattr(publisher.os, "fsync", fail_first)
        expected = OSError
    with pytest.raises(expected):
        publisher._atomic_publish_no_replace(
            anchor, payload, enforce_root=False
        )
    assert not anchor.exists()
    assert not (tmp_path / ".evidence.json.pending").exists()


def test_valid_fixed_pending_is_recovered_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _portable_atomic(monkeypatch)
    anchor = tmp_path / "evidence.json"
    pending = tmp_path / ".evidence.json.pending"
    payload = b'{"recover":true}\n'
    pending.write_bytes(payload)
    pending.chmod(0o400)
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    assert anchor.read_bytes() == payload
    assert not pending.exists()


def test_incomplete_mode_0600_pending_is_discarded_before_clean_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _portable_atomic(monkeypatch)
    anchor = tmp_path / "evidence.json"
    pending = tmp_path / ".evidence.json.pending"
    payload = b'{"recover":"complete"}\n'
    pending.write_bytes(payload[:7])
    pending.chmod(0o600)
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    assert anchor.read_bytes() == payload
    assert not pending.exists()


def test_postcommit_directory_fsync_failure_keeps_complete_final_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _portable_atomic(monkeypatch)
    anchor = tmp_path / "evidence.json"
    payload = b'{"durable":"retry"}\n'
    real_sync = publisher._fsync_directory
    calls = 0

    def fail_after_commit(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(errno.EIO, "directory fsync")
        real_sync(path)

    monkeypatch.setattr(publisher, "_fsync_directory", fail_after_commit)
    with pytest.raises(OSError):
        publisher._atomic_publish_no_replace(
            anchor, payload, enforce_root=False
        )
    assert anchor.read_bytes() == payload
    monkeypatch.setattr(publisher, "_fsync_directory", real_sync)
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor


@pytest.mark.skipif(sys.platform != "linux", reason="requires fork, flock, and renameat2")
def test_sigkill_before_commit_leaves_recoverable_fixed_pending(tmp_path: Path) -> None:
    anchor = tmp_path / "evidence.json"
    payload = b'{"kill-window":"before"}\n'
    child = os.fork()
    if child == 0:
        publisher._rename_noreplace = lambda *_args: os.kill(os.getpid(), 9)
        publisher._atomic_publish_no_replace(anchor, payload, enforce_root=False)
        os._exit(99)
    _pid, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
    assert not anchor.exists()
    pending = tmp_path / ".evidence.json.pending"
    assert pending.read_bytes() == payload
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    assert not pending.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="requires fork, flock, and renameat2")
def test_sigkill_at_pending_file_fsync_recovers_by_fsyncing_same_inode_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = tmp_path / "evidence.json"
    pending = tmp_path / ".evidence.json.pending"
    payload = b'{"kill-window":"file-fsync"}\n'
    child = os.fork()
    if child == 0:
        real_fsync = publisher.os.fsync

        def kill_at_pending_fsync(descriptor: int) -> None:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if target == str(pending) and (os.fstat(descriptor).st_mode & 0o777) == 0o400:
                os.kill(os.getpid(), 9)
            real_fsync(descriptor)

        publisher.os.fsync = kill_at_pending_fsync
        publisher._atomic_publish_no_replace(anchor, payload, enforce_root=False)
        os._exit(99)
    _pid, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
    before = pending.stat()
    assert (before.st_mode & 0o777) == 0o400
    fsynced_pending_inodes: list[int] = []
    real_fsync = publisher.os.fsync

    def observe_recovery_fsync(descriptor: int) -> None:
        try:
            if os.readlink(f"/proc/self/fd/{descriptor}") == str(pending):
                fsynced_pending_inodes.append(os.fstat(descriptor).st_ino)
        except OSError:
            pass
        real_fsync(descriptor)

    monkeypatch.setattr(publisher.os, "fsync", observe_recovery_fsync)
    assert publisher._atomic_publish_no_replace(
        anchor, payload, enforce_root=False
    ) == anchor
    assert fsynced_pending_inodes == [before.st_ino]
    assert anchor.stat().st_ino == before.st_ino
    assert not pending.exists()


@pytest.mark.parametrize("remaining", [6, 5, 2, 0])
def test_durable_anchor_authorizes_idempotent_partial_stage_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remaining: int
) -> None:
    _disable_trace_reverification(monkeypatch)
    evidence = tmp_path / "evidence" / "proof"
    anchor = tmp_path / "proof.json"
    stage = tmp_path / "proof"
    stage.mkdir(mode=0o700)
    for name in sorted(STAGE_FILES)[:remaining]:
        member = stage / name
        member.write_text("{}\n", encoding="utf-8")
        member.chmod(0o600)
    expected = {
        "release": "0.1.0.dev29-a1234567890b",
        "version": "0.1.0.dev29",
        "commit": "a1234567890b1234567890b1234567890b123456",
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "registry_digest": "d" * 64,
        "verified": True,
    }
    bundle_sha256 = "e" * 64
    anchor.write_bytes(
        publisher.canonical_json(
            _durable_anchor_document(
                evidence=evidence,
                release_identity=expected,
                bundle_sha256=bundle_sha256,
            )
        )
        + b"\n"
    )
    anchor.chmod(0o400)
    monkeypatch.setattr(publisher, "STAGING_PARENT", tmp_path)
    monkeypatch.setattr(
        publisher, "stable_read", lambda path, **_kwargs: Path(path).read_bytes()
    )
    monkeypatch.setattr(publisher, "_fsync_directory", lambda _path: None)
    publisher._validate_existing_anchor_for_stage_cleanup(
        anchor,
        evidence=evidence,
        expected_release_identity=expected,
        expected_bundle_manifest_sha256=bundle_sha256,
        expected_ldconfig_sha256=LDCONFIG_SHA256,
        expected_runtime_open_index_sha256=RUNTIME_INDEX_SHA256,
        expected_strace_sha256=STRACE_SHA256,
    )
    publisher._remove_staging_dir(
        stage, expected_files=STAGE_FILES, allow_subset=True
    )
    assert not stage.exists()


def test_conflicting_durable_anchor_never_authorizes_stage_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_trace_reverification(monkeypatch)
    evidence = tmp_path / "evidence" / "proof"
    anchor = tmp_path / "proof.json"
    stage = tmp_path / "proof"
    stage.mkdir(mode=0o700)
    member = stage / "validation-report.json"
    member.write_text("{}\n", encoding="utf-8")
    member.chmod(0o600)
    expected = {
        "release": "0.1.0.dev29-a1234567890b",
        "version": "0.1.0.dev29",
        "commit": "a1234567890b1234567890b1234567890b123456",
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "registry_digest": "d" * 64,
        "verified": True,
    }
    anchor.write_bytes(
        publisher.canonical_json(
            _durable_anchor_document(
                evidence=evidence,
                release_identity=expected,
                bundle_sha256="e" * 64,
            )
        )
        + b"\n"
    )
    anchor.chmod(0o400)
    monkeypatch.setattr(
        publisher, "stable_read", lambda path, **_kwargs: Path(path).read_bytes()
    )
    monkeypatch.setattr(publisher, "_fsync_directory", lambda _path: None)
    with pytest.raises(publisher.PublishError, match="cannot authorize"):
        publisher._validate_existing_anchor_for_stage_cleanup(
            anchor,
            evidence=evidence,
            expected_release_identity=expected,
            expected_bundle_manifest_sha256="f" * 64,
            expected_ldconfig_sha256=LDCONFIG_SHA256,
            expected_runtime_open_index_sha256=RUNTIME_INDEX_SHA256,
            expected_strace_sha256=STRACE_SHA256,
        )
    assert stage.exists()
    assert member.exists()


def test_durable_anchor_rejects_external_ldconfig_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_trace_reverification(monkeypatch)
    evidence = tmp_path / "evidence" / "proof"
    anchor = tmp_path / "proof.json"
    expected = {
        "release": "0.1.0.dev29-a1234567890b",
        "version": "0.1.0.dev29",
        "commit": "a1234567890b1234567890b1234567890b123456",
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "registry_digest": "d" * 64,
        "verified": True,
    }
    anchor.write_bytes(
        publisher.canonical_json(
            _durable_anchor_document(
                evidence=evidence,
                release_identity=expected,
                bundle_sha256="e" * 64,
            )
        )
        + b"\n"
    )
    monkeypatch.setattr(
        publisher, "stable_read", lambda path, **_kwargs: Path(path).read_bytes()
    )
    with pytest.raises(publisher.PublishError, match="cannot authorize"):
        publisher._validate_existing_anchor_for_stage_cleanup(
            anchor,
            evidence=evidence,
            expected_release_identity=expected,
            expected_bundle_manifest_sha256="e" * 64,
            expected_ldconfig_sha256="f" * 64,
            expected_runtime_open_index_sha256=RUNTIME_INDEX_SHA256,
            expected_strace_sha256=STRACE_SHA256,
        )


def test_publisher_independently_requeries_and_binds_live_systemd_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    systemctl = {
        "path": str(publisher.SYSTEMCTL),
        "sha256": "a" * 64,
        "size": 123,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
    }
    execution = {
        "method": "open-fd-ptrace-exec-v1",
        "file": systemctl,
        "pinned_device": 1,
        "pinned_inode": 2,
        "proc_exe_device": 1,
        "proc_exe_inode": 2,
        "ptrace_exitkill_set": True,
        "ptrace_exec_stop_verified": True,
        "ptrace_detached_before_communicate": True,
        "parent_death_signal": "SIGKILL",
        "parent_identity_checked": True,
        "security_capability_absent": True,
        "child_reaped": True,
        "all_checks_passed": True,
    }
    properties = {field: f"value-{field}" for field in publisher.SYSTEMD_UNIT_FIELDS}
    wrapper_pid = 4321
    worker_pid = os.getpid()
    cgroup = "/system.slice/proof.service"
    properties["MainPID"] = str(wrapper_pid)
    properties["ControlGroup"] = cgroup
    properties["ReadOnlyPaths"] = str(publisher.LEASE_PARENT)
    worker_argv = ["worker"]
    wrapper_argv = ["wrapper"]
    proc = {
        "argv": worker_argv,
        "argv_sha256": publisher.hashlib.sha256(
            publisher.canonical_json(worker_argv)
        ).hexdigest(),
        "cgroup": cgroup,
    }
    outer = {
        "schema_version": 1,
        "unit": "odoo-accounting-cli-v3-dev29-proof.service",
        "supervisor_pid": os.getpid(),
        "wrapper_pid": wrapper_pid,
        "worker_pid": worker_pid,
        "systemctl": systemctl,
        "systemctl_execution": execution,
        "properties": properties,
        "proc": proc,
        "wrapper": {
            "pid": wrapper_pid,
            "starttime": 11,
            "argv": wrapper_argv,
            "argv_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(wrapper_argv)
            ).hexdigest(),
            "cgroup": cgroup,
            "main_pid": True,
            "lease_monitor_fds": [7],
            "worker_pidfd_verified": True,
        },
        "worker": {
            "pid": worker_pid,
            "starttime": 12,
            "parent_pid": wrapper_pid,
            "argv": worker_argv,
            "argv_sha256": proc["argv_sha256"],
            "cgroup": cgroup,
            "parent_death_signal": "SIGKILL",
            "launcher_lease_fd_inherited": False,
            "bootstrap": {"verified": True},
        },
        "launcher_lease": {"verified": True},
        "expected_environment": publisher.PUBLISHER_ENVIRONMENT,
        "read_write_paths": [],
        "read_only_paths": [str(publisher.LEASE_PARENT)],
        "capability_bounding_set": [],
        "all_checks_passed": True,
    }
    observed = {}

    def live_query(unit: str, *, expected_sha256: str):
        observed["unit"] = unit
        observed["sha256"] = expected_sha256
        return deepcopy(properties), deepcopy(execution)

    monkeypatch.setattr(publisher, "_query_systemctl_properties", live_query)
    monkeypatch.setattr(publisher.os, "getppid", lambda: wrapper_pid)
    monkeypatch.setattr(
        publisher, "_proc_starttime", lambda pid: 11 if pid == wrapper_pid else 12
    )
    monkeypatch.setattr(publisher, "_read_proc_argv", lambda _pid: wrapper_argv)
    monkeypatch.setattr(publisher, "_parent_death_signal", lambda: publisher.SIGKILL)
    monkeypatch.setattr(publisher, "_process_has_pidfd_for", lambda *_args: True)
    monkeypatch.setattr(publisher, "_validate_live_launcher_lease", lambda *_args, **_kwargs: None)
    result = publisher._reverify_outer_unit(outer)
    assert observed == {"unit": outer["unit"], "sha256": "a" * 64}
    assert result["all_checks_passed"] is True
    assert result["systemctl_execution"] == execution

    drifted = deepcopy(properties)
    drifted["ProtectSystem"] = "full"
    monkeypatch.setattr(
        publisher,
        "_query_systemctl_properties",
        lambda *_args, **_kwargs: (drifted, deepcopy(execution)),
    )
    with pytest.raises(publisher.PublishError, match="properties drifted"):
        publisher._reverify_outer_unit(outer)


def test_publisher_systemctl_preexec_sets_parent_death_before_ptrace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class Library:
        def prctl(self, option, signal_number, arg3, arg4, arg5):
            calls.append(("prctl", option, signal_number, arg3, arg4, arg5))
            return 0

        def ptrace(self, request, pid, address, options):
            calls.append(("ptrace", request, pid, address, options))
            return 0

    monkeypatch.setattr(publisher.ctypes, "CDLL", lambda *_args, **_kwargs: Library())
    monkeypatch.setattr(publisher.os, "getppid", lambda: 4321)
    publisher._ptrace_traceme_with_parent_death(4321)
    assert calls == [
        ("prctl", publisher.PR_SET_PDEATHSIG, publisher.SIGKILL, 0, 0, 0),
        ("ptrace", 0, 0, None, None),
    ]


def test_publisher_systemctl_file_capability_xattr_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        publisher.os, "getxattr", lambda *_args: b"capability", raising=False
    )
    with pytest.raises(publisher.PublishError, match="has file capabilities"):
        publisher._reject_systemctl_file_capabilities(7)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root-owned proc-fd release member",
)
def test_publisher_validates_and_closes_inherited_script_fd_before_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = "0.1.0.dev29-a1234567890b"
    script = tmp_path / release / publisher.PUBLISHER_RELATIVE
    script.parent.mkdir(parents=True)
    script.write_bytes(b"#!/usr/bin/python3\n")
    script.chmod(0o400)
    descriptor = os.open(script, os.O_RDONLY)
    argv_path = f"/proc/self/fd/{descriptor}"
    status = "\n".join(
        (
            "Uid:\t0\t0\t0\t0",
            "Gid:\t0\t0\t0\t0",
            "Groups:\t",
            "CapInh:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000",
            "NoNewPrivs:\t1",
        )
    )
    original_read_text = Path.read_text

    def read_text(path: Path, *args, **kwargs):
        if path == Path("/proc/self/status"):
            return status
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(publisher, "RELEASE_PARENT", tmp_path)
    monkeypatch.setattr(publisher, "__file__", argv_path)
    monkeypatch.setattr(publisher.sys, "argv", [argv_path])
    monkeypatch.setattr(publisher, "PUBLISHER_ENVIRONMENT", dict(os.environ))
    monkeypatch.setattr(publisher.os, "getgroups", lambda: [])
    monkeypatch.setattr(Path, "read_text", read_text)
    proof = publisher._validate_publisher_process(release)
    assert proof["fd_closed_before_children"] is True
    with pytest.raises(OSError) as error:
        os.fstat(descriptor)
    assert error.value.errno == errno.EBADF


def test_pending_recovery_reattributes_final_commit_to_current_recovery_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_trace_reverification(monkeypatch)
    evidence = tmp_path / "evidence" / "proof"
    anchor = tmp_path / "proof.json"
    pending = tmp_path / ".proof.json.pending"
    expected = {
        "release": "0.1.0.dev29-a1234567890b",
        "version": "0.1.0.dev29",
        "commit": "a1234567890b1234567890b1234567890b123456",
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "registry_digest": "d" * 64,
        "verified": True,
    }
    bundle_sha256 = "e" * 64
    original = _durable_anchor_document(
        evidence=evidence,
        release_identity=expected,
        bundle_sha256=bundle_sha256,
    )
    original_payload = publisher.canonical_json(original) + b"\n"
    pending.write_bytes(original_payload)
    pending.chmod(0o400)
    field_map = {
        "validation-report.json": "validation_report",
        "cleanup-receipt.json": "cleanup_receipt",
        "verifier-child.json": "verifier_child",
        "verifier-process-control.json": "verifier_process_control",
        "verifier-runtime-trace.json": "verifier_runtime_trace",
        "prepublication-guard.json": "prepublication_guard",
        "supervisor-bootstrap.json": "supervisor_bootstrap",
    }
    documents = {name: deepcopy(original[field]) for name, field in field_map.items()}
    anchored_without_publication = {
        key: value
        for key, value in original["frozen_evidence_identity"].items()
        if key != "publication_outer_unit_reverification"
    }
    recovery_cgroup = {
        "version": 2,
        "relative_path": "/system.slice/recovery.service",
        "device": 1,
        "inode": 2,
        "sole_process": os.getpid(),
        "descendant_cgroups": 0,
        "descendant_processes": 0,
    }
    recovery_execution = {"current_recovery_exec": True}
    captured = {}
    monkeypatch.setattr(
        publisher,
        "_anchor_lock",
        lambda *_args, **_kwargs: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        publisher,
        "_read_and_fsync_pending",
        lambda *_args, **_kwargs: original_payload,
    )
    monkeypatch.setattr(publisher, "_prove_cleanup_live", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        publisher,
        "_evidence_identity",
        lambda *_args, **_kwargs: deepcopy(anchored_without_publication),
    )
    monkeypatch.setattr(
        publisher, "_prove_supervisor_cgroup", lambda: deepcopy(recovery_cgroup)
    )
    monkeypatch.setattr(
        publisher,
        "_reverify_recovery_outer_unit",
        lambda *_args, **_kwargs: {
            "unit": original["frozen_evidence_identity"]["outer_unit"]["unit"],
            "systemctl": original["frozen_evidence_identity"]["outer_unit"][
                "systemctl"
            ],
            "properties": {
                field: f"recovery-{field}"
                for field in publisher.SYSTEMD_UNIT_FIELDS
            },
            "properties_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(
                    {
                        field: f"recovery-{field}"
                        for field in publisher.SYSTEMD_UNIT_FIELDS
                    }
                )
            ).hexdigest(),
            "proc": {
                "argv": ["recovery-publisher"],
                "argv_sha256": publisher.hashlib.sha256(
                    publisher.canonical_json(["recovery-publisher"])
                ).hexdigest(),
                "cgroup": recovery_cgroup["relative_path"],
            },
            "systemctl_execution": recovery_execution,
            "outer_unit": {"current_recovery": True},
            "outer_unit_sha256": publisher.hashlib.sha256(
                publisher.canonical_json({"current_recovery": True})
            ).hexdigest(),
            "all_checks_passed": True,
        },
    )

    def publish_recovery(path: Path, payload: bytes) -> Path:
        captured["path"] = path
        captured["payload"] = payload
        return path

    removed = []
    monkeypatch.setattr(
        publisher, "_publish_recovery_payload_locked", publish_recovery
    )
    monkeypatch.setattr(
        publisher,
        "_remove_pending_anchor",
        lambda path, **_kwargs: removed.append(path),
    )
    monkeypatch.setattr(publisher, "_fsync_directory", lambda _path: None)
    result = publisher._recover_validated_pending_anchor(
        anchor,
        evidence=evidence,
        documents=documents,
        expected_release_identity=expected,
        expected_bundle_manifest_sha256=bundle_sha256,
        expected_ldconfig_sha256=LDCONFIG_SHA256,
        expected_runtime_open_index_sha256=RUNTIME_INDEX_SHA256,
        expected_strace_sha256=STRACE_SHA256,
        publisher_script_execution=original["final_publication"][
            "publisher_script_execution"
        ],
        recovery_outer_unit={"current_recovery": True},
    )
    assert result == anchor
    recovered = publisher.parse_json(
        captured["payload"], label="captured recovered anchor"
    )
    final = recovered["final_publication"]
    assert final["mode"] == "recovered_pending"
    assert final["publisher_pid"] == os.getpid()
    assert final["publisher_cgroup"] == recovery_cgroup
    assert final["systemctl_execution"] == recovery_execution
    assert set(final["properties"]) == set(publisher.SYSTEMD_UNIT_FIELDS)
    assert final["properties"]["InvocationID"] == "recovery-InvocationID"
    assert final["properties"]["ExecStart"] == "recovery-ExecStart"
    assert final["proc"]["argv"] == ["recovery-publisher"]
    assert final["outer_unit"] == {"current_recovery": True}
    assert final["systemctl"] == original["frozen_evidence_identity"][
        "outer_unit"
    ]["systemctl"]
    assert final["publisher_script_execution"]["fd_closed_before_children"] is True
    assert final["resumed_pending_sha256"] == publisher.hashlib.sha256(
        original_payload
    ).hexdigest()
    assert recovered["publisher_cgroup"] == original["publisher_cgroup"]
    assert removed == [pending]


def test_publisher_cli_requires_all_six_root_only_stage_inputs() -> None:
    destinations = {action.dest for action in publisher._parser()._actions}
    assert {
        "validation_report",
        "cleanup_receipt",
        "verifier_child",
        "verifier_process_control",
        "prepublication_guard",
        "supervisor_bootstrap",
        "staging_dir",
        "expected_ldconfig_sha256",
    } <= destinations


def test_expected_verifier_command_binds_external_ldconfig_digest_exactly() -> None:
    release_identity = {
        "release": "0.1.0.dev29-a1234567890b",
        "version": "0.1.0.dev29",
        "commit": "a1234567890b1234567890b1234567890b123456",
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
    }
    report = {
        "closure_identity": {
            "anchor_sha256": "d" * 64,
            "image_sha256": "e" * 64,
            "system_python_sha256": "f" * 64,
            "loader_preload_sha256": "1" * 64,
        }
    }
    command = publisher._expected_verifier_command(
        Path("/evidence/dev29-proof-001"),
        report,
        "2" * 64,
        release_identity,
        LDCONFIG_SHA256,
        RUNTIME_INDEX_SHA256,
        STRACE_SHA256,
    )
    assert command.count("--expected-ldconfig-sha256") == 1
    index = command.index("--expected-ldconfig-sha256")
    assert command[index + 1] == LDCONFIG_SHA256
    assert command[command.index("--expected-runtime-open-index-sha256") + 1] == (
        RUNTIME_INDEX_SHA256
    )
    assert command[command.index("--expected-strace-sha256") + 1] == STRACE_SHA256


def test_publisher_reverifies_full_verifier_trace_and_rejects_sidecar_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = "0.1.0.dev29-a1234567890b"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    releases = tmp_path / "releases"
    release_root = releases / release
    runtime_path = release_root.joinpath(*publisher.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    runtime_payload = b"""\
import hashlib

class TraceRequest:
    def __init__(self, **values):
        self.__dict__.update(values)

def validate_manifest_document(value, request):
    if value["expected_child_environment_sha256"] != request.expected_child_environment_sha256:
        raise RuntimeError("child environment mismatch")
    if value["expected_static_closure_sha256"] != request.expected_static_closure_sha256:
        raise RuntimeError("static closure mismatch")
    return value

class Result:
    def __init__(self, path):
        self.path = path
    def document(self):
        return {
            "canonical_path_count": 1,
            "canonical_path_set_sha256": "a" * 64,
            "trace_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
        }

def validate_trace_file(path, _manifest, *, expected_leader_pid):
    if expected_leader_pid <= 1:
        raise RuntimeError("leader pid mismatch")
    return Result(path)
"""
    runtime_path.write_bytes(runtime_payload)
    runtime_sha256 = publisher.hashlib.sha256(runtime_payload).hexdigest()
    version = "0.1.0.dev29"
    commit = "a1234567890b" + "c" * 28
    version_payload = (version + "\n").encode("ascii")
    (release_root / "VERSION").write_bytes(version_payload)
    release_manifest_unsigned = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "files": [
            {
                "path": str(publisher.TRACE_RELATIVE),
                "sha256": runtime_sha256,
                "size": len(runtime_payload),
            },
            {
                "path": "VERSION",
                "sha256": publisher.hashlib.sha256(version_payload).hexdigest(),
                "size": len(version_payload),
            },
        ],
    }
    release_manifest = {
        **release_manifest_unsigned,
        "manifest_sha256": publisher.hashlib.sha256(
            publisher.canonical_json(release_manifest_unsigned)
        ).hexdigest(),
    }
    release_manifest_payload = (
        publisher.json.dumps(
            release_manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    (release_root / "RELEASE-MANIFEST.json").write_bytes(
        release_manifest_payload
    )
    release_manifest_sha256 = publisher.hashlib.sha256(
        release_manifest_payload
    ).hexdigest()
    release_manifest_semantic_sha256 = release_manifest["manifest_sha256"]
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    child_environment_sha256 = publisher.hashlib.sha256(
        publisher.canonical_json(environment)
    ).hexdigest()
    policy = {
        "path": "/usr/bin/python3.12",
        "role": "verifier",
        "classification": "immutable",
        "allowed_access": ["execute", "metadata", "read"],
        "create_suffixes": [],
        "delta_verifier": None,
        "delta_contract_sha256": None,
        "allow_success": True,
        "allowed_errnos": [],
        "failure_guard": None,
    }
    watches = ["/dev", "/etc", "/opt", "/proc", "/usr", "/var"]
    watch_roots_sha256 = publisher.hashlib.sha256(
        publisher.canonical_json(tuple(watches))
    ).hexdigest()
    assert publisher.TRACE_MANIFEST_SCOPE == runtime_trace.SCOPE
    manifest = {
        "schema_version": 1,
        "scope": runtime_trace.SCOPE,
        "release": release,
        "target_id": "independent-verifier",
        "role": "verifier",
        "environment": environment,
        "expected_child_environment_sha256": child_environment_sha256,
        "expected_watch_roots_sha256": watch_roots_sha256,
        "expected_static_closure_sha256": "2" * 64,
        "path_access_policy": [policy],
        "watch_roots": watches,
    }
    manifests = tmp_path / "manifests" / release
    manifests.mkdir(parents=True)
    manifest_documents: dict[str, dict[str, object]] = {}
    targets: list[dict[str, str]] = []
    for target_id in publisher.expected_runtime_trace_targets():
        document = {**manifest, "target_id": target_id}
        payload = publisher.canonical_json(document) + b"\n"
        (manifests / f"{target_id}.json").write_bytes(payload)
        manifest_documents[target_id] = document
        targets.append(
            {
                "target_id": target_id,
                "manifest_sha256": publisher.hashlib.sha256(payload).hexdigest(),
                "watch_roots_sha256": watch_roots_sha256,
                "child_environment_sha256": child_environment_sha256,
            }
        )
    manifest_payload = publisher.canonical_json(manifest) + b"\n"
    manifest_sha256 = publisher.hashlib.sha256(manifest_payload).hexdigest()
    policy_source = {
        "schema_version": 1,
        "scope": publisher.TRACE_POLICY_SOURCE_SCOPE,
        "release": release,
        "expected_strace_sha256": STRACE_SHA256,
        "expected_static_closure_sha256": "2" * 64,
        "expected_runtime_module_sha256": runtime_sha256,
        "expected_release_manifest_sha256": release_manifest_sha256,
        "targets": [
            manifest_documents[target_id]
            for target_id in publisher.expected_runtime_trace_targets()
        ],
        "production_promotion_allowed": False,
    }
    policy_source_sha256 = publisher.hashlib.sha256(
        publisher.canonical_json(policy_source) + b"\n"
    ).hexdigest()
    index = {
        "schema_version": 1,
        "scope": publisher.TRACE_INDEX_SCOPE,
        "release": release,
        "expected_strace_sha256": STRACE_SHA256,
        "expected_static_closure_sha256": "2" * 64,
        "policy_source_sha256": policy_source_sha256,
        "runtime_module_sha256": runtime_sha256,
        "release_manifest_sha256": release_manifest_sha256,
        "targets": targets,
        "production_promotion_allowed": False,
    }
    index_payload = publisher.canonical_json(index) + b"\n"
    (manifests / "INDEX.json").write_bytes(index_payload)
    index_sha256 = publisher.hashlib.sha256(index_payload).hexdigest()
    private_parent = tmp_path / "private"
    sidecar = private_parent / f"{evidence.name}.verifier"
    sidecar.mkdir(parents=True)
    raw_path = sidecar / "independent-verifier.strace"
    raw_payload = b"verified trace\n"
    raw_path.write_bytes(raw_payload)
    metadata = raw_path.stat()
    raw = {
        "target_id": "independent-verifier",
        "manifest_sha256": manifest_sha256,
        "expected_leader_pid": 1234,
        "path": str(raw_path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mode": "0400",
        "sha256": publisher.hashlib.sha256(raw_payload).hexdigest(),
    }
    private_manifest = {
        "schema_version": 1,
        "sidecar_type": "odoo-accounting-cli-v3.dev29.private-runtime-open.v1",
        "release": release,
        "evidence_name": sidecar.name,
        "entries": [raw],
        "production_promotion_allowed": False,
    }
    private_manifest_payload = publisher.canonical_json(private_manifest) + b"\n"
    (sidecar / "MANIFEST.json").write_bytes(private_manifest_payload)
    identity = {
        key: raw[key]
        for key in ("target_id", "device", "inode", "size", "sha256")
    }
    private_summary = {
        "schema_version": 1,
        "manifest_sha256": publisher.hashlib.sha256(
            private_manifest_payload
        ).hexdigest(),
        "trace_count": 1,
        "tree_identity_sha256": publisher.hashlib.sha256(
            publisher.canonical_json([identity])
        ).hexdigest(),
        "production_promotion_allowed": False,
    }
    receipt = {
        "schema_version": 1,
        "scope": runtime_trace.SCOPE,
        "target_id": "independent-verifier",
        "role": "verifier",
        "manifest_sha256": manifest_sha256,
        "policy_sha256": publisher.hashlib.sha256(
            publisher.canonical_json([policy])
        ).hexdigest(),
        "watch_roots_sha256": watch_roots_sha256,
        "child_environment_sha256": child_environment_sha256,
        "static_closure_sha256": "2" * 64,
        "dynamic_namespace_receipt_sha256": "7" * 64,
        "canonical_path_count": 1,
        "canonical_path_set_sha256": "a" * 64,
        "trace_sha256": raw["sha256"],
        "production_promotion_allowed": False,
    }
    value = {
        "schema_version": 1,
        "scope": publisher.TRACE_RECEIPTS_SCOPE,
        "release": release,
        "index_sha256": index_sha256,
        "expected_strace_sha256": STRACE_SHA256,
        "expected_static_closure_sha256": "2" * 64,
        "policy_source_sha256": policy_source_sha256,
        "runtime_module_sha256": runtime_sha256,
        "release_manifest_sha256": release_manifest_sha256,
        "receipts": [receipt],
        "private_sidecar": private_summary,
        "production_promotion_allowed": False,
    }
    monkeypatch.setattr(publisher, "RELEASE_PARENT", releases)
    monkeypatch.setattr(publisher, "TRACE_INDEX_PARENT", tmp_path / "manifests")
    monkeypatch.setattr(publisher, "PRIVATE_EVIDENCE_PARENT", private_parent)

    def rebuilt_policy_source_sha256() -> str:
        source = {
            "schema_version": 1,
            "scope": publisher.TRACE_POLICY_SOURCE_SCOPE,
            "release": index["release"],
            "expected_strace_sha256": index["expected_strace_sha256"],
            "expected_static_closure_sha256": index[
                "expected_static_closure_sha256"
            ],
            "expected_runtime_module_sha256": index["runtime_module_sha256"],
            "expected_release_manifest_sha256": index[
                "release_manifest_sha256"
            ],
            "targets": [
                manifest_documents[target_id]
                for target_id in publisher.expected_runtime_trace_targets()
            ],
            "production_promotion_allowed": False,
        }
        return publisher.hashlib.sha256(
            publisher.canonical_json(source) + b"\n"
        ).hexdigest()

    def install_index() -> str:
        updated_index_payload = publisher.canonical_json(index) + b"\n"
        (manifests / "INDEX.json").write_bytes(updated_index_payload)
        updated_index_sha256 = publisher.hashlib.sha256(
            updated_index_payload
        ).hexdigest()
        value["index_sha256"] = updated_index_sha256
        return updated_index_sha256

    def bind_valid_policy_source() -> str:
        digest = rebuilt_policy_source_sha256()
        index["policy_source_sha256"] = digest
        value["policy_source_sha256"] = digest
        return install_index()

    def install_policy_manifest(
        target_id: str, document: dict[str, object]
    ) -> str:
        payload = publisher.canonical_json(document) + b"\n"
        (manifests / f"{target_id}.json").write_bytes(payload)
        manifest_documents[target_id] = document
        entry = next(
            item for item in targets if item["target_id"] == target_id
        )
        entry["manifest_sha256"] = publisher.hashlib.sha256(payload).hexdigest()
        return bind_valid_policy_source()

    def install_release_manifest(document: dict[str, object]) -> str:
        payload = (
            publisher.json.dumps(
                document,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        (release_root / "RELEASE-MANIFEST.json").write_bytes(payload)
        digest = publisher.hashlib.sha256(payload).hexdigest()
        index["release_manifest_sha256"] = digest
        value["release_manifest_sha256"] = digest
        return bind_valid_policy_source()

    def seal_release_manifest(unsigned: dict[str, object]) -> dict[str, object]:
        return {
            **unsigned,
            "manifest_sha256": publisher.hashlib.sha256(
                publisher.canonical_json(unsigned)
            ).hexdigest(),
        }

    arbitrary_policy_source_sha256 = "3" * 64
    assert arbitrary_policy_source_sha256 != rebuilt_policy_source_sha256()
    index["policy_source_sha256"] = arbitrary_policy_source_sha256
    value["policy_source_sha256"] = arbitrary_policy_source_sha256
    arbitrary_index_sha256 = install_index()
    with pytest.raises(publisher.PublishError, match="policy source digest"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=arbitrary_index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
    index_sha256 = bind_valid_policy_source()

    release_snapshot_calls: list[tuple[Path, bool]] = []
    real_release_snapshot = publisher._sealed_release_tree_identity
    policy_directory_calls: list[tuple[int, bool, set[str] | None]] = []
    real_directory_identity = publisher._sealed_directory_identity

    def release_snapshot_spy(
        root: Path, *, enforce_root: bool
    ) -> tuple[object, object]:
        release_snapshot_calls.append((root, enforce_root))
        return real_release_snapshot(root, enforce_root=enforce_root)

    def directory_identity_spy(
        path: Path,
        *,
        label: str,
        expected_mode: int,
        enforce_root: bool,
        expected_names: set[str] | None = None,
    ) -> tuple[tuple[int, ...], tuple[str, ...]]:
        if path == manifests:
            policy_directory_calls.append(
                (expected_mode, enforce_root, expected_names)
            )
        return real_directory_identity(
            path,
            label=label,
            expected_mode=expected_mode,
            enforce_root=enforce_root,
            expected_names=expected_names,
        )

    with monkeypatch.context() as snapshot_patch:
        snapshot_patch.setattr(
            publisher, "_sealed_release_tree_identity", release_snapshot_spy
        )
        snapshot_patch.setattr(
            publisher, "_sealed_directory_identity", directory_identity_spy
        )
        proof = publisher._validate_verifier_runtime_trace(
            evidence,
            value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
    assert release_snapshot_calls == [
        (release_root, False),
        (release_root, False),
    ]
    expected_policy_names = {
        "INDEX.json",
        *(
            f"{target_id}.json"
            for target_id in publisher.expected_runtime_trace_targets()
        ),
    }
    assert policy_directory_calls == [
        (0o555, False, expected_policy_names),
        (0o555, False, expected_policy_names),
        (0o555, False, expected_policy_names),
        (0o555, False, expected_policy_names),
    ]
    assert proof["policy_source_sha256"] == policy_source_sha256
    assert proof["runtime_module_sha256"] == runtime_sha256
    assert proof["release_manifest_sha256"] == release_manifest_sha256

    real_sidecar_reverification = (
        publisher._reverify_private_runtime_trace_sidecar
    )
    for location in ("receipt-set", "receipt"):
        invalid_schema = deepcopy(value)
        if location == "receipt-set":
            invalid_schema["schema_version"] = True
        else:
            invalid_schema["receipts"][0]["schema_version"] = True
        sidecar_calls = 0

        def sidecar_spy(*args: object, **kwargs: object) -> dict[str, object]:
            nonlocal sidecar_calls
            sidecar_calls += 1
            return real_sidecar_reverification(*args, **kwargs)

        with monkeypatch.context() as schema_patch:
            schema_patch.setattr(
                publisher,
                "_reverify_private_runtime_trace_sidecar",
                sidecar_spy,
            )
            with pytest.raises(
                publisher.PublishError,
                match="verifier runtime-open trace receipt is invalid",
            ):
                publisher._validate_verifier_runtime_trace(
                    evidence,
                    invalid_schema,
                    expected_release=release,
                    expected_release_manifest_semantic_sha256=(
                        release_manifest_semantic_sha256
                    ),
                    expected_index_sha256=index_sha256,
                    expected_strace_sha256=STRACE_SHA256,
                    enforce_root=False,
                )
        assert sidecar_calls == 0

    extra_policy_member = manifests / "unapproved.json"
    extra_policy_member.write_bytes(b"{}\n")
    with pytest.raises(publisher.PublishError, match="file set is not exact"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
    extra_policy_member.unlink()

    policy_target = "release-identity"
    policy_path = manifests / f"{policy_target}.json"
    original_policy_document = deepcopy(manifest_documents[policy_target])
    original_policy_payload = policy_path.read_bytes()
    digest_tampered = {**original_policy_document, "role": "tampered"}
    policy_path.write_bytes(publisher.canonical_json(digest_tampered) + b"\n")
    with pytest.raises(publisher.PublishError, match="manifest digest differs"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
    policy_path.write_bytes(original_policy_payload)

    binding_mutations = (
        {**original_policy_document, "target_id": "witness-pre"},
        {
            **original_policy_document,
            "environment": {
                **original_policy_document["environment"],
                "UNAPPROVED": "1",
            },
        },
        {
            **original_policy_document,
            "watch_roots": [*original_policy_document["watch_roots"], "/zzz"],
        },
        {
            **original_policy_document,
            "expected_watch_roots_sha256": "9" * 64,
        },
    )
    for mutated_policy_document in binding_mutations:
        mutated_index_sha256 = install_policy_manifest(
            policy_target, mutated_policy_document
        )
        with pytest.raises(
            publisher.PublishError, match="manifest index binding differs"
        ):
            publisher._validate_verifier_runtime_trace(
                evidence,
                value,
                expected_release=release,
                expected_release_manifest_semantic_sha256=(
                    release_manifest_semantic_sha256
                ),
                expected_index_sha256=mutated_index_sha256,
                expected_strace_sha256=STRACE_SHA256,
                enforce_root=False,
            )
        index_sha256 = install_policy_manifest(
            policy_target, deepcopy(original_policy_document)
        )

    for field in ("schema_version", "trace_count"):
        invalid_summary = deepcopy(value)
        invalid_summary["private_sidecar"][field] = True
        with pytest.raises(publisher.PublishError, match="summary is invalid"):
            publisher._validate_verifier_runtime_trace(
                evidence,
                invalid_summary,
                expected_release=release,
                expected_release_manifest_semantic_sha256=(
                    release_manifest_semantic_sha256
                ),
                expected_index_sha256=index_sha256,
                expected_strace_sha256=STRACE_SHA256,
                enforce_root=False,
            )

    invalid_private_manifest = deepcopy(private_manifest)
    invalid_private_manifest["schema_version"] = True
    invalid_private_payload = publisher.canonical_json(invalid_private_manifest) + b"\n"
    (sidecar / "MANIFEST.json").write_bytes(invalid_private_payload)
    invalid_private_value = deepcopy(value)
    invalid_private_value["private_sidecar"]["manifest_sha256"] = (
        publisher.hashlib.sha256(invalid_private_payload).hexdigest()
    )
    with pytest.raises(publisher.PublishError, match="manifest is invalid"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            invalid_private_value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
    (sidecar / "MANIFEST.json").write_bytes(private_manifest_payload)

    duplicate_member_unsigned = deepcopy(release_manifest_unsigned)
    duplicate_member_unsigned["files"].append(
        deepcopy(duplicate_member_unsigned["files"][0])
    )
    wrong_member_unsigned = deepcopy(release_manifest_unsigned)
    wrong_member_unsigned["files"][0]["size"] = len(runtime_payload) + 1
    wrong_member_sha_unsigned = deepcopy(release_manifest_unsigned)
    wrong_member_sha_unsigned["files"][0]["sha256"] = "f" * 64
    wrong_other_member_size_unsigned = deepcopy(release_manifest_unsigned)
    wrong_other_member_size_unsigned["files"][1]["size"] = (
        len(version_payload) + 1
    )
    wrong_other_member_sha_unsigned = deepcopy(release_manifest_unsigned)
    wrong_other_member_sha_unsigned["files"][1]["sha256"] = "e" * 64
    boolean_member_size_unsigned = deepcopy(release_manifest_unsigned)
    boolean_member_size_unsigned["files"][0]["size"] = True
    boolean_schema_unsigned = deepcopy(release_manifest_unsigned)
    boolean_schema_unsigned["schema_version"] = True
    wrong_identity_unsigned = deepcopy(release_manifest_unsigned)
    wrong_identity_unsigned["commit"] = "b" * 40
    invalid_release_manifests = (
        ({"schema_version": 1}, release_manifest_semantic_sha256, "identity"),
        (
            {**release_manifest, "manifest_sha256": "0" * 64},
            release_manifest_semantic_sha256,
            "semantic digest is invalid",
        ),
        (
            seal_release_manifest(duplicate_member_unsigned),
            None,
            "member is invalid",
        ),
        (
            seal_release_manifest(wrong_member_unsigned),
            None,
            "runtime member is invalid",
        ),
        (
            seal_release_manifest(wrong_member_sha_unsigned),
            None,
            "runtime member is invalid",
        ),
        (
            seal_release_manifest(wrong_other_member_size_unsigned),
            None,
            "sealed release member differs: VERSION",
        ),
        (
            seal_release_manifest(wrong_other_member_sha_unsigned),
            None,
            "sealed release member differs: VERSION",
        ),
        (
            seal_release_manifest(boolean_member_size_unsigned),
            None,
            "member is invalid",
        ),
        (
            seal_release_manifest(boolean_schema_unsigned),
            None,
            "identity is invalid",
        ),
        (
            seal_release_manifest(wrong_identity_unsigned),
            None,
            "identity is invalid",
        ),
    )
    for invalid_release_manifest, expected_semantic, expected_error in (
        invalid_release_manifests
    ):
        invalid_index_sha256 = install_release_manifest(invalid_release_manifest)
        if expected_semantic is None:
            expected_semantic = invalid_release_manifest["manifest_sha256"]
        with pytest.raises(publisher.PublishError, match=expected_error):
            publisher._validate_verifier_runtime_trace(
                evidence,
                value,
                expected_release=release,
                expected_release_manifest_semantic_sha256=(
                    expected_semantic
                ),
                expected_index_sha256=invalid_index_sha256,
                expected_strace_sha256=STRACE_SHA256,
                enforce_root=False,
            )
    index_sha256 = install_release_manifest(release_manifest)
    release_manifest_sha256 = value["release_manifest_sha256"]

    semantic_tamper_unsigned = deepcopy(release_manifest_unsigned)
    semantic_tamper_unsigned["files"].reverse()
    semantic_tamper = seal_release_manifest(semantic_tamper_unsigned)
    semantic_index_sha256 = install_release_manifest(semantic_tamper)
    semantic_validator_calls = 0
    real_release_validator = publisher._validate_runtime_release_manifest

    def release_validator_spy(*args: object, **kwargs: object) -> object:
        nonlocal semantic_validator_calls
        semantic_validator_calls += 1
        return real_release_validator(*args, **kwargs)

    with monkeypatch.context() as semantic_patch:
        semantic_patch.setattr(
            publisher,
            "_validate_runtime_release_manifest",
            release_validator_spy,
        )
        with pytest.raises(
            publisher.PublishError, match="semantic digest.*expected identity"
        ):
            publisher._validate_verifier_runtime_trace(
                evidence,
                value,
                expected_release=release,
                expected_release_manifest_semantic_sha256=(
                    release_manifest_semantic_sha256
                ),
                expected_index_sha256=semantic_index_sha256,
                expected_strace_sha256=STRACE_SHA256,
                enforce_root=False,
            )
    assert semantic_validator_calls == 1
    index_sha256 = install_release_manifest(release_manifest)
    release_manifest_sha256 = value["release_manifest_sha256"]

    changed = deepcopy(value)
    changed["receipts"][0]["child_environment_sha256"] = "8" * 64
    with pytest.raises(publisher.PublishError, match="raw trace reparse differs"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            changed,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )

    (sidecar / ".independent-verifier.seal.json").write_text(
        "{}\n", encoding="utf-8"
    )
    with pytest.raises(publisher.PublishError, match="sidecar member set"):
        publisher._validate_verifier_runtime_trace(
            evidence,
            value,
            expected_release=release,
            expected_release_manifest_semantic_sha256=(
                release_manifest_semantic_sha256
            ),
            expected_index_sha256=index_sha256,
            expected_strace_sha256=STRACE_SHA256,
            enforce_root=False,
        )
