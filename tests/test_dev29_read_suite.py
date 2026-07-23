from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
from copy import deepcopy
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "deployment" / "dev29" / "run_read_suite.py"
SPEC = importlib.util.spec_from_file_location("dev29_run_read_suite", PATH)
assert SPEC is not None and SPEC.loader is not None
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)

TRACE_PATH = ROOT / "deployment" / "dev29" / "runtime_open_trace.py"
TRACE_SPEC = importlib.util.spec_from_file_location(
    "dev29_runtime_open_trace_for_suite", TRACE_PATH
)
assert TRACE_SPEC is not None and TRACE_SPEC.loader is not None
runtime_trace = importlib.util.module_from_spec(TRACE_SPEC)
sys.modules[TRACE_SPEC.name] = runtime_trace
TRACE_SPEC.loader.exec_module(runtime_trace)

ORACLE_PATH = ROOT / "deployment" / "dev29" / "read_oracles.py"
ORACLE_SPEC = importlib.util.spec_from_file_location(
    "dev29_read_oracles_for_suite", ORACLE_PATH
)
assert ORACLE_SPEC is not None and ORACLE_SPEC.loader is not None
read_oracles = importlib.util.module_from_spec(ORACLE_SPEC)
sys.modules[ORACLE_SPEC.name] = read_oracles
ORACLE_SPEC.loader.exec_module(read_oracles)

VERSION = "0.1.0.dev29"
COMMIT = "a1234567890bcdef1234567890abcdef12345678"
RELEASE = f"{VERSION}-{COMMIT[:12]}"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink resolution is required")
def test_external_runtime_allows_only_symlink_reachable_outside_roots(
    tmp_path: Path,
) -> None:
    root = tmp_path / "usr/lib/python3.12"
    outside = tmp_path / "etc/python3.12/sitecustomize.py"
    root.mkdir(parents=True)
    outside.parent.mkdir(parents=True)
    outside.write_text("pass\n", encoding="utf-8")
    link = root / "sitecustomize.py"
    link.symlink_to(outside)
    entries = [
        {"path": str(root), "kind": "directory"},
        {"path": str(link), "kind": "symlink", "target": str(outside)},
        {"path": str(outside), "kind": "regular"},
    ]

    allowed = suite._external_runtime_allowed_roots(
        [PurePosixPath(str(root))], entries
    )

    assert PurePosixPath(str(outside)) in allowed
    assert not suite._under_any_root(
        PurePosixPath(str(tmp_path / "etc/passwd")), allowed
    )
    with pytest.raises(suite.ReadSuiteError, match="symlink target is uncovered"):
        suite._external_runtime_allowed_roots(
            [PurePosixPath(str(root))], entries[:2]
        )


def test_source_tree_snapshot_skips_backup_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "v2"
    backup = root / "backups"
    backup.mkdir(parents=True)
    (root / "live.py").write_text("print('live')\n", encoding="utf-8")
    (backup / "old.py").write_text("print('backup')\n", encoding="utf-8")
    monkeypatch.setattr(suite, "MAX_TREE_FILES", 1)

    snapshot = suite._tree_snapshot(root)

    assert snapshot["count"] == 1


def test_systemctl_show_accepts_not_found_socket_missing_service_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b"Id=odoo-accounting-cli-v3-pi-broker.socket\n"
                b"Names=odoo-accounting-cli-v3-pi-broker.socket\n"
                b"LoadState=not-found\n"
                b"ActiveState=inactive\n"
                b"SubState=dead\n"
                b"FragmentPath=\n"
                b"SourcePath=\n"
                b"DropInPaths=\n"
                b"UnitFileState=\n"
                b"StateChangeTimestampMonotonic=0\n"
                b"InvocationID=\n"
            ),
            stderr=b"",
        )

    monkeypatch.setattr(suite.subprocess, "run", run)

    identity = suite._systemctl_show("odoo-accounting-cli-v3-pi-broker.socket")

    assert identity["properties"]["LoadState"] == "not-found"
    assert identity["properties"]["MainPID"] == "0"
    assert identity["properties"]["ExecMainStartTimestampMonotonic"] == ""
    assert identity["properties"]["NRestarts"] == "0"


def test_dedicated_supervisor_processes_accepts_worker_and_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(suite.os, "getpid", lambda: 200)
    monkeypatch.setattr(suite.os, "getppid", lambda: 100)

    assert suite._dedicated_supervisor_processes([200])
    assert suite._dedicated_supervisor_processes([100, 200])
    assert not suite._dedicated_supervisor_processes([100, 200, 300])


def test_direct_child_failure_context_is_bounded_and_hashes_stderr() -> None:
    stderr = b"Dev29 direct child refused: sample reason\n" + b"x" * 600

    context = suite._direct_child_failure_context(126, stderr)

    assert "returncode=126" in context
    assert hashlib.sha256(stderr).hexdigest() in context
    assert "sample reason" in context
    assert len(context) < 700


def test_direct_child_does_not_require_child_access_to_host_namespace() -> None:
    source = (ROOT / "deployment" / "dev29" / "direct_child.py").read_text("utf-8")

    assert '_namespace("self")' in source
    assert '_namespace("1")' not in source
    assert "arguments.expected_host_namespace_device" in source
    assert "arguments.expected_host_namespace_inode" in source


def test_direct_child_does_not_require_child_access_to_bind_source() -> None:
    source = (ROOT / "deployment" / "dev29" / "direct_child.py").read_text("utf-8")

    assert '_canonical_path(item["source_path"])' in source
    assert '_safe_endpoint(item["source_path"])' not in source
    assert '"source_device": item["source_device"]' in source
    assert '(item["source_device"], item["source_inode"])' in source


def test_direct_child_mount_endpoint_failure_reports_path_and_errno() -> None:
    source = (ROOT / "deployment" / "dev29" / "direct_child.py").read_text("utf-8")

    assert "child mount endpoint is unavailable: " in source
    assert "path={path_text!r}" in source
    assert "errno={exc.errno}" in source


def test_direct_child_allows_unstatable_closure_root_only() -> None:
    source = (ROOT / "deployment" / "dev29" / "direct_child.py").read_text("utf-8")

    assert "if len(expected) == 0:" in source
    assert "if index == 0:" in source
    assert 'read_only = "ro" in rows[item["destination_path"]]["options"]' in source
    assert "index != 0" in source


def test_direct_child_environment_declares_odoo_venv_python_for_oracles() -> None:
    suite_source = (ROOT / "deployment" / "dev29" / "run_read_suite.py").read_text("utf-8")
    child_source = (ROOT / "deployment" / "dev29" / "direct_child.py").read_text("utf-8")
    trace_source = (ROOT / "deployment" / "dev29" / "runtime_open_trace.py").read_text("utf-8")

    for source in (suite_source, child_source, trace_source):
        assert "ODOO_ACCOUNTING_CLI_V3_EXPECTED_PYTHON" in source
        assert "/opt/odoo/odoo19/odoo19-venv/bin/python" in source
    for source in (suite_source, child_source):
        assert 'role in {"odoo", "postgres"}' in source


def test_child_attestation_uses_closure_identity_external_runtime_paths() -> None:
    source = (ROOT / "deployment" / "dev29" / "run_read_suite.py").read_text("utf-8")

    assert 'closure["closure_identity"]["external_runtime_paths"]' in source
    assert 'closure["external_runtime_paths"]' not in source


def test_child_credential_attestation_failure_reports_bounded_context() -> None:
    source = (ROOT / "deployment" / "dev29" / "run_read_suite.py").read_text("utf-8")

    assert "credential_sha256=" in source
    assert "credential_preview=" in source
    assert '"mismatches": mismatches' in source
    assert "payload[:2048]" in source


def test_child_credential_uid_gid_status_whitespace_is_normalized() -> None:
    source = (ROOT / "deployment" / "dev29" / "run_read_suite.py").read_text("utf-8")

    assert 'for key in ("Uid", "Gid")' in source
    assert '".join(comparable_status[key].split())' in source
    assert "comparable_credentials != expected_credentials" in source


def test_runtime_open_traces_stage_under_private_sidecar() -> None:
    source = (ROOT / "deployment" / "dev29" / "run_read_suite.py").read_text("utf-8")

    assert 'private_sidecar / ".trace-staging"' in source
    assert "parent=self.private_sidecar / \".trace-staging\"" in source


def expected_identity():
    return suite.ExpectedIdentity(
        release=RELEASE,
        version=VERSION,
        commit=COMMIT,
        manifest_sha256="b" * 64,
        package_sha256="c" * 64,
    )


def test_all_dev29_numeric_schema_versions_have_explicit_integer_guards() -> None:
    failures: list[str] = []
    for path in sorted((ROOT / "deployment" / "dev29").glob("*.py")):
        source = path.read_text("utf-8")
        tree = ast.parse(source, filename=str(path))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for comparison in (
            node for node in ast.walk(tree) if isinstance(node, ast.Compare)
        ):
            values = [comparison.left, *comparison.comparators]
            if not any(
                isinstance(item, ast.Constant)
                and type(item.value) is int
                and item.value == 1
                for item in values
            ) or not any(
                isinstance(item, ast.Constant) and item.value == "schema_version"
                for item in ast.walk(comparison)
            ):
                continue
            context: ast.AST | None = comparison
            while context is not None and not isinstance(context, ast.BoolOp):
                context = parents.get(context)
            guarded = False
            if isinstance(context, ast.BoolOp):
                for candidate in ast.walk(context):
                    if (
                        isinstance(candidate, ast.Compare)
                        and any(isinstance(operator, ast.IsNot) for operator in candidate.ops)
                        and isinstance(candidate.left, ast.Call)
                        and isinstance(candidate.left.func, ast.Name)
                        and candidate.left.func.id == "type"
                        and any(
                            isinstance(item, ast.Name) and item.id == "int"
                            for item in candidate.comparators
                        )
                        and any(
                            isinstance(item, ast.Constant)
                            and item.value == "schema_version"
                            for item in ast.walk(candidate.left)
                        )
                    ):
                        guarded = True
                        break
            if not guarded:
                failures.append(f"{path.name}:{comparison.lineno}")
    assert failures == []


def expected_closure():
    return suite.ExpectedClosure(
        anchor_sha256="d" * 64,
        image_sha256="e" * 64,
        system_python_sha256="f" * 64,
        loader_preload_sha256="8" * 64,
        ldconfig_sha256="9" * 64,
    )


def plan() -> dict:
    return json.loads((ROOT / "deployment" / "dev29" / "read_plan.json").read_text("utf-8"))


def runtime() -> dict:
    fixed = plan()["runtime"]
    state = f"/var/lib/odoo-accounting-cli-v3/test/candidates/{RELEASE}"
    secrets = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE}"
    return {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        **fixed,
        "release_root": f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}",
        "canonical_package_path": (
            f"/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-{RELEASE}.tar.gz"
        ),
        "canonical_package_sha256": "c" * 64,
        "auth_state_path": f"{state}/auth/state.sqlite3",
        "receipt_state_path": f"{state}/receipt/state.sqlite3",
        "gcov_state_path": f"{state}/gcov",
        "auth_key_id": "test-auth-dev29-unit",
        "receipt_key_id": "test-receipt-dev29-unit",
        "auth_secret_path": f"{secrets}/auth.hmac",
        "receipt_secret_path": f"{secrets}/receipt.hmac",
    }


def closure_document() -> dict:
    identity = expected_identity()
    configuration = runtime()
    mount = f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"
    sealed = f"/etc/odoo-accounting-cli-v3/dependencies/{RELEASE}/odoo-server19.conf"
    binds = [
        {
            "source": f"{mount}/odoo-server",
            "destination": "/opt/odoo/odoo19/odoo-server",
        },
        {
            "source": f"{mount}/odoo19-venv",
            "destination": "/opt/odoo/odoo19/odoo19-venv",
        },
        {
            "source": f"{mount}/custom-addons",
            "destination": "/mnt/odoo/odoo19/custom/addons",
        },
        {"source": sealed, "destination": configuration["odoo_config"]},
    ]
    return {
        "schema_version": 1,
        "status": "active_verified",
        "release_identity": identity.document(),
        "closure_identity": {
            "anchor_path": f"/opt/odoo-accounting-cli-v3/dependency-anchors/{RELEASE}.json",
            "anchor_sha256": "d" * 64,
            "image_path": f"/opt/odoo-accounting-cli-v3/dependency-images/{RELEASE}.squashfs",
            "image_sha256": "e" * 64,
            "closure_manifest_sha256": "1" * 64,
            "source_manifest_sha256": "2" * 64,
            "sealed_config_path": sealed,
            "sealed_config_sha256": configuration["odoo_config_sha256"],
            "system_python_sha256": "f" * 64,
            "loader_preload_sha256": "8" * 64,
            "loader_preload": {
                "path": "/etc/ld.so.preload",
                "sha256": "8" * 64,
                "size": 18,
                "mode": "0644",
                "uid": 0,
                "gid": 0,
                "libraries": [
                    {
                        "configured_path": "/$LIB/libonion.so",
                        "expanded_path": "/lib/x86_64-linux-gnu/libonion.so",
                        "rooted_path": "/lib/x86_64-linux-gnu/libonion.so",
                        "resolved_path": "/usr/lib/x86_64-linux-gnu/libonion.so",
                    }
                ],
                "symlink_chain": [
                    {
                        "path": "/lib/x86_64-linux-gnu/libonion.so",
                        "target": "/usr/lib/x86_64-linux-gnu/libonion.so",
                        "uid": 0,
                        "gid": 0,
                    }
                ],
                "loader_token_profile": "glibc-x86_64-debian-lib-v1",
            },
            "installed_modules_count": 138,
            "installed_modules_sha256": "3" * 64,
            "database_graph_sha256": "4" * 64,
            "module_mapping_sha256": "5" * 64,
            "module_payload_mapping_sha256": "7" * 64,
            "external_runtime_manifest_sha256": "6" * 64,
            "external_runtime_manifest_path": f"{mount}/EXTERNAL-RUNTIME-MANIFEST.json",
            "external_runtime_paths": [
                "/etc/ld.so.cache",
                "/etc/ld.so.preload",
                "/usr/bin/python3.12",
                "/usr/lib/python3.12",
                "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/usr/lib/x86_64-linux-gnu/libonion.so",
            ],
            "external_runtime_derivation_method": (
                "static-python-elf-dt-needed-loader-preload-plus-root-owned-ld-cache-v2"
            ),
            "external_runtime_entry_count": 1200,
            "external_runtime_native_path_count": 3,
            "closure_elf_count": 48,
        },
        "database_scope": {
            "database_name": "odoo_test",
            "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        },
        "mount": {
            "mount_point": mount,
            "filesystem_type": "squashfs",
            "read_only": True,
            "nodev": True,
            "nosuid": True,
            "backing_image_sha256": "e" * 64,
            "namespace_scope": "systemd-private",
            "self_mount_namespace": {"device": 1, "inode": 2},
            "host_mount_namespace": {"device": 1, "inode": 3},
            "loop_device": "/dev/loop7",
            "loop_backing_device": 4,
            "loop_backing_inode": 5,
            "loop_offset": 0,
            "loop_sizelimit": 0,
            "loop_read_only": True,
            "loop_autoclear": True,
        },
        "systemd": {
            "execution_model": "single-supervisor-private-mount-namespace-v1",
            "private_mounts": True,
            "bind_read_only_paths": binds,
            "binding_phase": "root-supervisor-after-squashfs-mount",
            "supervisor_unit_properties": ["PrivateMounts=yes"],
            "child_execution": {
                "method": "direct-fork-exec",
                "systemd_run_forbidden": True,
                "credential_drop_required": True,
                "capabilities_zero_required": True,
                "no_new_privileges_required": True,
            },
        },
        "activation": {
            "execution_model": "single-supervisor-private-mount-namespace-v1",
            "bindings": [
                {
                    **item,
                    "mount_id": 100 + index,
                    "major_minor": "7:7",
                    "filesystem_type": "squashfs" if index < 3 else "ext4",
                    "source_device": 4,
                    "source_inode": 1000 + index,
                    "read_only": True,
                    "nodev": True,
                    "nosuid": True,
                }
                for index, item in enumerate(binds)
            ],
            "binding_count": 4,
            "config_binding_last": True,
            "host_mounts_absent": True,
            "direct_child_fork_exec_required": True,
            "systemd_run_forbidden": True,
        },
        "lifecycle": {
            "lock_held_until_cleanup": True,
            "same_supervisor_namespace": True,
            "cleanup_required_before_success_anchor": True,
        },
        "security": dict(suite.CLOSURE_SECURITY_EXPECTED),
    }


def test_release_member_mode_policy_matches_the_builder_whitelist() -> None:
    expected = frozenset(
        {
            "bin/odoo-accounting-cli-v3",
            "bin/odoo-accounting-cli-v3-broker",
            "bin/odoo-accounting-cli-v3-effect-finalizer",
            "deployment/dev9/run-private-mount-gate.sh",
        }
    )
    assert suite.EXECUTABLE_RELEASE_MEMBERS == expected
    assert all(suite._expected_release_member_mode(name) == 0o555 for name in expected)
    assert suite._expected_release_member_mode("VERSION") == 0o444
    assert suite._expected_release_member_mode(str(suite.TRACE_RELATIVE)) == 0o444


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
@pytest.mark.parametrize(
    ("name", "drifted_mode"),
    [
        ("VERSION", 0o555),
        ("bin/odoo-accounting-cli-v3", 0o444),
    ],
)
def test_release_member_mode_policy_rejects_execution_bit_drift(
    tmp_path: Path, name: str, drifted_mode: int
) -> None:
    member = tmp_path / "member"
    member.write_bytes(b"sealed\n")
    member.chmod(drifted_mode)
    with pytest.raises(suite.ReadSuiteError, match="metadata is invalid"):
        suite.stable_read(
            member,
            label="release member mode drift",
            allowed_modes=frozenset({suite._expected_release_member_mode(name)}),
        )


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root fork/SIGKILL private-MANIFEST recovery",
)
@pytest.mark.parametrize(
    "crash_point",
    [
        "private-manifest-after-pending-write",
        "private-manifest-after-chmod-fsync",
        "private-manifest-after-rename-before-directory-fsync",
        "private-manifest-after-directory-fsync",
        "private-manifest-after-seal-journal-cleanup",
    ],
)
def test_private_runtime_trace_manifest_recovers_every_sigkill_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    staging_parent = tmp_path / "staging"
    private_root = tmp_path / "private"
    sidecar = private_root / "evidence" / "runtime-open"
    staging_parent.mkdir(mode=0o700)
    sidecar.mkdir(parents=True, mode=0o700)
    private_root.chmod(0o700)
    (private_root / "evidence").chmod(0o700)
    sidecar.chmod(0o700)
    monkeypatch.setattr(runtime_trace, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(runtime_trace, "PRIVATE_EVIDENCE_PARENT", private_root)
    monkeypatch.setattr(runtime_trace, "_validate_root_chain", lambda _path: None)
    with runtime_trace.PrivateTraceStaging("target") as staging:
        staging.path.write_bytes(b"raw-trace\n")
        identity = staging.seal_to(
            sidecar / "target.strace",
            target_id="target",
            manifest_sha256="a" * 64,
            expected_leader_pid=321,
        )
    entry = {
        "target_id": "target",
        "manifest_sha256": "a" * 64,
        "expected_leader_pid": 321,
        **identity,
    }

    def gate() -> object:
        value = object.__new__(suite.RuntimeTraceGate)
        value.module = runtime_trace
        value.private_sidecar = sidecar
        value.private_entries = [entry]
        value.expected = expected_identity()
        return value

    child = os.fork()
    if child == 0:
        def kill_at(point: str) -> None:
            if point == crash_point:
                os.kill(os.getpid(), signal.SIGKILL)

        suite._crash_injection_gate = kill_at
        gate().seal_private_manifest(("target",))
        os._exit(70)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL
    suite._crash_injection_gate = lambda _point: None
    result = gate().seal_private_manifest(("target",))
    assert result["trace_count"] == 1
    assert result["production_promotion_allowed"] is False
    manifest_path = sidecar / "MANIFEST.json"
    assert manifest_path.is_file()
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
    assert not (sidecar / ".MANIFEST.json.pending").exists()
    assert not (sidecar / ".target.seal.json").exists()


def test_runtime_trace_gate_rejects_callback_child_environment_drift() -> None:
    expected = {"HOME": "/var/lib/postgresql", "PATH": "/usr/bin:/bin"}
    digest = hashlib.sha256(suite.canonical_json(expected)).hexdigest()
    completed = subprocess.CompletedProcess(["child"], 0)
    completed.dev29_attestation = {"environment": dict(expected)}
    assert suite._attested_child_environment_sha256(completed, digest) == digest
    completed.dev29_attestation["environment"]["HOME"] = "/supervisor-home"
    with pytest.raises(suite.ReadSuiteError, match="child environment"):
        suite._attested_child_environment_sha256(completed, digest)


def test_runtime_trace_gate_materializes_approved_dynamic_argv_template() -> None:
    target_id = "release-identity"
    template = SimpleNamespace(target_id=target_id, dynamic_argv_template=True)
    effective = SimpleNamespace(target_id=target_id, dynamic_argv_template=False)
    observed: dict[str, object] = {}

    class TraceError(Exception):
        pass

    def load_manifest(request):
        observed["request"] = request
        return template, SimpleNamespace()

    def materialize(candidate, bootstrap, final):
        observed["materialize"] = (candidate, bootstrap, final)
        return effective

    gate = object.__new__(suite.RuntimeTraceGate)
    gate.expected = SimpleNamespace(release=RELEASE)
    gate.index = {
        "expected_strace_sha256": "1" * 64,
        "expected_static_closure_sha256": "2" * 64,
    }
    gate.targets = {
        target_id: {
            "manifest_sha256": "3" * 64,
            "child_environment_sha256": "4" * 64,
            "watch_roots_sha256": "5" * 64,
        }
    }
    gate.consumed = set()
    gate.module = SimpleNamespace(
        TraceRequest=lambda **values: SimpleNamespace(**values),
        RuntimeOpenTraceError=TraceError,
        load_trace_manifest=load_manifest,
        materialize_bootstrap_template=materialize,
    )
    bootstrap = ("/usr/bin/python3.12", "bootstrap")
    final = ("/usr/bin/python3.12", "final")

    assert gate.manifest(target_id, bootstrap, final) is effective
    request = observed["request"]
    assert request.target_id == target_id
    assert request.expected_manifest_sha256 == "3" * 64
    assert observed["materialize"] == (template, bootstrap, final)


def test_runtime_trace_receipt_set_binds_policy_and_release_members() -> None:
    gate = object.__new__(suite.RuntimeTraceGate)
    gate.expected = SimpleNamespace(release="0.1.0.dev29-a1234567890b")
    gate.index_sha256 = "1" * 64
    gate.index = {
        "expected_strace_sha256": "2" * 64,
        "expected_static_closure_sha256": "3" * 64,
        "policy_source_sha256": "4" * 64,
        "runtime_module_sha256": "5" * 64,
        "release_manifest_sha256": "6" * 64,
    }
    gate.receipts = [{"target_id": "release-identity"}]
    document = gate.document(("release-identity",))
    assert document["policy_source_sha256"] == "4" * 64
    assert document["runtime_module_sha256"] == "5" * 64
    assert document["release_manifest_sha256"] == "6" * 64


def test_runtime_trace_discovery_inventory_is_nonapproval_suite_fragment() -> None:
    gate = object.__new__(suite.RuntimeTraceDiscoveryGate)
    gate.expected = SimpleNamespace(release=RELEASE)
    gate.static_closure_sha256 = "1" * 64
    targets = suite.suite_runtime_trace_targets()
    gate.entries = [
        {
            "target_id": target_id,
            "trace_path": f"/private/{target_id}.strace",
            "expected_leader_pid": 1000 + index,
            "role": "odoo",
            "working_directory": f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}",
            "bootstrap_argv": ["/usr/bin/python3.12", "-I"],
            "final_argv": ["/usr/bin/python3.12", "-I"],
            "expected_returncodes": [0],
        }
        for index, target_id in enumerate(targets)
    ]
    inventory = gate.inventory(
        required_targets=targets,
        expected_static_closure_sha256=None,
        watch_roots=("/opt/odoo-accounting-cli-v3/releases/" + RELEASE,),
        mutable_roots=("/var/lib/odoo-accounting-cli-v3/test/candidates/" + RELEASE,),
        sqlite_delta_contract_sha256=suite.discovery_sqlite_delta_contract_sha256(),
    )
    assert inventory["scope"].endswith("runtime-open-discovery-suite-fragment.v1")
    assert [item["target_id"] for item in inventory["targets"]] == list(targets)
    assert inventory.get("production_promotion_allowed") is None
    gate.entries = gate.entries[:-1]
    with pytest.raises(suite.ReadSuiteError, match="target set"):
        gate.inventory(
            required_targets=targets,
            expected_static_closure_sha256="1" * 64,
            watch_roots=("/opt/odoo-accounting-cli-v3/releases/" + RELEASE,),
            mutable_roots=(),
            sqlite_delta_contract_sha256=suite.discovery_sqlite_delta_contract_sha256(),
        )


def test_runtime_trace_discovery_inventory_rejects_static_closure_mismatch() -> None:
    gate = object.__new__(suite.RuntimeTraceDiscoveryGate)
    gate.expected = SimpleNamespace(release=RELEASE)
    targets = suite.suite_runtime_trace_targets()
    gate.entries = [
        {
            "target_id": target_id,
            "trace_path": f"/private/{target_id}.strace",
            "expected_leader_pid": 1000 + index,
            "role": "odoo",
            "working_directory": f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}",
            "bootstrap_argv": ["/usr/bin/python3.12", "-I"],
            "final_argv": ["/usr/bin/python3.12", "-I"],
            "expected_returncodes": [0],
        }
        for index, target_id in enumerate(targets)
    ]
    gate.static_closure_sha256 = "a" * 64
    with pytest.raises(suite.ReadSuiteError, match="static closure"):
        gate.inventory(
            required_targets=targets,
            expected_static_closure_sha256="b" * 64,
            watch_roots=("/opt/odoo-accounting-cli-v3/releases/" + RELEASE,),
            mutable_roots=(),
            sqlite_delta_contract_sha256=suite.discovery_sqlite_delta_contract_sha256(),
        )


def _runtime_trace_release_fixture(
    tmp_path: Path,
) -> tuple[suite.ExpectedIdentity, dict[str, object], bytes, Path]:
    runtime_payload = b"BOUND_VALUE = 'verified-bytes'\n"
    runtime_sha256 = hashlib.sha256(runtime_payload).hexdigest()
    required = (
        suite.PLAN_RELATIVE,
        suite.SIGNER_RELATIVE,
        suite.ORACLE_RELATIVE,
        suite.CLOSURE_RELATIVE,
        suite.DIRECT_CHILD_RELATIVE,
        suite.RUNNER_RELATIVE,
        suite.VERIFIER_RELATIVE,
        suite.LAUNCHER_RELATIVE,
    )
    files = [
        {"path": str(path), "sha256": "1" * 64, "size": 1}
        for path in required
    ]
    files.append(
        {
            "path": str(suite.TRACE_RELATIVE),
            "sha256": runtime_sha256,
            "size": len(runtime_payload),
        }
    )
    unsigned = {
        "commit": COMMIT,
        "files": files,
        "schema_version": 1,
        "version": VERSION,
    }
    semantic_sha256 = hashlib.sha256(suite.canonical_json(unsigned)).hexdigest()
    manifest = {**unsigned, "manifest_sha256": semantic_sha256}
    manifest_payload = suite.canonical_json(manifest) + b"\n"
    identity = suite.ExpectedIdentity(
        release=RELEASE,
        version=VERSION,
        commit=COMMIT,
        manifest_sha256=semantic_sha256,
        package_sha256="c" * 64,
    )
    release_root = tmp_path / identity.release
    runtime_path = release_root.joinpath(*suite.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_bytes(runtime_payload)
    (release_root / "RELEASE-MANIFEST.json").write_bytes(manifest_payload)
    index = {
        "runtime_module_sha256": runtime_sha256,
        "release_manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
    }
    return identity, index, runtime_payload, runtime_path


def test_runtime_trace_release_binding_rejects_wrong_module_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, index, _payload, _runtime_path = _runtime_trace_release_fixture(tmp_path)
    monkeypatch.setattr(suite, "RELEASE_PARENT", tmp_path)
    index["runtime_module_sha256"] = "7" * 64
    with pytest.raises(suite.ReadSuiteError, match="runtime-open trace module digest"):
        suite._read_runtime_trace_release_binding(
            identity, index, enforce_root=False
        )


def test_runtime_trace_release_binding_rejects_wrong_manifest_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, index, _payload, _runtime_path = _runtime_trace_release_fixture(tmp_path)
    monkeypatch.setattr(suite, "RELEASE_PARENT", tmp_path)
    index["release_manifest_sha256"] = "8" * 64
    with pytest.raises(suite.ReadSuiteError, match="release manifest digest"):
        suite._read_runtime_trace_release_binding(
            identity, index, enforce_root=False
        )


@pytest.mark.parametrize(
    ("member_field", "wrong_value"),
    (("sha256", "9" * 64), ("size", 999_999)),
)
def test_runtime_trace_release_binding_rejects_wrong_manifest_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    member_field: str,
    wrong_value: object,
) -> None:
    identity, index, _payload, _runtime_path = _runtime_trace_release_fixture(tmp_path)
    monkeypatch.setattr(suite, "RELEASE_PARENT", tmp_path)
    manifest_path = tmp_path / identity.release / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    runtime_member = next(
        item
        for item in manifest["files"]
        if item["path"] == str(suite.TRACE_RELATIVE)
    )
    runtime_member[member_field] = wrong_value
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    semantic_sha256 = hashlib.sha256(suite.canonical_json(unsigned)).hexdigest()
    manifest["manifest_sha256"] = semantic_sha256
    manifest_payload = suite.canonical_json(manifest) + b"\n"
    manifest_path.write_bytes(manifest_payload)
    index["release_manifest_sha256"] = hashlib.sha256(manifest_payload).hexdigest()
    bound_identity = suite.ExpectedIdentity(
        release=identity.release,
        version=identity.version,
        commit=identity.commit,
        manifest_sha256=semantic_sha256,
        package_sha256=identity.package_sha256,
    )
    with pytest.raises(suite.ReadSuiteError, match="exactly bound"):
        suite._read_runtime_trace_release_binding(
            bound_identity, index, enforce_root=False
        )


def test_runtime_open_module_executes_only_digest_bound_bytes(
    tmp_path: Path,
) -> None:
    identity, index, payload, runtime_path = _runtime_trace_release_fixture(tmp_path)
    runtime_path.write_bytes(b"BOUND_VALUE = 'replacement-path-bytes'\n")
    module = suite._load_runtime_trace_module(
        payload,
        runtime_path,
        expected_sha256=index["runtime_module_sha256"],
    )
    assert module.BOUND_VALUE == "verified-bytes"


def test_runtime_trace_gate_validates_index_before_loading_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []

    def reject_index(*_args, **_kwargs):
        events.append("index")
        raise suite.ReadSuiteError("invalid index")

    monkeypatch.setattr(suite, "load_runtime_trace_index", reject_index)
    monkeypatch.setattr(
        suite,
        "_read_runtime_trace_release_binding",
        lambda *_args, **_kwargs: events.append("release-binding"),
    )
    monkeypatch.setattr(
        suite,
        "_load_runtime_trace_module",
        lambda *_args, **_kwargs: events.append("module-exec"),
    )
    with pytest.raises(suite.ReadSuiteError, match="invalid index"):
        suite.RuntimeTraceGate(
            expected_identity(),
            expected_index_sha256="1" * 64,
            expected_strace_sha256="2" * 64,
            private_sidecar=tmp_path,
        )
    assert events == ["index"]


def test_runtime_trace_gate_uses_bound_bytes_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = expected_identity()
    monkeypatch.setattr(suite, "RELEASE_PARENT", tmp_path)
    runtime_path = tmp_path / identity.release
    runtime_path = runtime_path.joinpath(*suite.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_bytes(b"BOUND_VALUE = 'initial-path'\n")
    payload = b"BOUND_VALUE = 'verified-before-replacement'\n"
    runtime_sha256 = hashlib.sha256(payload).hexdigest()
    index = {"runtime_module_sha256": runtime_sha256}
    monkeypatch.setattr(
        suite,
        "load_runtime_trace_index",
        lambda *_args, **_kwargs: (index, {}),
    )

    def replace_after_binding(*_args, **_kwargs):
        runtime_path.write_bytes(b"BOUND_VALUE = 'replacement-path'\n")
        return payload, b"release-manifest"

    monkeypatch.setattr(
        suite, "_read_runtime_trace_release_binding", replace_after_binding
    )
    gate = suite.RuntimeTraceGate(
        identity,
        expected_index_sha256="1" * 64,
        expected_strace_sha256="2" * 64,
        private_sidecar=tmp_path / "sidecar",
    )
    assert gate.module.BOUND_VALUE == "verified-before-replacement"


def test_fixed_plan_is_strict_and_covers_all_read_and_negative_cases():
    value, payload = suite.load_plan(
        {"plan": ROOT / "deployment" / "dev29" / "read_plan.json"},
        enforce_root=False,
    )
    assert payload
    assert [item["name"] for item in value["cases"]] == list(suite.POSITIVE_NAMES)
    assert [item["name"] for item in value["negative_cases"]] == list(
        suite.NEGATIVE_NAMES
    )


def test_fixed_plan_rejects_boolean_schema_version(tmp_path: Path) -> None:
    value = plan()
    value["schema_version"] = True
    plan_path = tmp_path / "read_plan.json"
    plan_path.write_bytes(suite.canonical_json(value) + b"\n")
    with pytest.raises(suite.ReadSuiteError, match="read plan envelope"):
        suite.load_plan({"plan": plan_path}, enforce_root=False)


def test_closure_document_requires_exact_ordered_four_bind_plan_and_security_schema(
    monkeypatch: pytest.MonkeyPatch,
):
    document = closure_document()
    real_path = suite.Path
    configuration = runtime()
    mount = f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"
    observed = {
        document["closure_identity"]["image_path"]: SimpleNamespace(
            st_dev=4, st_ino=5
        ),
        "/proc/self/ns/mnt": SimpleNamespace(st_dev=1, st_ino=2),
        "/proc/1/ns/mnt": SimpleNamespace(st_dev=1, st_ino=3),
        f"{mount}/odoo-server": SimpleNamespace(st_mode=stat.S_IFDIR, st_uid=0),
        f"{mount}/odoo19-venv": SimpleNamespace(st_mode=stat.S_IFDIR, st_uid=0),
        f"{mount}/custom-addons": SimpleNamespace(st_mode=stat.S_IFDIR, st_uid=0),
        document["closure_identity"]["sealed_config_path"]: SimpleNamespace(
            st_mode=stat.S_IFREG, st_uid=0, st_nlink=1
        ),
        f"{mount}/custom-addons/{Path(configuration['odoo_config']).name}": SimpleNamespace(
            st_mode=stat.S_IFREG, st_uid=0, st_nlink=1
        ),
    }

    class ObservedPath:
        def __init__(self, value: object) -> None:
            self.value = str(value)

        def lstat(self) -> SimpleNamespace:
            return observed[self.value]

        def stat(self) -> SimpleNamespace:
            return self.lstat()

        def is_symlink(self) -> bool:
            return False

        @property
        def parents(self):
            return real_path(self.value).parents

    monkeypatch.setattr(
        suite,
        "Path",
        lambda value: ObservedPath(value) if str(value) in observed else real_path(value),
    )
    monkeypatch.setattr(
        suite.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=getattr(suite.os, "ST_RDONLY", 1)),
        raising=False,
    )
    assert (
        suite.validate_closure_document(
            document,
            runtime=runtime(),
            plan=plan(),
            expected=expected_identity(),
            expected_closure=expected_closure(),
        )
        is document
    )
    for mutation in (
        lambda value: value["systemd"]["bind_read_only_paths"].reverse(),
        lambda value: value["systemd"]["supervisor_unit_properties"].pop(),
        lambda value: value["security"].update({"unexpected": True}),
        lambda value: value["security"].__setitem__("python_path_escape_absent", False),
        lambda value: value["mount"].__setitem__("read_only", False),
        lambda value: value["mount"].__setitem__(
            "host_mount_namespace", value["mount"]["self_mount_namespace"]
        ),
        lambda value: value["mount"].__setitem__("loop_device", "/dev/loop7-fake"),
        lambda value: value["mount"].__setitem__("loop_read_only", False),
        lambda value: value["mount"].__setitem__("loop_autoclear", False),
        lambda value: value["closure_identity"].__setitem__(
            "external_runtime_derivation_method", "untrusted-list-v1"
        ),
        lambda value: value["closure_identity"].__setitem__(
            "anchor_path", f"/tmp/{RELEASE}.json"
        ),
        lambda value: value["closure_identity"].__setitem__(
            "image_path", f"/tmp/{RELEASE}.squashfs"
        ),
    ):
        changed = deepcopy(document)
        mutation(changed)
        with pytest.raises(suite.ReadSuiteError):
            suite.validate_closure_document(
                changed,
                runtime=runtime(),
                plan=plan(),
                expected=expected_identity(),
                expected_closure=expected_closure(),
            )


def test_direct_child_allowlist_requires_explicit_interpreters_and_roles():
    identity = expected_identity()
    configuration = runtime()
    paths = suite._release_paths(identity)
    launcher = [configuration["odoo_python"], "-I", str(paths["launcher"]), "release", "identity"]
    signer = [
        suite.CLOSURE_PYTHON,
        "-I",
        "-S",
        str(paths["signer"]),
        "--case",
        "registry",
        "--runtime-config",
        str(paths["runtime"]),
    ]
    oracle = [
        configuration["odoo_python"],
        "-I",
        str(paths["oracle"]),
        "witness",
        "--plan",
        str(paths["plan"]),
    ]
    oracle_verify = [
        configuration["odoo_python"],
        "-I",
        str(paths["oracle"]),
        "verify",
        "--plan",
        str(paths["plan"]),
        "--case",
        "trial_balance",
        "--request-stdin",
        "--response-stdin",
    ]
    assert suite._validate_direct_child_command("odoo", launcher, runtime=configuration, expected=identity) == launcher
    assert suite._validate_direct_child_command("signer", signer, runtime=configuration, expected=identity) == signer
    assert suite._validate_direct_child_command("postgres", oracle, runtime=configuration, expected=identity) == oracle
    assert suite._validate_direct_child_command("postgres", oracle_verify, runtime=configuration, expected=identity) == oracle_verify
    for role, command in (
        ("odoo", ["/bin/true"]),
        ("odoo", signer),
        ("postgres", ["systemd-run", "/bin/true"]),
    ):
        with pytest.raises(suite.ReadSuiteError):
            suite._validate_direct_child_command(role, command, runtime=configuration, expected=identity)


def test_oracle_staging_uses_outer_readwrite_run_directory() -> None:
    assert suite.ORACLE_STAGING_PARENT == Path("/run/odoo-accounting-cli-v3-dev29")


def test_read_oracle_currency_rounding_uses_canonical_decimal_text() -> None:
    assert read_oracles._rounding_text("0.010000") == "0.01"
    assert read_oracles._rounding_text("1.000000") == "1"
    assert read_oracles._rounding_text("0.000001") == "0.000001"


def test_sandbox_profile_forbids_nested_systemd_and_has_exact_role_accounts():
    outer = {
        "read_write_paths": [
            "/var/lib/odoo-accounting-cli-v3/evidence",
            "/var/lib/odoo-accounting-cli-v3/evidence-anchors",
            "/var/lib/odoo-accounting-cli-v3/test/candidates/auth",
            "/var/lib/odoo-accounting-cli-v3/test/candidates/receipt",
            "/var/lib/odoo-accounting-cli-v3-broker",
            "/run/odoo-accounting-cli-v3-dev29",
        ]
    }
    profile = suite.sandbox_profile(
        runtime(), expected_identity(), closure_document(), outer
    )
    assert profile["execution_model"] == "single-supervisor-direct-role-children-v1"
    assert profile["nested_systemd_run_forbidden"] is True
    assert profile["actual_systemd_properties_verified"] is True
    assert profile["outer_unit_evidence_sha256"] == suite.hashlib.sha256(
        suite.canonical_json(outer)
    ).hexdigest()
    assert profile["roles"] == {
        "odoo": {"user": "odoo", "group": "odoo"},
        "signer": {"user": "odoo", "group": "odoo"},
        "postgres": {"user": "postgres", "group": "postgres"},
        "verifier": {"user": "root", "group": "root"},
    }


def test_closure_preverification_uses_fixed_root_python_not_odoo_venv(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, b"{}\n", b"")

    monkeypatch.setattr(suite.subprocess, "run", fake_run)
    suite.run_closure_verify(
        {"closure": Path(f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}/deployment/dev29/odoo_closure.py")},
        runtime(),
        plan(),
        expected_identity(),
        expected_closure(),
    )
    assert captured["argv"][:3] == ["/usr/bin/python3.12", "-I", "-S"]
    assert "verify-active" in captured["argv"]
    assert runtime()["odoo_python"] not in captured["argv"]


def test_all_suite_execution_calls_transport_closure_and_expected_identity():
    tree = ast.parse(PATH.read_text("utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    for node in calls:
        name = node.func.id if isinstance(node.func, ast.Name) else None
        keywords = {item.arg for item in node.keywords}
        if name == "_run_odoo_isolated":
            assert {"runtime", "expected", "closure"} <= keywords
        elif name == "_run_postgres":
            assert {"expected", "closure"} <= keywords
        elif name == "dependency_snapshot":
            assert len(node.args) >= 3
        elif name == "_dependency_roots":
            assert len(node.args) >= 3


def test_cli_requires_external_closure_anchor_and_image_digests():
    destinations = {action.dest for action in suite._parser()._actions}
    assert "expected_closure_anchor_sha256" in destinations
    assert "expected_closure_image_sha256" in destinations
    assert "expected_system_python_sha256" in destinations
    assert "expected_ld_so_preload_sha256" in destinations


def test_required_service_identity_hashes_fragment_dropins_and_detects_continuity_drift(
    monkeypatch,
):
    unit = "odoo19.service"
    fragment = "/etc/systemd/system/odoo19.service"
    dropins = (
        "/etc/systemd/system/odoo19.service.d/10-runtime.conf",
        "/run/systemd/system/odoo19.service.d/20-override.conf",
    )
    values = {
        "Id": unit,
        "Names": unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "1234",
        "ExecMainStartTimestampMonotonic": "9000",
        "InvocationID": "a" * 32,
        "NRestarts": "7",
        "StateChangeTimestampMonotonic": "8000",
        "FragmentPath": fragment,
        "SourcePath": "",
        "UnitFileState": "enabled",
        "DropInPaths": " ".join(dropins),
    }

    def fake_run(argv, **kwargs):
        payload = "".join(f"{key}={value}\n" for key, value in values.items())
        return subprocess.CompletedProcess(argv, 0, payload.encode(), b"")

    def fake_snapshot(path, *, label):
        path_text = path.as_posix()
        return {
            "path": path_text,
            "sha256": hashlib.sha256(path_text.encode()).hexdigest(),
            "size": 10,
            "uid": 0,
            "gid": 0,
            "mode": "0644",
        }

    monkeypatch.setattr(suite.subprocess, "run", fake_run)
    monkeypatch.setattr(suite, "_hash_file_snapshot", fake_snapshot)
    before = suite._required_service_identity(unit)
    assert before["properties"]["InvocationID"] == "a" * 32
    assert before["properties"]["NRestarts"] == "7"
    assert [item["path"] for item in before["dropins"]] == list(dropins)

    for mutate in (
        lambda value: value["properties"].__setitem__("InvocationID", "b" * 32),
        lambda value: value["properties"].__setitem__("NRestarts", "8"),
        lambda value: value["dropins"][0].__setitem__("sha256", "c" * 64),
    ):
        after = deepcopy(before)
        mutate(after)
        with pytest.raises(suite.ReadSuiteError, match="system identity changed"):
            suite.require_system_continuity(
                {"services": [before]},
                {"services": [after]},
            )
