from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from tools import build_release as release_builder


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "runtime_open_policy_source.py"
TEMPLATE = (
    ROOT
    / "deployment"
    / "dev29"
    / "runtime_open_policy_source.template.json"
)
SPEC = importlib.util.spec_from_file_location("dev29_runtime_open_source", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
source_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_tool
SPEC.loader.exec_module(source_tool)


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = _load(
    "dev29_runtime_open_builder_for_source_test",
    "deployment/dev29/runtime_open_manifest_builder.py",
)
runtime_trace = _load(
    "dev29_runtime_open_trace_for_source_test",
    "deployment/dev29/runtime_open_trace.py",
)
read_suite = _load(
    "dev29_read_suite_for_source_test",
    "deployment/dev29/run_read_suite.py",
)


def test_expected_targets_match_immediate_replay_execution_order() -> None:
    targets = list(source_tool.expected_targets())

    trial_signer = targets.index("positive-trial_balance-signer")
    trial_oracle = targets.index("positive-trial_balance-oracle")
    acl_signer = targets.index("negative-acl_deny-signer")
    assert tuple(targets[:-1]) == tuple(
        target
        for target in read_suite.suite_runtime_trace_targets()
        if target != "boundary-probe" and not target.endswith("-read")
    )
    assert "boundary-probe" not in targets
    assert not any(target.endswith("-read") for target in targets)
    assert trial_signer < trial_oracle < acl_signer
    assert "negative-replay-read" not in targets
    assert "negative-replay-signer" not in targets


def _manifests(parent: Path) -> None:
    parent.mkdir()
    environment = {"HOME": "/fixed-home", "PATH": "/usr/bin:/bin"}
    environment_sha256 = hashlib.sha256(
        source_tool.canonical_json(environment)
    ).hexdigest()
    for target_id in reversed(source_tool.expected_targets()):
        document = {
            "target_id": target_id,
            "environment": environment,
            "expected_child_environment_sha256": environment_sha256,
        }
        (parent / f"{target_id}.json").write_bytes(
            source_tool.canonical_json(document) + b"\n"
        )


def _build(parent: Path) -> dict[str, object]:
    return source_tool.build_candidate(
        parent,
        release="0.1.0.dev29-a1234567890b",
        expected_strace_sha256="1" * 64,
        expected_static_closure_sha256="2" * 64,
        expected_runtime_module_sha256="3" * 64,
        expected_release_manifest_sha256="4" * 64,
    )


def _target_role(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith(
        "-oracle"
    ):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"


def _full_manifests(
    parent: Path, release: str, *, dynamic_template: bool = True
) -> None:
    parent.mkdir()
    release_root = f"/opt/odoo-accounting-cli-v3/releases/{release}"
    mounts = [
        json.dumps({"mount": index}, sort_keys=True, separators=(",", ":"))
        for index in range(5)
    ]
    watches = ["/dev", "/etc", "/opt", "/proc", "/usr", "/var"]
    watch_sha256 = hashlib.sha256(
        runtime_trace.canonical_json(tuple(watches))
    ).hexdigest()
    for target_id in source_tool.expected_targets():
        role = _target_role(target_id)
        no_site = role in {"signer", "verifier"}
        script = {
            "odoo": f"{release_root}/bin/odoo-accounting-cli-v3",
            "signer": f"{release_root}/deployment/dev29/sign_read.py",
            "postgres": f"{release_root}/deployment/dev29/read_oracles.py",
            "verifier": f"{release_root}/deployment/dev29/verify_read_evidence.py",
        }[role]
        final = [
            "/usr/bin/python3.12",
            "-I",
            "-B",
            *(["-S"] if no_site else []),
            script,
            "--fixed-test-target",
            target_id,
        ]
        bootstrap = [
            "/usr/bin/python3.12",
            "-I",
            "-B",
            *(["-S"] if no_site else []),
            f"{release_root}/deployment/dev29/direct_child.py",
            "--role",
            role,
            "--attestation-fd",
            "7",
            "--expected-uid",
            "1001",
            "--expected-gid",
            "1001",
            "--expected-python",
            "/usr/bin/python3.12",
            "--expected-venv-root",
            "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
            "--release-root",
            release_root,
            "--expected-self-namespace-device",
            "4",
            "--expected-self-namespace-inode",
            "100",
            "--expected-host-namespace-device",
            "4",
            "--expected-host-namespace-inode",
            "200",
            "--expected-loop-device",
            "/dev/loop7",
        ]
        for mount in mounts:
            bootstrap.extend(("--expected-mount-json", mount))
        bootstrap.extend(("--", *final))
        if dynamic_template:
            bootstrap = list(
                runtime_trace.dynamic_bootstrap_template(
                    tuple(bootstrap),
                    tuple(final),
                    role=role,
                    release_root=release_root,
                )
            )
        environment = dict(runtime_trace.ROLE_ENVIRONMENTS[role])
        document = {
            "schema_version": 1,
            "scope": runtime_trace.SCOPE,
            "release": release,
            "target_id": target_id,
            "role": role,
            "working_directory": release_root,
            "environment": environment,
            "bootstrap_argv": bootstrap,
            "final_argv": final,
            "allowed_paths": ["/usr/bin/python3.12"],
            "path_access_policy": [
                {
                    "path": "/usr/bin/python3.12",
                    "role": role,
                    "classification": "immutable",
                    "allowed_access": ["execute", "metadata", "read"],
                    "create_suffixes": [],
                    "delta_verifier": None,
                    "delta_contract_sha256": None,
                    "allow_success": True,
                    "allowed_errnos": [],
                    "failure_guard": None,
                }
            ],
            "watch_roots": watches,
            "expected_static_closure_sha256": "2" * 64,
            "expected_child_environment_sha256": hashlib.sha256(
                runtime_trace.canonical_json(environment)
            ).hexdigest(),
            "expected_watch_roots_sha256": watch_sha256,
            "expected_returncodes": [0],
        }
        (parent / f"{target_id}.json").write_bytes(
            source_tool.canonical_json(document) + b"\n"
        )


def _release_artifacts(release_root: Path, *, commit: str) -> tuple[str, str]:
    version_payload = b"0.1.0.dev29\n"
    (release_root / "VERSION").parent.mkdir(parents=True, exist_ok=True)
    (release_root / "VERSION").write_bytes(version_payload)
    runtime_path = release_root / "deployment" / "dev29" / "runtime_open_trace.py"
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_payload = (ROOT / "deployment/dev29/runtime_open_trace.py").read_bytes()
    runtime_path.write_bytes(runtime_payload)
    manifest = release_builder.payload_manifest(
        {
            "VERSION": version_payload,
            "deployment/dev29/runtime_open_trace.py": runtime_payload,
        },
        release_builder.ReleaseIdentity(
            version="0.1.0.dev29",
            commit=commit,
        ),
    )
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    manifest_path.write_bytes(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    return (
        hashlib.sha256(runtime_payload).hexdigest(),
        hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    )


def test_checked_in_template_is_the_canonical_generator_contract() -> None:
    assert TEMPLATE.read_bytes() == (
        source_tool.canonical_json(source_tool.template_document()) + b"\n"
    )
    assert source_tool.template_document()["approval_contract"] == {
        "artifact": "canonical-policy-source-json-plus-lf",
        "builder_argument": "--expected-source-sha256",
        "candidate_is_approval": False,
    }


def test_candidate_generation_is_deterministic_and_target_ordered(
    tmp_path: Path,
) -> None:
    manifests = tmp_path / "manifests"
    _manifests(manifests)
    first = _build(manifests)
    second = _build(manifests)
    assert source_tool.canonical_json(first) == source_tool.canonical_json(second)
    assert tuple(item["target_id"] for item in first["targets"]) == (
        source_tool.expected_targets()
    )
    assert first["production_promotion_allowed"] is False


def test_cli_writes_once_and_reports_review_digest(
    tmp_path: Path, capsys
) -> None:
    manifests = tmp_path / "manifests"
    _manifests(manifests)
    output = tmp_path / "candidate.json"
    arguments = [
        "--manifest-directory",
        str(manifests),
        "--release",
        "0.1.0.dev29-a1234567890b",
        "--expected-strace-sha256",
        "1" * 64,
        "--expected-static-closure-sha256",
        "2" * 64,
        "--expected-runtime-module-sha256",
        "3" * 64,
        "--expected-release-manifest-sha256",
        "4" * 64,
        "--output",
        str(output),
    ]
    assert source_tool.main(arguments) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert result["candidate_is_approval"] is False
    assert output.read_bytes().endswith(b"\n")
    assert source_tool.main(arguments) == 2
    assert "candidate refused" in capsys.readouterr().err


def test_candidate_rejects_extra_or_noncanonical_manifest(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    _manifests(manifests)
    (manifests / "extra.json").write_text("{}\n", encoding="utf-8")
    try:
        _build(manifests)
    except source_tool.CandidateSourceError as exc:
        assert "target set" in str(exc)
    else:
        raise AssertionError("extra manifest was accepted")
    (manifests / "extra.json").unlink()
    target = source_tool.expected_targets()[0]
    document = json.loads((manifests / f"{target}.json").read_text(encoding="utf-8"))
    (manifests / f"{target}.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    try:
        _build(manifests)
    except source_tool.CandidateSourceError as exc:
        assert "not canonical" in str(exc)
    else:
        raise AssertionError("noncanonical manifest was accepted")


def test_full_32_target_candidate_uses_real_validator_and_fresh_index(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    release = "0.1.0.dev29-a1234567890b"
    release_root = tmp_path / "release"
    runtime_sha256, release_manifest_sha256 = _release_artifacts(
        release_root,
        commit="a1234567890b" + "c" * 28,
    )
    manifests = tmp_path / "full-manifests"
    _full_manifests(manifests, release)
    candidate_path = tmp_path / "candidate.json"
    assert (
        source_tool.main(
            [
                "--manifest-directory",
                str(manifests),
                "--release",
                release,
                "--expected-strace-sha256",
                "1" * 64,
                "--expected-static-closure-sha256",
                "2" * 64,
                "--expected-runtime-module-sha256",
                runtime_sha256,
                "--expected-release-manifest-sha256",
                release_manifest_sha256,
                "--output",
                str(candidate_path),
            ]
        )
        == 0
    )
    candidate_result = json.loads(capsys.readouterr().out)
    source_sha256 = candidate_result["source_sha256"]
    candidate = json.loads(candidate_path.read_bytes())
    install_parent = tmp_path / "installed"
    install_parent.mkdir()
    result = builder.build_policy(
        candidate,
        expected_source_sha256=source_sha256,
        expected_strace_sha256="1" * 64,
        expected_runtime_module_sha256=runtime_sha256,
        expected_release_manifest_sha256=release_manifest_sha256,
        release_root=release_root,
        install_parent=install_parent,
        enforce_root=False,
    )
    assert result["target_count"] == len(source_tool.expected_targets())
    index_path = install_parent / release / "INDEX.json"
    index_sha256 = hashlib.sha256(index_path.read_bytes()).hexdigest()
    monkeypatch.setattr(read_suite, "TRACE_INDEX_PARENT", install_parent)
    expected = read_suite.ExpectedIdentity(
        release=release,
        version="0.1.0.dev29",
        commit="a1234567890bcdef1234567890abcdef12345678",
        manifest_sha256="a" * 64,
        package_sha256="b" * 64,
    )
    index, targets = read_suite.load_runtime_trace_index(
        expected,
        expected_sha256=index_sha256,
        expected_strace_sha256="1" * 64,
        enforce_root=False,
    )
    assert tuple(targets) == source_tool.expected_targets()
    assert index["policy_source_sha256"] == source_sha256
    assert index["runtime_module_sha256"] == runtime_sha256
    assert index["release_manifest_sha256"] == release_manifest_sha256

    original_index_payload = index_path.read_bytes()
    index_path.parent.chmod(0o700)
    index_path.chmod(0o600)
    extra_path = index_path.parent / "EXTRA.json"
    extra_path.write_bytes(b"{}\n")
    with pytest.raises(read_suite.ReadSuiteError, match="policy file set"):
        read_suite.load_runtime_trace_index(
            expected,
            expected_sha256=index_sha256,
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    extra_path.unlink()

    first_target = source_tool.expected_targets()[0]
    manifest_path = index_path.parent / f"{first_target}.json"
    manifest_path.chmod(0o600)
    original_manifest_payload = manifest_path.read_bytes()
    environment_manifest = json.loads(original_manifest_payload)
    environment_manifest["environment"]["HOME"] = "/tampered-home"
    environment_sha256 = hashlib.sha256(
        read_suite.canonical_json(environment_manifest["environment"])
    ).hexdigest()
    environment_manifest["expected_child_environment_sha256"] = (
        environment_sha256
    )
    environment_payload = read_suite.canonical_json(environment_manifest) + b"\n"
    manifest_path.write_bytes(environment_payload)
    environment_index = json.loads(original_index_payload)
    environment_index["targets"][0]["manifest_sha256"] = hashlib.sha256(
        environment_payload
    ).hexdigest()
    environment_index_payload = read_suite.canonical_json(environment_index) + b"\n"
    index_path.write_bytes(environment_index_payload)
    with pytest.raises(read_suite.ReadSuiteError, match="index binding differs"):
        read_suite.load_runtime_trace_index(
            expected,
            expected_sha256=hashlib.sha256(environment_index_payload).hexdigest(),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    watch_manifest = json.loads(original_manifest_payload)
    watch_manifest["watch_roots"].append("/tampered-watch")
    watch_sha256 = hashlib.sha256(
        read_suite.canonical_json(tuple(watch_manifest["watch_roots"]))
    ).hexdigest()
    watch_manifest["expected_watch_roots_sha256"] = watch_sha256
    watch_payload = read_suite.canonical_json(watch_manifest) + b"\n"
    manifest_path.write_bytes(watch_payload)
    watch_index = json.loads(original_index_payload)
    watch_index["targets"][0]["manifest_sha256"] = hashlib.sha256(
        watch_payload
    ).hexdigest()
    watch_index_payload = read_suite.canonical_json(watch_index) + b"\n"
    index_path.write_bytes(watch_index_payload)
    with pytest.raises(read_suite.ReadSuiteError, match="index binding differs"):
        read_suite.load_runtime_trace_index(
            expected,
            expected_sha256=hashlib.sha256(watch_index_payload).hexdigest(),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    manifest_path.write_bytes(original_manifest_payload)
    tampered = json.loads(original_index_payload)
    tampered["policy_source_sha256"] = "7" * 64
    tampered_payload = read_suite.canonical_json(tampered) + b"\n"
    index_path.write_bytes(tampered_payload)
    with pytest.raises(read_suite.ReadSuiteError, match="policy source digest"):
        read_suite.load_runtime_trace_index(
            expected,
            expected_sha256=hashlib.sha256(tampered_payload).hexdigest(),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )


def test_builder_rejects_policy_bound_to_one_ephemeral_namespace(
    tmp_path: Path,
) -> None:
    release = "0.1.0.dev29-a1234567890b"
    release_root = tmp_path / "release"
    runtime_sha256, release_manifest_sha256 = _release_artifacts(
        release_root,
        commit="a1234567890b" + "c" * 28,
    )
    manifests = tmp_path / "ephemeral-manifests"
    _full_manifests(manifests, release, dynamic_template=False)
    candidate = source_tool.build_candidate(
        manifests,
        release=release,
        expected_strace_sha256="1" * 64,
        expected_static_closure_sha256="2" * 64,
        expected_runtime_module_sha256=runtime_sha256,
        expected_release_manifest_sha256=release_manifest_sha256,
    )
    source_sha256 = hashlib.sha256(
        source_tool.canonical_json(candidate) + b"\n"
    ).hexdigest()
    install_parent = tmp_path / "installed"
    install_parent.mkdir()

    with pytest.raises(builder.PolicyBuildError, match="dynamic bootstrap template"):
        builder.build_policy(
            candidate,
            expected_source_sha256=source_sha256,
            expected_strace_sha256="1" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=release_root,
            install_parent=install_parent,
            enforce_root=False,
        )

    assert not any(install_parent.iterdir())


@pytest.mark.skipif(
    os.environ.get("DEV29_REAL_POLICY_INSTALL_TEST") != "1",
    reason="set DEV29_REAL_POLICY_INSTALL_TEST=1 for canonical Linux/root install",
)
def test_real_root_full_policy_cli_installs_canonical_fresh_release(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.skip("canonical runtime-open policy installation requires Linux root")
    base = Path("/opt/odoo-accounting-cli-v3")
    releases = base / "releases"
    install_parent = base / "runtime-open-manifests"
    if (
        not base.is_dir()
        or base.is_symlink()
        or stat.S_IMODE(base.stat().st_mode) != 0o755
        or not releases.is_dir()
        or releases.is_symlink()
    ):
        pytest.skip("canonical sealed-release parents are unavailable")
    commit = hashlib.sha256(
        f"dev29-policy-e2e-{os.getpid()}".encode("ascii")
    ).hexdigest()[:40]
    release = f"0.1.0.dev29-{commit[:12]}"
    release_root = releases / release
    destination = install_parent / release
    assert not release_root.exists()
    assert not destination.exists()
    try:
        runtime_sha256, release_manifest_sha256 = _release_artifacts(
            release_root,
            commit=commit,
        )
        for member in (
            release_root / "deployment/dev29/runtime_open_trace.py",
            release_root / "RELEASE-MANIFEST.json",
        ):
            member.chmod(0o444)
        release_root.chmod(0o555)
        manifests = tmp_path / "full-manifests"
        _full_manifests(manifests, release)
        candidate_path = tmp_path / "approved-policy-source.json"
        assert (
            source_tool.main(
                [
                    "--manifest-directory",
                    str(manifests),
                    "--release",
                    release,
                    "--expected-strace-sha256",
                    "1" * 64,
                    "--expected-static-closure-sha256",
                    "2" * 64,
                    "--expected-runtime-module-sha256",
                    runtime_sha256,
                    "--expected-release-manifest-sha256",
                    release_manifest_sha256,
                    "--output",
                    str(candidate_path),
                ]
            )
            == 0
        )
        source_result = json.loads(capsys.readouterr().out)
        assert source_result["candidate_is_approval"] is False
        assert (
            builder.main(
                [
                    "--source",
                    str(candidate_path),
                    "--expected-source-sha256",
                    source_result["source_sha256"],
                    "--expected-strace-sha256",
                    "1" * 64,
                    "--expected-runtime-module-sha256",
                    runtime_sha256,
                    "--expected-release-manifest-sha256",
                    release_manifest_sha256,
                    "--release-root",
                    str(release_root),
                ]
            )
            == 0
        )
        build_result = json.loads(capsys.readouterr().out)
        assert build_result["target_count"] == len(source_tool.expected_targets())
        destination_metadata = destination.lstat()
        assert (destination_metadata.st_uid, destination_metadata.st_gid) == (0, 0)
        assert stat.S_IMODE(destination_metadata.st_mode) == 0o555
        installed_members = tuple(destination.iterdir())
        assert len(installed_members) == len(source_tool.expected_targets()) + 1
        for installed_member in installed_members:
            metadata = installed_member.lstat()
            assert (metadata.st_uid, metadata.st_gid) == (0, 0)
            assert stat.S_IMODE(metadata.st_mode) == 0o400
            assert metadata.st_nlink == 1
        index_path = destination / "INDEX.json"
        monkeypatch.setattr(read_suite, "TRACE_INDEX_PARENT", install_parent)
        expected = read_suite.ExpectedIdentity(
            release=release,
            version="0.1.0.dev29",
            commit=commit,
            manifest_sha256="a" * 64,
            package_sha256="b" * 64,
        )
        index, targets = read_suite.load_runtime_trace_index(
            expected,
            expected_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(),
            expected_strace_sha256="1" * 64,
            enforce_root=True,
        )
        assert tuple(targets) == source_tool.expected_targets()
        assert index["policy_source_sha256"] == source_result["source_sha256"]
    finally:
        if destination.is_dir():
            destination.chmod(0o700)
            for child in destination.iterdir():
                child.chmod(0o600)
                child.unlink()
            destination.rmdir()
        if release_root.is_dir():
            release_root.chmod(0o700)
            for child in sorted(
                release_root.rglob("*"), key=lambda item: len(item.parts), reverse=True
            ):
                if child.is_dir():
                    child.chmod(0o700)
                    child.rmdir()
                else:
                    child.chmod(0o600)
                    child.unlink()
            release_root.rmdir()
