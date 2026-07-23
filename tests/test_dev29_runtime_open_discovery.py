from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "runtime_open_discovery.py"
SPEC = importlib.util.spec_from_file_location("dev29_runtime_open_discovery", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
discovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = discovery
SPEC.loader.exec_module(discovery)

runtime_trace = discovery.runtime_trace

RELEASE = "0.1.0.dev37-9a570b7ad90f"
RELEASE_ROOT = f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}"
STATIC_SHA = "2" * 64
DELTA_SHA = "d" * 64
WATCH_ROOTS = (
    "/dev/loop7",
    "/etc",
    "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
    RELEASE_ROOT,
    "/usr/bin/python3.12",
)


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def argv_text(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(quoted(value) for value in values) + "]"


def target_role(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith("-oracle"):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"


def final_argv(target_id: str) -> tuple[str, ...]:
    role = target_role(target_id)
    no_site = role in {"signer", "verifier"}
    script = {
        "odoo": f"{RELEASE_ROOT}/bin/odoo-accounting-cli-v3",
        "signer": f"{RELEASE_ROOT}/deployment/dev29/sign_read.py",
        "postgres": f"{RELEASE_ROOT}/deployment/dev29/read_oracles.py",
        "verifier": f"{RELEASE_ROOT}/deployment/dev29/verify_read_evidence.py",
    }[role]
    return (
        "/usr/bin/python3.12",
        "-I",
        *(("-S",) if no_site else ()),
        script,
        "--fixed-test-target",
        target_id,
    )


def bootstrap_argv(target_id: str) -> tuple[str, ...]:
    role = target_role(target_id)
    final = final_argv(target_id)
    no_site = role in {"signer", "verifier"}
    mounts = tuple(
        json.dumps({"mount": index}, sort_keys=True, separators=(",", ":"))
        for index in range(5)
    )
    values = [
        "/usr/bin/python3.12",
        "-I",
        *(["-S"] if no_site else []),
        f"{RELEASE_ROOT}/deployment/dev29/direct_child.py",
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
        RELEASE_ROOT,
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
        values.extend(("--expected-mount-json", mount))
    values.extend(("--", *final))
    return tuple(values)


def demotion_argv(target_id: str) -> tuple[str, ...]:
    bootstrap = bootstrap_argv(target_id)
    final = final_argv(target_id)
    return (
        "/usr/bin/python3.12",
        "-I",
        "-S",
        f"{RELEASE_ROOT}/deployment/dev29/runtime_open_trace.py",
        "__dev29_demote_exec_v1__",
        target_role(target_id),
        RELEASE,
        "1001",
        "1001",
        str(len(final)),
        hashlib.sha256(runtime_trace.canonical_json(bootstrap)).hexdigest(),
        hashlib.sha256(runtime_trace.canonical_json(final)).hexdigest(),
        "--",
        *bootstrap,
    )


def raw_trace(target_id: str, trace_path: Path, *, exit_code: int = 0) -> None:
    lines = [
        f'410 execve("/usr/bin/python3.12", {argv_text(demotion_argv(target_id))}, 0x7fff) = 0',
        f'410 execve("/usr/bin/python3.12", {argv_text(bootstrap_argv(target_id))}, 0x7fff) = 0',
        '410 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>',
        f'410 stat("{RELEASE_ROOT}", {{st_mode=S_IFDIR|0555}}, 0) = 0',
        '410 readlink("/proc/self/exe", "/usr/bin/python3.12", 4096) = 19',
        f'410 openat2(AT_FDCWD, "runtime.json", {{flags=O_RDONLY, resolve=RESOLVE_BENEATH}}, 24) = 5<{RELEASE_ROOT}/runtime.json>',
        f'410 execve("/usr/bin/python3.12", {argv_text(final_argv(target_id))}, 0x7fff) = 0',
        f"410 +++ exited with {exit_code} +++",
    ]
    trace_path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def inventory(tmp_path: Path, *, output_traces: bool = True) -> dict[str, object]:
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    targets = []
    for target_id in discovery.policy_source.expected_targets():
        path = trace_dir / f"{target_id}.strace"
        if output_traces:
            raw_trace(target_id, path)
        targets.append(
            {
                "target_id": target_id,
                "trace_path": str(path),
                "expected_leader_pid": 410,
                "role": target_role(target_id),
                "working_directory": RELEASE_ROOT,
                "bootstrap_argv": list(bootstrap_argv(target_id)),
                "final_argv": list(final_argv(target_id)),
                "expected_returncodes": [0],
            }
        )
    return {
        "schema_version": 1,
        "scope": discovery.DISCOVERY_SCOPE,
        "release": RELEASE,
        "expected_static_closure_sha256": STATIC_SHA,
        "watch_roots": list(WATCH_ROOTS),
        "mutable_roots": [],
        "sqlite_delta_contract_sha256": DELTA_SHA,
        "targets": targets,
    }


def test_discovery_builds_nonapproval_review_manifests(tmp_path: Path) -> None:
    output = tmp_path / "review"
    result = discovery.build_review(inventory(tmp_path), output_directory=output)
    assert result["target_count"] == 32
    assert result["candidate_is_approval"] is False
    assert result["production_promotion_allowed"] is False

    review = json.loads((output / "DISCOVERY-REVIEW.json").read_bytes())
    assert review["candidate_is_approval"] is False
    assert tuple(review["target_order"]) == discovery.policy_source.expected_targets()
    assert len(review["reviews"]) == 32
    assert (output / "INDEX.json").exists() is False

    first = json.loads(
        (output / f"{discovery.policy_source.expected_targets()[0]}.json").read_bytes()
    )
    assert first["bootstrap_argv"].count("@DEV29_SELF_NAMESPACE_DEVICE@") == 1
    assert first["expected_static_closure_sha256"] == STATIC_SHA
    assert first["expected_watch_roots_sha256"] == hashlib.sha256(
        runtime_trace.canonical_json(WATCH_ROOTS)
    ).hexdigest()
    process_policy = next(
        item for item in first["path_access_policy"] if item["path"] == "/proc/self/exe"
    )
    assert process_policy["classification"] == "process-view"
    assert process_policy["failure_guard"] is None
    assert "/proc/self" not in first["watch_roots"]


def test_discovery_rejects_incomplete_target_set(tmp_path: Path) -> None:
    value = inventory(tmp_path)
    value["targets"] = value["targets"][:-1]  # type: ignore[index]
    with pytest.raises(discovery.DiscoveryError, match="target order"):
        discovery.build_review(value, output_directory=tmp_path / "review")


def fragments(tmp_path: Path) -> tuple[dict[str, object], dict[str, object]]:
    full = inventory(tmp_path)
    suite_fragment = json.loads(json.dumps(full))
    verifier_fragment = json.loads(json.dumps(full))
    expected = discovery.policy_source.expected_targets()
    suite_fragment["scope"] = discovery.SUITE_FRAGMENT_SCOPE
    suite_fragment["targets"] = suite_fragment["targets"][:-1]
    assert [item["target_id"] for item in suite_fragment["targets"]] == list(
        expected[:-1]
    )
    verifier_fragment["scope"] = discovery.VERIFIER_FRAGMENT_SCOPE
    verifier_fragment["targets"] = verifier_fragment["targets"][-1:]
    assert verifier_fragment["targets"][0]["target_id"] == expected[-1]
    return suite_fragment, verifier_fragment


def test_discovery_merges_suite_and_verifier_fragments(tmp_path: Path) -> None:
    suite_fragment, verifier_fragment = fragments(tmp_path)
    output = tmp_path / "inventory.json"
    result = discovery.merge_fragments(
        suite_fragment,
        verifier_fragment,
        output_inventory=output,
    )
    merged = json.loads(output.read_bytes())
    assert result["target_count"] == 32
    assert result["candidate_is_approval"] is False
    assert result["production_promotion_allowed"] is False
    assert merged["scope"] == discovery.DISCOVERY_SCOPE
    assert tuple(item["target_id"] for item in merged["targets"]) == (
        discovery.policy_source.expected_targets()
    )
    assert result["inventory_sha256"] == hashlib.sha256(
        discovery.canonical_json(merged) + b"\n"
    ).hexdigest()
    with pytest.raises(FileExistsError):
        discovery.merge_fragments(
            suite_fragment,
            verifier_fragment,
            output_inventory=output,
        )


def test_discovery_merge_refuses_fragment_identity_drift(tmp_path: Path) -> None:
    suite_fragment, verifier_fragment = fragments(tmp_path)
    verifier_fragment["expected_static_closure_sha256"] = "3" * 64
    with pytest.raises(discovery.DiscoveryError, match="one identity"):
        discovery.merge_fragments(
            suite_fragment,
            verifier_fragment,
            output_inventory=tmp_path / "inventory.json",
        )


def test_discovery_cli_merges_fragments(tmp_path: Path, capsys) -> None:
    suite_fragment, verifier_fragment = fragments(tmp_path)
    suite_path = tmp_path / "suite.json"
    verifier_path = tmp_path / "verifier.json"
    output = tmp_path / "inventory.json"
    suite_path.write_bytes(discovery.canonical_json(suite_fragment) + b"\n")
    verifier_path.write_bytes(discovery.canonical_json(verifier_fragment) + b"\n")
    assert (
        discovery.main(
            [
                "--suite-fragment",
                str(suite_path),
                "--verifier-fragment",
                str(verifier_path),
                "--output-inventory",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["inventory_path"] == str(output)
    assert json.loads(output.read_bytes())["scope"] == discovery.DISCOVERY_SCOPE


def test_discovery_refuses_watched_process_view(tmp_path: Path) -> None:
    value = inventory(tmp_path)
    value["watch_roots"] = sorted((*WATCH_ROOTS, "/proc/self"))
    with pytest.raises(discovery.DiscoveryError, match="process-view"):
        discovery.build_review(value, output_directory=tmp_path / "review")


def test_discovery_cli_requires_canonical_inventory_and_writes_once(
    tmp_path: Path, capsys
) -> None:
    value = inventory(tmp_path)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_bytes(discovery.canonical_json(value) + b"\n")
    output = tmp_path / "review"
    assert (
        discovery.main(
            ["--inventory", str(inventory_path), "--output-directory", str(output)]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["review_sha256"] == hashlib.sha256(
        (output / "DISCOVERY-REVIEW.json").read_bytes()
    ).hexdigest()
    assert discovery.main(
        ["--inventory", str(inventory_path), "--output-directory", str(output)]
    ) == 2
    assert "discovery refused" in capsys.readouterr().err
