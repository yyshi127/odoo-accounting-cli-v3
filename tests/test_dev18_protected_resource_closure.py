from __future__ import annotations

import importlib.util
import os
import stat
import sys
from copy import deepcopy
from pathlib import Path, PurePosixPath

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = PROJECT_ROOT / "deployment" / "dev18" / "sandbox_capacity_gate.py"
FIXTURE_PATH = PROJECT_ROOT / "tests" / "test_dev18_sandbox_capacity_gate.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_module("dev18_protected_resource_gate", GATE_PATH)
fixtures = _load_module("dev18_protected_resource_fixtures", FIXTURE_PATH)


def _mount_identity(
    *,
    kernel_mount_id: str = "29",
    mount_source: str = "/dev/vda2",
    major_minor: str = "AUTO",
) -> dict[str, object]:
    return {
        "kernel_mount_id": kernel_mount_id,
        "parent_mount_id": "1",
        "major_minor": major_minor,
        "mount_root": "/",
        "mount_point": "/",
        "mount_options": "rw,relatime",
        "optional_fields": ["shared:1"],
        "filesystem_type": "ext4",
        "mount_source": mount_source,
        "super_options": "rw,errors=remount-ro",
    }


def _tree_resource(path: Path, *, expected_entry_count: int) -> dict[str, object]:
    return {
        "resource_id": "legacy-v2-tree",
        "path": str(path),
        "kind": "directory_tree",
        "expected_state": "present",
        "expected_identity_sha256": "1" * 64,
        "expected_entry_count": expected_entry_count,
        "expected_total_regular_file_bytes": expected_entry_count - 1,
    }


def _absent_resource(path: Path) -> dict[str, object]:
    return {
        "resource_id": "v3-current-route",
        "path": str(path),
        "kind": "absent",
        "expected_state": "absent",
        "expected_identity_sha256": "2" * 64,
        "expected_entry_count": 0,
        "expected_total_regular_file_bytes": 0,
    }


def _capture(
    resource: dict[str, object],
    *,
    mount: dict[str, object],
    suffix: str = "before",
) -> dict[str, object]:
    candidate = Path(str(resource["path"]))
    while True:
        try:
            metadata = candidate.lstat()
            break
        except (FileNotFoundError, NotADirectoryError):
            if candidate.parent == candidate:
                raise
            candidate = candidate.parent
    if mount["major_minor"] == "AUTO" and hasattr(os, "major"):
        mount["major_minor"] = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    try:
        captured = gate._capture_resources(
            [resource], suffix=suffix, mount_entries=[mount]
        )
    except TypeError as exc:
        # Keep the red test diagnostic focused on the missing security
        # property while the pre-closure collector has no mount snapshot
        # parameter. Once that parameter exists, unrelated TypeErrors must not
        # be hidden by this compatibility path.
        if "unexpected keyword argument 'mount_entries'" not in str(exc):
            raise
        captured = gate._capture_resources([resource], suffix=suffix)
    return captured[str(resource["resource_id"])]


def _closed_resource_contract() -> tuple[dict[str, object], dict[str, object]]:
    policy = deepcopy(fixtures.policy())
    observation = deepcopy(fixtures.observation())
    expected_metrics = {
        "v2-source": (669, 5_000_000),
        "pi-bridge-v2": (1, 50_000),
        "v3-current-route": (0, 0),
    }

    for item in policy["protected_resources"]:
        resource_id = item["resource_id"]
        entry_count, total_bytes = expected_metrics[resource_id]
        item["expected_entry_count"] = entry_count
        item["expected_total_regular_file_bytes"] = total_bytes
        if resource_id == "v2-source":
            item["path"] = "/srv/odoo-v2"
            item["kind"] = "directory_tree"
        elif resource_id == "v3-current-route":
            # Absence is evidence only when its ancestor and covering mount are
            # represented by a non-null, policy-bound aggregate identity.
            item["expected_identity_sha256"] = "e" * 64

    for item in observation["protected_resources"]:
        resource_id = item["resource_id"]
        entry_count, total_bytes = expected_metrics[resource_id]
        item["entry_count_before"] = entry_count
        item["entry_count_after"] = entry_count
        item["total_regular_file_bytes_before"] = total_bytes
        item["total_regular_file_bytes_after"] = total_bytes
        if resource_id == "v3-current-route":
            item["identity_sha256_before"] = "e" * 64
            item["identity_sha256_after"] = "e" * 64
        elif resource_id == "v2-source":
            item["actual_kind_before"] = "directory_tree"
            item["actual_kind_after"] = "directory_tree"
    return policy, observation


def test_directory_tree_aggregate_covers_content_and_metadata_after_entry_128(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy_v2 = tmp_path / "legacy-v2"
    legacy_v2.mkdir()
    files = []
    for index in range(137):
        child = legacy_v2 / f"entry-{index:03d}.py"
        child.write_bytes(b"A")
        files.append(child)

    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    resource = _tree_resource(legacy_v2, expected_entry_count=138)
    first = _capture(resource, mount=mount)

    # Keep length and directory membership unchanged. A collector that hashes
    # only the directory, or truncates a manifest at 128 rows, misses this.
    files[136].write_bytes(b"B")
    second = _capture(resource, mount=mount, suffix="after")

    assert first["identity_sha256_before"] != second["identity_sha256_after"]
    assert first["state_before"] == "present"
    assert first["entry_count_before"] == 138  # root plus 137 descendants
    assert first["total_regular_file_bytes_before"] == 137
    assert second["entry_count_after"] == 138
    assert second["total_regular_file_bytes_after"] == 137

    original_mode = stat.S_IMODE(files[136].stat().st_mode)
    changed_mode = original_mode ^ stat.S_IWUSR
    try:
        files[136].chmod(changed_mode)
        third = _capture(resource, mount=mount, suffix="after")
        assert third["identity_sha256_after"] != second["identity_sha256_after"]
    finally:
        files[136].chmod(original_mode)


def test_capture_ancestor_identity_tolerates_sibling_churn_but_rejects_mode_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "reviewed-parent"
    parent.mkdir()
    target = parent / "protected"
    target.write_bytes(b"x")
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    original_read = gate._read_live_bytes
    sibling_created = False

    def read_with_unrelated_sibling(
        path: Path, label: str, *, maximum: int = 64 * 1024 * 1024
    ) -> bytes:
        nonlocal sibling_created
        payload = original_read(path, label, maximum=maximum)
        if path == target and not sibling_created:
            (parent / "unrelated-sibling").mkdir()
            sibling_created = True
        return payload

    monkeypatch.setattr(gate, "_read_live_bytes", read_with_unrelated_sibling)
    resource = {
        **_tree_resource(target, expected_entry_count=1),
        "kind": "regular_file",
    }

    captured = _capture(resource, mount=mount)

    assert sibling_created is True
    assert captured["state_before"] == "present"

    original_mode = stat.S_IMODE(parent.stat().st_mode)
    changed_mode = original_mode ^ stat.S_IWUSR

    def read_with_ancestor_permission_change(
        path: Path, label: str, *, maximum: int = 64 * 1024 * 1024
    ) -> bytes:
        payload = original_read(path, label, maximum=maximum)
        parent.chmod(changed_mode)
        return payload

    monkeypatch.setattr(
        gate, "_read_live_bytes", read_with_ancestor_permission_change
    )
    try:
        with pytest.raises(gate.CapacityGateError, match="(?i)ancestor.*changed"):
            _capture(resource, mount=mount, suffix="after")
    finally:
        parent.chmod(original_mode)


def test_absent_identity_binds_existing_ancestor_and_covering_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "v3-release-root"
    parent.mkdir()
    missing = parent / "current"
    resource = _absent_resource(missing)
    mount_a = _mount_identity()
    active_mount = mount_a
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: active_mount)

    first = _capture(resource, mount=mount_a)
    assert first["state_before"] == "absent"
    assert first["identity_sha256_before"] is not None
    assert first["entry_count_before"] == 0

    # The target remains absent, but replacing its nearest existing ancestor
    # must invalidate the reviewed absence proof.
    original_parent = tmp_path / "original-v3-release-root"
    parent.rename(original_parent)
    parent.mkdir()
    second = _capture(resource, mount=mount_a, suffix="after")
    assert second["state_after"] == "absent"
    assert second["identity_sha256_after"] != first["identity_sha256_before"]

    # A stable bind mount is visible through mountinfo even when the target is
    # absent on both sides. The covering mount therefore belongs in the hash.
    active_mount = _mount_identity(
        kernel_mount_id="41", mount_source="/dev/mapper/hidden-tree"
    )
    third = _capture(resource, mount=active_mount, suffix="after")
    assert third["identity_sha256_after"] != second["identity_sha256_after"]


def test_absent_capture_rejects_symlink_in_existing_ancestor_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_parent = tmp_path / "real-v3-release-root"
    real_parent.mkdir()
    routed_parent = tmp_path / "v3-release-root"
    try:
        os.symlink(real_parent, routed_parent, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    with pytest.raises(gate.CapacityGateError, match="(?i)ancestor.*symlink"):
        _capture(_absent_resource(routed_parent / "current"), mount=mount)
    with pytest.raises(gate.CapacityGateError, match="(?i)ancestor.*symlink"):
        gate._resource_ancestor_identity(routed_parent, routed_parent.lstat())


def test_policy_and_observation_bind_tree_metrics_and_absence_identity() -> None:
    policy, observation = _closed_resource_contract()

    report = gate.evaluate(policy, observation, now=fixtures.NOW)
    assert report["capacity_gate_passed"] is True

    count_drift = deepcopy(observation)
    count_drift["protected_resources"][0]["entry_count_after"] -= 1
    report = gate.evaluate(policy, count_drift, now=fixtures.NOW)
    assert "protected_resource:v2-source" in report["blockers"]

    byte_drift = deepcopy(observation)
    byte_drift["protected_resources"][0]["total_regular_file_bytes_after"] -= 1
    report = gate.evaluate(policy, byte_drift, now=fixtures.NOW)
    assert "protected_resource:v2-source" in report["blockers"]

    absence_drift = deepcopy(observation)
    absence_drift["protected_resources"][2]["identity_sha256_after"] = "f" * 64
    report = gate.evaluate(policy, absence_drift, now=fixtures.NOW)
    assert "protected_resource:v3-current-route" in report["blockers"]


def test_policy_rejects_overlapping_v2_and_v3_resource_roots() -> None:
    policy, _ = _closed_resource_contract()
    v2_root = PurePosixPath(policy["protected_resources"][0]["path"])
    policy["protected_resources"][2]["path"] = str(v2_root / "v3" / "current")

    with pytest.raises(gate.CapacityGateError, match="(?i)overlap"):
        gate._validate_policy(policy)


def test_capture_rejects_declared_regular_file_when_path_is_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_directory = tmp_path / "expected-file"
    actual_directory.mkdir()
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    resource = {
        **_tree_resource(actual_directory, expected_entry_count=1),
        "kind": "regular_file",
    }

    with pytest.raises(gate.CapacityGateError, match="(?i)kind.*regular_file"):
        _capture(resource, mount=mount)


def test_capture_rejects_declared_directory_tree_when_path_is_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_file = tmp_path / "expected-directory"
    actual_file.write_bytes(b"x")
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)

    with pytest.raises(gate.CapacityGateError, match="(?i)kind.*directory_tree"):
        _capture(_tree_resource(actual_file, expected_entry_count=1), mount=mount)


def test_capture_rejects_protected_resource_root_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"x")
    routed = tmp_path / "routed"
    try:
        os.symlink(target, routed)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    resource = {
        **_tree_resource(routed, expected_entry_count=1),
        "kind": "regular_file",
    }

    with pytest.raises(gate.CapacityGateError, match="(?i)symlink"):
        _capture(resource, mount=mount)


@pytest.mark.parametrize("kind", ("regular_file", "directory_tree"))
def test_capture_rejects_intermediate_directory_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    target = real_parent / "protected"
    if kind == "regular_file":
        target.write_bytes(b"x")
        resource = {
            **_tree_resource(target, expected_entry_count=1),
            "kind": "regular_file",
        }
    else:
        target.mkdir()
        resource = _tree_resource(target, expected_entry_count=1)
    routed_parent = tmp_path / "routed-parent"
    try:
        os.symlink(real_parent, routed_parent, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    resource["path"] = str(routed_parent / "protected")
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)

    with pytest.raises(gate.CapacityGateError, match="(?i)physical|ancestor|symlink"):
        _capture(resource, mount=mount)


@pytest.mark.skipif(not hasattr(os, "major"), reason="device major/minor is POSIX-only")
def test_capture_rejects_covering_mount_device_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "protected"
    target.write_bytes(b"x")
    metadata = target.stat()
    observed = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    wrong = "0:1" if observed != "0:1" else "0:2"
    mount = _mount_identity(major_minor=wrong)
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    resource = {
        **_tree_resource(target, expected_entry_count=1),
        "kind": "regular_file",
    }

    with pytest.raises(gate.CapacityGateError, match="(?i)device.*mount"):
        _capture(resource, mount=mount)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is POSIX-only")
def test_capture_rejects_protected_resource_root_special_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fifo = tmp_path / "protected-fifo"
    os.mkfifo(fifo)
    mount = _mount_identity()
    monkeypatch.setattr(gate, "_covering_mount", lambda path, entries: mount)
    resource = {
        **_tree_resource(fifo, expected_entry_count=1),
        "kind": "regular_file",
    }

    with pytest.raises(gate.CapacityGateError, match="(?i)unsupported|kind"):
        _capture(resource, mount=mount)


def test_evaluator_binds_observed_actual_kind_to_policy_kind() -> None:
    policy, observation = _closed_resource_contract()
    observation["protected_resources"][0]["actual_kind_after"] = "regular_file"

    report = gate.evaluate(policy, observation, now=fixtures.NOW)

    assert "protected_resource:v2-source" in report["blockers"]
