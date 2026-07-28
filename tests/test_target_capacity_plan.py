import json
from pathlib import Path

from odoo_accounting_cli_v3 import capacity_plan as target_capacity_plan
from tools import target_capacity_plan as target_capacity_plan_script


def _write(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_capacity_plan_lists_reviewable_v3_candidates_without_cleanup(tmp_path):
    root = tmp_path
    _write(
        root
        / "var/lib/odoo-accounting-cli-v3/evidence-private/dev151-trace/blob",
        100,
    )
    _write(
        root
        / "opt/odoo-accounting-cli-v3/dependency-images/0.1.0.dev150-old.squashfs",
        200,
    )
    _write(
        root
        / "opt/odoo-accounting-cli-v3/dependency-images/0.1.0.dev151-keep.squashfs",
        300,
    )
    _write(
        root
        / "opt/odoo-accounting-cli-v3/upload-sources/odoo-accounting-cli-v3-0.1.0.dev151.tar.gz",
        50,
    )
    _write(
        root
        / "opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev149-old.tar.gz",
        60,
    )

    plan = target_capacity_plan.build_plan(
        root=root,
        required_free_bytes=1,
        keep_releases=frozenset({"0.1.0.dev151-keep"}),
    )

    assert plan["mode"] == "read_only_plan_no_delete"
    assert plan["authorization_required_before_cleanup"] is True
    assert plan["cleanup_executed"] is False
    filesystem = plan["filesystem"]
    assert filesystem["used_bytes"] + filesystem["free_bytes"] == filesystem["total_bytes"]
    assert (
        filesystem["free_bytes"] - filesystem["available_bytes"]
        == filesystem["reserved_unavailable_bytes"]
    )
    paths = {item["path"]: item for item in plan["candidates"]}
    assert "/opt/odoo-accounting-cli-v3/dependency-images/0.1.0.dev151-keep.squashfs" not in paths
    assert paths[
        "/opt/odoo-accounting-cli-v3/dependency-images/0.1.0.dev150-old.squashfs"
    ]["category"] == "old_dependency_image"
    assert paths[
        "/var/lib/odoo-accounting-cli-v3/evidence-private/dev151-trace"
    ]["category"] == "evidence_private"
    assert all(item["requires_explicit_authorization"] is True for item in paths.values())


def test_capacity_plan_does_not_follow_symlink_candidates(tmp_path):
    target = tmp_path / "outside"
    target.write_bytes(b"secret")
    link = (
        tmp_path
        / "var/lib/odoo-accounting-cli-v3/evidence-private/link-to-outside"
    )
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError:
        return

    plan = target_capacity_plan.build_plan(
        root=tmp_path,
        required_free_bytes=1,
        keep_releases=frozenset(),
    )

    assert plan["candidates"] == []


def test_cli_outputs_canonical_read_only_json(tmp_path, capsys):
    _write(
        tmp_path / "var/lib/odoo-accounting-cli-v3/dependency-build/stale/file",
        10,
    )

    code = target_capacity_plan_script.main(
        ["--root", str(tmp_path), "--required-free-bytes", "1"]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == target_capacity_plan.PLAN_KIND
    assert payload["cleanup_executed"] is False
    assert payload["candidates"][0]["category"] == "stale_dependency_build_stage"


def test_legacy_script_uses_packaged_capacity_plan(tmp_path, capsys):
    _write(
        tmp_path / "opt/odoo-accounting-cli-v3/upload-sources/source.tar.gz",
        10,
    )

    code = target_capacity_plan_script.main(
        ["--root", str(tmp_path), "--required-free-bytes", "1"]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == target_capacity_plan.PLAN_KIND
    assert payload["cleanup_executed"] is False
    assert payload["candidates"][0]["category"] == "uploaded_release_source"
