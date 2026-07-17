from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEV15 = PROJECT_ROOT / "deployment" / "dev15"
CHECK_TOOL = DEV15 / "check_toolchain.py"
PLAN_BYTES = (DEV15 / "read_plan.json").read_bytes()
EXPECTED_TOOLCHAIN_MANIFEST_SHA256 = (
    "912a85bdc2bd307b2952d8aed1da0734657350afe4d01a86dc3c0d9631c2a4d3"
)


def _load_check_tool():
    name = "odoo_v3_dev15_check_toolchain_contract"
    spec = importlib.util.spec_from_file_location(name, CHECK_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture(scope="module")
def check_tool():
    return _load_check_tool()


def _set_plan(check_tool, monkeypatch, tmp_path: Path, payload: bytes) -> None:
    (tmp_path / "read_plan.json").write_bytes(payload)
    monkeypatch.setattr(check_tool, "ROOT", tmp_path)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def test_fixed_contract_and_committed_plan_pass(check_tool) -> None:
    assert check_tool.FILES == (
        "install_toolchain.py",
        "runtime_setup.py",
        "sign_read.py",
        "run_multicurrency_read.py",
        "multicurrency_sql_oracle.py",
        "verify_evidence.py",
        "read_plan.json",
    )
    assert check_tool.MANIFEST_CONTROL_FILES == (
        "README.md",
        "check_toolchain.py",
    )
    assert hashlib.sha256(PLAN_BYTES).hexdigest() == check_tool.READ_PLAN_SHA256
    check_tool.check_plan()


def test_committed_manifest_raw_digest_and_payload_are_pinned(check_tool) -> None:
    payload = (DEV15 / "TOOLCHAIN-MANIFEST.json").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_TOOLCHAIN_MANIFEST_SHA256
    document = check_tool.check_manifest(EXPECTED_TOOLCHAIN_MANIFEST_SHA256)
    assert document["application"] == check_tool.APPLICATION
    assert document["toolchain_version"] == check_tool.TOOLCHAIN_VERSION


def test_plan_rejects_raw_byte_drift(
    check_tool, monkeypatch, tmp_path: Path
) -> None:
    _set_plan(check_tool, monkeypatch, tmp_path, PLAN_BYTES + b"\n")

    with pytest.raises(RuntimeError, match="raw SHA-256 mismatch"):
        check_tool.check_plan()


def test_plan_rejects_database_baseline_drift_even_if_repinned(
    check_tool, monkeypatch, tmp_path: Path
) -> None:
    plan = json.loads(PLAN_BYTES)
    plan["database"]["name"] = "different_database"
    payload = _json_bytes(plan)
    _set_plan(check_tool, monkeypatch, tmp_path, payload)
    monkeypatch.setattr(
        check_tool, "READ_PLAN_SHA256", hashlib.sha256(payload).hexdigest()
    )

    with pytest.raises(RuntimeError, match="database baseline mismatch"):
        check_tool.check_plan()


def test_plan_rejects_system_baseline_drift_even_if_repinned(
    check_tool, monkeypatch, tmp_path: Path
) -> None:
    plan = json.loads(PLAN_BYTES)
    plan["system_baseline"]["v2_combined_count"] += 1
    payload = _json_bytes(plan)
    _set_plan(check_tool, monkeypatch, tmp_path, payload)
    monkeypatch.setattr(
        check_tool, "READ_PLAN_SHA256", hashlib.sha256(payload).hexdigest()
    )

    with pytest.raises(RuntimeError, match="system baseline mismatch"):
        check_tool.check_plan()


def _manifest_fixture(check_tool, tmp_path: Path) -> dict[str, object]:
    payloads: dict[str, bytes] = {}
    for name in (*check_tool.FILES, *check_tool.MANIFEST_CONTROL_FILES):
        payload = (DEV15 / name).read_bytes()
        (tmp_path / name).write_bytes(payload)
        payloads[name] = payload

    def entries(names: tuple[str, ...]) -> list[dict[str, object]]:
        return [
            {
                "name": name,
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "size": len(payloads[name]),
            }
            for name in names
        ]

    return {
        "application": deepcopy(check_tool.APPLICATION),
        "control_files": entries(check_tool.MANIFEST_CONTROL_FILES),
        "files": entries(check_tool.FILES),
        "schema_version": 2,
        "toolchain_version": check_tool.TOOLCHAIN_VERSION,
    }


def test_manifest_checks_ordered_payload_and_control_files(
    check_tool, monkeypatch, tmp_path: Path
) -> None:
    manifest = _manifest_fixture(check_tool, tmp_path)
    path = tmp_path / "TOOLCHAIN-MANIFEST.json"
    path.write_bytes(_json_bytes(manifest))
    monkeypatch.setattr(check_tool, "ROOT", tmp_path)
    monkeypatch.setattr(check_tool, "MANIFEST", path)

    manifest_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    assert check_tool.check_manifest(manifest_sha256) == manifest


def test_manifest_rejects_control_file_reordering(
    check_tool, monkeypatch, tmp_path: Path
) -> None:
    manifest = _manifest_fixture(check_tool, tmp_path)
    manifest["control_files"].reverse()
    path = tmp_path / "TOOLCHAIN-MANIFEST.json"
    path.write_bytes(_json_bytes(manifest))
    monkeypatch.setattr(check_tool, "ROOT", tmp_path)
    monkeypatch.setattr(check_tool, "MANIFEST", path)

    manifest_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="control file order or set mismatch"):
        check_tool.check_manifest(manifest_sha256)


def test_main_requires_expected_manifest_sha256(check_tool, capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        check_tool.main([])

    assert raised.value.code == 2
    assert "expected_manifest_sha256" in capsys.readouterr().err


def test_main_rejects_malformed_expected_manifest_sha256(
    check_tool, capsys
) -> None:
    with pytest.raises(SystemExit) as raised:
        check_tool.main(["A" * 64])

    assert raised.value.code == 2
    assert "64 lowercase hex" in capsys.readouterr().err


def test_main_rejects_wrong_manifest_sha256(
    check_tool, monkeypatch, tmp_path: Path, capsys
) -> None:
    manifest = _manifest_fixture(check_tool, tmp_path)
    path = tmp_path / "TOOLCHAIN-MANIFEST.json"
    path.write_bytes(_json_bytes(manifest))
    monkeypatch.setattr(check_tool, "ROOT", tmp_path)
    monkeypatch.setattr(check_tool, "MANIFEST", path)

    with pytest.raises(RuntimeError, match="manifest raw SHA-256 mismatch"):
        check_tool.main(["0" * 64])

    assert capsys.readouterr().out == ""


def test_main_prints_success_summary_with_manifest_sha256(
    check_tool, monkeypatch, tmp_path: Path, capsys
) -> None:
    manifest = _manifest_fixture(check_tool, tmp_path)
    path = tmp_path / "TOOLCHAIN-MANIFEST.json"
    path.write_bytes(_json_bytes(manifest))
    manifest_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(check_tool, "ROOT", tmp_path)
    monkeypatch.setattr(check_tool, "MANIFEST", path)

    assert check_tool.main([manifest_sha256]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "all_checks_passed": True,
        "application_release": check_tool.APPLICATION["release"],
        "toolchain_manifest_sha256": manifest_sha256,
        "toolchain_version": check_tool.TOOLCHAIN_VERSION,
    }
