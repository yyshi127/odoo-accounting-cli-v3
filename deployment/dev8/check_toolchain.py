#!/usr/bin/env python3
"""Check the tracked dev8 deployment toolchain without importing server code."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "TOOLCHAIN-MANIFEST.json"
RELEASE = "0.1.0.dev8-bd21ca07c168"
COMMIT = "bd21ca07c1689a42fbf903b91486269397b44733"
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
TOOLCHAIN_VERSION = "0.1.0.dev8-toolchain.6"
TOOLS = (
    "dev8-install.sh",
    "dev8-runtime-setup.sh",
    "dev8-server-gate.sh",
    "dev8-stage-execution-tools.py",
    "dev8-run-real-reads.sh",
    "dev8-sign-read.py",
    "dev8-launcher-isolation-gate.py",
    "dev8-run-read-oracles.sh",
    "dev6-trial-balance-sql-oracle.py",
    "dev6-ar-sql-oracle.py",
    "dev7-ap-sql-oracle.py",
    "dev8-persistence-audit.py",
    "dev8-runtime-dependency-inventory.py",
    "dev8-canonical-package-negative-gates.py",
    "dev8-freeze-evidence.py",
    "dev8-verify-frozen-evidence.py",
)
SERVER_BASELINE_NAME = "SERVER-BASELINE.json"
MANIFEST_FILES = (*TOOLS, SERVER_BASELINE_NAME)
CONTROL_FILES = {
    "README.md", "TOOLCHAIN-MANIFEST.json", "check_toolchain.py",
    SERVER_BASELINE_NAME,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEREDOC = re.compile(r"<<'(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)'\s*$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON field: {key}")
        value[key] = item
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                return ast.literal_eval(node.value)
    raise RuntimeError(f"missing literal assignment {name}: {path}")


def compile_python_heredocs(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    compiled = 0
    index = 0
    while index < len(lines):
        match = HEREDOC.search(lines[index].rstrip("\r\n"))
        if match is None:
            index += 1
            continue
        delimiter = match.group("delimiter")
        start = index + 1
        end = start
        while end < len(lines) and lines[end].rstrip("\r\n") != delimiter:
            end += 1
        require(end < len(lines), f"unterminated heredoc at {path}:{index + 1}")
        if delimiter == "PY":
            compile("".join(lines[start:end]), f"{path}:{start + 1}", "exec")
            compiled += 1
        index = end + 1
    return compiled


def main() -> None:
    actual_files = {path.name for path in ROOT.iterdir() if path.is_file()}
    require(actual_files == set(TOOLS) | CONTROL_FILES, "deployment/dev8 file set is not exact")

    document = json.loads(
        MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )
    require(
        isinstance(document, dict)
        and set(document)
        == {
            "schema_version",
            "toolchain_version",
            "application_release",
            "application_commit",
            "application_package_sha256",
            "source_directory",
            "files",
        },
        "toolchain manifest fields are not exact",
    )
    require(
        isinstance(document["schema_version"], int)
        and not isinstance(document["schema_version"], bool)
        and document["schema_version"] == 1
        and document["toolchain_version"] == TOOLCHAIN_VERSION
        and document["application_release"] == RELEASE
        and document["application_commit"] == COMMIT
        and document["application_package_sha256"] == PACKAGE_SHA256
        and document["source_directory"] == "deployment/dev8",
        "toolchain manifest identity mismatch",
    )
    entries = document["files"]
    require(isinstance(entries, list) and len(entries) == len(MANIFEST_FILES), "tool manifest count mismatch")
    require(
        [entry.get("name") for entry in entries if isinstance(entry, dict)] == list(MANIFEST_FILES),
        "tool manifest order or names mismatch",
    )
    for entry in entries:
        require(
            isinstance(entry, dict) and set(entry) == {"name", "sha256", "size"},
            "tool manifest entry fields are not exact",
        )
        name = entry["name"]
        size = entry["size"]
        expected_hash = entry["sha256"]
        path = ROOT / name
        require(
            isinstance(size, int)
            and not isinstance(size, bool)
            and size == path.stat().st_size
            and isinstance(expected_hash, str)
            and HEX64.fullmatch(expected_hash) is not None
            and expected_hash == sha256(path),
            f"tool manifest digest or size mismatch: {name}",
        )

    baseline = json.loads(
        (ROOT / SERVER_BASELINE_NAME).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    require(
        isinstance(baseline, dict)
        and set(baseline)
        == {
            "schema_version", "application_release", "captured_at", "hostname",
            "database_uuid", "services", "critical_files", "v3_paths_absent",
            "v3_unit_files", "v3_active_units", "production_dependency_metadata_safe",
            "production_promotion_allowed", "promotion_blockers",
        }
        and isinstance(baseline["schema_version"], int)
        and not isinstance(baseline["schema_version"], bool)
        and baseline["schema_version"] == 1
        and baseline["application_release"] == RELEASE
        and baseline["database_uuid"] == "19b09656-d10f-11f0-9065-00163e54a5ad"
        and baseline["production_dependency_metadata_safe"] is False
        and baseline["production_promotion_allowed"] is False,
        "server baseline envelope mismatch",
    )
    services = baseline["services"]
    require(
        isinstance(services, list)
        and [(item.get("unit"), item.get("main_pid")) for item in services]
        == [("odoo19.service", 2257341), ("sudo-pi-agent-bridge.service", 2065799)],
        "server baseline service identity mismatch",
    )
    critical_files = baseline["critical_files"]
    require(
        isinstance(critical_files, list) and len(critical_files) == 12
        and len({item.get("path") for item in critical_files}) == 12
        and [item["path"] for item in critical_files if int(item["mode"], 8) & 0o022]
        == ["/mnt/odoo/odoo19/custom/addons/sudo_ai_bot/__manifest__.py"],
        "server baseline critical metadata mismatch",
    )

    for name in ("dev8-freeze-evidence.py", "dev8-verify-frozen-evidence.py"):
        require(tuple(literal_assignment(ROOT / name, "TOOL_FILES")) == TOOLS, f"TOOL_FILES mismatch: {name}")

    python_files = [ROOT / name for name in TOOLS if name.endswith(".py")]
    for path in python_files:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    heredoc_count = sum(
        compile_python_heredocs(ROOT / name) for name in TOOLS if name.endswith(".sh")
    )
    require(heredoc_count > 0, "no embedded Python heredocs were checked")

    runtime_gate = (ROOT / "dev8-runtime-setup.sh").read_text(encoding="utf-8")
    server_gate = (ROOT / "dev8-server-gate.sh").read_text(encoding="utf-8")
    for forbidden in ("test-venv", "test-checkout", "pip install", "python3.12"):
        require(forbidden not in runtime_gate and forbidden not in server_gate, f"mutable test fixture returned: {forbidden}")
    require("mutable_candidate_test_fixture_used=false" in server_gate, "mutable fixture marker is missing")
    require("server_unit_test_source=github-ci-run-29319326192" in server_gate, "CI source marker is missing")
    require("production_critical_metadata_safe=false" in server_gate, "production metadata blocker marker is missing")
    install_gate = (ROOT / "dev8-install.sh").read_text(encoding="utf-8")
    require("root_metadata.st_mode & 0o022" in install_gate, "upload parent write guard is missing")
    require("root_metadata.st_mode & 0o007" in install_gate, "upload parent other-access guard is missing")
    require("upload_not_traversable_by_odoo=true" in install_gate, "Odoo upload traversal probe is missing")
    require("root_metadata.st_mode & 0o022" in runtime_gate, "runtime upload parent write guard is missing")
    require("root_metadata.st_mode & 0o007" in runtime_gate, "runtime upload parent other-access guard is missing")
    require("runtime_upload_not_traversable_by_odoo=true" in runtime_gate, "runtime Odoo upload traversal probe is missing")
    require(
        "load_registry(pathlib.Path(sys.argv[1]))" in runtime_gate,
        "runtime registry path conversion is missing",
    )
    for name in ("dev8-server-gate.sh", "dev8-freeze-evidence.py", "dev8-verify-frozen-evidence.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        require(source.count("run_unit_listing(") >= 3, f"systemd no-match listing gate is missing: {name}")
        require("completed.returncode == 1" in source, f"systemd no-match exit contract is missing: {name}")

    print(
        json.dumps(
            {
                "toolchain_version": TOOLCHAIN_VERSION,
                "tool_count": len(TOOLS),
                "python_file_count": len(python_files),
                "embedded_python_blocks": heredoc_count,
                "all_checks_passed": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
