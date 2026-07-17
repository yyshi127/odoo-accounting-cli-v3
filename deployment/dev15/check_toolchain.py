#!/usr/bin/env python3
"""Verify the exact Dev15 multicurrency read-evidence toolchain bytes."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "TOOLCHAIN-MANIFEST.json"
TOOLCHAIN_VERSION = "0.1.0.dev15-read-toolchain.2"
READ_PLAN_SHA256 = (
    "f15442df9d707ed77dc9c79ce0aa67fb022b4e5c1c94889ca4ab5ff0d1b2f161"
)
APPLICATION = {
    "commit": "c4616386f921946cf43cde2de449d2938a837422",
    "manifest_sha256": (
        "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
    ),
    "package_sha256": (
        "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
    ),
    "registry_digest": (
        "ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b"
    ),
    "release": "0.1.0.dev15-c4616386f921",
    "version": "0.1.0.dev15",
}
FILES = (
    "install_toolchain.py",
    "runtime_setup.py",
    "sign_read.py",
    "run_multicurrency_read.py",
    "multicurrency_sql_oracle.py",
    "verify_evidence.py",
    "read_plan.json",
)
MANIFEST_CONTROL_FILES = ("README.md", "check_toolchain.py")
DATABASE = {
    "current_user": "postgres",
    "instance_id": "odoo19@43.165.173.80",
    "name": "odoo_test",
    "oracle_psql": "/usr/lib/postgresql/16/bin/psql",
    "oracle_psql_sha256": (
        "6d593ef8e95e5275691fcc28927cc540282db141ca1ec5e3806e7db5523613cb"
    ),
    "oracle_python": "/usr/bin/python3.12",
    "oracle_python_sha256": (
        "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
    ),
    "server_version_num": 160014,
    "system_identifier": "7616327373742442245",
    "unix_socket_directory": "/var/run/postgresql",
    "unix_socket_path": "/var/run/postgresql/.s.PGSQL.5432",
    "uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
}
SYSTEM_BASELINE = {
    "historical_v2_digest": (
        "1d258235a87bb23d42bd49f5b2055fca4be78ed9e81063b0378d31e3f4696812"
    ),
    "pi_bridge_control_digest": (
        "52fb10453c439d7f3877d0208f335023bef0952a3911c049ab06e64e09974b62"
    ),
    "pi_bridge_control_entries": [
        {
            "component": "pi_bridge_control",
            "path": "extensions/odoo-tools.ts",
            "sha256": (
                "c34484bfb5934513db85a594049a3360b1af62f2496c4c951b4caa000a6e5455"
            ),
            "size": 4117,
        },
        {
            "component": "pi_bridge_control",
            "path": "package-lock.json",
            "sha256": (
                "d61184e2b0270cf151e5ff676f65c8331dd0e6249805037feeb9721d5a4dcf7e"
            ),
            "size": 73928,
        },
        {
            "component": "pi_bridge_control",
            "path": "package.json",
            "sha256": (
                "e3d6676f91231bc000c7d07b28f3100497bc3d442517f1be1c0609e224ef9152"
            ),
            "size": 303,
        },
        {
            "component": "pi_bridge_control",
            "path": "server.mjs",
            "sha256": (
                "fae40056f346df95e55443a1ca44cfd580577c6a7505b87bb46abf9f1d60df9f"
            ),
            "size": 9160,
        },
        {
            "component": "pi_bridge_systemd",
            "path": "sudo-pi-agent-bridge.service",
            "sha256": (
                "e67fabc92fb8e8a3bbf50124d2cf194ca38ad516c4d34b85b0ae17eeb6571764"
            ),
            "size": 424,
        },
    ],
    "pi_bridge_control_roots": {
        "pi_bridge_control": (
            "/mnt/odoo/odoo19/custom/services/pi-agent-bridge"
        ),
        "pi_bridge_systemd": "/etc/systemd/system",
    },
    "services": ["odoo19.service", "sudo-pi-agent-bridge.service"],
    "v2_combined_count": 668,
    "v2_combined_digest": (
        "eb4b194e034fba683794c5d5fd39707588e88fda569f3ac1c982e4b7c23aa891"
    ),
    "v2_components": [
        {
            "component": "tools_v2",
            "count": 576,
            "digest": (
                "860c26d2bca049c46de6696598202de514b2d66c08657a2296d18fd9e210caf1"
            ),
            "root": "/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2",
        },
        {
            "component": "pi_bridge_v2_package",
            "count": 92,
            "digest": (
                "fd2d28fb28c21e983a08d594f31f32f3867ca2ea5c2c4e004f7807ee7cdd5cf9"
            ),
            "root": (
                "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/"
                "odoo_accounting_agent_cli_v2/src/odoo_acc_cli"
            ),
        },
    ],
    "v3_unit_files": [
        "/etc/systemd/system/odoo-accounting-cli-v3-broker.service",
        "/etc/systemd/system/odoo-accounting-cli-v3-pi-broker.socket",
        "/etc/systemd/system/odoo-accounting-cli-v3-session-mint.socket",
        "/etc/systemd/system/odoo-accounting-cli-v3-trusted-approval.socket",
        "/etc/systemd/system/odoo-accounting-cli-v3-pi-bridge.service",
        "/etc/systemd/system/odoo-accounting-cli-v3-pi-bridge.socket",
    ],
}
CONTROL_FILES = frozenset(
    {"README.md", "TOOLCHAIN-MANIFEST.json", "check_toolchain.py", *FILES}
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE = (
    re.compile(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise RuntimeError(f"non-finite JSON number: {value}")


def load_json_bytes(payload: bytes) -> object:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("toolchain manifest must be strict UTF-8 JSON") from exc


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def check_manifest(expected_manifest_sha256: str) -> dict[str, object]:
    require(
        isinstance(expected_manifest_sha256, str)
        and HEX64.fullmatch(expected_manifest_sha256) is not None,
        "expected toolchain manifest SHA-256 must be 64 lowercase hex characters",
    )
    payload = MANIFEST.read_bytes()
    require(
        sha256(payload) == expected_manifest_sha256,
        "toolchain manifest raw SHA-256 mismatch",
    )
    value = load_json_bytes(payload)
    require(isinstance(value, dict), "toolchain manifest must be an object")
    require(
        set(value)
        == {
            "application",
            "control_files",
            "files",
            "schema_version",
            "toolchain_version",
        },
        "toolchain manifest fields are invalid",
    )
    require(
        isinstance(value["schema_version"], int)
        and not isinstance(value["schema_version"], bool)
        and value["schema_version"] == 2,
        "toolchain manifest schema mismatch",
    )
    require(
        value["toolchain_version"] == TOOLCHAIN_VERSION,
        "toolchain version mismatch",
    )
    require(value["application"] == APPLICATION, "application identity mismatch")
    check_entries(value["files"], names=FILES, label="toolchain file")
    check_entries(
        value["control_files"],
        names=MANIFEST_CONTROL_FILES,
        label="toolchain control file",
    )
    return value


def check_entries(value: object, *, names: tuple[str, ...], label: str) -> None:
    entries = value
    require(
        isinstance(entries, list)
        and len(entries) == len(names)
        and all(isinstance(item, dict) for item in entries),
        f"{label} manifest is invalid",
    )
    require(
        tuple(item.get("name") for item in entries) == names,
        f"{label} order or set mismatch",
    )
    for item in entries:
        require(
            set(item) == {"name", "sha256", "size"}
            and isinstance(item["sha256"], str)
            and HEX64.fullmatch(item["sha256"]) is not None
            and isinstance(item["size"], int)
            and not isinstance(item["size"], bool)
            and item["size"] > 0,
            f"invalid manifest entry: {item.get('name')!r}",
        )
        path = ROOT / item["name"]
        require(path.is_file() and not path.is_symlink(), f"missing tool: {path.name}")
        payload = path.read_bytes()
        require(len(payload) == item["size"], f"size mismatch: {path.name}")
        require(sha256(payload) == item["sha256"], f"SHA-256 mismatch: {path.name}")
        require(
            not any(pattern.search(payload) for pattern in SENSITIVE),
            f"sensitive material found in tool: {path.name}",
        )
        if path.suffix == ".py":
            ast.parse(payload.decode("utf-8"), filename=str(path))


def check_plan() -> None:
    payload = (ROOT / "read_plan.json").read_bytes()
    require(
        sha256(payload) == READ_PLAN_SHA256,
        "read plan raw SHA-256 mismatch",
    )
    try:
        plan = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("read plan must be strict UTF-8 JSON") from exc
    require(isinstance(plan, dict), "read plan must be an object")
    require(
        set(plan)
        == {
            "allowed_company_ids",
            "application",
            "capability_id",
            "company_id",
            "database",
            "expected",
            "parameters",
            "principal",
            "runtime",
            "schema_version",
            "system_baseline",
            "user_id",
        },
        "read plan fields are invalid",
    )
    require(
        isinstance(plan.get("schema_version"), int)
        and not isinstance(plan.get("schema_version"), bool)
        and plan["schema_version"] == 1,
        "read plan schema mismatch",
    )
    require(plan.get("application") == APPLICATION, "read plan release mismatch")
    require(plan.get("database") == DATABASE, "read plan database baseline mismatch")
    require(
        plan.get("system_baseline") == SYSTEM_BASELINE,
        "read plan system baseline mismatch",
    )
    pi_entries = plan["system_baseline"]["pi_bridge_control_entries"]
    require(
        pi_entries
        == sorted(
            pi_entries,
            key=lambda item: (item["component"], item["path"]),
        ),
        "Pi Bridge control entries are not canonically ordered",
    )
    pi_digest = sha256(
        json.dumps(
            pi_entries,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    require(
        pi_digest == plan["system_baseline"]["pi_bridge_control_digest"],
        "Pi Bridge control aggregate digest mismatch",
    )
    require(
        plan.get("capability_id") == "acct.multicurrency.balance_read.v1"
        and plan.get("principal") == "pi:test-user-2"
        and plan.get("user_id") == 2
        and plan.get("company_id") == 9
        and plan.get("allowed_company_ids") == [9],
        "read plan authority mismatch",
    )
    parameters = plan.get("parameters")
    require(
        parameters
        == {
            "as_of_date": "2026-07-13",
            "balance_basis": "posted_ledger_cumulative",
            "company_id": 9,
            "currency_ids": [6, 1],
            "limit": 500,
            "off_balance_policy": "exclude",
            "offset": 0,
        },
        "read plan parameters mismatch",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected_manifest_sha256")
    arguments = parser.parse_args(argv)
    if HEX64.fullmatch(arguments.expected_manifest_sha256) is None:
        parser.error(
            "expected_manifest_sha256 must be exactly 64 lowercase hex characters"
        )
    check_manifest(arguments.expected_manifest_sha256)
    check_plan()
    actual_files = {
        path.name
        for path in ROOT.iterdir()
        if path.is_file() and not path.name.endswith((".pyc", ".pyo"))
    }
    require(actual_files == CONTROL_FILES, "unexpected Dev15 toolchain file set")
    print(
        json.dumps(
            {
                "all_checks_passed": True,
                "application_release": APPLICATION["release"],
                "toolchain_manifest_sha256": arguments.expected_manifest_sha256,
                "toolchain_version": TOOLCHAIN_VERSION,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
