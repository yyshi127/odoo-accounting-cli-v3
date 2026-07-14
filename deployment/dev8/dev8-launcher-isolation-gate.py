#!/usr/bin/python3 -I
"""Prove the exact dev8 launcher ignores cwd and Python injection paths."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import stat
import subprocess
import tempfile
from pathlib import Path


RELEASE_ID = "0.1.0.dev8-bd21ca07c168"
LAUNCHER = (
    Path("/opt/odoo-accounting-cli-v3/releases")
    / RELEASE_ID
    / "bin"
    / "odoo-accounting-cli-v3"
)
EXPECTED_LAUNCHER_SHA256 = (
    "3532fb5e83f9cc74d594f1020ea1572a5a2c6fa1a250c64fd3b210f110ef9944"
)
PRIVILEGED_GROUP_NAMES = {
    "adm",
    "disk",
    "docker",
    "kvm",
    "libvirt",
    "lxd",
    "root",
    "shadow",
    "sudo",
    "systemd-journal",
    "wheel",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_output_path(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise RuntimeError("output must be an absolute file path")
    if os.path.lexists(path):
        raise RuntimeError("output must not already exist")
    parent = path.parent
    metadata = parent.lstat()
    resolved = parent.resolve(strict=True)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or parent.is_symlink()
        or resolved != parent
        or resolved == Path("/tmp")
        or Path("/tmp") not in resolved.parents
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("output directory must be a private caller-owned directory under /tmp")


def secure_write(path: Path, payload: bytes) -> None:
    validate_output_path(path)
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure output requires O_NOFOLLOW")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid():
            raise RuntimeError("secure output descriptor is invalid")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise RuntimeError("secure output write did not progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(arguments: list[str], cwd: Path, environment: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(
        [str(LAUNCHER), *arguments],
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    return {
        "arguments": arguments,
        "exit_code": completed.returncode,
        "stderr": completed.stderr,
        "stdout": completed.stdout,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
    }


def group_identity(service: pwd.struct_passwd) -> tuple[dict[str, object], bool]:
    groups = {entry.gr_gid: entry for entry in grp.getgrall()}
    if not hasattr(os, "getgrouplist"):
        raise RuntimeError("service group verification requires os.getgrouplist")
    configured = set(os.getgrouplist(service.pw_name, service.pw_gid))
    configured.add(service.pw_gid)
    supplementary = set(os.getgroups())
    actual = supplementary | {os.getgid(), os.getegid()}
    for gid in actual | configured:
        if gid not in groups:
            try:
                groups[gid] = grp.getgrgid(gid)
            except KeyError:
                pass
    unexpected = actual - configured
    privileged = {
        gid
        for gid in actual
        if gid == 0
        or (groups.get(gid) is not None and groups[gid].gr_name in PRIVILEGED_GROUP_NAMES)
    }

    def describe(gid: int) -> dict[str, object]:
        entry = groups.get(gid)
        if entry is None:
            try:
                entry = grp.getgrgid(gid)
            except KeyError:
                entry = None
        return {
            "gid": gid,
            "name": entry.gr_name if entry is not None else None,
        }

    identity = {
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "expected_uid": service.pw_uid,
        "user": service.pw_name,
        "gid": os.getgid(),
        "egid": os.getegid(),
        "expected_primary_gid": service.pw_gid,
        "primary_group": describe(service.pw_gid),
        "supplementary_groups": [describe(gid) for gid in sorted(supplementary)],
        "configured_groups": [describe(gid) for gid in sorted(configured)],
        "missing_configured_groups": [
            describe(gid) for gid in sorted(configured - actual)
        ],
        "unexpected_groups": [describe(gid) for gid in sorted(unexpected)],
        "privileged_groups": [describe(gid) for gid in sorted(privileged)],
    }
    valid = (
        os.getuid() == service.pw_uid
        and os.geteuid() == service.pw_uid
        and os.getgid() == service.pw_gid
        and os.getegid() == service.pw_gid
        and not unexpected
        and not privileged
    )
    return identity, valid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    service = pwd.getpwnam("odoo")
    identity, identity_valid = group_identity(service)
    if not identity_valid:
        raise SystemExit(
            "launcher isolation gate requires the exact unprivileged odoo UID/GID/group identity"
        )
    validate_output_path(args.output)
    if LAUNCHER.is_symlink() or not LAUNCHER.is_file():
        raise SystemExit("exact launcher is not a regular non-symlink file")
    if sha256(LAUNCHER) != EXPECTED_LAUNCHER_SHA256:
        raise SystemExit("exact launcher digest mismatch")
    if not os.access(LAUNCHER, os.X_OK):
        raise SystemExit("exact launcher is not executable")

    with tempfile.TemporaryDirectory(prefix="dev8-launcher-attacker-", dir="/tmp") as raw:
        attacker = Path(raw)
        site_marker = attacker / "sitecustomize.marker"
        package_marker = attacker / "shadow-package.marker"
        shadow_package = attacker / "odoo_accounting_cli_v3"
        shadow_package.mkdir()
        (attacker / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(site_marker)!r}).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        (shadow_package / "__init__.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(package_marker)!r}).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        (shadow_package / "cli.py").write_text(
            "raise SystemExit('shadow package executed')\n", encoding="utf-8"
        )
        environment = {
            "HOME": str(attacker),
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(attacker),
            "PYTHONSTARTUP": str(attacker / "sitecustomize.py"),
            "PYTHONUSERBASE": str(attacker / "userbase"),
        }

        version = run(["--version"], attacker, environment)
        version_marker_absent = not site_marker.exists() and not package_marker.exists()
        registry = run(["registry", "list"], attacker, environment)
        registry_marker_absent = not site_marker.exists() and not package_marker.exists()
        try:
            registry_document = json.loads(str(registry["stdout"]))
            registry_ids = [
                item["id"]
                for item in registry_document["data"]["capabilities"]
            ]
            staged_ids = [
                item["id"]
                for item in registry_document["data"]["capabilities"]
                if "test" in item.get("staged_environments", [])
            ]
            enabled_ids = [
                item["id"]
                for item in registry_document["data"]["capabilities"]
                if item.get("enabled_environments")
            ]
        except (KeyError, TypeError, ValueError):
            registry_ids = []
            staged_ids = []
            enabled_ids = []

        checks = {
            "exact_odoo_uid_gid_groups": identity_valid,
            "version_exit_zero": version["exit_code"] == 0,
            "version_stderr_empty": version["stderr"] == "",
            "version_is_dev8": "0.1.0.dev8" in str(version["stdout"]),
            "version_markers_absent": version_marker_absent,
            "registry_exit_zero": registry["exit_code"] == 0,
            "registry_stderr_empty": registry["stderr"] == "",
            "registry_has_22_contracts": len(registry_ids) == 22,
            "registry_has_four_staged_contracts": staged_ids
            == [
                "acct.ap.open_items.v1",
                "acct.ar.open_items.v1",
                "acct.gl.trial_balance.v1",
                "acct.registry.list.v1",
            ],
            "registry_has_no_enabled_contracts": enabled_ids == [],
            "registry_markers_absent": registry_marker_absent,
        }
        report = {
            "schema_version": 1,
            "release": RELEASE_ID,
            "launcher": str(LAUNCHER),
            "launcher_sha256": EXPECTED_LAUNCHER_SHA256,
            "identity": identity,
            "identity_valid": identity_valid,
            "attacker_cwd_used": True,
            "pythonpath_injection_used": True,
            "sitecustomize_marker_created": site_marker.exists(),
            "shadow_package_marker_created": package_marker.exists(),
            "registry_ids": registry_ids,
            "staged_ids": staged_ids,
            "enabled_ids": enabled_ids,
            "version": version,
            "registry": registry,
            "checks": checks,
            "all_checks_passed": all(checks.values()),
            "production_promotion_allowed": False,
            "odoo_connected": False,
            "odoo_action_performed": False,
        }

    encoded = (
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    secure_write(
        args.output,
        encoded,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
