"""Render a V3 service only from its externally anchored release tree."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


_TOKEN = "@V3_RELEASE@"
_FINALIZER_MANIFEST_SHA_TOKEN = "@V3_FINALIZER_RUNTIME_MANIFEST_SHA256@"
_SERVICE = Path("deployment/dev9/systemd/odoo-accounting-cli-v3-broker.service")
_EFFECT_FINALIZER_SERVICE = Path(
    "deployment/dev23/systemd/odoo-accounting-cli-v3-effect-finalizer.service"
)
_LAUNCHERS = (
    Path("bin/odoo-accounting-cli-v3"),
    Path("bin/odoo-accounting-cli-v3-broker"),
    Path("bin/odoo-accounting-cli-v3-effect-finalizer"),
)
_BROKER_LAUNCHER = Path("bin/odoo-accounting-cli-v3-broker")
_EFFECT_FINALIZER_LAUNCHER = Path(
    "bin/odoo-accounting-cli-v3-effect-finalizer"
)
_PRODUCTION_RELEASES_ROOT = Path("/opt/odoo-accounting-cli-v3/releases")
_BROKER_RUNTIME_CONFIG = "/etc/odoo-accounting-cli-v3/broker-runtime.json"
_EFFECT_FINALIZER_RUNTIME_CONFIG = (
    "/etc/odoo-accounting-cli-v3/effect-finalizer-runtime.json"
)
_EFFECT_FINALIZER_RUNTIME_GATE = Path(
    "deployment/dev27/finalizer_runtime_gate.py"
)
_EFFECT_FINALIZER_RUNTIME_MANIFEST = (
    "/etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json"
)
_SYSTEM_PYTHON = "/usr/bin/python3"
_RELEASE_NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,255}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ANCHOR_FIELDS = {"commit", "manifest_sha256", "package_sha256", "release"}


class RenderError(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RenderError("trusted JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise RenderError("trusted JSON contains a non-finite number")


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        raise RenderError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise RenderError(f"{label} is invalid")
    return value


def _secure_root_path(path: Path, *, regular_file: bool) -> None:
    if os.name != "posix":
        raise RenderError("trusted service rendering requires POSIX")
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise RenderError("trusted release path is not canonical")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RenderError("trusted release path is unavailable") from exc
    expected = stat.S_ISREG(metadata.st_mode) if regular_file else stat.S_ISDIR(
        metadata.st_mode
    )
    if not expected or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RenderError("trusted release path ownership or mode is unsafe")
    parent = path.parent
    while True:
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise RenderError("trusted release ancestor is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or parent.is_symlink()
            or parent.resolve() != parent
        ):
            raise RenderError("trusted release ancestor ownership or mode is unsafe")
        if parent == parent.parent:
            break
        parent = parent.parent


def _verify_canonical_launchers(
    release_root: Path, *, require_root_owner: bool
) -> None:
    for relative in _LAUNCHERS:
        launcher = release_root / relative
        try:
            metadata = os.lstat(launcher)
        except OSError as exc:
            raise RenderError("canonical release launcher is unavailable") from exc
        if launcher.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise RenderError("canonical release launcher is invalid")
        if (require_root_owner or os.name == "posix") and stat.S_IMODE(
            metadata.st_mode
        ) != 0o555:
            raise RenderError("canonical release launcher mode is invalid")
        if require_root_owner:
            _secure_root_path(launcher, regular_file=True)


def render_service(
    release_root: Path,
    *,
    script_root: Path,
    require_root_owner: bool = True,
    component: str = "broker",
    finalizer_runtime_manifest_sha256: str | None = None,
) -> str:
    if type(require_root_owner) is not bool:
        raise RenderError("root ownership policy is invalid")
    if not release_root.is_absolute() or not script_root.is_absolute():
        raise RenderError("release paths must be absolute")
    if component not in {"broker", "effect-finalizer"}:
        raise RenderError("service component is invalid")
    if component == "effect-finalizer":
        if (
            not isinstance(finalizer_runtime_manifest_sha256, str)
            or _SHA256.fullmatch(finalizer_runtime_manifest_sha256) is None
        ):
            raise RenderError("finalizer runtime manifest digest is invalid")
    elif finalizer_runtime_manifest_sha256 is not None:
        raise RenderError("broker service cannot bind a finalizer runtime digest")
    if release_root.parent != _PRODUCTION_RELEASES_ROOT:
        raise RenderError("release is outside the production releases root")
    if (
        release_root.is_symlink()
        or script_root.is_symlink()
        or release_root.resolve(strict=True) != script_root.resolve(strict=True)
    ):
        raise RenderError("renderer must run from the selected canonical release")
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_path = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    template_path = release_root / (
        _SERVICE if component == "broker" else _EFFECT_FINALIZER_SERVICE
    )
    finalizer_gate_path = release_root / _EFFECT_FINALIZER_RUNTIME_GATE
    if component == "effect-finalizer":
        try:
            gate_metadata = os.lstat(finalizer_gate_path)
        except OSError as exc:
            raise RenderError("effect-finalizer runtime gate is unavailable") from exc
        if finalizer_gate_path.is_symlink() or not stat.S_ISREG(
            gate_metadata.st_mode
        ):
            raise RenderError("effect-finalizer runtime gate is invalid")
    if require_root_owner:
        _secure_root_path(release_root, regular_file=False)
        for trusted_file in (manifest_path, anchor_path, template_path):
            _secure_root_path(trusted_file, regular_file=True)
        if component == "effect-finalizer":
            _secure_root_path(finalizer_gate_path, regular_file=True)
    _verify_canonical_launchers(
        release_root, require_root_owner=require_root_owner
    )
    source_root = release_root / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        raise RenderError("release source is unavailable")
    previous_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source_root))
    try:
        from odoo_accounting_cli_v3.release import verify_manifest

        manifest = _object(manifest_path, "release manifest")
        anchor = _object(anchor_path, "deployment anchor")
        if (
            set(anchor) != _ANCHOR_FIELDS
            or anchor["release"] != release_root.name
            or anchor["commit"] != manifest.get("commit")
            or not isinstance(anchor["manifest_sha256"], str)
            or not isinstance(anchor["package_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", anchor["package_sha256"]) is None
        ):
            raise RenderError("deployment anchor is invalid")
        verify_manifest(
            release_root,
            manifest,
            expected_manifest_sha256=anchor["manifest_sha256"],
        )
    except RenderError:
        raise
    except Exception as exc:
        raise RenderError("release integrity verification failed") from exc
    finally:
        if sys.path and sys.path[0] == str(source_root):
            del sys.path[0]
        sys.dont_write_bytecode = previous_dont_write_bytecode
    release_name = anchor["release"]
    if _RELEASE_NAME.fullmatch(release_name) is None:
        raise RenderError("release name is invalid")
    template = template_path.read_text(encoding="utf-8")
    expected_token_count = 1 if component == "broker" else 2
    if template.count(_TOKEN) != expected_token_count:
        raise RenderError("service template release token is invalid")
    expected_manifest_tokens = 1 if component == "effect-finalizer" else 0
    if template.count(_FINALIZER_MANIFEST_SHA_TOKEN) != expected_manifest_tokens:
        raise RenderError("service template finalizer digest token is invalid")
    rendered = template.replace(_TOKEN, release_name)
    if component == "effect-finalizer":
        rendered = rendered.replace(
            _FINALIZER_MANIFEST_SHA_TOKEN,
            finalizer_runtime_manifest_sha256,
        )
    if (
        _TOKEN in rendered
        or _FINALIZER_MANIFEST_SHA_TOKEN in rendered
        or not rendered.endswith("\n")
    ):
        raise RenderError("rendered service is invalid")
    launcher = (
        _BROKER_LAUNCHER
        if component == "broker"
        else _EFFECT_FINALIZER_LAUNCHER
    )
    runtime_config = (
        _BROKER_RUNTIME_CONFIG
        if component == "broker"
        else _EFFECT_FINALIZER_RUNTIME_CONFIG
    )
    exec_prefix = (
        f"{_SYSTEM_PYTHON} -I -B -X utf8 "
        if component == "effect-finalizer"
        else ""
    )
    expected_exec_start = (
        "ExecStart="
        f"{exec_prefix}{(release_root / launcher).as_posix()} "
        f"--config {runtime_config}"
    )
    exec_starts = [
        line for line in rendered.splitlines() if line.startswith("ExecStart=")
    ]
    if exec_starts != [expected_exec_start]:
        raise RenderError("rendered service ExecStart is not the verified launcher")
    exec_start_pres = [
        line for line in rendered.splitlines() if line.startswith("ExecStartPre=")
    ]
    expected_exec_start_pres = []
    if component == "effect-finalizer":
        expected_exec_start_pres = [
            "ExecStartPre="
            f"{_SYSTEM_PYTHON} -I -B -X utf8 "
            f"{(release_root / _EFFECT_FINALIZER_RUNTIME_GATE).as_posix()} "
            f"verify --interpreter {_SYSTEM_PYTHON} "
            f"--manifest {_EFFECT_FINALIZER_RUNTIME_MANIFEST} "
            "--expected-manifest-sha256 "
            f"{finalizer_runtime_manifest_sha256}"
        ]
    if exec_start_pres != expected_exec_start_pres:
        raise RenderError(
            "rendered service ExecStartPre is not the verified runtime gate"
        )
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--release-root", required=True)
    parser.add_argument(
        "--component",
        choices=("broker", "effect-finalizer"),
        default="broker",
    )
    parser.add_argument("--finalizer-runtime-manifest-sha256")
    arguments = parser.parse_args(argv)
    release_root = Path(arguments.release_root)
    script = Path(__file__)
    if script.is_symlink():
        raise RenderError("service renderer must not be a symlink")
    script_root = script.resolve(strict=True).parents[2]
    sys.stdout.write(
        render_service(
            release_root,
            script_root=script_root,
            component=arguments.component,
            finalizer_runtime_manifest_sha256=(
                arguments.finalizer_runtime_manifest_sha256
            ),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RenderError:
        print("trusted V3 service rendering failed", file=sys.stderr)
        raise SystemExit(1)
