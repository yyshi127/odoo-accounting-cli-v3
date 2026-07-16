"""Render the V3 Pi sidecar only from anchored release and runtime bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


_TOKEN = "@V3_RELEASE@"
_NODE_TOKEN = "@V3_NODE@"
_SERVICE = Path(
    "deployment/dev11/systemd/odoo-accounting-cli-v3-pi-bridge.service"
)
_INSTALL_ROOT = Path("/opt/odoo-accounting-cli-v3")
_RELEASES_ROOT = _INSTALL_ROOT / "releases"
_RUNTIMES_ROOT = _INSTALL_ROOT / "pi-runtime"
_NODE_PATH = Path("/usr/bin/node")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RELEASE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,255}\Z")


class RenderError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RenderError("trusted JSON contains a duplicate key")
        result[key] = value
    return result


def _constant(_value: str) -> Any:
    raise RenderError("trusted JSON contains a non-finite number")


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise RenderError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise RenderError(f"{label} is invalid")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RenderError("trusted JSON is not canonical") from exc


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise RenderError("trusted file is unavailable") from exc
    return digest.hexdigest()


def _secure(path: Path, *, directory: bool) -> None:
    if os.name != "posix" or not path.is_absolute() or path.is_symlink():
        raise RenderError("trusted path is not a canonical POSIX path")
    try:
        if path.resolve(strict=True) != path:
            raise RenderError("trusted path is not canonical")
        metadata = os.lstat(path)
    except OSError as exc:
        raise RenderError("trusted path is unavailable") from exc
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(
        metadata.st_mode
    )
    if (
        not expected
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (not directory and metadata.st_nlink != 1)
    ):
        raise RenderError("trusted path ownership or mode is unsafe")
    parent = path if directory else path.parent
    while True:
        metadata = os.lstat(parent)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or parent.is_symlink()
            or parent.resolve(strict=True) != parent
        ):
            raise RenderError("trusted path ancestor is unsafe")
        if parent == parent.parent:
            break
        parent = parent.parent


def _verify_release(release_root: Path, *, require_root_owner: bool) -> dict[str, Any]:
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_path = _INSTALL_ROOT / "trusted-artifacts" / f"{release_root.name}.json"
    package_path = _INSTALL_ROOT / "packages" / (
        f"odoo-accounting-cli-v3-{release_root.name}.tar.gz"
    )
    if require_root_owner:
        for path in (release_root,):
            _secure(path, directory=True)
        for path in (manifest_path, anchor_path, package_path):
            _secure(path, directory=False)
    manifest = _object(manifest_path, "release manifest")
    anchor = _object(anchor_path, "release anchor")
    if (
        set(manifest) != {
            "commit", "files", "manifest_sha256", "schema_version", "version"
        }
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("files"), list)
        or not manifest["files"]
        or _SHA256.fullmatch(str(manifest.get("manifest_sha256"))) is None
        or set(anchor) != {"commit", "manifest_sha256", "package_sha256", "release"}
        or anchor.get("release") != release_root.name
        or anchor.get("commit") != manifest.get("commit")
        or anchor.get("manifest_sha256") != manifest.get("manifest_sha256")
        or _SHA256.fullmatch(str(anchor.get("package_sha256"))) is None
        or release_root.name
        != f"{manifest.get('version')}-{str(manifest.get('commit'))[:12]}"
    ):
        raise RenderError("release identity is invalid")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != manifest["manifest_sha256"]:
        raise RenderError("release manifest digest does not match")
    expected: dict[str, tuple[str, int]] = {}
    for item in manifest["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256", "size"}
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("size"), int)
            or item["size"] < 0
            or _SHA256.fullmatch(str(item.get("sha256"))) is None
            or item["path"] in expected
        ):
            raise RenderError("release manifest member is invalid")
        expected[item["path"]] = (item["sha256"], item["size"])
    actual = {
        path.relative_to(release_root).as_posix()
        for path in release_root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual != set(expected):
        raise RenderError("release file set does not match")
    for name, (expected_sha, expected_size) in expected.items():
        candidate = release_root / name
        if require_root_owner:
            _secure(candidate, directory=False)
        if candidate.is_symlink() or candidate.stat().st_size != expected_size:
            raise RenderError("release member is unsafe")
        if _digest(candidate) != expected_sha:
            raise RenderError("release member digest does not match")
    if _digest(package_path) != anchor["package_sha256"]:
        raise RenderError("canonical release package does not match")
    return {"anchor": anchor, "manifest": manifest}


def _verify_runtime(
    release_root: Path,
    runtime_root: Path,
    release: dict[str, Any],
    *,
    require_root_owner: bool,
) -> None:
    manifest_path = runtime_root / "PI-RUNTIME-MANIFEST.json"
    anchor_path = _INSTALL_ROOT / "trusted-artifacts" / (
        f"{release_root.name}.pi-runtime.json"
    )
    if require_root_owner:
        _secure(runtime_root, directory=True)
        for path in (manifest_path, anchor_path, _NODE_PATH):
            _secure(path, directory=False)
    manifest = _object(manifest_path, "Pi runtime manifest")
    anchor = _object(anchor_path, "Pi runtime anchor")
    if (
        set(manifest) != {
            "files",
            "manifest_sha256",
            "node",
            "package_lock_sha256",
            "release",
            "release_manifest_sha256",
            "schema_version",
        }
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("files"), list)
        or not manifest["files"]
        or set(manifest.get("node", {}))
        != {"arch", "path", "platform", "sha256", "size", "version"}
        or set(anchor)
        != {"release", "release_manifest_sha256", "runtime_manifest_sha256", "schema_version"}
        or anchor.get("schema_version") != 1
        or manifest.get("release") != release_root.name
        or anchor.get("release") != release_root.name
        or manifest.get("release_manifest_sha256")
        != release["manifest"]["manifest_sha256"]
        or anchor.get("release_manifest_sha256")
        != release["manifest"]["manifest_sha256"]
        or anchor.get("runtime_manifest_sha256") != manifest.get("manifest_sha256")
    ):
        raise RenderError("Pi runtime identity is invalid")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != manifest["manifest_sha256"]:
        raise RenderError("Pi runtime manifest digest does not match")
    node = manifest["node"]
    if (
        node.get("path") != _NODE_PATH.as_posix()
        or node.get("platform") != "linux"
        or _SHA256.fullmatch(str(node.get("sha256"))) is None
        or not isinstance(node.get("size"), int)
        or node["size"] != _NODE_PATH.stat().st_size
        or node["sha256"] != _digest(_NODE_PATH)
        or manifest.get("package_lock_sha256")
        != _digest(release_root / "pi_bridge" / "package-lock.json")
    ):
        raise RenderError("Pi runtime Node or package lock does not match")


def render_pi_bridge_service(
    release_root: Path,
    runtime_root: Path,
    *,
    script_root: Path,
    require_root_owner: bool = True,
) -> str:
    if type(require_root_owner) is not bool:
        raise RenderError("root ownership policy is invalid")
    if (
        not release_root.is_absolute()
        or not runtime_root.is_absolute()
        or not script_root.is_absolute()
        or release_root.parent != _RELEASES_ROOT
        or runtime_root != _RUNTIMES_ROOT / release_root.name / "pi_bridge"
        or _RELEASE.fullmatch(release_root.name) is None
        or release_root.resolve(strict=True) != script_root.resolve(strict=True)
    ):
        raise RenderError("Pi service paths are not canonical")
    release = _verify_release(release_root, require_root_owner=require_root_owner)
    _verify_runtime(
        release_root,
        runtime_root,
        release,
        require_root_owner=require_root_owner,
    )
    template_path = release_root / _SERVICE
    if require_root_owner:
        _secure(template_path, directory=False)
    template = template_path.read_text("utf-8")
    if template.count(_TOKEN) != 5 or template.count(_NODE_TOKEN) != 1:
        raise RenderError("Pi service release token count is invalid")
    rendered = template.replace(_TOKEN, release_root.name).replace(
        _NODE_TOKEN, _NODE_PATH.as_posix()
    )
    expected_exec = (
        f"ExecStart={_NODE_PATH.as_posix()} "
        f"{(release_root / 'pi_bridge' / 'bootstrap.mjs').as_posix()} "
        f"{runtime_root.as_posix()}"
    )
    if (
        _TOKEN in rendered
        or _NODE_TOKEN in rendered
        or not rendered.endswith("\n")
        or [line for line in rendered.splitlines() if line.startswith("ExecStart=")]
        != [expected_exec]
        or "PI_BRIDGE_REQUIRE_V3_IDENTITY=1" not in rendered
        or "PI_BRIDGE_HARDENED_V3_ONLY=1" not in rendered
        or "PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET=1" not in rendered
        or "PI_AGENT_BRIDGE_HOST=127.0.0.1" not in rendered
        or "PI_AGENT_BRIDGE_PORT=18788" not in rendered
    ):
        raise RenderError("rendered Pi service does not preserve the fixed boundary")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", required=True)
    parser.add_argument("--runtime-root", required=True)
    arguments = parser.parse_args(argv)
    script = Path(__file__)
    if script.is_symlink():
        raise RenderError("Pi service renderer must not be a symlink")
    release_root = Path(arguments.release_root)
    runtime_root = Path(arguments.runtime_root)
    rendered = render_pi_bridge_service(
        release_root,
        runtime_root,
        script_root=script.resolve(strict=True).parents[2],
    )
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RenderError:
        print("trusted Pi Bridge service rendering failed", file=sys.stderr)
        raise SystemExit(1)
