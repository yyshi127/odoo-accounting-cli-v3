"""Deterministic release identity and manifest helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ReleaseError(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseIdentity:
    version: str
    commit: str

    def __post_init__(self) -> None:
        if not VERSION_PATTERN.fullmatch(self.version):
            raise ReleaseError("invalid release version")
        if not COMMIT_PATTERN.fullmatch(self.commit):
            raise ReleaseError("commit must be a full lowercase SHA-1")

    @property
    def package_name(self) -> str:
        return f"odoo-accounting-cli-v3-{self.version}-{self.commit[:12]}.tar.gz"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest(root: Path, paths: Iterable[Path], identity: ReleaseIdentity) -> dict:
    files = []
    seen: set[str] = set()
    resolved_root = root.resolve()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ReleaseError("release source escapes repository root") from exc
        portable = PurePosixPath(relative.as_posix())
        if path.is_symlink() or not resolved.is_file() or ".git" in portable.parts:
            raise ReleaseError(f"invalid release source: {portable}")
        portable_name = str(portable)
        if portable_name in seen:
            raise ReleaseError(f"duplicate release source: {portable}")
        seen.add(portable_name)
        files.append({"path": portable_name, "sha256": sha256_file(resolved), "size": resolved.stat().st_size})
    payload = {"schema_version": 1, "version": identity.version, "commit": identity.commit, "files": files}
    payload["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload


def verify_manifest(
    root: Path,
    manifest: dict,
    *,
    expected_manifest_sha256: str,
) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {
        "commit", "files", "manifest_sha256", "schema_version", "version"
    }:
        raise ReleaseError("release manifest fields are invalid")
    if manifest["schema_version"] != 1:
        raise ReleaseError("unsupported release manifest schema")
    supplied_digest = manifest.get("manifest_sha256")
    if (
        not isinstance(expected_manifest_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is None
        or supplied_digest != expected_manifest_sha256
    ):
        raise ReleaseError("release manifest does not match the external trust anchor")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    expected_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if supplied_digest != expected_digest:
        raise ReleaseError("release manifest digest mismatch")
    ReleaseIdentity(version=manifest.get("version", ""), commit=manifest.get("commit", ""))
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ReleaseError("release manifest files must be a non-empty array")
    expected_files: set[str] = set()
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise ReleaseError("release root must be a directory")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise ReleaseError("release manifest file entry is invalid")
        if not isinstance(item["path"], str):
            raise ReleaseError("release manifest path is invalid")
        portable = PurePosixPath(item["path"])
        if (
            portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != item["path"]
        ):
            raise ReleaseError("release manifest path is invalid")
        if item["path"] in expected_files:
            raise ReleaseError("release manifest contains duplicate paths")
        expected_files.add(item["path"])
        if not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] < 0:
            raise ReleaseError("release manifest file size is invalid")
        if not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise ReleaseError("release manifest file digest is invalid")
        path = root.joinpath(*portable.parts)
        if path.is_symlink():
            raise ReleaseError(f"release symlink is forbidden: {item['path']}")
        resolved = path.resolve()
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ReleaseError("manifest path escapes release root") from exc
        if not resolved.is_file() or resolved.stat().st_size != item["size"] or sha256_file(resolved) != item["sha256"]:
            raise ReleaseError(f"release file mismatch: {item['path']}")
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ReleaseError(f"release symlink is forbidden: {path.relative_to(root).as_posix()}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative != "RELEASE-MANIFEST.json":
                actual_files.add(relative)
    if actual_files != expected_files:
        extra = sorted(actual_files - expected_files)
        missing = sorted(expected_files - actual_files)
        raise ReleaseError(f"release file set mismatch; extra={extra}, missing={missing}")
