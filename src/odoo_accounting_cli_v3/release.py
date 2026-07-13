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
    resolved_root = root.resolve()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ReleaseError("release source escapes repository root") from exc
        portable = PurePosixPath(relative.as_posix())
        if not resolved.is_file() or ".git" in portable.parts:
            raise ReleaseError(f"invalid release source: {portable}")
        files.append({"path": str(portable), "sha256": sha256_file(resolved), "size": resolved.stat().st_size})
    payload = {"schema_version": 1, "version": identity.version, "commit": identity.commit, "files": files}
    payload["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload


def verify_manifest(root: Path, manifest: dict) -> None:
    supplied_digest = manifest.get("manifest_sha256")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    expected_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if supplied_digest != expected_digest:
        raise ReleaseError("release manifest digest mismatch")
    ReleaseIdentity(version=manifest.get("version", ""), commit=manifest.get("commit", ""))
    for item in manifest.get("files", []):
        path = (root / item["path"]).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise ReleaseError("manifest path escapes release root") from exc
        if not path.is_file() or path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise ReleaseError(f"release file mismatch: {item['path']}")
