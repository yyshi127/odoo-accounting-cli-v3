"""Build the one deployable package from a clean committed source tree."""

from __future__ import annotations

import gzip
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

from odoo_accounting_cli_v3.release import ReleaseError, ReleaseIdentity, source_manifest


ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return result.stdout.strip()


def tracked_sources() -> list[Path]:
    names = git("ls-files").splitlines()
    excluded = {"dist"}
    return [ROOT / name for name in names if not excluded.intersection(Path(name).parts)]


def build() -> Path:
    if git("status", "--porcelain"):
        raise ReleaseError("refusing release from a dirty worktree")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    identity = ReleaseIdentity(version=version, commit=git("rev-parse", "HEAD"))
    sources = tracked_sources()
    manifest = source_manifest(ROOT, sources, identity)
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    output = dist / identity.package_name
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for path in sources:
                    relative = path.relative_to(ROOT).as_posix()
                    info = archive.gettarinfo(str(path), arcname=relative)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                info = tarfile.TarInfo("RELEASE-MANIFEST.json")
                info.size = len(manifest_bytes)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(manifest_bytes))
    print(output)
    return output


if __name__ == "__main__":
    try:
        build()
    except (ReleaseError, subprocess.CalledProcessError) as exc:
        print(f"release failed: {exc}", file=sys.stderr)
        sys.exit(1)
