"""Build the one deployable package from a clean committed source tree."""

from __future__ import annotations

import gzip
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

from odoo_accounting_cli_v3.release import (
    ReleaseError,
    ReleaseIdentity,
    sha256_file,
    source_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
LAUNCHERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
    }
)
LOCAL_RUNTIME_FILENAMES = frozenset(
    {
        "authority-runtime.json",
        "broker-runtime.json",
        "historical-routes.json",
        "read-runtime.json",
        "write-runtime.json",
    }
)
PRIVATE_KEY_FILENAMES = frozenset(
    {
        "id_dsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
        "id_rsa",
    }
)
SENSITIVE_CONTENT_PATTERNS = (
    ("SQLite database", re.compile(rb"\ASQLite format 3\x00")),
    (
        "private key",
        re.compile(
            rb"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
            + rb"|-----BEGIN PGP "
            + rb"PRIVATE KEY BLOCK-----"
        ),
    ),
    ("GitHub token", re.compile(rb"github_pat_[A-Za-z0-9_]{20,}")),
    ("GitHub token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key", re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("Slack token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("OpenAI project key", re.compile(rb"sk-proj-[0-9A-Za-z_-]{40,}")),
)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return result.stdout.strip()


def tracked_sources() -> list[Path]:
    names = git("ls-files").splitlines()
    excluded = {"dist"}
    return [ROOT / name for name in names if not excluded.intersection(Path(name).parts)]


def validate_release_member(relative: Path, payload: bytes) -> None:
    """Reject credentials and host-local mutable state from the release."""

    name = relative.name.lower()
    sensitive_name = (
        name == ".env"
        or name.startswith(".env.")
        or name in LOCAL_RUNTIME_FILENAMES
        or name in PRIVATE_KEY_FILENAMES
        or name.endswith((".key", ".pem", ".p12", ".pfx", ".ppk"))
        or name.endswith(".db")
        or name.endswith((".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm"))
        or name.endswith((".sqlite3-wal", ".sqlite3-shm", "-wal", "-shm"))
    )
    if sensitive_name:
        raise ReleaseError(
            f"refusing host-local or credential filename in release: {relative.as_posix()}"
        )
    for label, pattern in SENSITIVE_CONTENT_PATTERNS:
        if pattern.search(payload) is not None:
            raise ReleaseError(
                f"refusing high-confidence {label} content in release: "
                f"{relative.as_posix()}"
            )


def validate_release_sources(sources: list[Path]) -> None:
    for path in sources:
        validate_release_member(path.relative_to(ROOT), path.read_bytes())


def build() -> Path:
    if git("status", "--porcelain"):
        raise ReleaseError("refusing release from a dirty worktree")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    identity = ReleaseIdentity(version=version, commit=git("rev-parse", "HEAD"))
    sources = tracked_sources()
    validate_release_sources(sources)
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
                    info.mode = 0o755 if relative in LAUNCHERS else 0o644
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
    print(
        json.dumps(
            {
                "manifest_sha256": manifest["manifest_sha256"],
                "package": str(output),
                "package_sha256": sha256_file(output),
            },
            sort_keys=True,
        )
    )
    return output


if __name__ == "__main__":
    try:
        build()
    except (ReleaseError, subprocess.CalledProcessError) as exc:
        print(f"release failed: {exc}", file=sys.stderr)
        sys.exit(1)
