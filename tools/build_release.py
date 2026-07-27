"""Build the one deployable package from a clean committed source tree."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

from odoo_accounting_cli_v3.release import (
    ReleaseError,
    ReleaseIdentity,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
LAUNCHERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
    }
)
EXECUTABLE_RELEASE_MEMBERS = LAUNCHERS | frozenset(
    {"deployment/dev9/run-private-mount-gate.sh"}
)
MAX_ARCHIVE_MEMBERS = 10_000
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RELEASE_NAME_CHARACTERS = 128
LOCAL_RUNTIME_FILENAMES = frozenset(
    {
        "authority-runtime.json",
        "broker-runtime.json",
        "effect-finalizer-runtime.json",
        "effect-finalizer-runtime-manifest.json",
        "historical-routes.json",
        "read-runtime.json",
        "write-runtime.json",
        "pi-attestation-keys.json",
    }
)
HOST_LOCAL_EVIDENCE_FILENAMES = frozenset(
    {
        "bundle-manifest.json",
        "cleanup-receipt.json",
        "lease.json",
        "odoo-server19.conf",
        "prepublication-guard.json",
        "release-manifest.json",
        "runtime-open-trace.json",
        "seal.json",
        "supervisor-bootstrap.json",
        "trace.log",
        "validation-report.json",
        "verifier-child.json",
        "verifier-process-control.json",
        "verifier-runtime-trace.json",
    }
)
HOST_LOCAL_JSON_SCOPES = frozenset(
    {
        "direct-child-bootstrap-through-final-exec-v1",
        "odoo-accounting-cli-v3.dev29.runtime-open-index.v1",
        "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1",
    }
)
HOST_LOCAL_JSON_KINDS = frozenset(
    {"odoo_dependency_closure", "odoo_dependency_closure_anchor"}
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
FORBIDDEN_SOURCE_IMPORT_SUFFIXES = (
    ".bundle",
    ".dll",
    ".dylib",
    ".pyc",
    ".pyd",
    ".pyo",
    ".pyw",
    ".so",
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


def git_bytes(*args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True
    )
    return result.stdout


def git(*args: str) -> str:
    return git_bytes(*args).decode("utf-8").strip()


def tracked_sources(revision: str | None = None) -> list[Path]:
    command = (
        ("ls-files", "-z")
        if revision is None
        else ("ls-tree", "-r", "--name-only", "-z", revision)
    )
    names = git_bytes(*command).decode("utf-8").split("\0")
    excluded = {"dist"}
    return [
        ROOT / name
        for name in names
        if name and not excluded.intersection(PurePosixPath(name).parts)
    ]


def validate_release_member(relative: Path, payload: bytes) -> None:
    """Reject credentials and host-local mutable state from the release."""

    if not relative.as_posix().isascii():
        raise ReleaseError(
            f"refusing non-ASCII release path: {relative.as_posix()}"
        )
    name = relative.name.lower()
    parts = relative.parts
    if parts and parts[0].lower() == "src":
        if parts[0] != "src":
            raise ReleaseError(
                "refusing case-variant canonical source root: "
                f"{relative.as_posix()}"
            )
        if len(parts) < 2 or parts[1] != "odoo_accounting_cli_v3":
            raise ReleaseError(
                "refusing import-shadowing source outside the canonical package: "
                f"{relative.as_posix()}"
            )
        if (
            name.endswith(FORBIDDEN_SOURCE_IMPORT_SUFFIXES)
            or any(part.lower() == "__pycache__" for part in parts[2:-1])
        ):
            raise ReleaseError(
                "refusing bytecode/native importable in canonical source: "
                f"{relative.as_posix()}"
            )
    sensitive_name = (
        name == ".env"
        or name.startswith(".env.")
        or name in LOCAL_RUNTIME_FILENAMES
        or name in HOST_LOCAL_EVIDENCE_FILENAMES
        or (name.startswith("runtime-test-") and name.endswith(".json"))
        or (name.startswith("pi-attestation-keys") and name.endswith(".json"))
        or name in PRIVATE_KEY_FILENAMES
        or name.endswith(
            (".key", ".pem", ".p12", ".pfx", ".ppk", ".hmac", ".pgpass")
        )
        or name.endswith(".db")
        or name.endswith((".seal.json", ".squashfs", ".strace"))
        or name.endswith((".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm"))
        or name.endswith((".sqlite3-wal", ".sqlite3-shm", "-wal", "-shm"))
    )
    if sensitive_name:
        raise ReleaseError(
            f"refusing host-local or credential filename in release: {relative.as_posix()}"
        )
    if relative.suffix.lower() == ".json":
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            schema_version = document.get("schema_version")
            if (
                document.get("scope") in HOST_LOCAL_JSON_SCOPES
                or document.get("kind") in HOST_LOCAL_JSON_KINDS
                or document.get("bundle_type")
                == "odoo-accounting-cli-v3.dev29.read-suite-evidence"
                or document.get("anchor_type")
                == "odoo-accounting-cli-v3.dev29.read-suite-verification"
            ):
                raise ReleaseError(
                    "refusing host-local evidence document in release: "
                    f"{relative.as_posix()}"
                )
            if (
                set(document)
                == {"commit", "manifest_sha256", "package_sha256", "release"}
                and isinstance(document.get("commit"), str)
                and re.fullmatch(r"[0-9a-f]{40}", document["commit"])
                and isinstance(document.get("manifest_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", document["manifest_sha256"])
                and isinstance(document.get("package_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", document["package_sha256"])
                and isinstance(document.get("release"), str)
                and document["release"]
            ):
                raise ReleaseError(
                    "refusing external trusted-artifact anchor in release: "
                    f"{relative.as_posix()}"
                )
            if (
                schema_version
                == "odoo-accounting-cli-v3.pi-attestation-keys.v1"
                and isinstance(document.get("keys"), dict)
            ):
                raise ReleaseError(
                    "refusing Pi attestation key document in release: "
                    f"{relative.as_posix()}"
                )
            if schema_version == (
                "odoo-accounting-cli-v3.finalizer-runtime-manifest.v2"
            ):
                raise ReleaseError(
                    "refusing finalizer runtime manifest in release: "
                    f"{relative.as_posix()}"
                )
    for label, pattern in SENSITIVE_CONTENT_PATTERNS:
        if pattern.search(payload) is not None:
            raise ReleaseError(
                f"refusing high-confidence {label} content in release: "
                f"{relative.as_posix()}"
            )


def committed_source_payloads(
    sources: list[Path], *, revision: str = "HEAD"
) -> dict[str, bytes]:
    """Capture exact worktree bytes only when they equal their HEAD blobs."""

    payloads: dict[str, bytes] = {}
    resolved_root = ROOT.resolve()
    for path in sorted(sources, key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ReleaseError(f"release source is a symlink: {path}")
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise ReleaseError("release source escapes or is missing from the worktree") from exc
        if not resolved.is_file() or ".git" in relative.parts:
            raise ReleaseError(f"invalid release source: {relative.as_posix()}")
        portable = relative.as_posix()
        if portable in payloads:
            raise ReleaseError(f"duplicate release source: {portable}")
        worktree_payload = resolved.read_bytes()
        committed_payload = git_bytes("cat-file", "blob", f"{revision}:{portable}")
        if worktree_payload != committed_payload:
            raise ReleaseError(
                "worktree bytes differ from committed blob: " + portable
            )
        payloads[portable] = worktree_payload
    if not payloads:
        raise ReleaseError("release source set is empty")
    return payloads


def validate_release_payloads(payloads: dict[str, bytes]) -> None:
    if len(payloads) + 1 > MAX_ARCHIVE_MEMBERS:
        raise ReleaseError(
            "release archive member count exceeds the installer limit"
        )
    total_bytes = 0
    for name, payload in payloads.items():
        if len(payload) > MAX_RELEASE_FILE_BYTES:
            raise ReleaseError(
                f"release member exceeds the installer file limit: {name}"
            )
        total_bytes += len(payload)
        if total_bytes > MAX_RELEASE_BYTES:
            raise ReleaseError(
                "release payload exceeds the installer total size limit"
            )
        validate_release_member(Path(name), payload)


def validate_release_identity(identity: ReleaseIdentity) -> None:
    release = f"{identity.version}-{identity.commit[:12]}"
    if len(release) > MAX_RELEASE_NAME_CHARACTERS:
        raise ReleaseError(
            "canonical release name exceeds the 128-character runtime limit"
        )


def validate_release_manifest_payload(payload: bytes) -> None:
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ReleaseError(
            "release manifest exceeds the installer size limit"
        )


def payload_manifest(
    payloads: dict[str, bytes], identity: ReleaseIdentity
) -> dict[str, object]:
    files = [
        {
            "path": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        for name, payload in payloads.items()
    ]
    manifest: dict[str, object] = {
        "schema_version": 1,
        "version": identity.version,
        "commit": identity.commit,
        "files": files,
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return manifest


def build() -> Path:
    if git_bytes("status", "--porcelain"):
        raise ReleaseError("refusing release from a dirty worktree")
    commit = git("rev-parse", "HEAD")
    sources = tracked_sources(commit)
    payloads = committed_source_payloads(sources, revision=commit)
    try:
        version = payloads["VERSION"].decode("utf-8").strip()
    except (KeyError, UnicodeDecodeError) as exc:
        raise ReleaseError("committed VERSION is missing or not UTF-8") from exc
    identity = ReleaseIdentity(version=version, commit=commit)
    validate_release_identity(identity)
    validate_release_payloads(payloads)
    manifest = payload_manifest(payloads, identity)
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    validate_release_manifest_payload(manifest_bytes)
    manifest_file_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    output = dist / identity.package_name
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for relative, payload in payloads.items():
                    info = tarfile.TarInfo(relative)
                    info.size = len(payload)
                    info.mode = (
                        0o755 if relative in EXECUTABLE_RELEASE_MEMBERS else 0o644
                    )
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(payload))
                info = tarfile.TarInfo("RELEASE-MANIFEST.json")
                info.size = len(manifest_bytes)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(manifest_bytes))
    package_sha256 = sha256_file(output)
    release_name = f"{identity.version}-{identity.commit[:12]}"
    trusted_artifact = {
        "commit": identity.commit,
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": package_sha256,
        "release": release_name,
    }
    trusted_artifact_path = dist / f"{release_name}.trusted-artifact.json"
    trusted_artifact_bytes = (
        json.dumps(
            trusted_artifact,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    trusted_artifact_path.write_bytes(trusted_artifact_bytes)
    print(
        json.dumps(
            {
                "manifest_file_sha256": manifest_file_sha256,
                "manifest_sha256": manifest["manifest_sha256"],
                "package": str(output),
                "package_sha256": package_sha256,
                "trusted_artifact": str(trusted_artifact_path),
                "trusted_artifact_sha256": hashlib.sha256(
                    trusted_artifact_bytes
                ).hexdigest(),
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
