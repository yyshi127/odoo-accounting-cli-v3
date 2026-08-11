from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.util
import json
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from odoo_accounting_cli_v3.release import ReleaseIdentity, source_manifest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OPT_ROOT = Path("/opt/odoo-accounting-cli-v3")
ETC_ROOT = Path("/etc/odoo-accounting-cli-v3")
VAR_ROOT = Path("/var/lib/odoo-accounting-cli-v3")
LEDGER_PATH = VAR_ROOT / "read-evidence-v3" / "admissions.sqlite3"
LEDGER_LOCK_PATH = Path(f"{LEDGER_PATH}.writer.lock")
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")

SOURCE_MEMBERS = (
    "VERSION",
    "registry/capabilities.json",
    "src/odoo_accounting_cli_v3/__init__.py",
    "src/odoo_accounting_cli_v3/monotonic_deadline.py",
    "src/odoo_accounting_cli_v3/operations.py",
    "src/odoo_accounting_cli_v3/read_evidence_admission.py",
    "src/odoo_accounting_cli_v3/read_evidence_v3.py",
    "src/odoo_accounting_cli_v3/registry.py",
    "src/odoo_accounting_cli_v3/release.py",
    "src/odoo_accounting_cli_v3/sqlite_process_lifecycle.py",
    "src/odoo_accounting_cli_v3/sshsig.py",
)
PI_EVENT_ORDER = (
    "user_input",
    "capability_selected",
    "clarification_completed",
    "material_parameters_finalized",
    "cli_input",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
)
SECURITY_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)

pytestmark = pytest.mark.skipif(
    not (
        os.name == "posix"
        and sys.platform.startswith("linux")
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    ),
    reason="real read-evidence v3 integration requires Linux root",
)


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _canonical_without_newline(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_new(path: Path, raw: bytes, *, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json_new(path: Path, value: Any) -> None:
    _write_new(path, _canonical(value))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


class _RootLayout:
    """Own and remove only this invocation's proven root-managed artifacts."""

    def __init__(self, token: str, release: str) -> None:
        self.token = token
        self.release = release
        self.release_root = OPT_ROOT / "releases" / release
        self.deployment_anchor = OPT_ROOT / "trusted-artifacts" / f"{release}.json"
        self.read_trust_anchor = (
            OPT_ROOT / "trusted-artifacts" / f"{release}.read-evidence-v3.json"
        )
        self.key_root = OPT_ROOT / f"{token}-keys"
        self.trust_root = ETC_ROOT / "trust" / "read-evidence-v3" / release
        self.evidence_root = VAR_ROOT / "read-evidence-v3" / release
        self._unique_roots: dict[Path, tuple[int, int]] = {}
        self._unique_files: dict[Path, tuple[int, int]] = {}
        self._created_parents: dict[Path, tuple[int, int]] = {}
        self._ledger_identity: tuple[int, int] | None = None
        self._writer_lock_identity: tuple[int, int] | None = None

    @staticmethod
    def _identity(path: Path) -> tuple[int, int]:
        metadata = path.lstat()
        return int(metadata.st_dev), int(metadata.st_ino)

    @staticmethod
    def _lexists(path: Path) -> bool:
        return os.path.lexists(path)

    def _assert_allowed(self, path: Path) -> None:
        if not any(_inside(path, root) for root in (OPT_ROOT, ETC_ROOT, VAR_ROOT)):
            raise AssertionError(f"integration path escapes fixed roots: {path}")

    def ensure_directory(self, path: Path, *, mode: int = 0o755) -> None:
        self._assert_allowed(path)
        missing: list[Path] = []
        current = path
        while not self._lexists(current):
            missing.append(current)
            current = current.parent
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError(f"integration ancestor is unsafe: {current}")
        for directory in reversed(missing):
            os.mkdir(directory, mode)
            os.chmod(directory, mode)
            self._created_parents[directory] = self._identity(directory)

    def create_unique_root(self, path: Path, *, mode: int = 0o755) -> None:
        self._assert_allowed(path)
        if self.token not in path.name and self.release != path.name:
            raise AssertionError(f"integration root lacks its unique token: {path}")
        if self._lexists(path):
            raise AssertionError(f"integration refuses an existing target: {path}")
        self.ensure_directory(path.parent)
        os.mkdir(path, mode)
        os.chmod(path, mode)
        self._unique_roots[path] = self._identity(path)

    def write_unique_file(self, path: Path, raw: bytes) -> None:
        self._assert_allowed(path)
        if self.release not in path.name:
            raise AssertionError(f"integration file lacks its unique release: {path}")
        if self._lexists(path):
            raise AssertionError(f"integration refuses an existing target: {path}")
        self.ensure_directory(path.parent)
        _write_new(path, raw)
        self._unique_files[path] = self._identity(path)

    def prepare_ledger_parent(self) -> None:
        if self._lexists(LEDGER_PATH.parent):
            raise AssertionError(
                "integration refuses an existing global read-evidence ledger path"
            )
        self.ensure_directory(LEDGER_PATH.parent.parent)
        os.mkdir(LEDGER_PATH.parent, 0o700)
        os.chmod(LEDGER_PATH.parent, 0o700)
        self._created_parents[LEDGER_PATH.parent] = self._identity(LEDGER_PATH.parent)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(LEDGER_PATH, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            self._ledger_identity = (int(opened.st_dev), int(opened.st_ino))
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = LEDGER_PATH.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
            or self._identity(LEDGER_PATH) != self._ledger_identity
        ):
            raise AssertionError("integration ledger bootstrap is unsafe")

    def assert_ledger_bootstrap_recovered(self) -> None:
        if self._ledger_identity is None:
            raise AssertionError("integration did not reserve the fixed ledger inode")
        if not LEDGER_PATH.is_file() or LEDGER_PATH.is_symlink():
            raise AssertionError("admission store did not recover the fixed ledger")
        parent = LEDGER_PATH.parent
        metadata = parent.lstat()
        ledger_metadata = LEDGER_PATH.lstat()
        writer_lock_metadata = LEDGER_LOCK_PATH.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or self._identity(parent) != self._created_parents[parent]
            or self._identity(LEDGER_PATH) != self._ledger_identity
            or stat.S_IMODE(ledger_metadata.st_mode) != 0o600
            or ledger_metadata.st_size == 0
            or LEDGER_LOCK_PATH.is_symlink()
            or not stat.S_ISREG(writer_lock_metadata.st_mode)
            or writer_lock_metadata.st_nlink != 1
            or writer_lock_metadata.st_uid != 0
            or stat.S_IMODE(writer_lock_metadata.st_mode) != 0o600
        ):
            raise AssertionError("admission store did not recover the owned bootstrap")
        self._writer_lock_identity = self._identity(LEDGER_LOCK_PATH)

    def _safe_unlink(self, path: Path, identity: tuple[int, int]) -> None:
        self._assert_allowed(path)
        if not self._lexists(path):
            return
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or self._identity(path) != identity
            or metadata.st_uid != 0
        ):
            raise AssertionError(f"refusing to unlink replaced integration file: {path}")
        path.unlink()

    def _safe_rmtree(self, path: Path, identity: tuple[int, int]) -> None:
        self._assert_allowed(path)
        if not self._lexists(path):
            return
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or self._identity(path) != identity
            or metadata.st_uid != 0
            or (self.token not in path.name and self.release != path.name)
        ):
            raise AssertionError(f"refusing to delete replaced integration root: {path}")
        shutil.rmtree(path)

    def cleanup(self) -> None:
        for path, identity in sorted(
            self._unique_roots.items(), key=lambda item: len(item[0].parts), reverse=True
        ):
            self._safe_rmtree(path, identity)
        for path, identity in self._unique_files.items():
            self._safe_unlink(path, identity)
        if self._ledger_identity is not None:
            parent_identity = self._created_parents.get(LEDGER_PATH.parent)
            if parent_identity is None or not self._lexists(LEDGER_PATH.parent):
                raise AssertionError("integration ledger parent identity is unavailable")
            parent_metadata = LEDGER_PATH.parent.lstat()
            if (
                stat.S_ISLNK(parent_metadata.st_mode)
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or self._identity(LEDGER_PATH.parent) != parent_identity
            ):
                raise AssertionError("refusing cleanup under a replaced ledger parent")
            if self._lexists(LEDGER_PATH):
                ledger_metadata = LEDGER_PATH.lstat()
                if (
                    stat.S_ISLNK(ledger_metadata.st_mode)
                    or not stat.S_ISREG(ledger_metadata.st_mode)
                    or ledger_metadata.st_nlink != 1
                    or ledger_metadata.st_uid != 0
                    or self._identity(LEDGER_PATH) != self._ledger_identity
                ):
                    raise AssertionError("refusing to remove a replaced ledger inode")
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(f"{LEDGER_PATH}{suffix}")
                if self._lexists(sidecar):
                    metadata = sidecar.lstat()
                    if (
                        stat.S_ISLNK(metadata.st_mode)
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != 0
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or not _inside(sidecar, VAR_ROOT)
                    ):
                        raise AssertionError(
                            f"refusing to remove unsafe SQLite sidecar: {sidecar}"
                    )
                    sidecar.unlink()
            if self._lexists(LEDGER_LOCK_PATH):
                writer_lock_metadata = LEDGER_LOCK_PATH.lstat()
                writer_lock_identity = self._identity(LEDGER_LOCK_PATH)
                if (
                    LEDGER_LOCK_PATH.is_symlink()
                    or not stat.S_ISREG(writer_lock_metadata.st_mode)
                    or writer_lock_metadata.st_nlink != 1
                    or writer_lock_metadata.st_uid != 0
                    or stat.S_IMODE(writer_lock_metadata.st_mode) != 0o600
                    or (
                        self._writer_lock_identity is not None
                        and writer_lock_identity != self._writer_lock_identity
                    )
                ):
                    raise AssertionError(
                        "refusing to remove an unsafe admission writer lock"
                    )
                self._safe_unlink(LEDGER_LOCK_PATH, writer_lock_identity)
            elif self._writer_lock_identity is not None:
                raise AssertionError("admission writer lock disappeared before cleanup")
            self._safe_unlink(LEDGER_PATH, self._ledger_identity)
        for path, identity in sorted(
            self._created_parents.items(),
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            if not self._lexists(path):
                continue
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or self._identity(path) != identity
            ):
                raise AssertionError(f"refusing to remove replaced parent: {path}")
            try:
                path.rmdir()
            except OSError:
                # Existing parents may gain unrelated entries; never recurse into them.
                continue


def _build_release(layout: _RootLayout, *, version: str, commit: str) -> dict[str, Any]:
    layout.create_unique_root(layout.release_root)
    for relative in SOURCE_MEMBERS:
        source = PROJECT_ROOT / relative
        if not source.is_file() or source.is_symlink():
            raise AssertionError(f"release integration source is invalid: {relative}")
        destination = layout.release_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_new(destination, source.read_bytes())
    identity = ReleaseIdentity(version=version, commit=commit)
    members = [path for path in layout.release_root.rglob("*") if path.is_file()]
    manifest = source_manifest(layout.release_root, members, identity)
    _write_json_new(layout.release_root / "RELEASE-MANIFEST.json", manifest)
    package_sha256 = _digest(f"linux-root-integration:{layout.release}".encode("ascii"))
    layout.write_unique_file(
        layout.deployment_anchor,
        _canonical(
            {
                "commit": commit,
                "manifest_sha256": manifest["manifest_sha256"],
                "package_sha256": package_sha256,
                "release": layout.release,
            }
        ),
    )
    return {
        "commit": commit,
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": package_sha256,
        "release": layout.release,
        "verified": True,
        "version": version,
    }


def _import_release(layout: _RootLayout) -> tuple[str, ModuleType, ModuleType, ModuleType]:
    package_name = "_odoo_v3_linux_it_" + layout.token.replace("-", "_")
    package_path = layout.release_root / "src" / "odoo_accounting_cli_v3"
    specification = importlib.util.spec_from_file_location(
        package_name,
        package_path / "__init__.py",
        submodule_search_locations=[str(package_path)],
    )
    if specification is None or specification.loader is None:
        raise AssertionError("temporary release package cannot be imported")
    package = importlib.util.module_from_spec(specification)
    sys.modules[package_name] = package
    specification.loader.exec_module(package)
    return (
        package_name,
        importlib.import_module(f"{package_name}.read_evidence_v3"),
        importlib.import_module(f"{package_name}.read_evidence_admission"),
        importlib.import_module(f"{package_name}.registry"),
    )


def _contracts(registry_module: ModuleType, layout: _RootLayout) -> tuple[dict[str, str], str]:
    capabilities = registry_module.load_registry(
        layout.release_root / "registry" / "capabilities.json"
    )
    contracts = {
        capability.id: _digest(_canonical_without_newline(capability.data))
        for capability in sorted(capabilities, key=lambda item: item.id)
        if capability.data["access"] == "read"
    }
    if len(contracts) != 13:
        raise AssertionError(f"expected 13 read contracts, observed {len(contracts)}")
    return contracts, registry_module.registry_digest(capabilities)


def _generate_trust(
    layout: _RootLayout,
    v3: ModuleType,
    identity: dict[str, Any],
) -> dict[str, Path]:
    if not SSH_KEYGEN.is_file() or SSH_KEYGEN.is_symlink():
        raise AssertionError("fixed /usr/bin/ssh-keygen is unavailable or symlinked")
    layout.create_unique_root(layout.key_root, mode=0o700)
    layout.create_unique_root(layout.trust_root)
    roles_directory = layout.trust_root / "roles"
    roles_directory.mkdir(mode=0o755)
    revocations = layout.trust_root / v3.REVOCATIONS_FILENAME
    _write_new(revocations, b"# no revoked keys\n")
    environment = {
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    keys: dict[str, Path] = {}
    role_anchors: dict[str, dict[str, str]] = {}
    fingerprints: set[str] = set()
    for role, binding in sorted(v3.ROLE_BINDINGS.items()):
        filename = role.replace(".", "__")
        private_key = layout.key_root / filename
        subprocess.run(
            [
                str(SSH_KEYGEN),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"{layout.token}:{role}",
                "-f",
                str(private_key),
            ],
            check=True,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        key_descriptor = os.open(
            private_key,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            generated_key = os.fstat(key_descriptor)
            if (
                not stat.S_ISREG(generated_key.st_mode)
                or generated_key.st_nlink != 1
                or generated_key.st_uid != 0
                or generated_key.st_gid != 0
            ):
                raise AssertionError(f"generated private key is unsafe: {role}")
            os.fchmod(key_descriptor, 0o600)
            hardened_key = os.fstat(key_descriptor)
            if (
                (hardened_key.st_dev, hardened_key.st_ino)
                != (generated_key.st_dev, generated_key.st_ino)
                or stat.S_IMODE(hardened_key.st_mode) != 0o600
            ):
                raise AssertionError(f"generated private key was not hardened: {role}")
        finally:
            os.close(key_descriptor)
        public_fields = Path(f"{private_key}.pub").read_text("ascii").split()
        if len(public_fields) < 2 or public_fields[0] != "ssh-ed25519":
            raise AssertionError(f"generated role key is not Ed25519: {role}")
        allowed_raw = (
            f"{binding.principal} {public_fields[0]} {public_fields[1]}\n"
        ).encode("ascii")
        allowed_path = roles_directory / v3._role_filename(role)
        _write_new(allowed_path, allowed_raw)
        fingerprint = _digest(base64.b64decode(public_fields[1], validate=True))
        if fingerprint in fingerprints:
            raise AssertionError("role keys are not unique")
        fingerprints.add(fingerprint)
        role_anchors[role] = {
            "allowed_signers_sha256": _digest(allowed_raw),
            "public_key_sha256": fingerprint,
        }
        keys[role] = private_key
    if len(keys) != 9 or len(fingerprints) != 9:
        raise AssertionError("the real trust fixture must contain nine unique roles")
    layout.write_unique_file(
        layout.read_trust_anchor,
        _canonical(
            {
                "release_identity": identity,
                "revocations_sha256": _digest(revocations.read_bytes()),
                "roles": role_anchors,
                "schema_version": v3.TRUST_ANCHOR_SCHEMA,
                "ssh_keygen_sha256": _digest(SSH_KEYGEN.read_bytes()),
            }
        ),
    )
    return keys


def _sign(path: Path, *, role: str, v3: ModuleType, keys: dict[str, Path]) -> Path:
    signature = Path(f"{path}.sshsig")
    generated = Path(f"{path}.sig")
    if os.path.lexists(signature) or os.path.lexists(generated):
        raise AssertionError(f"signature target already exists: {path}")
    completed = subprocess.run(
        [
            str(SSH_KEYGEN),
            "-Y",
            "sign",
            "-f",
            str(keys[role]),
            "-n",
            v3.ROLE_BINDINGS[role].namespace,
            str(path),
        ],
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        key_metadata = keys[role].lstat()
        payload_metadata = path.lstat()
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        if len(stderr) > 1000:
            stderr = f"{stderr[:997]}..."
        raise AssertionError(
            "ssh-keygen detached signing failed: "
            f"role={role} exit={completed.returncode} stderr={stderr!r} "
            f"euid={os.geteuid()} egid={os.getegid()} "
            f"key_mode={stat.S_IMODE(key_metadata.st_mode):o} "
            f"key_uid={key_metadata.st_uid} key_gid={key_metadata.st_gid} "
            f"key_nlink={key_metadata.st_nlink} "
            f"payload_mode={stat.S_IMODE(payload_metadata.st_mode):o} "
            f"payload_uid={payload_metadata.st_uid} "
            f"payload_gid={payload_metadata.st_gid} "
            f"payload_nlink={payload_metadata.st_nlink}"
        )
    if not generated.is_file() or generated.is_symlink():
        raise AssertionError(f"ssh-keygen did not create a detached signature: {path}")
    generated.replace(signature)
    os.chmod(signature, 0o644)
    return signature


def _file_ref(root: Path, relative: str) -> dict[str, Any]:
    raw = (root / relative).read_bytes()
    return {"path": relative, "sha256": _digest(raw), "size": len(raw)}


def _signed_ref(root: Path, relative: str, role: str) -> dict[str, Any]:
    signature = relative + ".sshsig"
    return {
        **_file_ref(root, relative),
        "role": role,
        "signature_path": signature,
        "signature_sha256": _digest((root / signature).read_bytes()),
        "signature_size": (root / signature).stat().st_size,
    }


def _tree_digest(entries: list[dict[str, Any]]) -> str:
    return _digest(_canonical(sorted(entries, key=lambda item: item["path"])))


def _raw_case(
    kind: str,
    capability_id: str,
    contract: str,
    *,
    identity: dict[str, Any],
    database_uuid: str,
) -> dict[str, Any]:
    seed = _digest(f"{kind}:{capability_id}".encode("utf-8"))
    if kind == "accounting_oracle":
        return {
            "actual_sha256": seed,
            "difference_count": 0,
            "expected_sha256": seed,
            "input_sha256": _digest(f"input:{capability_id}".encode("utf-8")),
            "row_count": 1,
        }
    if kind == "live_odoo":
        return {
            "company_id": 1,
            "database_uuid": database_uuid,
            "odoo_model": "account.move.line",
            "odoo_write_count": 0,
            "read_only": True,
            "receipt_sha256": _digest(f"receipt:{capability_id}".encode("utf-8")),
            "record_count": 1,
            "request_sha256": _digest(f"request:{capability_id}".encode("utf-8")),
            "response_sha256": seed,
        }
    if kind == "pi_e2e":
        return {
            "audit_receipt_sha256": _digest(f"audit:{capability_id}".encode("utf-8")),
            "cli_parameters_sha256": _digest(
                f"parameters:{capability_id}".encode("utf-8")
            ),
            "event_order": list(PI_EVENT_ORDER),
            "natural_language_sha256": _digest(
                f"natural-language:{capability_id}".encode("utf-8")
            ),
            "odoo_result_sha256": seed,
            "selected_capability_id": capability_id,
        }
    if kind == "release_identity":
        return {
            "capability_contract_sha256": contract,
            "observed_release_identity": dict(identity),
        }
    if kind == "security_negative":
        return {
            "cases": [
                {
                    "case_id": case_id,
                    "expected_error_code": error_code,
                    "observed_error_code": error_code,
                    "odoo_write_count": 0,
                    "postgresql_write_count": 0,
                    "receipt_count": 0,
                }
                for case_id, error_code in SECURITY_CASES
            ]
        }
    raise AssertionError(f"unsupported evidence kind: {kind}")


def _raw_document(
    kind: str,
    *,
    v3: ModuleType,
    identity: dict[str, Any],
    contracts: dict[str, str],
    run_id: str,
    scope_sha256: str,
    database_uuid: str,
) -> dict[str, Any]:
    return {
        "capabilities": [
            {
                "capability_contract_sha256": contract,
                "capability_id": capability_id,
                "case": _raw_case(
                    kind,
                    capability_id,
                    contract,
                    identity=identity,
                    database_uuid=database_uuid,
                ),
            }
            for capability_id, contract in sorted(contracts.items())
        ],
        "evidence_kind": kind,
        "release_identity": dict(identity),
        "run_id": run_id,
        "schema_version": v3.RAW_EVIDENCE_SCHEMA,
        "scope_sha256": scope_sha256,
    }


def _semantic_summary(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "capabilities": [
            {
                "capability_contract_sha256": item["capability_contract_sha256"],
                "capability_id": item["capability_id"],
                "case_sha256": _digest(_canonical(item["case"])),
            }
            for item in raw["capabilities"]
        ],
        "evidence_kind": raw["evidence_kind"],
    }


def _projection(identity: dict[str, Any], v3: ModuleType) -> dict[str, Any]:
    return {field: identity[field] for field in v3.ADMISSION_RELEASE_IDENTITY_FIELDS}


def test_real_linux_root_active_closure_publication_and_tamper_rejection() -> None:
    token = f"dev263-linux-it-{os.getpid()}-{secrets.token_hex(6)}"
    version = (PROJECT_ROOT / "VERSION").read_text("utf-8").strip()
    commit = hashlib.sha1(token.encode("ascii"), usedforsecurity=False).hexdigest()
    release = f"odoo-accounting-cli-v3-{version}-{token}"
    layout = _RootLayout(token, release)
    package_name: str | None = None
    previous_bytecode_setting = sys.dont_write_bytecode
    try:
        if not Path("/proc/self/fd").is_dir():
            raise AssertionError("Linux root integration requires /proc/self/fd")
        for target in (
            layout.release_root,
            layout.deployment_anchor,
            layout.read_trust_anchor,
            layout.key_root,
            layout.trust_root,
            layout.evidence_root,
        ):
            if os.path.lexists(target):
                raise AssertionError(f"integration refuses an existing target: {target}")
        identity = _build_release(layout, version=version, commit=commit)
        sys.dont_write_bytecode = True
        package_name, v3, admission, registry = _import_release(layout)
        contracts, observed_registry_digest = _contracts(registry, layout)
        identity["registry_digest"] = observed_registry_digest

        layout.prepare_ledger_parent()
        store = admission.SQLiteReadEvidenceAdmissionStore()
        layout.assert_ledger_bootstrap_recovered()
        keys = _generate_trust(layout, v3, identity)
        with sqlite3.connect(f"file:{LEDGER_PATH}?mode=ro", uri=True) as connection:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(journal_mode).lower() == "delete"
        assert not Path(f"{LEDGER_PATH}-wal").exists()
        assert not Path(f"{LEDGER_PATH}-shm").exists()

        layout.create_unique_root(layout.evidence_root)
        run_id = f"run-{token}"
        run_root = layout.evidence_root / "runs" / run_id
        layout.ensure_directory(run_root)
        database_uuid = "11111111-2222-4333-8444-555555555555"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        not_before = now - timedelta(minutes=1)
        expires_at = now + timedelta(minutes=15)

        scope = {
            "capability_contracts": contracts,
            "company_ids": [1],
            "database_name": "odoo_linux_root_integration",
            "database_uuid": database_uuid,
            "environment": "sandbox",
            "release_identity": dict(identity),
            "run_id": run_id,
            "schema_version": v3.SCOPE_SCHEMA,
        }
        scope_path = run_root / v3.SCOPE_FILENAME
        _write_json_new(scope_path, scope)
        _sign(scope_path, role="scope", v3=v3, keys=keys)
        scope_sha256 = _digest(scope_path.read_bytes())

        authorization_id = f"auth-{token}"
        nonce_sha256 = _digest(f"nonce:{token}".encode("ascii"))
        authorization = {
            "authorization_id": authorization_id,
            "collector_role": "collector",
            "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce_sha256": nonce_sha256,
            "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "release_identity": dict(identity),
            "run_id": run_id,
            "schema_version": v3.AUTHORIZATION_SCHEMA,
            "scope_sha256": scope_sha256,
            "verifier_roles": {
                kind: f"verifier.{kind}" for kind in v3.EVIDENCE_KINDS
            },
        }
        authorization_path = run_root / v3.AUTHORIZATION_FILENAME
        _write_json_new(authorization_path, authorization)
        _sign(authorization_path, role="authorization", v3=v3, keys=keys)
        authorization_sha256 = _digest(authorization_path.read_bytes())

        raw_paths = [f"raw/{kind}.json" for kind in v3.EVIDENCE_KINDS]
        collection_plan = {
            "authorization_sha256": authorization_sha256,
            "expected_raw_paths": raw_paths,
            "release_identity": dict(identity),
            "run_id": run_id,
            "schema_version": v3.COLLECTION_PLAN_SCHEMA,
            "scope_sha256": scope_sha256,
        }
        collection_plan_path = run_root / v3.COLLECTION_PLAN_FILENAME
        _write_json_new(collection_plan_path, collection_plan)
        _sign(collection_plan_path, role="collector", v3=v3, keys=keys)
        collection_plan_sha256 = _digest(collection_plan_path.read_bytes())

        raw_references: list[dict[str, Any]] = []
        for kind, relative in zip(v3.EVIDENCE_KINDS, raw_paths, strict=True):
            path = run_root / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            _write_json_new(
                path,
                _raw_document(
                    kind,
                    v3=v3,
                    identity=identity,
                    contracts=contracts,
                    run_id=run_id,
                    scope_sha256=scope_sha256,
                    database_uuid=database_uuid,
                ),
            )
            raw_references.append(_file_ref(run_root, relative))
        raw_manifest = {
            "authorization_sha256": authorization_sha256,
            "collection_plan_sha256": collection_plan_sha256,
            "files": raw_references,
            "release_identity": dict(identity),
            "run_id": run_id,
            "schema_version": v3.RAW_MANIFEST_SCHEMA,
            "scope_sha256": scope_sha256,
        }
        raw_manifest_path = run_root / v3.RAW_MANIFEST_FILENAME
        _write_json_new(raw_manifest_path, raw_manifest)
        _sign(raw_manifest_path, role="collector", v3=v3, keys=keys)
        raw_manifest_sha256 = _digest(raw_manifest_path.read_bytes())

        verifier_references: list[dict[str, Any]] = []
        for kind, raw_reference in zip(
            v3.EVIDENCE_KINDS, raw_references, strict=True
        ):
            raw_path = str(raw_reference["path"])
            raw_document = json.loads((run_root / raw_path).read_text("utf-8"))
            relative = f"verifiers/{kind}.json"
            report_path = run_root / relative
            report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            report = {
                "authorization_sha256": authorization_sha256,
                "collection_plan_sha256": collection_plan_sha256,
                "evidence_kind": kind,
                "raw_manifest_sha256": raw_manifest_sha256,
                "raw_path": raw_path,
                "raw_sha256": raw_reference["sha256"],
                "raw_size": raw_reference["size"],
                "release_identity": dict(identity),
                "run_id": run_id,
                "schema_version": v3.VERIFIER_REPORT_SCHEMA,
                "scope_sha256": scope_sha256,
                "verification_summary": _semantic_summary(raw_document),
            }
            _write_json_new(report_path, report)
            role = f"verifier.{kind}"
            _sign(report_path, role=role, v3=v3, keys=keys)
            verifier_references.append(
                {"evidence_kind": kind, **_signed_ref(run_root, relative, role)}
            )

        pre_admission_paths = sorted(
            {
                v3.SCOPE_FILENAME,
                f"{v3.SCOPE_FILENAME}.sshsig",
                v3.AUTHORIZATION_FILENAME,
                f"{v3.AUTHORIZATION_FILENAME}.sshsig",
                v3.COLLECTION_PLAN_FILENAME,
                f"{v3.COLLECTION_PLAN_FILENAME}.sshsig",
                v3.RAW_MANIFEST_FILENAME,
                f"{v3.RAW_MANIFEST_FILENAME}.sshsig",
                v3.INDEX_FILENAME,
                f"{v3.INDEX_FILENAME}.sshsig",
                *raw_paths,
                *(
                    relative
                    for kind in v3.EVIDENCE_KINDS
                    for relative in (
                        f"verifiers/{kind}.json",
                        f"verifiers/{kind}.json.sshsig",
                    )
                ),
            }
        )
        index = {
            "admission_path": v3.ADMISSION_FILENAME,
            "authorization": _signed_ref(
                run_root, v3.AUTHORIZATION_FILENAME, "authorization"
            ),
            "closure_paths": pre_admission_paths,
            "collection_plan": _signed_ref(
                run_root, v3.COLLECTION_PLAN_FILENAME, "collector"
            ),
            "raw_manifest": _signed_ref(
                run_root, v3.RAW_MANIFEST_FILENAME, "collector"
            ),
            "release_identity": dict(identity),
            "run_id": run_id,
            "schema_version": v3.EVIDENCE_INDEX_SCHEMA,
            "scope": _signed_ref(run_root, v3.SCOPE_FILENAME, "scope"),
            "verifier_reports": verifier_references,
        }
        index_path = run_root / v3.INDEX_FILENAME
        _write_json_new(index_path, index)
        index_signature = _sign(index_path, role="collector", v3=v3, keys=keys)

        pre_admission = [
            _file_ref(run_root, path.relative_to(run_root).as_posix())
            for path in sorted(run_root.rglob("*"))
            if path.is_file()
        ]
        assert [item["path"] for item in pre_admission] == pre_admission_paths
        request = admission.ReadEvidenceAdmissionRequest(
            release_identity=_projection(identity, v3),
            index_path=v3.INDEX_FILENAME,
            index_sha256=_digest(index_path.read_bytes()),
            index_size=index_path.stat().st_size,
            index_signature_path=f"{v3.INDEX_FILENAME}.sshsig",
            index_signature_sha256=_digest(index_signature.read_bytes()),
            index_signature_size=index_signature.stat().st_size,
            closure_tree_sha256=_tree_digest(pre_admission),
            closure_file_count=len(pre_admission),
            closure_total_bytes=sum(item["size"] for item in pre_admission),
            scope_sha256=scope_sha256,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            nonce_sha256=nonce_sha256,
            run_id=run_id,
            authorization_not_before=not_before,
            authorization_expires_at=expires_at,
        )
        consumed = store.consume(request)
        assert consumed.state is admission.AdmissionState.CONSUMED
        admission_path = run_root / v3.ADMISSION_FILENAME
        _write_new(admission_path, consumed.payload_bytes)
        admission_signature = _sign(
            admission_path, role="admission", v3=v3, keys=keys
        )
        active_record = {
            "admission_sha256": _digest(admission_path.read_bytes()),
            "index_sha256": _digest(index_path.read_bytes()),
            "payload_sha256": _digest(admission_path.read_bytes()),
            "release_identity": _projection(identity, v3),
            "run_id": run_id,
            "schema_version": v3.ACTIVE_RECORD_SCHEMA,
            "sequence": consumed.sequence,
        }
        _write_json_new(layout.evidence_root / "active.json", active_record)

        with pytest.raises(
            v3.ReadEvidenceV3Error, match="publication ledger lookup failed"
        ):
            v3.verify_read_evidence_v3(
                index_path,
                expected_release_identity=identity,
            )

        published = store.mark_published(
            authorization_id=authorization_id,
            payload_sha256=consumed.payload_sha256,
            admission_signature_path=f"{v3.ADMISSION_FILENAME}.sshsig",
            admission_signature_sha256=_digest(admission_signature.read_bytes()),
            admission_signature_size=admission_signature.stat().st_size,
        )
        assert published.state is admission.AdmissionState.PUBLISHED
        with sqlite3.connect(f"file:{LEDGER_PATH}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT state, payload_sha256 FROM read_evidence_admissions "
                "WHERE sequence=?",
                (consumed.sequence,),
            ).fetchone()
        assert row == ("published", consumed.payload_sha256)

        verified = v3.verify_read_evidence_v3(
            index_path,
            expected_release_identity=identity,
        )
        assert verified["cryptographic_closure_verified"] is True
        assert verified["external_read_evidence_verified"] is False
        assert verified["goal_evidence_admissible"] is False
        assert verified["production_promotion_allowed"] is False
        assert verified["mode"] == "active"
        assert verified["release_identity"] == identity
        assert verified["file_count"] == 27
        assert len(verified["capabilities"]) == 13
        assert [item["capability_id"] for item in verified["capabilities"]] == sorted(
            contracts
        )
        assert all(item["verified"] is False for item in verified["capabilities"])

        tampered_path = run_root / "raw/live_odoo.json"
        tampered_path.write_bytes(tampered_path.read_bytes() + b" ")
        os.chmod(tampered_path, 0o644)
        with pytest.raises(v3.ReadEvidenceV3Error, match="digest mismatch"):
            v3.verify_read_evidence_v3(
                index_path,
                expected_release_identity=identity,
            )
    finally:
        if package_name is not None:
            for name in tuple(sys.modules):
                if name == package_name or name.startswith(package_name + "."):
                    sys.modules.pop(name, None)
        sys.dont_write_bytecode = previous_bytecode_setting
        layout.cleanup()
