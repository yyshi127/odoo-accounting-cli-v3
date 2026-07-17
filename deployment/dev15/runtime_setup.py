#!/usr/bin/env python3
"""Create the isolated Dev15 staged read runtime without changing live routing."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable


RELEASE_ID = "0.1.0.dev15-c4616386f921"
VERSION = "0.1.0.dev15"
COMMIT = "c4616386f921946cf43cde2de449d2938a837422"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
PACKAGE_NAME = f"odoo-accounting-cli-v3-{RELEASE_ID}.tar.gz"
PACKAGE_SHA256 = "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
MANIFEST_SHA256 = "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
RELEASE_MANIFEST_RAW_SHA256 = (
    "21b220ab3bea012201d3d8d06b3f12c4841c08d5a37afd416889729f47d8e3d6"
)
ODOO_PYTHON_SHA256 = "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
ODOO_BIN_SHA256 = "e0fb7977c59f73e652805d169bcd1bffe41df7bbf0c39ce47e8ad32126529003"
ODOO_CONFIG_SHA256 = "98a90d839e3ad16c32335057b27e33bc689cbccbb367350e31fbf41778ed70c3"
CONFIG_NAME = "runtime-test-dev15-c4616386f921.json"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_TREE_ENTRIES = 20_000
MAX_TRUSTED_ARTIFACT_BYTES = 64 * 1024
RUNTIME_LOCK_TIMEOUT_SECONDS = 30.0
RUNTIME_LOCK_POLL_SECONDS = 0.05
CONFIG_FIELDS = frozenset(
    {
        "instance_id",
        "environment",
        "capability_channel",
        "database_name",
        "database_uuid",
        "odoo_python",
        "odoo_python_sha256",
        "odoo_bin",
        "odoo_bin_sha256",
        "odoo_config",
        "odoo_config_sha256",
        "release_root",
        "canonical_package_path",
        "canonical_package_sha256",
        "auth_state_path",
        "receipt_state_path",
        "auth_key_id",
        "receipt_key_id",
        "auth_secret_path",
        "receipt_secret_path",
    }
)


class RuntimeSetupError(RuntimeError):
    """The candidate runtime cannot be published without weakening isolation."""


@dataclass(frozen=True)
class Layout:
    root: Path
    release_root: Path
    package: Path
    trusted_artifact_parent: Path
    trusted_artifact: Path
    odoo_python: Path
    odoo_bin: Path
    odoo_config: Path
    config_parent: Path
    config: Path
    secret_root: Path
    auth_secret: Path
    receipt_secret: Path
    state_root: Path
    auth_state_parent: Path
    receipt_state_parent: Path
    child_home: Path


@dataclass(frozen=True)
class SetupResult:
    config_path: Path
    child_home: Path
    release_id: str = RELEASE_ID
    already_exists: bool = False

    def public_record(self) -> dict[str, object]:
        # Secret material, secret paths, and Key IDs are intentionally absent.
        return {
            "already_exists": self.already_exists,
            "child_home": str(self.child_home),
            "config_path": str(self.config_path),
            "environment": "test",
            "release": self.release_id,
            "routed": False,
        }


def _rooted(root: Path, absolute: str) -> Path:
    parts = PurePosixPath(absolute).parts
    if not parts or parts[0] != "/":
        raise RuntimeSetupError("internal runtime path is not absolute")
    return root.joinpath(*parts[1:])


def build_layout(root: Path) -> Layout:
    root = Path(root).absolute()
    release_root = _rooted(
        root, f"/opt/odoo-accounting-cli-v3/releases/{RELEASE_ID}"
    )
    config_parent = _rooted(root, "/etc/odoo-accounting-cli-v3/candidates")
    secret_root = _rooted(
        root, f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE_ID}"
    )
    state_root = _rooted(
        root,
        f"/var/lib/odoo-accounting-cli-v3-dev15-candidates/{RELEASE_ID}/read-state",
    )
    trusted_artifact_parent = _rooted(
        root, "/opt/odoo-accounting-cli-v3/trusted-artifacts"
    )
    return Layout(
        root=root,
        release_root=release_root,
        package=_rooted(root, f"/opt/odoo-accounting-cli-v3/packages/{PACKAGE_NAME}"),
        trusted_artifact_parent=trusted_artifact_parent,
        trusted_artifact=trusted_artifact_parent / f"{RELEASE_ID}.json",
        odoo_python=_rooted(root, "/opt/odoo/odoo19/odoo19-venv/bin/python"),
        odoo_bin=_rooted(root, "/opt/odoo/odoo19/odoo-server/odoo-bin"),
        odoo_config=_rooted(
            root, "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf"
        ),
        config_parent=config_parent,
        config=config_parent / CONFIG_NAME,
        secret_root=secret_root,
        auth_secret=secret_root / "auth.hmac",
        receipt_secret=secret_root / "receipt.hmac",
        state_root=state_root,
        auth_state_parent=state_root / "auth",
        receipt_state_parent=state_root / "receipt",
        child_home=_rooted(root, "/var/lib/odoo-accounting-cli-v3-broker"),
    )


def _identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_directory(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise RuntimeSetupError(f"unsafe directory: {path}")
        return metadata
    except RuntimeSetupError:
        raise
    except OSError as exc:
        raise RuntimeSetupError(f"cannot verify directory: {path}") from exc


def _verify_owner_mode(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    directory: bool,
    test_mode: bool,
) -> os.stat_result:
    metadata = _canonical_directory(path) if directory else path.lstat()
    if not directory and (
        not stat.S_ISREG(metadata.st_mode) or path.is_symlink()
    ):
        raise RuntimeSetupError(f"unsafe regular file: {path}")
    if not directory and metadata.st_nlink != 1:
        raise RuntimeSetupError(f"link-count drift detected: {path}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != mode:
        raise RuntimeSetupError(f"mode drift detected: {path}")
    if os.name == "posix" and not test_mode:
        if metadata.st_uid != uid or metadata.st_gid != gid:
            raise RuntimeSetupError(f"owner drift detected: {path}")
    return metadata


@dataclass
class _Transaction:
    files: list[tuple[Path, tuple[int, int]]] = field(default_factory=list)
    directories: list[tuple[Path, tuple[int, int]]] = field(default_factory=list)

    def remember_file(self, path: Path) -> None:
        self.files.append((path, _identity(path)))

    def remember_directory(self, path: Path) -> None:
        self.directories.append((path, _identity(path)))

    def rollback(self) -> None:
        for path, identity in reversed(self.files):
            try:
                if _identity(path) == identity and stat.S_ISREG(path.lstat().st_mode):
                    path.unlink()
                    _fsync_directory(path.parent)
            except (FileNotFoundError, OSError):
                pass
        for path, identity in reversed(self.directories):
            try:
                if _identity(path) == identity and stat.S_ISDIR(path.lstat().st_mode):
                    path.rmdir()
                    _fsync_directory(path.parent)
            except (FileNotFoundError, OSError):
                pass


def _set_metadata(path: Path, *, uid: int, gid: int, mode: int, test_mode: bool) -> None:
    if os.name == "posix" and not test_mode:
        os.chown(path, uid, gid, follow_symlinks=False)
    # Windows does not implement chmod(follow_symlinks=False); managed objects
    # were created without following links, so its reduced chmod is sufficient
    # for the test-only redirected root.
    if os.name == "posix":
        os.chmod(path, mode, follow_symlinks=False)
    else:
        os.chmod(path, mode)


def _ensure_chain(
    root: Path,
    path: Path,
    *,
    uid: int,
    gid: int,
    test_mode: bool,
    transaction: _Transaction,
    allowed_existing_uids: set[int] | None = None,
) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise RuntimeSetupError("managed path escaped the selected root") from exc
    current = root
    _canonical_directory(root)
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                metadata = current.lstat()
            else:
                created_identity = _identity(current)
                transaction.directories.append((current, created_identity))
                _set_metadata(
                    current, uid=uid, gid=gid, mode=0o755, test_mode=test_mode
                )
                if _identity(current) != created_identity:
                    raise RuntimeSetupError("created parent identity changed")
                _fsync_directory(current.parent)
                continue
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or current.is_symlink()
            or current.resolve(strict=True) != current
        ):
            raise RuntimeSetupError(f"unsafe parent: {current}")
        if os.name == "posix":
            allowed_uids = (
                {os.geteuid()}
                if test_mode
                else (allowed_existing_uids if allowed_existing_uids is not None else {uid})
            )
            if metadata.st_uid not in allowed_uids or metadata.st_mode & 0o022:
                raise RuntimeSetupError(f"unsafe parent ownership or mode: {current}")


def _verify_chain(
    root: Path,
    path: Path,
    *,
    allowed_uids: set[int],
    test_mode: bool,
) -> None:
    """Verify every existing component; never create or repair one."""

    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise RuntimeSetupError("managed path escaped the selected root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        metadata = _canonical_directory(current)
        if os.name == "posix":
            expected_uids = {os.geteuid()} if test_mode else allowed_uids
            if metadata.st_uid not in expected_uids or metadata.st_mode & 0o022:
                raise RuntimeSetupError(f"unsafe parent ownership or mode: {current}")


def _mkdir_exact(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    test_mode: bool,
    transaction: _Transaction,
) -> None:
    try:
        path.mkdir(mode=mode)
    except FileExistsError as exc:
        raise RuntimeSetupError(f"candidate object already exists: {path}") from exc
    created_identity = _identity(path)
    transaction.directories.append((path, created_identity))
    _set_metadata(path, uid=uid, gid=gid, mode=mode, test_mode=test_mode)
    if _identity(path) != created_identity:
        raise RuntimeSetupError("created candidate directory identity changed")
    _fsync_directory(path.parent)


def _acquire_posix_flock(
    descriptor: int,
    *,
    timeout_seconds: float | None = None,
    poll_seconds: float | None = None,
    acquire=None,
    monotonic=None,
    sleep=None,
) -> None:
    """Acquire one flock without allowing an unbounded setup process hang."""

    timeout = (
        RUNTIME_LOCK_TIMEOUT_SECONDS
        if timeout_seconds is None
        else timeout_seconds
    )
    poll = RUNTIME_LOCK_POLL_SECONDS if poll_seconds is None else poll_seconds
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout < 0
        or not isinstance(poll, (int, float))
        or isinstance(poll, bool)
        or not math.isfinite(poll)
        or poll <= 0
    ):
        raise RuntimeSetupError("runtime lock timing configuration is invalid")
    if acquire is None:
        import fcntl

        acquire = lambda fd: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    clock = monotonic or time.monotonic
    pause = sleep or time.sleep
    deadline = clock() + float(timeout)
    while True:
        try:
            acquire(descriptor)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise RuntimeSetupError(
                    "candidate runtime lock cannot be acquired"
                ) from exc
            now = clock()
            if now >= deadline:
                raise RuntimeSetupError(
                    "timed out waiting for candidate runtime setup lock"
                ) from exc
            pause(min(float(poll), deadline - now))


def _open_runtime_lock(path: Path, *, test_mode: bool) -> tuple[int, bool, tuple[int, int]]:
    """Acquire an auto-released production flock; Windows tests use O_EXCL."""

    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    created = False
    if os.name == "posix":
        try:
            descriptor = os.open(path, flags | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            descriptor = os.open(path, flags, 0o600)
    else:
        try:
            descriptor = os.open(path, flags | os.O_EXCL, 0o600)
            created = True
        except FileExistsError as exc:
            raise RuntimeSetupError("candidate runtime setup is already locked") from exc
    try:
        if created:
            if os.name == "posix" and not test_mode:
                os.fchown(descriptor, 0, 0)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync_directory(path.parent)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (os.name == "posix" and stat.S_IMODE(opened.st_mode) != 0o600)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or (
                os.name == "posix"
                and not test_mode
                and (opened.st_uid != 0 or opened.st_gid != 0)
            )
        ):
            raise RuntimeSetupError("candidate runtime lock metadata drift detected")
        if os.name == "posix":
            _acquire_posix_flock(descriptor)
        return descriptor, created, (opened.st_dev, opened.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def _close_runtime_lock(
    path: Path,
    descriptor: int,
    *,
    remove: bool,
    identity: tuple[int, int],
) -> None:
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
    if remove:
        try:
            if _identity(path) == identity and stat.S_ISREG(path.lstat().st_mode):
                path.unlink()
                _fsync_directory(path.parent)
        except FileNotFoundError:
            pass


def _publish_file(
    path: Path,
    payload: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
    test_mode: bool,
    transaction: _Transaction,
) -> None:
    stage = path.parent / f".{path.name}.{uuid.uuid4().hex}.staging"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(stage, flags, 0o600)
    staged_identity = _identity(stage)
    try:
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise RuntimeSetupError("short write while staging runtime object")
                view = view[written:]
            if os.name == "posix" and not test_mode:
                os.fchown(descriptor, uid, gid)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, mode)
            else:
                os.chmod(stage, mode)
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != staged_identity:
                raise RuntimeSetupError("staged runtime object identity changed")
        finally:
            os.close(descriptor)
        try:
            os.link(stage, path, follow_symlinks=False)
            transaction.remember_file(path)
            if _identity(path) != staged_identity:
                raise RuntimeSetupError("published runtime object identity changed")
            _fsync_directory(path.parent)
        except FileExistsError as exc:
            raise RuntimeSetupError(f"candidate object already exists: {path}") from exc
    finally:
        try:
            if _identity(stage) != staged_identity:
                raise RuntimeSetupError("staged runtime object identity changed")
            stage.unlink()
            _fsync_directory(stage.parent)
        except RuntimeSetupError:
            raise
        except OSError as exc:
            raise RuntimeSetupError(
                "staged runtime object cannot be removed durably"
            ) from exc
    published = _verify_owner_mode(
        path,
        uid=uid,
        gid=gid,
        mode=mode,
        directory=False,
        test_mode=test_mode,
    )
    if (
        (published.st_dev, published.st_ino) != staged_identity
        or published.st_size != len(payload)
    ):
        raise RuntimeSetupError("published runtime object metadata changed")


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )


def _stable_regular_file(
    path: Path,
    *,
    label: str,
    maximum: int,
    allow_path_symlink: bool = False,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
    capture: bool = False,
) -> tuple[str, int, bytes | None]:
    """Hash one stable single-link file through a no-follow descriptor."""

    try:
        path_before = path.lstat()
        target = path.resolve(strict=True)
        if not allow_path_symlink and (path.is_symlink() or target != path):
            raise RuntimeSetupError(f"{label} contains a symlink")
        before = target.lstat()
        if (
            target.is_symlink()
            or target.resolve(strict=True) != target
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise RuntimeSetupError(f"{label} is not a canonical single-link file")
        if os.name == "posix" and (
            (expected_uid is not None and before.st_uid != expected_uid)
            or (expected_gid is not None and before.st_gid != expected_gid)
            or (
                expected_mode is not None
                and stat.S_IMODE(before.st_mode) != expected_mode
            )
        ):
            raise RuntimeSetupError(f"{label} metadata drift detected")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(target, flags)
        digest = hashlib.sha256()
        payload = bytearray() if capture else None
        size = 0
        try:
            opened = os.fstat(descriptor)
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise RuntimeSetupError(f"{label} exceeds its size limit")
                digest.update(chunk)
                if payload is not None:
                    payload.extend(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = target.lstat()
        path_after = path.lstat()
        if (
            _stat_fingerprint(before)
            != _stat_fingerprint(opened)
            or _stat_fingerprint(before) != _stat_fingerprint(opened_after)
            or _stat_fingerprint(before) != _stat_fingerprint(after)
            or _stat_fingerprint(path_before) != _stat_fingerprint(path_after)
            or path.resolve(strict=True) != target
            or size != before.st_size
        ):
            raise RuntimeSetupError(f"{label} changed while it was verified")
        return digest.hexdigest(), size, bytes(payload) if payload is not None else None
    except RuntimeSetupError:
        raise
    except OSError as exc:
        raise RuntimeSetupError(f"{label} cannot be verified safely") from exc


def _strict_json_object(payload: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeSetupError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise RuntimeSetupError(f"{label} contains a non-finite number: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except RuntimeSetupError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeSetupError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeSetupError(f"{label} must be a JSON object")
    return value


def _verify_release_directory(
    path: Path, *, uid: int, gid: int, test_mode: bool
) -> os.stat_result:
    metadata = _canonical_directory(path)
    if os.name == "posix" and (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o555
    ):
        raise RuntimeSetupError(f"release directory metadata drift detected: {path}")
    return metadata


def _validate_manifest(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    if set(manifest) != {
        "commit",
        "files",
        "manifest_sha256",
        "schema_version",
        "version",
    } or type(manifest.get("schema_version")) is not int or manifest.get(
        "schema_version"
    ) != 1:
        raise RuntimeSetupError("release manifest fields are invalid")
    if manifest.get("version") != VERSION or manifest.get("commit") != COMMIT:
        raise RuntimeSetupError("installed release identity is not exact Dev15")
    supplied = manifest.get("manifest_sha256")
    if supplied != MANIFEST_SHA256:
        raise RuntimeSetupError("installed release manifest digest is not exact Dev15")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    try:
        calculated = hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeSetupError("release manifest cannot be canonicalized") from exc
    if calculated != supplied:
        raise RuntimeSetupError("release manifest unsigned digest mismatch")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_RELEASE_TREE_ENTRIES:
        raise RuntimeSetupError("release manifest files are invalid")
    indexed: dict[str, dict[str, object]] = {}
    total_size = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise RuntimeSetupError("release manifest file entry is invalid")
        name = item.get("path")
        if not isinstance(name, str):
            raise RuntimeSetupError("release manifest path is invalid")
        portable = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or portable.is_absolute()
            or not portable.parts
            or any(
                part in {"", ".", ".."}
                or len(part.encode("utf-8")) > 255
                for part in portable.parts
            )
            or portable.as_posix() != name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or len(name.encode("utf-8")) > 4095
            or name == "RELEASE-MANIFEST.json"
            or name in indexed
        ):
            raise RuntimeSetupError("release manifest path is invalid or duplicated")
        size = item.get("size")
        sha256 = item.get("sha256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_RELEASE_FILE_BYTES
            or not isinstance(sha256, str)
            or SHA256_PATTERN.fullmatch(sha256) is None
        ):
            raise RuntimeSetupError("release manifest file metadata is invalid")
        total_size += size
        if total_size > MAX_RELEASE_BYTES:
            raise RuntimeSetupError("release manifest exceeds total size limit")
        indexed[name] = item
    return indexed


def _inventory_release_tree(
    root: Path, *, uid: int, gid: int, test_mode: bool
) -> tuple[dict[str, Path], set[str]]:
    files: dict[str, Path] = {}
    directories: set[str] = set()
    pending: list[tuple[Path, str]] = [(root, "")]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        before = _verify_release_directory(
            directory, uid=uid, gid=gid, test_mode=test_mode
        )
        try:
            with os.scandir(directory) as iterator:
                children = list(iterator)
        except OSError as exc:
            raise RuntimeSetupError("release tree cannot be inventoried safely") from exc
        after = directory.lstat()
        if _stat_fingerprint(before) != _stat_fingerprint(after):
            raise RuntimeSetupError("release directory changed during inventory")
        for child in children:
            entries += 1
            if entries > MAX_RELEASE_TREE_ENTRIES:
                raise RuntimeSetupError("release tree contains too many entries")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            path = directory / child.name
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeSetupError("release tree entry cannot be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeSetupError(f"release symlink is forbidden: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = path
            else:
                raise RuntimeSetupError(f"release object type is unsafe: {relative}")
    return files, directories


def _verify_release(layout: Layout, *, test_mode: bool) -> None:
    owner_uid = os.geteuid() if test_mode and hasattr(os, "geteuid") else 0
    owner_gid = os.getegid() if test_mode and hasattr(os, "getegid") else 0
    _verify_owner_mode(
        layout.trusted_artifact_parent,
        uid=owner_uid,
        gid=owner_gid,
        mode=0o755,
        directory=True,
        test_mode=test_mode,
    )
    _, _, trusted_artifact_payload = _stable_regular_file(
        layout.trusted_artifact,
        label="trusted artifact anchor",
        maximum=MAX_TRUSTED_ARTIFACT_BYTES,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=0o444,
        capture=True,
    )
    assert trusted_artifact_payload is not None
    trusted_artifact = _strict_json_object(
        trusted_artifact_payload, label="trusted artifact anchor"
    )
    if trusted_artifact != {
        "commit": COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256,
        "release": RELEASE_ID,
    }:
        raise RuntimeSetupError("trusted artifact anchor is not exact Dev15")
    _verify_release_directory(
        layout.release_root, uid=owner_uid, gid=owner_gid, test_mode=test_mode
    )
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest_raw_sha256, _, manifest_payload = _stable_regular_file(
        manifest_path,
        label="release manifest",
        maximum=MAX_MANIFEST_BYTES,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=0o444,
        capture=True,
    )
    assert manifest_payload is not None
    if manifest_raw_sha256 != RELEASE_MANIFEST_RAW_SHA256:
        raise RuntimeSetupError("release manifest raw SHA-256 mismatch")
    indexed = _validate_manifest(
        _strict_json_object(manifest_payload, label="release manifest")
    )
    actual_files, actual_directories = _inventory_release_tree(
        layout.release_root, uid=owner_uid, gid=owner_gid, test_mode=test_mode
    )
    expected_files = set(indexed) | {"RELEASE-MANIFEST.json"}
    expected_directories: set[str] = set()
    for name in indexed:
        parent = PurePosixPath(name).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if actual_files.keys() != expected_files or actual_directories != expected_directories:
        raise RuntimeSetupError("installed release tree entry set mismatch")
    for name, item in indexed.items():
        digest, size, _ = _stable_regular_file(
            actual_files[name],
            label=f"release member {name}",
            maximum=MAX_RELEASE_FILE_BYTES,
            expected_uid=owner_uid,
            expected_gid=owner_gid,
            expected_mode=0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444,
        )
        if digest != item["sha256"] or size != item["size"]:
            raise RuntimeSetupError(f"release member mismatch: {name}")

    package_digest, _, _ = _stable_regular_file(
        layout.package,
        label="canonical Dev15 package",
        maximum=MAX_RELEASE_BYTES,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=0o444,
    )
    if package_digest != PACKAGE_SHA256:
        raise RuntimeSetupError("canonical package digest is not exact Dev15")
    for path, label, expected, allow_symlink in (
        (layout.odoo_python, "odoo_python", ODOO_PYTHON_SHA256, True),
        (layout.odoo_bin, "odoo_bin", ODOO_BIN_SHA256, False),
        (layout.odoo_config, "odoo_config", ODOO_CONFIG_SHA256, False),
    ):
        observed, _, _ = _stable_regular_file(
            path,
            label=label,
            maximum=MAX_RELEASE_FILE_BYTES,
            allow_path_symlink=allow_symlink,
        )
        if observed != expected:
            raise RuntimeSetupError(f"{label} digest drift detected")


def _config_document(
    layout: Layout, *, auth_key_id: str, receipt_key_id: str
) -> dict[str, str]:
    return {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID,
        "odoo_python": str(layout.odoo_python),
        "odoo_python_sha256": ODOO_PYTHON_SHA256,
        "odoo_bin": str(layout.odoo_bin),
        "odoo_bin_sha256": ODOO_BIN_SHA256,
        "odoo_config": str(layout.odoo_config),
        "odoo_config_sha256": ODOO_CONFIG_SHA256,
        "release_root": str(layout.release_root),
        "canonical_package_path": str(layout.package),
        "canonical_package_sha256": PACKAGE_SHA256,
        "auth_state_path": str(layout.auth_state_parent / "state.sqlite3"),
        "receipt_state_path": str(layout.receipt_state_parent / "state.sqlite3"),
        "auth_key_id": auth_key_id,
        "receipt_key_id": receipt_key_id,
        "auth_secret_path": str(layout.auth_secret),
        "receipt_secret_path": str(layout.receipt_secret),
    }


def _read_config(path: Path, *, test_mode: bool) -> dict[str, object]:
    owner_uid = os.geteuid() if test_mode and hasattr(os, "geteuid") else 0
    owner_gid = os.getegid() if test_mode and hasattr(os, "getegid") else 0
    _, _, payload = _stable_regular_file(
        path,
        label="existing runtime config",
        maximum=65_536,
        expected_uid=owner_uid,
        expected_gid=owner_gid,
        expected_mode=0o600 if test_mode else 0o644,
        capture=True,
    )
    assert payload is not None
    return _strict_json_object(payload, label="existing runtime config")


def _verify_secret(path: Path, *, uid: int, gid: int, test_mode: bool) -> bytes:
    before = _verify_owner_mode(
        path,
        uid=uid,
        gid=gid,
        mode=0o600 if test_mode else 0o640,
        directory=False,
        test_mode=test_mode,
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            value = bytearray()
            while len(value) < 33:
                chunk = os.read(descriptor, 33 - len(value))
                if not chunk:
                    break
                value.extend(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as exc:
        raise RuntimeSetupError("existing runtime secret cannot be read safely") from exc

    def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_uid,
            metadata.st_gid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_nlink,
        )

    if not (
        fingerprint(before)
        == fingerprint(opened)
        == fingerprint(opened_after)
        == fingerprint(after)
    ) or len(value) != 32:
        raise RuntimeSetupError("existing runtime secret has drifted")
    return bytes(value)


def _new_secret_pair() -> tuple[bytes, bytes]:
    """Return two distinct opaque 32-byte values without text normalization."""

    auth_secret = secrets.token_bytes(32)
    receipt_secret = secrets.token_bytes(32)
    while secrets.compare_digest(auth_secret, receipt_secret):
        receipt_secret = secrets.token_bytes(32)
    return auth_secret, receipt_secret


def _verify_child_home(
    path: Path, *, uid: int, gid: int, test_mode: bool, require_empty: bool
) -> None:
    _verify_owner_mode(
        path,
        uid=uid,
        gid=gid,
        mode=0o700,
        directory=True,
        test_mode=test_mode,
    )
    if require_empty and any(path.iterdir()):
        raise RuntimeSetupError("fixed Odoo child HOME is not empty")


def _existing_runtime(
    layout: Layout, *, service_uid: int, service_gid: int, test_mode: bool
) -> SetupResult | None:
    if not os.path.lexists(layout.config):
        return None
    _verify_chain(
        layout.root,
        layout.config_parent,
        allowed_uids={0},
        test_mode=test_mode,
    )
    _verify_chain(
        layout.root,
        layout.secret_root,
        allowed_uids={0},
        test_mode=test_mode,
    )
    _verify_chain(
        layout.root,
        layout.state_root,
        allowed_uids={0},
        test_mode=test_mode,
    )
    _verify_chain(
        layout.root,
        layout.child_home,
        allowed_uids={0, service_uid},
        test_mode=test_mode,
    )
    _verify_owner_mode(
        layout.config_parent,
        uid=0,
        gid=0,
        mode=0o755,
        directory=True,
        test_mode=test_mode,
    )
    _verify_owner_mode(
        layout.config,
        uid=0,
        gid=0,
        mode=0o600 if test_mode else 0o644,
        directory=False,
        test_mode=test_mode,
    )
    config = _read_config(layout.config, test_mode=test_mode)
    if set(config) != CONFIG_FIELDS:
        raise RuntimeSetupError("existing runtime config field drift detected")
    auth_key_id = config.get("auth_key_id")
    receipt_key_id = config.get("receipt_key_id")
    if (
        not isinstance(auth_key_id, str)
        or not auth_key_id.startswith("test-auth-dev15-")
        or not isinstance(receipt_key_id, str)
        or not receipt_key_id.startswith("test-receipt-dev15-")
        or auth_key_id == receipt_key_id
        or config != _config_document(
            layout, auth_key_id=auth_key_id, receipt_key_id=receipt_key_id
        )
    ):
        raise RuntimeSetupError("existing runtime config value drift detected")
    _verify_owner_mode(
        layout.secret_root,
        uid=0,
        gid=service_gid,
        mode=0o700 if test_mode else 0o750,
        directory=True,
        test_mode=test_mode,
    )
    _verify_owner_mode(
        layout.state_root,
        uid=0,
        gid=service_gid,
        mode=0o710,
        directory=True,
        test_mode=test_mode,
    )
    auth = _verify_secret(
        layout.auth_secret, uid=0, gid=service_gid, test_mode=test_mode
    )
    receipt = _verify_secret(
        layout.receipt_secret, uid=0, gid=service_gid, test_mode=test_mode
    )
    if secrets.compare_digest(auth, receipt):
        raise RuntimeSetupError("read runtime secrets are not purpose-isolated")
    for parent in (layout.auth_state_parent, layout.receipt_state_parent):
        _verify_owner_mode(
            parent,
            uid=service_uid,
            gid=service_gid,
            mode=0o700,
            directory=True,
            test_mode=test_mode,
        )
    for base in (
        layout.auth_state_parent / "state.sqlite3",
        layout.receipt_state_parent / "state.sqlite3",
    ):
        for state_path in (base, Path(f"{base}-wal"), Path(f"{base}-shm")):
            if os.path.lexists(state_path):
                _verify_owner_mode(
                    state_path,
                    uid=service_uid,
                    gid=service_gid,
                    mode=0o600,
                    directory=False,
                    test_mode=test_mode,
                )
    _verify_child_home(
        layout.child_home,
        uid=service_uid,
        gid=service_gid,
        test_mode=test_mode,
        require_empty=True,
    )
    return SetupResult(layout.config, layout.child_home, already_exists=True)


def _service_identity(test_mode: bool) -> tuple[int, int]:
    if test_mode:
        return (
            os.geteuid() if hasattr(os, "geteuid") else 0,
            os.getegid() if hasattr(os, "getegid") else 0,
        )
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeSetupError("production runtime setup must run as root on POSIX")
    try:
        import grp
        import pwd

        return pwd.getpwnam("odoo").pw_uid, grp.getgrnam("odoo").gr_gid
    except (ImportError, KeyError) as exc:
        raise RuntimeSetupError("the production odoo:odoo identity is absent") from exc


def setup_candidate_runtime(*, root: Path = Path("/"), test_mode: bool = False) -> SetupResult:
    """Publish the exact Dev15 test/staged read runtime, config last."""

    root = Path(root).absolute()
    if test_mode:
        if root == Path(root.anchor):
            raise RuntimeSetupError("test mode requires a private non-system root")
    elif root != Path("/"):
        raise RuntimeSetupError("production mode does not permit a redirected root")
    service_uid, service_gid = _service_identity(test_mode)
    root_metadata = _canonical_directory(root)
    if os.name == "posix" and (
        root_metadata.st_mode & 0o022
        or (test_mode and root_metadata.st_uid != os.geteuid())
        or (not test_mode and root_metadata.st_uid != 0)
    ):
        raise RuntimeSetupError("selected runtime root is not privately managed")

    layout = build_layout(root)
    _verify_release(layout, test_mode=test_mode)
    existing = _existing_runtime(
        layout,
        service_uid=service_uid,
        service_gid=service_gid,
        test_mode=test_mode,
    )
    if existing is not None:
        return existing

    transaction = _Transaction()
    lock: Path | None = None
    lock_descriptor: int | None = None
    lock_created = False
    lock_identity: tuple[int, int] | None = None
    try:
        _ensure_chain(
            root,
            layout.config_parent,
            uid=0,
            gid=0,
            test_mode=test_mode,
            transaction=transaction,
        )
        _verify_owner_mode(
            layout.config_parent,
            uid=0,
            gid=0,
            mode=0o755,
            directory=True,
            test_mode=test_mode,
        )
        lock = layout.config_parent / ".runtime-test-dev15-c4616386f921.lock"
        lock_descriptor, lock_created, lock_identity = _open_runtime_lock(
            lock, test_mode=test_mode
        )
        _verify_owner_mode(
            layout.config_parent,
            uid=0,
            gid=0,
            mode=0o755,
            directory=True,
            test_mode=test_mode,
        )
        # Another process may have completed the config-last transaction while
        # this process waited for the lock. Re-validate the complete runtime.
        existing = _existing_runtime(
            layout,
            service_uid=service_uid,
            service_gid=service_gid,
            test_mode=test_mode,
        )
        if existing is not None:
            return existing
        # Once locked, pre-existing release-specific objects are drift, never reusable.
        for path in (layout.secret_root, layout.state_root):
            if os.path.lexists(path):
                raise RuntimeSetupError(f"partial candidate runtime already exists: {path}")

        for parent in (layout.secret_root.parent, layout.state_root.parent):
            _ensure_chain(
                root,
                parent,
                uid=0,
                gid=0,
                test_mode=test_mode,
                transaction=transaction,
                allowed_existing_uids={0},
            )
        _ensure_chain(
            root,
            layout.child_home.parent,
            uid=0,
            gid=0,
            test_mode=test_mode,
            transaction=transaction,
        )
        if os.path.lexists(layout.child_home):
            _verify_child_home(
                layout.child_home,
                uid=service_uid,
                gid=service_gid,
                test_mode=test_mode,
                require_empty=True,
            )
        else:
            _mkdir_exact(
                layout.child_home,
                uid=service_uid,
                gid=service_gid,
                mode=0o700,
                test_mode=test_mode,
                transaction=transaction,
            )

        _mkdir_exact(
            layout.secret_root,
            uid=0,
            gid=service_gid,
            mode=0o750 if not test_mode else 0o700,
            test_mode=test_mode,
            transaction=transaction,
        )
        _mkdir_exact(
            layout.state_root,
            uid=0,
            gid=service_gid,
            mode=0o710,
            test_mode=test_mode,
            transaction=transaction,
        )
        for parent in (layout.auth_state_parent, layout.receipt_state_parent):
            _mkdir_exact(
                parent,
                uid=service_uid,
                gid=service_gid,
                mode=0o700,
                test_mode=test_mode,
                transaction=transaction,
            )

        auth_secret, receipt_secret = _new_secret_pair()
        secret_mode = 0o600 if test_mode else 0o640
        _publish_file(
            layout.auth_secret,
            auth_secret,
            uid=0,
            gid=service_gid,
            mode=secret_mode,
            test_mode=test_mode,
            transaction=transaction,
        )
        _publish_file(
            layout.receipt_secret,
            receipt_secret,
            uid=0,
            gid=service_gid,
            mode=secret_mode,
            test_mode=test_mode,
            transaction=transaction,
        )
        auth_key_id = f"test-auth-dev15-{secrets.token_hex(12)}"
        receipt_key_id = f"test-receipt-dev15-{secrets.token_hex(12)}"
        document = _config_document(
            layout, auth_key_id=auth_key_id, receipt_key_id=receipt_key_id
        )
        if set(document) != CONFIG_FIELDS or len(document) != 20:
            raise RuntimeSetupError("internal runtime configuration contract failed")
        config_bytes = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        _publish_file(
            layout.config,
            config_bytes,
            uid=0,
            gid=0,
            mode=0o600 if test_mode else 0o644,
            test_mode=test_mode,
            transaction=transaction,
        )
        return SetupResult(layout.config, layout.child_home)
    except Exception:
        transaction.rollback()
        raise
    finally:
        if (
            lock is not None
            and lock_descriptor is not None
            and lock_identity is not None
        ):
            _close_runtime_lock(
                lock,
                lock_descriptor,
                remove=os.name != "posix" and lock_created,
                identity=lock_identity,
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-root",
        type=Path,
        help="redirect all absolute paths below one private root (unit tests only)",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = setup_candidate_runtime(
            root=arguments.test_root or Path("/"),
            test_mode=arguments.test_root is not None,
        )
    except RuntimeSetupError as exc:
        print(f"runtime setup refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.public_record(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
