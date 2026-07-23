#!/usr/bin/env python3
"""Build, mount, and verify the immutable Dev29 Odoo dependency closure.

The production CLI is deliberately standard-library-only so it can be invoked
with ``/usr/bin/python3.12 -I -S`` before any mutable Odoo virtual environment is
trusted.  The public image never contains the real Odoo configuration: a
fail-closed placeholder occupies the path in the image and an independently
sealed root:odoo file is the final systemd read-only bind.
"""

from __future__ import annotations

import argparse
import ast
import configparser
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator, Sequence

try:
    import pwd  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Windows unit-test import only.
    class _PwdUnavailable:
        @staticmethod
        def getpwnam(_name: str) -> object:
            raise KeyError(_name)

    pwd = _PwdUnavailable()  # type: ignore[assignment]

try:  # The production path is Linux; this keeps pure helpers unit-testable elsewhere.
    import fcntl  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows test import.
    class _FcntlUnavailable:
        LOCK_EX = 0
        LOCK_UN = 0

        @staticmethod
        def flock(_descriptor: int, _operation: int) -> None:
            return None

        @staticmethod
        def ioctl(*_arguments: object, **_keywords: object) -> object:
            raise OSError(errno.ENOSYS, "fcntl ioctl is unavailable")

    fcntl = _FcntlUnavailable()  # type: ignore[assignment]


SCHEMA_VERSION = 1
RELEASE_SCRIPT = PurePosixPath("deployment/dev29/odoo_closure.py")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
RELEASE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
DATABASE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")
DATABASE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MODULE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
MAX_RELEASE_ENTRIES = 25_000
MAX_RELEASE_BYTES = 768 * 1024 * 1024
MAX_RELEASE_FILE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_ENTRIES = 150_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_PSQL_BYTES = 32 * 1024 * 1024
PLACEHOLDER = (
    b"# Odoo Accounting CLI V3 fail-closed dependency closure placeholder.\n"
    b"# The exact root:odoo 0440 configuration must be bound over this file.\n"
)

SOURCE_SERVER = PurePosixPath("/opt/odoo/odoo19/odoo-server")
SOURCE_VENV = PurePosixPath("/opt/odoo/odoo19/odoo19-venv")
SOURCE_CUSTOM = PurePosixPath("/mnt/odoo/odoo19/custom/addons")
SOURCE_CONFIG = SOURCE_CUSTOM / "odoo-server19.conf"
BUILTIN_ADDONS = SOURCE_SERVER / "odoo/addons"
COMMUNITY_ADDONS = SOURCE_SERVER / "addons"
EXPECTED_CONFIG_ADDONS = (str(COMMUNITY_ADDONS), str(SOURCE_CUSTOM))
MOUNT_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/dependencies")
IMAGE_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/dependency-images")
TRUSTED_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/trusted-artifacts")
DEPENDENCY_ANCHOR_BASE = PurePosixPath(
    "/opt/odoo-accounting-cli-v3/dependency-anchors"
)
SEALED_CONFIG_BASE = PurePosixPath("/etc/odoo-accounting-cli-v3/dependencies")
BUILD_BASE = PurePosixPath("/var/lib/odoo-accounting-cli-v3/dependency-build")
LOCK_BASE = PurePosixPath("/run/lock/odoo-accounting-cli-v3")
RELEASES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/releases")
PACKAGES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/packages")
PSQL = Path("/usr/lib/postgresql/16/bin/psql")
RUNUSER = Path("/usr/sbin/runuser")
MKSQUASHFS = Path("/usr/bin/mksquashfs")
MOUNT = Path("/usr/bin/mount")
UMOUNT = Path("/usr/bin/umount")
MOUNT_UTILITY_MODE = 0o4755
LDCONFIG = Path("/usr/sbin/ldconfig.real")
SYSTEM_PYTHON = PurePosixPath("/usr/bin/python3.12")
LD_SO_PRELOAD = PurePosixPath("/etc/ld.so.preload")
X86_64_LIB_TOKEN = "lib/x86_64-linux-gnu"

EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)

# A .pth execution line runs before application imports.  Only the standard
# setuptools compatibility hook is accepted, and only when its imported module
# is physically present in this exact venv closure.
DISTUTILS_PTH_LINE = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = "
    "os.environ.get(var, 'local') == 'local'; enabled and "
    "__import__('_distutils_hack').add_shim();"
)
ALLOWED_PTH_EXECUTION = frozenset({DISTUTILS_PTH_LINE, DISTUTILS_PTH_LINE + " "})
FORBIDDEN_EDITABLE_PREFIXES = (
    "__editable__.",
    "__editable___",
)
ALLOWED_RELATIVE_ELF_SEARCH_PATHS = frozenset({"pillow.libs"})
FORBIDDEN_AUTOSTART_NAMES = frozenset(
    {
        "sitecustomize.py",
        "sitecustomize.pyc",
        "sitecustomize.pyo",
        "usercustomize.py",
        "usercustomize.pyc",
        "usercustomize.pyo",
    }
)


class ClosureError(RuntimeError):
    """The immutable Odoo dependency closure cannot be trusted."""


@dataclass(frozen=True)
class ExpectedIdentity:
    release: str
    version: str
    commit: str
    manifest_sha256: str
    package_sha256: str

    def validate(self) -> None:
        if (
            not isinstance(self.release, str)
            or RELEASE.fullmatch(self.release) is None
            or not isinstance(self.version, str)
            or VERSION.fullmatch(self.version) is None
            or not isinstance(self.commit, str)
            or HEX40.fullmatch(self.commit) is None
            or self.release != f"{self.version}-{self.commit[:12]}"
            or not isinstance(self.manifest_sha256, str)
            or HEX64.fullmatch(self.manifest_sha256) is None
            or not isinstance(self.package_sha256, str)
            or HEX64.fullmatch(self.package_sha256) is None
        ):
            raise ClosureError("expected release identity is invalid")

    def public(self) -> dict[str, str]:
        return {
            "release": self.release,
            "version": self.version,
            "commit": self.commit,
            "manifest_sha256": self.manifest_sha256,
            "package_sha256": self.package_sha256,
        }


@dataclass(frozen=True)
class Layout:
    root: Path
    release_root: Path
    package: Path
    release_anchor: Path
    script: Path
    source_server: Path
    source_venv: Path
    source_custom: Path
    source_config: Path
    image_parent: Path
    image: Path
    closure_anchor: Path
    mount_parent: Path
    mount_point: Path
    sealed_config_parent: Path
    sealed_config: Path
    build_parent: Path
    lock_parent: Path
    lock: Path


@dataclass(frozen=True)
class SourceItem:
    source: Path
    destination: PurePosixPath
    component: str


def _rooted(root: Path, absolute: PurePosixPath) -> Path:
    root = Path(root).absolute()
    if not absolute.is_absolute():
        raise ClosureError("internal path is not absolute")
    return root.joinpath(*absolute.parts[1:])


def build_layout(root: Path, expected: ExpectedIdentity) -> Layout:
    expected.validate()
    release_root = _rooted(root, RELEASES_BASE / expected.release)
    image_parent = _rooted(root, IMAGE_BASE)
    mount_parent = _rooted(root, MOUNT_BASE)
    sealed_parent = _rooted(root, SEALED_CONFIG_BASE / expected.release)
    return Layout(
        root=Path(root).absolute(),
        release_root=release_root,
        package=_rooted(
            root,
            PACKAGES_BASE / f"odoo-accounting-cli-v3-{expected.release}.tar.gz",
        ),
        release_anchor=_rooted(root, TRUSTED_BASE / f"{expected.release}.json"),
        script=release_root.joinpath(*RELEASE_SCRIPT.parts),
        source_server=_rooted(root, SOURCE_SERVER),
        source_venv=_rooted(root, SOURCE_VENV),
        source_custom=_rooted(root, SOURCE_CUSTOM),
        source_config=_rooted(root, SOURCE_CONFIG),
        image_parent=image_parent,
        image=image_parent / f"{expected.release}.squashfs",
        closure_anchor=_rooted(root, DEPENDENCY_ANCHOR_BASE / f"{expected.release}.json"),
        mount_parent=mount_parent,
        mount_point=mount_parent / expected.release,
        sealed_config_parent=sealed_parent,
        sealed_config=sealed_parent / "odoo-server19.conf",
        build_parent=_rooted(root, BUILD_BASE),
        lock_parent=_rooted(root, LOCK_BASE),
        lock=_rooted(root, LOCK_BASE / f"odoo-closure-{expected.release}.lock"),
    )


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ClosureError("value cannot be canonicalized") from exc


def _schema_version_is_one(value: object) -> bool:
    return type(value) is int and value == 1


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _strict_object(payload: bytes, *, label: str) -> dict[str, Any]:
    duplicates: list[str] = []

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ClosureError(f"{label} contains non-finite number: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except ClosureError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ClosureError(f"{label} is not strict UTF-8 JSON") from exc
    if duplicates or not isinstance(value, dict):
        raise ClosureError(f"{label} is not a unique-key JSON object")
    return value


def _sha_file(path: Path, *, maximum: int | None = None) -> tuple[str, int]:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ClosureError(f"unsafe regular file: {path}")
        if maximum is not None and before.st_size > maximum:
            raise ClosureError(f"file exceeds size limit: {path}")
        digest = hashlib.sha256()
        total = 0
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ClosureError(f"file changed while opening: {path}")
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if maximum is not None and total > maximum:
                    raise ClosureError(f"file exceeds size limit: {path}")
                digest.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = path.lstat()
        fingerprint = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(opened) or fingerprint(opened) != fingerprint(after) or fingerprint(after) != fingerprint(final):
            raise ClosureError(f"file changed while hashing: {path}")
        return digest.hexdigest(), total
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError(f"cannot hash file safely: {path}") from exc


def _sha_open_descriptor(
    descriptor: int, *, maximum: int
) -> tuple[str, int, os.stat_result]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ClosureError("open descriptor is not a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise ClosureError("open descriptor exceeds size limit")
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ClosureError("open descriptor changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest(), total, after
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError("open descriptor cannot be hashed") from exc


def _read_file(path: Path, *, maximum: int, allow_symlink: bool = False) -> bytes:
    requested = path
    link_before: os.stat_result | None = None
    link_target: str | None = None
    try:
        before = requested.lstat()
        if stat.S_ISLNK(before.st_mode):
            if not allow_symlink:
                raise ClosureError(f"symlink is forbidden: {requested}")
            link_before = before
            link_target = os.readlink(requested)
            resolved = requested.resolve(strict=True)
            if not resolved.is_file():
                raise ClosureError(f"symlink target is not a regular file: {requested}")
            path = resolved
            before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1 or before.st_size > maximum:
            raise ClosureError(f"unsafe regular file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ClosureError(f"file changed while opening: {path}")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise ClosureError(f"file exceeds size limit: {path}")
                chunks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = path.lstat()
        fingerprint = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(opened) or fingerprint(opened) != fingerprint(after) or fingerprint(after) != fingerprint(final):
            raise ClosureError(f"file changed while reading: {path}")
        if link_before is not None:
            link_after = requested.lstat()
            if (
                fingerprint(link_before) != fingerprint(link_after)
                or os.readlink(requested) != link_target
                or requested.resolve(strict=True) != path
            ):
                raise ClosureError(f"symlink changed while reading: {requested}")
        payload = b"".join(chunks)
        if len(payload) != total:
            raise ClosureError(f"file changed while reading: {path}")
        return payload
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError(f"cannot read file safely: {path}") from exc


def _require_root(*, test_mode: bool) -> tuple[int, int]:
    if test_mode:
        return (
            os.geteuid() if hasattr(os, "geteuid") else 0,
            os.getegid() if hasattr(os, "getegid") else 0,
        )
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ClosureError("Odoo dependency closure commands require Linux root")
    return 0, 0


def _mode_owner(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    directory: bool,
    label: str,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ClosureError(f"{label} cannot be inspected") from exc
    if path.is_symlink() or (
        not stat.S_ISDIR(metadata.st_mode) if directory else not stat.S_ISREG(metadata.st_mode)
    ):
        raise ClosureError(f"{label} has unsafe object type")
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ClosureError(f"{label} metadata mismatch")
    return metadata


def _require_no_symlink_ancestors(path: Path, *, stop: Path = Path("/")) -> None:
    """Reject magic/symlink redirection anywhere in an absolute path chain."""

    path = Path(path).absolute()
    stop = Path(stop).absolute()
    if sys.platform != "linux" and stop == Path("/").absolute():
        stop = Path(path.anchor)
    try:
        path.relative_to(stop)
    except ValueError as exc:
        raise ClosureError("path escapes its approved ancestor") from exc
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ClosureError("path ancestor cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ClosureError("symlink ancestor is forbidden")
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise ClosureError("path ancestor is not a directory")
        if current == stop:
            return
        parent = current.parent
        if parent == current:
            raise ClosureError("approved path ancestor was not reached")
        current = parent


def _validate_system_python(
    *,
    expected_sha256: str,
    root: Path,
    test_mode: bool,
) -> dict[str, Any]:
    """Validate the fixed bootstrap interpreter without importing site code."""

    if not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None:
        raise ClosureError("expected system Python SHA-256 is invalid")
    uid, gid = _require_root(test_mode=test_mode)
    path = _rooted(root, SYSTEM_PYTHON)
    metadata = _mode_owner(
        path,
        uid=uid,
        gid=gid,
        mode=0o755,
        directory=False,
        label="system Python 3.12",
    )
    if metadata.st_nlink != 1 or path.resolve(strict=True) != path:
        raise ClosureError("system Python 3.12 is not a sealed single-link file")
    digest, size = _sha_file(path, maximum=64 * 1024 * 1024)
    if digest != expected_sha256:
        raise ClosureError("system Python 3.12 digest mismatch")
    return {
        "path": str(path),
        "sha256": digest,
        "size": size,
        "mode": "0755",
        "uid": uid,
        "gid": gid,
        "single_link": True,
    }


def _validate_loader_preload(
    *,
    expected_sha256: str,
    root: Path,
    test_mode: bool,
) -> dict[str, Any]:
    """Seal glibc's pre-Python injection file and resolve its approved ELF roots."""

    if not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None:
        raise ClosureError("expected ld.so.preload SHA-256 is invalid")
    uid, gid = _require_root(test_mode=test_mode)
    path = _rooted(root, LD_SO_PRELOAD)
    metadata = _mode_owner(
        path,
        uid=uid,
        gid=gid,
        mode=0o644,
        directory=False,
        label="ld.so.preload",
    )
    if metadata.st_nlink != 1 or path.resolve(strict=True) != path:
        raise ClosureError("ld.so.preload is not a sealed single-link file")
    payload = _read_file(path, maximum=64 * 1024)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_sha256:
        raise ClosureError("ld.so.preload digest mismatch")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ClosureError("ld.so.preload is not strict UTF-8") from exc
    if "\x00" in text or any(
        ord(character) < 0x20 and character not in "\t\n\r" for character in text
    ):
        raise ClosureError("ld.so.preload contains unsafe control characters")
    configured: list[str] = []
    for line in text.splitlines():
        configured.extend(line.split("#", 1)[0].split())
    if not configured or len(configured) > 32 or len(set(configured)) != len(configured):
        raise ClosureError("ld.so.preload entries are empty, duplicate, or excessive")
    libraries: list[dict[str, str]] = []
    symlink_chain: dict[str, dict[str, Any]] = {}
    for token in configured:
        expanded = token.replace("${LIB}", X86_64_LIB_TOKEN).replace(
            "$LIB", X86_64_LIB_TOKEN
        )
        if "$" in expanded:
            raise ClosureError("ld.so.preload contains an unsupported loader token")
        portable = PurePosixPath(expanded)
        if (
            not portable.is_absolute()
            or portable.as_posix() != expanded
            or any(part in {"", ".", ".."} for part in portable.parts)
        ):
            raise ClosureError("ld.so.preload entry is not a canonical absolute path")
        rooted = _rooted(root, portable)
        try:
            current = Path(root).absolute()
            for part in rooted.relative_to(current).parts:
                current = current / part
                component_metadata = current.lstat()
                if stat.S_ISLNK(component_metadata.st_mode):
                    target = os.readlink(current)
                    if (
                        component_metadata.st_uid != uid
                        or component_metadata.st_gid != gid
                        or not target
                        or "\x00" in target
                    ):
                        raise ClosureError(
                            "ld.so.preload library symlink chain is untrusted"
                        )
                    symlink_chain[str(current)] = {
                        "path": str(current),
                        "target": target,
                        "uid": uid,
                        "gid": gid,
                    }
            link_metadata = rooted.lstat()
            resolved = rooted.resolve(strict=True)
            resolved_metadata = resolved.lstat()
        except OSError as exc:
            raise ClosureError("ld.so.preload library cannot be resolved") from exc
        if (
            link_metadata.st_uid != uid
            or link_metadata.st_gid != gid
            or resolved_metadata.st_uid != uid
            or resolved_metadata.st_gid != gid
            or not stat.S_ISREG(resolved_metadata.st_mode)
            or stat.S_IMODE(resolved_metadata.st_mode) & 0o022
            or not _is_elf(resolved)
        ):
            raise ClosureError("ld.so.preload library metadata is untrusted")
        libraries.append(
            {
                "configured_path": token,
                "expanded_path": expanded,
                "rooted_path": str(rooted),
                "resolved_path": str(resolved),
            }
        )
    return {
        "path": str(path),
        "sha256": digest,
        "size": len(payload),
        "mode": "0644",
        "uid": uid,
        "gid": gid,
        "libraries": libraries,
        "symlink_chain": [symlink_chain[path] for path in sorted(symlink_chain)],
        "loader_token_profile": "glibc-x86_64-debian-lib-v1",
    }


def _validate_cli_interpreter(
    expected_sha256: str,
    expected_loader_preload_sha256: str,
) -> dict[str, Any]:
    """Fail before command dispatch unless the trusted isolated bootstrap is in use."""

    if (
        sys.executable != str(SYSTEM_PYTHON)
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
    ):
        raise ClosureError(
            "closure CLI requires exact /usr/bin/python3.12 -I -S invocation"
        )
    try:
        if Path("/proc/self/exe").resolve(strict=True) != Path(SYSTEM_PYTHON):
            raise ClosureError("running Python executable differs from fixed bootstrap")
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError("running Python executable cannot be inspected") from exc
    python_identity = _validate_system_python(
        expected_sha256=expected_sha256,
        root=Path("/"),
        test_mode=False,
    )
    preload_identity = _validate_loader_preload(
        expected_sha256=expected_loader_preload_sha256,
        root=Path("/"),
        test_mode=False,
    )
    return {"system_python": python_identity, "loader_preload": preload_identity}


def _expected_digest_from_argv(argv: Sequence[str], *, option: str, label: str) -> str:
    """Extract the trust root before argparse or command-specific processing."""

    values: list[str] = []
    for index, value in enumerate(argv):
        if value == option:
            if index + 1 >= len(argv):
                raise ClosureError(f"expected {label} SHA-256 is missing")
            values.append(argv[index + 1])
        elif value.startswith(option + "="):
            values.append(value[len(option) + 1 :])
    if len(values) != 1 or HEX64.fullmatch(values[0]) is None:
        raise ClosureError(f"expected {label} SHA-256 must occur exactly once")
    return values[0]


def _expected_system_python_from_argv(argv: Sequence[str]) -> str:
    return _expected_digest_from_argv(
        argv,
        option="--expected-system-python-sha256",
        label="system Python",
    )


def _release_manifest_index(
    document: dict[str, Any], expected: ExpectedIdentity
) -> dict[str, dict[str, Any]]:
    if (
        set(document)
        != {"schema_version", "version", "commit", "manifest_sha256", "files"}
        or not _schema_version_is_one(document.get("schema_version"))
        or document.get("version") != expected.version
        or document.get("commit") != expected.commit
        or document.get("manifest_sha256") != expected.manifest_sha256
    ):
        raise ClosureError("release manifest identity is invalid")
    unsigned = {key: value for key, value in document.items() if key != "manifest_sha256"}
    if canonical_sha256(unsigned) != expected.manifest_sha256:
        raise ClosureError("release manifest semantic digest mismatch")
    files = document.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_RELEASE_ENTRIES:
        raise ClosureError("release manifest file list is invalid")
    result: dict[str, dict[str, Any]] = {}
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise ClosureError("release manifest entry is invalid")
        name, digest, size = item.get("path"), item.get("sha256"), item.get("size")
        if not isinstance(name, str):
            raise ClosureError("release manifest path is invalid")
        portable = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or portable.is_absolute()
            or portable.as_posix() != name
            or any(part in {"", ".", ".."} for part in portable.parts)
            or name == "RELEASE-MANIFEST.json"
            or name in result
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_RELEASE_FILE_BYTES
        ):
            raise ClosureError("release manifest entry is invalid")
        total += size
        if total > MAX_RELEASE_BYTES:
            raise ClosureError("release manifest exceeds size limit")
        result[name] = item
    return result


def _inventory_release(root: Path, *, uid: int, gid: int) -> tuple[dict[str, Path], set[str]]:
    files: dict[str, Path] = {}
    directories: set[str] = set()
    pending: list[tuple[Path, str]] = [(root, "")]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        _mode_owner(directory, uid=uid, gid=gid, mode=0o555, directory=True, label="release directory")
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise ClosureError("release tree cannot be inventoried") from exc
        for child in children:
            entries += 1
            if entries > MAX_RELEASE_ENTRIES:
                raise ClosureError("release tree has too many entries")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ClosureError(f"release symlink is forbidden: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((Path(child.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = Path(child.path)
            else:
                raise ClosureError(f"release object type is unsafe: {relative}")
    return files, directories


def verify_release(
    layout: Layout,
    expected: ExpectedIdentity,
    *,
    script_path: Path,
    test_mode: bool,
) -> dict[str, str]:
    uid, gid = _require_root(test_mode=test_mode)
    if Path(script_path).absolute() != layout.script:
        raise ClosureError("closure script is outside the expected release")
    _mode_owner(layout.release_root, uid=uid, gid=gid, mode=0o555, directory=True, label="release root")
    script_metadata = _mode_owner(layout.script, uid=uid, gid=gid, mode=0o444, directory=False, label="closure script")
    if script_metadata.st_nlink != 1 or layout.script.resolve(strict=True) != layout.script:
        raise ClosureError("closure script is not a sealed single-link member")
    manifest_path = layout.release_root / "RELEASE-MANIFEST.json"
    manifest_payload = _read_file(manifest_path, maximum=MAX_JSON_BYTES)
    index = _release_manifest_index(
        _strict_object(manifest_payload, label="release manifest"), expected
    )
    if RELEASE_SCRIPT.as_posix() not in index:
        raise ClosureError("release manifest omits closure script")
    actual_files, actual_directories = _inventory_release(layout.release_root, uid=uid, gid=gid)
    expected_files = set(index) | {"RELEASE-MANIFEST.json"}
    expected_directories: set[str] = set()
    for name in index:
        parent = PurePosixPath(name).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if set(actual_files) != expected_files or actual_directories != expected_directories:
        raise ClosureError("release tree does not match manifest closure")
    for name, item in index.items():
        mode = 0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444
        metadata = _mode_owner(actual_files[name], uid=uid, gid=gid, mode=mode, directory=False, label=f"release member {name}")
        if metadata.st_nlink != 1:
            raise ClosureError(f"release member has unsafe link count: {name}")
        digest, size = _sha_file(actual_files[name], maximum=MAX_RELEASE_FILE_BYTES)
        if digest != item["sha256"] or size != item["size"]:
            raise ClosureError(f"release member digest mismatch: {name}")
    anchor_payload = _read_file(layout.release_anchor, maximum=64 * 1024)
    anchor = _strict_object(anchor_payload, label="release anchor")
    if anchor != {
        "commit": expected.commit,
        "manifest_sha256": expected.manifest_sha256,
        "package_sha256": expected.package_sha256,
        "release": expected.release,
    }:
        raise ClosureError("external release anchor mismatch")
    package_digest, _ = _sha_file(layout.package, maximum=MAX_RELEASE_BYTES)
    if package_digest != expected.package_sha256:
        raise ClosureError("canonical package digest mismatch")
    return expected.public()


DATABASE_GRAPH_SQL = r"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
SELECT jsonb_build_object(
  'database_name', current_database(),
  'database_uuid', (
    SELECT value FROM public.ir_config_parameter WHERE key = 'database.uuid'
  ),
  'modules', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', name,
        'latest_version', latest_version,
        'application', application
      ) ORDER BY name COLLATE "C"
    )
    FROM public.ir_module_module
    WHERE state = 'installed'
  ), '[]'::jsonb),
  'dependencies', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'module', module.name,
        'dependency', dependency.name,
        'auto_install_required', dependency.auto_install_required,
        'dependency_state', dependency_module.state
      ) ORDER BY module.name COLLATE "C", dependency.name COLLATE "C"
    )
    FROM public.ir_module_module_dependency AS dependency
    JOIN public.ir_module_module AS module ON module.id = dependency.module_id
    LEFT JOIN public.ir_module_module AS dependency_module
      ON dependency_module.name = dependency.name
    WHERE module.state = 'installed'
  ), '[]'::jsonb)
)::text;
COMMIT;
"""


def _verified_program(
    path: Path,
    *,
    label: str,
    test_mode: bool,
    expected_mode: int = 0o755,
) -> None:
    if test_mode:
        if not path.is_file():
            raise ClosureError(f"{label} is unavailable")
        return
    metadata = _mode_owner(
        path,
        uid=0,
        gid=0,
        mode=expected_mode,
        directory=False,
        label=label,
    )
    if metadata.st_nlink != 1:
        raise ClosureError(f"{label} has unsafe link count")


def query_database_graph(
    *,
    database_name: str,
    database_uuid: str,
    psql: Path = PSQL,
    runuser: Path = RUNUSER,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    test_mode: bool = False,
) -> dict[str, Any]:
    if DATABASE.fullmatch(database_name) is None or DATABASE_UUID.fullmatch(database_uuid) is None:
        raise ClosureError("expected database identity is invalid")
    _verified_program(psql, label="psql", test_mode=test_mode)
    command: list[str]
    if test_mode:
        command = [str(psql)]
    else:
        _verified_program(runuser, label="runuser", test_mode=False)
        command = [str(runuser), "-u", "postgres", "--", str(psql)]
    command.extend(
        [
            "-X",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set=ON_ERROR_STOP=1",
            "--dbname",
            database_name,
            "--command",
            DATABASE_GRAPH_SQL,
        ]
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PGHOST": "/var/run/postgresql",
        "PGPORT": "5432",
        "PGAPPNAME": "odoo-accounting-cli-v3-dev29-closure",
    }
    try:
        process = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClosureError("database installed-module query failed") from exc
    if process.returncode != 0 or len(process.stdout) > MAX_PSQL_BYTES:
        stderr_head = process.stderr[:2048].decode("utf-8", "replace")
        raise ClosureError(
            "database installed-module query failed "
            f"(returncode={process.returncode}, stdout_size={len(process.stdout)}, "
            f"stderr={stderr_head!r})"
        )
    lines = [line for line in process.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ClosureError("database installed-module query returned ambiguous output")
    document = _strict_object(lines[0], label="database installed-module graph")
    if set(document) != {"database_name", "database_uuid", "modules", "dependencies"}:
        raise ClosureError("database installed-module graph fields are invalid")
    if document["database_name"] != database_name or document["database_uuid"] != database_uuid:
        raise ClosureError("database identity does not match expectation")
    modules = document["modules"]
    dependencies = document["dependencies"]
    if not isinstance(modules, list) or not modules or not isinstance(dependencies, list):
        raise ClosureError("database installed-module graph is empty or invalid")
    names: list[str] = []
    for item in modules:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "latest_version", "application"}
            or not isinstance(item.get("name"), str)
            or MODULE.fullmatch(item["name"]) is None
            or item["name"] in names
            or (item["latest_version"] is not None and not isinstance(item["latest_version"], str))
            or type(item["application"]) is not bool
        ):
            raise ClosureError("database installed-module row is invalid")
        names.append(item["name"])
    if names != sorted(names):
        raise ClosureError("database installed modules are not uniquely sorted")
    valid_names = set(names)
    previous: tuple[str, str] | None = None
    for item in dependencies:
        if (
            not isinstance(item, dict)
            or set(item)
            != {"module", "dependency", "auto_install_required", "dependency_state"}
            or item.get("module") not in valid_names
            or not isinstance(item.get("dependency"), str)
            or MODULE.fullmatch(item["dependency"]) is None
            or type(item.get("auto_install_required")) is not bool
            or (item.get("dependency_state") is not None and not isinstance(item["dependency_state"], str))
        ):
            raise ClosureError("database module dependency row is invalid")
        pair = (item["module"], item["dependency"])
        if previous is not None and pair <= previous:
            raise ClosureError("database module dependencies are not uniquely sorted")
        previous = pair
        if item["dependency_state"] != "installed":
            raise ClosureError("installed module has an uninstalled dependency")
    return document


def _parse_odoo_config(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
        parser = configparser.RawConfigParser(
            interpolation=None, strict=True, empty_lines_in_values=False
        )
        parser.read_string(text)
        raw = parser.get("options", "addons_path")
    except (UnicodeError, configparser.Error, KeyError) as exc:
        raise ClosureError("Odoo configuration cannot be parsed safely") from exc
    paths = tuple(part.strip() for part in raw.split(",") if part.strip())
    if paths != EXPECTED_CONFIG_ADDONS:
        raise ClosureError("Odoo addons_path differs from reviewed source roots")


def _module_manifest(module_root: Path) -> tuple[Path, dict[str, Any]]:
    candidates = [module_root / "__manifest__.py", module_root / "__openerp__.py"]
    present = [path for path in candidates if os.path.lexists(path)]
    if len(present) != 1:
        raise ClosureError(f"module manifest is missing or ambiguous: {module_root.name}")
    path = present[0]
    payload = _read_file(path, maximum=1024 * 1024)
    try:
        value = ast.literal_eval(payload.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        raise ClosureError(f"module manifest is not a literal object: {module_root.name}") from exc
    if not isinstance(value, dict):
        raise ClosureError(f"module manifest is not an object: {module_root.name}")
    version = value.get("version", "1.0")
    dependencies = value.get("depends", [])
    if not isinstance(version, str) or not isinstance(dependencies, list) or any(
        not isinstance(item, str) or MODULE.fullmatch(item) is None for item in dependencies
    ):
        raise ClosureError(f"module manifest fields are invalid: {module_root.name}")
    return path, {"version": version, "depends": sorted(set(dependencies))}


def _tree_manifest(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    pending: list[tuple[Path, str]] = [(path, ".")]
    while pending:
        current, relative = pending.pop()
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ClosureError(f"module tree cannot be inspected: {path.name}") from exc
        base: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }
        if stat.S_ISDIR(metadata.st_mode):
            base["kind"] = "directory"
            try:
                children = sorted(os.scandir(current), key=lambda item: item.name, reverse=True)
            except OSError as exc:
                raise ClosureError(f"module tree cannot be read: {path.name}") from exc
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                pending.append((Path(child.path), child_relative))
        elif stat.S_ISREG(metadata.st_mode):
            digest, size = _sha_file(current, maximum=MAX_SOURCE_BYTES)
            base.update({"kind": "regular", "size": size, "sha256": digest})
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(current)
            except OSError as exc:
                raise ClosureError(f"module symlink cannot be read: {path.name}") from exc
            base.update({"kind": "symlink", "target": target})
        else:
            raise ClosureError(f"module tree contains unsafe object: {path.name}")
        result.append(base)
        if len(result) > MAX_SOURCE_ENTRIES:
            raise ClosureError("module tree exceeds entry limit")
    result.sort(key=lambda item: item["path"])
    return result


def resolve_installed_modules(
    layout: Layout, graph: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[SourceItem]]:
    roots = (
        ("builtin", layout.source_server / "odoo" / "addons", PurePosixPath("odoo-server/odoo/addons")),
        ("community", layout.source_server / "addons", PurePosixPath("odoo-server/addons")),
        ("custom", layout.source_custom, PurePosixPath("custom-addons")),
    )
    mapping: list[dict[str, Any]] = []
    selections: list[SourceItem] = []
    graph_dependencies: dict[str, list[str]] = {}
    for dependency in graph["dependencies"]:
        graph_dependencies.setdefault(dependency["module"], []).append(dependency["dependency"])
    for module in graph["modules"]:
        name = module["name"]
        candidates: list[tuple[str, Path, PurePosixPath]] = []
        for source_name, root, destination in roots:
            candidate = root / name
            if os.path.lexists(candidate):
                try:
                    metadata = candidate.lstat()
                except OSError as exc:
                    raise ClosureError(f"module root cannot be inspected: {name}") from exc
                if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise ClosureError(f"module root is not a canonical directory: {name}")
                candidates.append((source_name, candidate, destination / name))
        if len(candidates) != 1:
            raise ClosureError(f"installed module source is missing or duplicated: {name}")
        source_name, source_path, destination_path = candidates[0]
        _manifest_path, parsed = _module_manifest(source_path)
        if parsed["depends"] != sorted(graph_dependencies.get(name, [])):
            raise ClosureError(f"module manifest dependency graph mismatch: {name}")
        tree = _tree_manifest(source_path)
        mapping.append(
            {
                "name": name,
                "latest_version": module["latest_version"],
                "source": source_name,
                "path": str(source_path),
                "manifest_version": parsed["version"],
                "tree_sha256": canonical_sha256(tree),
            }
        )
        selections.append(SourceItem(source_path, destination_path, f"module:{name}"))
    return mapping, selections


def _core_selections(layout: Layout) -> list[SourceItem]:
    result = [
        SourceItem(layout.source_server / "odoo-bin", PurePosixPath("odoo-server/odoo-bin"), "odoo-core"),
        SourceItem(layout.source_venv, PurePosixPath("odoo19-venv"), "odoo-venv"),
    ]
    odoo = layout.source_server / "odoo"
    try:
        children = sorted(os.scandir(odoo), key=lambda item: item.name)
        addon_children = sorted(os.scandir(odoo / "addons"), key=lambda item: item.name)
    except OSError as exc:
        raise ClosureError("Odoo core tree cannot be enumerated") from exc
    for child in children:
        if child.name != "addons":
            result.append(
                SourceItem(Path(child.path), PurePosixPath("odoo-server/odoo") / child.name, "odoo-core")
            )
    for child in addon_children:
        metadata = child.stat(follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode):
            result.append(
                SourceItem(Path(child.path), PurePosixPath("odoo-server/odoo/addons") / child.name, "odoo-core")
            )
        elif not stat.S_ISDIR(metadata.st_mode):
            raise ClosureError("Odoo builtin addons root contains unsafe object")
    return result


def _source_entry(path: Path, destination: str, component: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ClosureError(f"source cannot be inspected: {path}") from exc
    result: dict[str, Any] = {
        "source": str(path),
        "destination": destination,
        "component": component,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    if stat.S_ISDIR(metadata.st_mode):
        result["kind"] = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        digest, size = _sha_file(path, maximum=MAX_SOURCE_BYTES)
        result.update({"kind": "regular", "size": size, "sha256": digest})
    elif stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(path)
            resolved = path.resolve(strict=True)
            resolved_metadata = resolved.lstat()
        except OSError as exc:
            raise ClosureError(f"source symlink is broken: {path}") from exc
        if stat.S_ISREG(resolved_metadata.st_mode):
            digest, size = _sha_file(resolved, maximum=MAX_SOURCE_BYTES)
            result.update(
                {
                    "kind": "materialized_symlink",
                    "target": target,
                    "resolved_path": str(resolved),
                    "size": size,
                    "sha256": digest,
                }
            )
        elif stat.S_ISDIR(resolved_metadata.st_mode):
            # Directory links are allowed only when they remain inside the same
            # selected component; their image link is separately checked.
            result.update({"kind": "symlink", "target": target, "resolved_path": str(resolved)})
        else:
            raise ClosureError(f"source symlink resolves to unsafe object: {path}")
    else:
        raise ClosureError(f"source contains unsafe object: {path}")
    return result


def source_manifest(selections: Sequence[SourceItem], config: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    seen_destinations: set[str] = set()
    for selection in sorted(selections, key=lambda item: item.destination.as_posix()):
        pending: list[tuple[Path, PurePosixPath]] = [(selection.source, selection.destination)]
        while pending:
            path, destination = pending.pop()
            name = destination.as_posix()
            if name in seen_destinations:
                raise ClosureError(f"source selections overlap: {name}")
            seen_destinations.add(name)
            entry = _source_entry(path, name, selection.component)
            entries.append(entry)
            if entry["kind"] == "directory":
                try:
                    children = sorted(os.scandir(path), key=lambda item: item.name, reverse=True)
                except OSError as exc:
                    raise ClosureError(f"source directory cannot be read: {path}") from exc
                for child in children:
                    pending.append((Path(child.path), destination / child.name))
            if len(entries) > MAX_SOURCE_ENTRIES:
                raise ClosureError("source closure exceeds entry limit")
    config_digest, config_size = _sha_file(config, maximum=MAX_CONFIG_BYTES)
    entries.append(
        {
            "source": str(config),
            "destination": "@sealed-config/odoo-server19.conf",
            "component": "sealed-config",
            "kind": "regular",
            "mode": f"{stat.S_IMODE(config.lstat().st_mode):04o}",
            "uid": config.lstat().st_uid,
            "gid": config.lstat().st_gid,
            "size": config_size,
            "sha256": config_digest,
        }
    )
    entries.sort(key=lambda item: (item["destination"], item["source"]))
    return {"schema_version": 1, "entries": entries}


class InotifyGuard:
    """Recursive mutation guard spanning every selected source root."""

    _EVENT = struct.Struct("iIII")
    _MASK = (
        0x00000002  # IN_MODIFY
        | 0x00000004  # IN_ATTRIB
        | 0x00000008  # IN_CLOSE_WRITE
        | 0x00000040  # IN_MOVED_FROM
        | 0x00000080  # IN_MOVED_TO
        | 0x00000100  # IN_CREATE
        | 0x00000200  # IN_DELETE
        | 0x00000400  # IN_DELETE_SELF
        | 0x00000800  # IN_MOVE_SELF
        | 0x00002000  # IN_UNMOUNT
        | 0x00004000  # IN_Q_OVERFLOW
        | 0x00008000  # IN_IGNORED
    )
    _COVERAGE_LOSS_MASK = (
        0x00000400  # IN_DELETE_SELF
        | 0x00000800  # IN_MOVE_SELF
        | 0x00002000  # IN_UNMOUNT
        | 0x00004000  # IN_Q_OVERFLOW
        | 0x00008000  # IN_IGNORED
    )
    _MAX_EVENT_BYTES = 16 * 1024 * 1024

    def __init__(self, roots: Iterable[Path], *, test_mode: bool = False) -> None:
        self.roots = tuple(dict.fromkeys(Path(path).absolute() for path in roots))
        self.test_mode = test_mode
        self.fd = -1
        self.watches = 0
        self._add_watch: Any = None
        self._watched_directories: set[Path] = set()
        self._watch_by_directory: dict[Path, int] = {}
        self._watch_all: set[int] = set()
        self._watch_names: dict[int, set[str]] = {}

    def __enter__(self) -> "InotifyGuard":
        if self.test_mode and sys.platform != "linux":
            return self
        if sys.platform != "linux":
            raise ClosureError("recursive inotify guard requires Linux")
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        self._add_watch = add
        self.fd = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if self.fd < 0:
            raise ClosureError("recursive inotify guard cannot be initialized")
        try:
            self.add_roots(self.roots)
            if not self.watches:
                raise ClosureError("recursive inotify guard installed no watches")
            return self
        except Exception:
            os.close(self.fd)
            self.fd = -1
            raise

    def add_roots(self, roots: Iterable[Path]) -> None:
        if self.test_mode and sys.platform != "linux":
            return
        if self.fd < 0 or self._add_watch is None:
            raise ClosureError("recursive inotify guard is not active")
        requests: dict[Path, set[str] | None] = {}

        def request(directory: Path, names: set[str] | None) -> None:
            current = requests.get(directory)
            if directory not in requests:
                requests[directory] = None if names is None else set(names)
            elif current is not None:
                if names is None:
                    requests[directory] = None
                else:
                    current.update(names)

        for root in roots:
            root = Path(root).absolute()
            if root.is_dir() and not root.is_symlink():
                request(root, None)
                for directory, names, _files in os.walk(root, followlinks=False):
                    request(Path(directory), None)
                    names[:] = [
                        name
                        for name in names
                        if not (Path(directory) / name).is_symlink()
                    ]
            else:
                request(root.parent, {root.name})
        for directory in sorted(requests, key=str):
            descriptor = self._watch_by_directory.get(directory)
            if descriptor is None:
                descriptor = self._add_watch(
                    self.fd, os.fsencode(directory), self._MASK
                )
                if descriptor < 0:
                    raise ClosureError(f"recursive inotify watch failed: {directory}")
                self._watch_by_directory[directory] = descriptor
                self._watched_directories.add(directory)
            names = requests[directory]
            if names is None:
                self._watch_all.add(descriptor)
                self._watch_names.pop(descriptor, None)
            elif descriptor not in self._watch_all:
                self._watch_names.setdefault(descriptor, set()).update(names)
        self.watches = len(self._watch_all | set(self._watch_names))

    def _payload_mutates_scope(self, payload: bytes) -> bool:
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < self._EVENT.size:
                raise ClosureError("recursive inotify event stream is malformed")
            watch, mask, _cookie, length = self._EVENT.unpack_from(payload, offset)
            offset += self._EVENT.size
            end = offset + length
            if length > 4096 or length % 4 or end > len(payload):
                raise ClosureError("recursive inotify event stream is malformed")
            raw_name = payload[offset:end]
            offset = end
            if raw_name:
                name, separator, padding = raw_name.partition(b"\0")
                if not separator or any(padding):
                    raise ClosureError("recursive inotify event name is malformed")
                try:
                    decoded_name = os.fsdecode(name)
                except UnicodeError as exc:
                    raise ClosureError("recursive inotify event name is invalid") from exc
            else:
                decoded_name = ""
            if mask & self._COVERAGE_LOSS_MASK:
                return True
            if watch in self._watch_all:
                return True
            names = self._watch_names.get(watch)
            if names is None:
                return True
            if decoded_name in names:
                return True
        return False

    def assert_quiet(self) -> None:
        if self.fd < 0:
            if self.test_mode and sys.platform != "linux":
                return
            raise ClosureError("recursive inotify guard is not active")
        observed = 0
        while True:
            try:
                payload = os.read(self.fd, 1024 * 1024)
            except BlockingIOError:
                return
            except OSError as exc:
                raise ClosureError("recursive inotify guard cannot be read") from exc
            if not payload:
                raise ClosureError("recursive inotify guard returned an empty read")
            observed += len(payload)
            if observed > self._MAX_EVENT_BYTES:
                raise ClosureError("recursive inotify event volume exceeds limit")
            if self._payload_mutates_scope(payload):
                raise ClosureError("Odoo dependency source changed during closure build")

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self._watch_by_directory.clear()
        self._watch_all.clear()
        self._watch_names.clear()
        self._watched_directories.clear()
        self.watches = 0


def _normalized_pyvenv(path: Path) -> tuple[bytes, dict[str, str]]:
    payload = _read_file(path, maximum=64 * 1024)
    values: dict[str, str] = {}
    try:
        for raw in payload.decode("utf-8").splitlines():
            if not raw.strip():
                continue
            if "=" not in raw:
                raise ClosureError("pyvenv.cfg contains an invalid line")
            key, value = (part.strip() for part in raw.split("=", 1))
            if not key or key in values:
                raise ClosureError("pyvenv.cfg keys are invalid or duplicated")
            values[key] = value
    except UnicodeError as exc:
        raise ClosureError("pyvenv.cfg is not UTF-8") from exc
    version = values.get("version", "")
    if (
        values.get("include-system-site-packages", "").lower() != "false"
        or re.fullmatch(r"3\.12(?:\.[0-9]+)?", version) is None
    ):
        raise ClosureError("pyvenv.cfg permits external site packages or wrong ABI")
    normalized_values = {
        "home": "/usr/bin",
        "include-system-site-packages": "false",
        "version": version,
        "executable": "/usr/bin/python3.12",
    }
    normalized = "".join(f"{key} = {value}\n" for key, value in normalized_values.items()).encode("utf-8")
    return normalized, normalized_values


def audit_python_paths(venv: Path) -> dict[str, Any]:
    """Return deterministic exclusions after rejecting every import escape."""
    site_packages = sorted(
        path
        for path in venv.glob("lib/python*/site-packages")
        if path.is_dir() and not path.is_symlink()
    )
    if len(site_packages) != 1:
        raise ClosureError("venv site-packages root is missing or ambiguous")
    site = site_packages[0]
    exclusions: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    for path in sorted(site.glob("*.pth"), key=lambda item: item.name):
        payload = _read_file(path, maximum=1024 * 1024)
        digest = hashlib.sha256(payload).hexdigest()
        try:
            lines = payload.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise ClosureError(f".pth is not UTF-8: {path.name}") from exc
        if path.name.startswith(FORBIDDEN_EDITABLE_PREFIXES):
            exclusions.append(
                {
                    "relative_path": path.relative_to(venv).as_posix(),
                    "sha256": digest,
                    "reason": "editable_import_escape_removed",
                }
            )
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("import ") or line.startswith("import\t"):
                if raw not in ALLOWED_PTH_EXECUTION:
                    raise ClosureError(f"unapproved executable .pth line: {path.name}")
                required = site / "_distutils_hack"
                if not required.is_dir() or required.is_symlink():
                    raise ClosureError("approved .pth module is outside the closure")
            else:
                raise ClosureError(f".pth path entries are forbidden: {path.name}")
        accepted.append(
            {"relative_path": path.relative_to(venv).as_posix(), "sha256": digest}
        )
    for path in sorted(site.iterdir(), key=lambda item: item.name):
        lowered = path.name.lower()
        if (
            lowered in {"sitecustomize", "usercustomize"}
            or lowered.startswith("sitecustomize.")
            or lowered.startswith("usercustomize.")
        ):
            raise ClosureError(f"automatic Python startup module is forbidden: {path.name}")
        if path.name.startswith(FORBIDDEN_EDITABLE_PREFIXES) and path.suffix != ".pth":
            if path.is_dir() and not path.is_symlink():
                digest = canonical_sha256(_tree_manifest(path))
            elif path.is_file() and not path.is_symlink():
                digest, _ = _sha_file(path, maximum=16 * 1024 * 1024)
            else:
                raise ClosureError("editable finder has unsafe object type")
            exclusions.append(
                {
                    "relative_path": path.relative_to(venv).as_posix(),
                    "sha256": digest,
                    "reason": "editable_import_escape_removed",
                }
            )
    for directory, names, files in os.walk(venv, followlinks=False):
        relative_directory = Path(directory).relative_to(venv)
        for name in list(names):
            path = Path(directory) / name
            if name == "__pycache__":
                exclusions.append(
                    {
                        "relative_path": path.relative_to(venv).as_posix(),
                        "sha256": canonical_sha256(_tree_manifest(path)),
                        "reason": "python_bytecode_cache_removed",
                    }
                )
                names.remove(name)
        for name in files:
            path = Path(directory) / name
            reason: str | None = None
            if path.suffix in {".pyc", ".pyo"}:
                reason = "python_bytecode_cache_removed"
            elif name in FORBIDDEN_AUTOSTART_NAMES:
                reason = "automatic_python_startup_removed"
            elif path.suffix == ".egg-link":
                reason = "editable_import_escape_removed"
            if reason is not None and not any(
                item["relative_path"] == path.relative_to(venv).as_posix()
                for item in exclusions
            ):
                digest, _ = _sha_file(path, maximum=16 * 1024 * 1024)
                exclusions.append(
                    {
                        "relative_path": path.relative_to(venv).as_posix(),
                        "sha256": digest,
                        "reason": reason,
                    }
                )
    for direct_url in sorted(site.glob("*.dist-info/direct_url.json"), key=str):
        document = _strict_object(
            _read_file(direct_url, maximum=1024 * 1024), label="dist-info direct_url"
        )
        directory_info = document.get("dir_info")
        if isinstance(directory_info, dict) and directory_info.get("editable") is True:
            root = direct_url.parent
            relative = root.relative_to(venv).as_posix()
            if not any(item["relative_path"] == relative for item in exclusions):
                exclusions.append(
                    {
                        "relative_path": relative,
                        "sha256": canonical_sha256(_tree_manifest(root)),
                        "reason": "editable_distribution_metadata_removed",
                    }
                )
    normalized, normalized_values = _normalized_pyvenv(venv / "pyvenv.cfg")
    pyvenv_source, _ = _sha_file(venv / "pyvenv.cfg", maximum=64 * 1024)
    exclusions.sort(key=lambda item: item["relative_path"])
    if len({item["relative_path"] for item in exclusions}) != len(exclusions):
        raise ClosureError("Python path audit exclusions overlap")
    accepted.sort(key=lambda item: item["relative_path"])
    return {
        "schema_version": 1,
        "accepted_pth": accepted,
        "excluded_editable_entries": exclusions,
        "pyvenv": {
            "source_sha256": pyvenv_source,
            "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
            "normalized_values": normalized_values,
        },
        "python_path_escape_absent": True,
    }


def _excluded_source(path: Path, venv: Path, audit: dict[str, Any]) -> bool:
    if "__pycache__" in path.parts or path.suffix.lower() in {".pyc", ".pyo"}:
        return True
    try:
        relative = path.relative_to(venv).as_posix()
    except ValueError:
        return False
    excluded = {
        item["relative_path"] for item in audit["excluded_editable_entries"]
    }
    return any(relative == item or relative.startswith(item + "/") for item in excluded)


def _assert_no_python_cache(root: Path) -> None:
    for directory, names, files in os.walk(root, followlinks=False):
        if "__pycache__" in names:
            raise ClosureError(
                f"image contains Python bytecode cache: {Path(directory) / '__pycache__'}"
            )
        for name in files:
            if Path(name).suffix.lower() in {".pyc", ".pyo"}:
                raise ClosureError(
                    f"image contains Python bytecode file: {Path(directory) / name}"
                )


def _all_selected_regular_files(selections: Sequence[SourceItem]) -> Iterator[Path]:
    seen: set[tuple[int, int]] = set()
    for selection in selections:
        pending = [selection.source]
        while pending:
            path = pending.pop()
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.extend(Path(child.path) for child in os.scandir(path))
            elif stat.S_ISREG(metadata.st_mode):
                identity = (metadata.st_dev, metadata.st_ino)
                if identity not in seen:
                    seen.add(identity)
                    yield path
            elif stat.S_ISLNK(metadata.st_mode):
                resolved = path.resolve(strict=True)
                resolved_metadata = resolved.lstat()
                if stat.S_ISREG(resolved_metadata.st_mode):
                    identity = (resolved_metadata.st_dev, resolved_metadata.st_ino)
                    if identity not in seen:
                        seen.add(identity)
                        yield resolved


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError as exc:
        raise ClosureError(f"ELF candidate cannot be read: {path}") from exc


def _elf_dynamic(path: Path) -> tuple[str | None, list[str], list[str]]:
    """Parse PT_INTERP/DT_NEEDED/RPATH without executing or loading the ELF."""
    payload = _read_file(path, maximum=256 * 1024 * 1024, allow_symlink=True)
    if len(payload) < 64 or payload[:4] != b"\x7fELF":
        raise ClosureError(f"ELF header is invalid: {path}")
    elf_class, data_encoding = payload[4], payload[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        raise ClosureError(f"ELF class/endianness is unsupported: {path}")
    endian = "<" if data_encoding == 1 else ">"
    try:
        if elf_class == 2:
            phoff = struct.unpack_from(endian + "Q", payload, 32)[0]
            phentsize = struct.unpack_from(endian + "H", payload, 54)[0]
            phnum = struct.unpack_from(endian + "H", payload, 56)[0]
            expected_phentsize = 56
        else:
            phoff = struct.unpack_from(endian + "I", payload, 28)[0]
            phentsize = struct.unpack_from(endian + "H", payload, 42)[0]
            phnum = struct.unpack_from(endian + "H", payload, 44)[0]
            expected_phentsize = 32
    except struct.error as exc:
        raise ClosureError(f"ELF header is truncated: {path}") from exc
    if phentsize < expected_phentsize or phnum <= 0 or phnum > 4096 or phoff + phentsize * phnum > len(payload):
        raise ClosureError(f"ELF program header table is invalid: {path}")
    loads: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        try:
            if elf_class == 2:
                p_type = struct.unpack_from(endian + "I", payload, offset)[0]
                p_offset, p_vaddr = struct.unpack_from(endian + "QQ", payload, offset + 8)
                p_filesz = struct.unpack_from(endian + "Q", payload, offset + 32)[0]
            else:
                p_type, p_offset, p_vaddr = struct.unpack_from(endian + "III", payload, offset)
                p_filesz = struct.unpack_from(endian + "I", payload, offset + 16)[0]
        except struct.error as exc:
            raise ClosureError(f"ELF program header is truncated: {path}") from exc
        if p_offset + p_filesz > len(payload):
            raise ClosureError(f"ELF segment exceeds file bounds: {path}")
        if p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:  # PT_DYNAMIC
            if dynamic is not None:
                raise ClosureError(f"ELF has multiple dynamic segments: {path}")
            dynamic = (p_offset, p_filesz)
        elif p_type == 3:  # PT_INTERP
            raw = payload[p_offset : p_offset + p_filesz]
            if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
                raise ClosureError(f"ELF interpreter is invalid: {path}")
            interpreter = os.fsdecode(raw[:-1])
            if not interpreter.startswith("/"):
                raise ClosureError(f"ELF interpreter path is not absolute: {path}")
    if dynamic is None:
        return interpreter, [], []
    entry_size = 16 if elf_class == 2 else 8
    dyn_offset, dyn_size = dynamic
    if dyn_size % entry_size:
        raise ClosureError(f"ELF dynamic table is unaligned: {path}")
    needed_offsets: list[int] = []
    search_offsets: list[int] = []
    strtab_address: int | None = None
    strtab_size: int | None = None
    terminated = False
    for offset in range(dyn_offset, dyn_offset + dyn_size, entry_size):
        try:
            tag, value = struct.unpack_from(
                endian + ("qQ" if elf_class == 2 else "iI"), payload, offset
            )
        except struct.error as exc:
            raise ClosureError(f"ELF dynamic entry is truncated: {path}") from exc
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 5:
            strtab_address = value
        elif tag == 10:
            strtab_size = value
        elif tag in {15, 29}:
            search_offsets.append(value)
    if not terminated or strtab_address is None or strtab_size is None:
        raise ClosureError(f"ELF dynamic string table is incomplete: {path}")
    string_file_offset: int | None = None
    for virtual, file_offset, file_size in loads:
        if virtual <= strtab_address < virtual + file_size:
            string_file_offset = file_offset + (strtab_address - virtual)
            break
    if string_file_offset is None or string_file_offset + strtab_size > len(payload):
        raise ClosureError(f"ELF dynamic string table is out of bounds: {path}")

    def dynamic_string(index: int) -> str:
        if index < 0 or index >= strtab_size:
            raise ClosureError(f"ELF dynamic string index is invalid: {path}")
        start = string_file_offset + index
        end = payload.find(b"\0", start, string_file_offset + strtab_size)
        if end < 0:
            raise ClosureError(f"ELF dynamic string is unterminated: {path}")
        try:
            value = os.fsdecode(payload[start:end])
        except UnicodeError as exc:
            raise ClosureError(f"ELF dynamic string is invalid: {path}") from exc
        if not value or "\x00" in value:
            raise ClosureError(f"ELF dynamic string is empty: {path}")
        return value

    needed = [dynamic_string(index) for index in needed_offsets]
    if any("/" in item or item in {".", ".."} for item in needed):
        raise ClosureError(f"ELF dependency name is unsafe: {path}")
    search: list[str] = []
    for index in search_offsets:
        search.extend(dynamic_string(index).split(":"))
    return interpreter, needed, search


def _trusted_program_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Stable executable identity; atime is intentionally excluded."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_pinned_ldconfig(
    path: Path,
    expected_sha256: str,
    *,
    test_mode: bool,
) -> tuple[int, tuple[int, ...]]:
    if not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None:
        raise ClosureError("expected ldconfig.real SHA-256 is invalid")
    if sys.platform != "linux" or os.name != "posix":
        raise ClosureError("pinned ldconfig.real execution requires Linux")
    path = Path(path)
    if not path.is_absolute() or (not test_mode and path != LDCONFIG):
        raise ClosureError("ldconfig.real path is not the fixed production path")
    uid, gid = _require_root(test_mode=test_mode)
    descriptor = -1
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode)
            or (before.st_uid, before.st_gid) != (uid, gid)
            or stat.S_IMODE(before.st_mode) != 0o755
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 64 * 1024 * 1024
        ):
            raise ClosureError("ldconfig.real identity is unsafe")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity = _trusted_program_identity(opened)
        if identity != _trusted_program_identity(before):
            raise ClosureError("ldconfig.real changed while opening")
        digest, size, hashed = _sha_open_descriptor(
            descriptor, maximum=64 * 1024 * 1024
        )
        path_after = path.lstat()
        if (
            size != opened.st_size
            or identity != _trusted_program_identity(hashed)
            or identity != _trusted_program_identity(path_after)
        ):
            raise ClosureError("ldconfig.real changed while hashing")
        if digest != expected_sha256:
            raise ClosureError("ldconfig.real digest mismatch")
        return descriptor, identity
    except ClosureError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ClosureError("ldconfig.real cannot be opened safely") from exc


def _ptrace_traceme() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(0, 0, None, None) != 0:  # PTRACE_TRACEME
        os._exit(126)


def _ptrace_set_exitkill(pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(
        0x4200, pid, None, ctypes.c_void_p(0x00100000)
    ) != 0:  # PTRACE_SETOPTIONS, PTRACE_O_EXITKILL
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _ptrace_detach(pid: int, signal_number: int = 0) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(17, pid, None, ctypes.c_void_p(signal_number)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _run_pinned_ldconfig(
    *,
    expected_sha256: str,
    ldconfig: Path = LDCONFIG,
    test_mode: bool = False,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
    ldconfig = Path(ldconfig)
    descriptor, identity = _open_pinned_ldconfig(
        ldconfig, expected_sha256, test_mode=test_mode
    )
    command = [str(ldconfig), "-p"]
    process: subprocess.Popen[bytes] | None = None
    traced = False
    executed: os.stat_result | None = None
    try:
        process = subprocess.Popen(
            command,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            preexec_fn=_ptrace_traceme,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        traced = True
        waited, wait_status = os.waitpid(process.pid, os.WUNTRACED)
        if os.WIFEXITED(wait_status):
            process.returncode = os.WEXITSTATUS(wait_status)
        elif os.WIFSIGNALED(wait_status):
            process.returncode = -os.WTERMSIG(wait_status)
        if (
            waited != process.pid
            or not os.WIFSTOPPED(wait_status)
            or os.WSTOPSIG(wait_status) != signal.SIGTRAP
        ):
            raise ClosureError("ldconfig.real exec trace stop is invalid")
        _ptrace_set_exitkill(process.pid)
        executed = Path(f"/proc/{process.pid}/exe").stat()
        if (executed.st_dev, executed.st_ino) != identity[:2]:
            raise ClosureError("ldconfig.real executed inode differs from pinned bytes")
        _ptrace_detach(process.pid)
        traced = False
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise ClosureError("root-owned ld.so cache listing timed out") from exc

        digest_after, size_after, descriptor_after = _sha_open_descriptor(
            descriptor, maximum=64 * 1024 * 1024
        )
        path_after = ldconfig.lstat()
        resolved_after = ldconfig.resolve(strict=True)
        path_final = ldconfig.lstat()
        if (
            digest_after != expected_sha256
            or size_after != identity[6]
            or _trusted_program_identity(descriptor_after) != identity
            or _trusted_program_identity(path_after) != identity
            or _trusted_program_identity(path_final) != identity
            or stat.S_ISLNK(path_final.st_mode)
            or resolved_after != ldconfig
        ):
            raise ClosureError("ldconfig.real changed across pinned execution")
        return subprocess.CompletedProcess(
            command, process.returncode, stdout, stderr
        ), {
            "method": "open-fd-ptrace-exec-v1",
            "path": str(ldconfig),
            "sha256": expected_sha256,
            "pinned_device": identity[0],
            "pinned_inode": identity[1],
            "proc_exe_device": executed.st_dev,
            "proc_exe_inode": executed.st_ino,
            "ptrace_exitkill_set": True,
            "post_execution_rehash_passed": True,
        }
    except BaseException as exc:
        cleanup_error: BaseException | None = None
        if process is not None and process.returncode is None:
            try:
                if traced:
                    _ptrace_detach(process.pid, signal.SIGKILL)
                    traced = False
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as first_cleanup_error:
                cleanup_error = first_cleanup_error
                try:
                    _ptrace_detach(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        os.kill(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                try:
                    process.wait(timeout=5)
                    cleanup_error = None
                except (OSError, subprocess.SubprocessError) as final_cleanup_error:
                    cleanup_error = final_cleanup_error
        if cleanup_error is not None:
            raise ClosureError("failed ldconfig.real child could not be reaped") from exc
        if isinstance(exc, ClosureError):
            raise
        if isinstance(exc, (OSError, subprocess.SubprocessError)):
            raise ClosureError("root-owned ld.so cache listing failed") from exc
        raise
    finally:
        os.close(descriptor)


def _ld_cache_mapping(
    *,
    expected_ldconfig_sha256: str,
    ldconfig: Path = LDCONFIG,
    test_mode: bool = False,
) -> dict[str, list[Path]]:
    process, _execution = _run_pinned_ldconfig(
        expected_sha256=expected_ldconfig_sha256,
        ldconfig=ldconfig,
        test_mode=test_mode,
    )
    if process.returncode != 0 or len(process.stdout) > 16 * 1024 * 1024:
        raise ClosureError("root-owned ld.so cache listing failed")
    mapping: dict[str, list[Path]] = {}
    for raw in process.stdout.decode("utf-8", "strict").splitlines():
        line = raw.strip()
        match = re.fullmatch(r"([^\s]+) \([^)]*\) => (/[^\s]+)", line)
        if match is None:
            continue
        name, path = match.groups()
        candidate = Path(path)
        if candidate.exists():
            mapping.setdefault(name, []).append(candidate)
    for name in mapping:
        mapping[name] = sorted(dict.fromkeys(mapping[name]), key=str)
    if not mapping:
        raise ClosureError("root-owned ld.so cache listing is empty")
    return mapping


def _native_dependency_roots(
    selections: Sequence[SourceItem],
    *,
    expected_ldconfig_sha256: str,
    injected_elfs: Sequence[Path] = (),
    runtime_working_directory: Path | None = None,
    test_mode: bool = False,
) -> list[Path]:
    files = list(_all_selected_regular_files(selections))
    selected_roots = [item.source.resolve(strict=True) for item in selections]
    by_basename: dict[str, list[Path]] = {}
    for path in files:
        by_basename.setdefault(path.name, []).append(path)
    cache = _ld_cache_mapping(
        expected_ldconfig_sha256=expected_ldconfig_sha256,
        test_mode=test_mode,
    )
    defaults = tuple(
        Path(path)
        for path in (
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        )
    )
    injected: list[Path] = []
    for path in injected_elfs:
        candidate = Path(path)
        resolved = candidate.resolve(strict=True)
        if not _is_elf(resolved):
            raise ClosureError("injected loader preload root is not ELF")
        injected.extend((candidate, resolved))
    queue = [path for path in files if _is_elf(path)] + injected
    if not queue:
        raise ClosureError("closure ELF inventory is empty")
    processed: set[tuple[int, int]] = set()
    external: set[Path] = set(injected)

    def inside_selected(candidate: Path) -> bool:
        resolved = candidate.resolve(strict=True)
        for root in selected_roots:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    while queue:
        elf = queue.pop()
        metadata = elf.resolve(strict=True).lstat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in processed:
            continue
        processed.add(identity)
        interpreter, needed, raw_search = _elf_dynamic(elf)
        if interpreter is not None:
            candidate = Path(interpreter)
            if not candidate.is_file():
                raise ClosureError(f"ELF interpreter is unavailable: {interpreter}")
            external.update({candidate, candidate.resolve(strict=True)})
            queue.append(candidate.resolve(strict=True))
        origin = elf.resolve(strict=True).parent
        search: list[Path] = []
        for raw in raw_search:
            expanded = raw.replace("${ORIGIN}", str(origin)).replace("$ORIGIN", str(origin))
            if "$" in expanded or not expanded:
                raise ClosureError(f"ELF search path is unsafe: {elf}")
            candidate = Path(expanded)
            if not candidate.is_absolute():
                if (
                    raw not in ALLOWED_RELATIVE_ELF_SEARCH_PATHS
                    or origin.name != raw
                    or runtime_working_directory is None
                ):
                    raise ClosureError(f"relative ELF search path is unsafe: {elf}")
                working_directory = Path(runtime_working_directory)
                if test_mode:
                    try:
                        working_metadata = working_directory.lstat()
                    except OSError as exc:
                        raise ClosureError(
                            "relative ELF search working directory cannot be inspected"
                        ) from exc
                    if working_directory.is_symlink() or not stat.S_ISDIR(
                        working_metadata.st_mode
                    ):
                        raise ClosureError(
                            "relative ELF search working directory is unsafe"
                        )
                else:
                    _mode_owner(
                        working_directory,
                        uid=0,
                        gid=0,
                        mode=0o555,
                        directory=True,
                        label="relative ELF search working directory",
                    )
                candidate = working_directory / raw
                if os.path.lexists(candidate):
                    raise ClosureError(
                        f"relative ELF search path is present in fixed working directory: {elf}"
                    )
            search.append(candidate)
        for dependency in needed:
            candidates: list[Path] = []
            for directory in search:
                candidate = directory / dependency
                if candidate.exists():
                    if not inside_selected(candidate):
                        raise ClosureError(f"ELF RPATH escapes selected closure: {elf}")
                    candidates.append(candidate)
            if not candidates:
                internal = by_basename.get(dependency, [])
                if len(internal) == 1:
                    candidates = internal
                elif len(internal) > 1:
                    raise ClosureError(f"ELF internal dependency is ambiguous: {dependency}")
            if not candidates:
                candidates = cache.get(dependency, [])
            if not candidates:
                candidates = [directory / dependency for directory in defaults if (directory / dependency).exists()]
            if not candidates:
                raise ClosureError(f"ELF dependency is unresolved: {dependency}")
            # The cache order is part of the root-owned /etc/ld.so.cache
            # identity.  Multiple distinct first-tier resolutions are rejected
            # instead of guessing across architectures.
            resolved_candidates = list(
                dict.fromkeys(candidate.resolve(strict=True) for candidate in candidates)
            )
            if len(resolved_candidates) != 1:
                same_arch = [
                    candidate
                    for candidate in resolved_candidates
                    if "x86_64-linux-gnu" in str(candidate)
                ]
                if len(same_arch) != 1:
                    raise ClosureError(f"ELF dependency resolution is ambiguous: {dependency}")
                resolved = same_arch[0]
            else:
                resolved = resolved_candidates[0]
            selected = candidates[0]
            if inside_selected(resolved):
                queue.append(resolved)
            else:
                external.update({selected, resolved})
                queue.append(resolved)
    return sorted(external, key=str)


def _external_entry(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    result: dict[str, Any] = {
        "path": str(path),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    if stat.S_ISDIR(metadata.st_mode):
        result["kind"] = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        digest, size = _sha_file(path, maximum=MAX_SOURCE_BYTES)
        result.update({"kind": "regular", "size": size, "sha256": digest})
    elif stat.S_ISLNK(metadata.st_mode):
        result.update({"kind": "symlink", "target": os.readlink(path)})
    else:
        raise ClosureError(f"external runtime contains unsafe object: {path}")
    return result


def external_runtime_manifest(
    roots: Sequence[Path],
    *,
    python_abi: str = "3.12",
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
) -> dict[str, Any]:
    if (trusted_uid is None) != (trusted_gid is None):
        raise ClosureError("external runtime trusted owner is incomplete")
    canonical_roots = sorted(dict.fromkeys(Path(path).absolute() for path in roots), key=str)
    if not canonical_roots:
        raise ClosureError("external runtime roots are empty")
    entries: dict[str, dict[str, Any]] = {}
    for root in canonical_roots:
        pending = [root]
        while pending:
            path = pending.pop()
            entry = _external_entry(path)
            if trusted_uid is not None and (
                entry["uid"] != trusted_uid
                or entry["gid"] != trusted_gid
                or (
                    entry["kind"] in {"directory", "regular"}
                    and int(entry["mode"], 8) & 0o022
                )
            ):
                raise ClosureError("external runtime contains untrusted writable metadata")
            prior = entries.get(str(path))
            if prior is not None and prior != entry:
                raise ClosureError("external runtime path identity is ambiguous")
            entries[str(path)] = entry
            if entry["kind"] == "directory":
                pending.extend(Path(child.path) for child in os.scandir(path))
            elif entry["kind"] == "symlink":
                resolved = path.resolve(strict=True)
                if str(resolved) not in entries:
                    pending.append(resolved)
            if len(entries) > MAX_SOURCE_ENTRIES:
                raise ClosureError("external runtime exceeds entry limit")
    return {
        "schema_version": 1,
        "python_abi": python_abi,
        "roots": [str(path) for path in canonical_roots],
        "entries": [entries[name] for name in sorted(entries)],
    }


def _copy_regular(source: Path, destination: Path) -> None:
    payload = _read_file(source, maximum=MAX_SOURCE_BYTES, allow_symlink=True)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    source_mode = stat.S_IMODE(source.resolve(strict=True).lstat().st_mode)
    os.chmod(destination, 0o555 if source_mode & 0o111 else 0o444)


def _copy_payload(destination: Path, payload: bytes, *, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    _write_new(
        destination,
        payload,
        mode=mode,
        uid=os.geteuid() if hasattr(os, "geteuid") else 0,
        gid=os.getegid() if hasattr(os, "getegid") else 0,
    )


def _copy_item(
    source: Path,
    destination: Path,
    *,
    component_root: Path,
    destination_component_root: Path,
    venv: Path,
    python_audit: dict[str, Any],
) -> None:
    if _excluded_source(source, venv, python_audit):
        return
    metadata = source.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        destination.mkdir(parents=True, exist_ok=False, mode=0o755)
        for child in sorted(os.scandir(source), key=lambda item: item.name):
            _copy_item(
                Path(child.path),
                destination / child.name,
                component_root=component_root,
                destination_component_root=destination_component_root,
                venv=venv,
                python_audit=python_audit,
            )
        os.chmod(destination, 0o555)
    elif stat.S_ISREG(metadata.st_mode):
        if source == venv / "pyvenv.cfg":
            normalized, _values = _normalized_pyvenv(source)
            if hashlib.sha256(normalized).hexdigest() != python_audit["pyvenv"]["normalized_sha256"]:
                raise ClosureError("pyvenv.cfg normalization changed during copy")
            _copy_payload(destination, normalized, mode=0o444)
        else:
            _copy_regular(source, destination)
    elif stat.S_ISLNK(metadata.st_mode):
        resolved = source.resolve(strict=True)
        resolved_metadata = resolved.lstat()
        if stat.S_ISREG(resolved_metadata.st_mode):
            try:
                resolved.relative_to(component_root.resolve(strict=True))
                internal = True
            except ValueError:
                internal = False
            target = os.readlink(source)
            if internal and not PurePosixPath(target).is_absolute():
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                os.symlink(target, destination)
            else:
                try:
                    relative_to_venv = source.relative_to(venv).as_posix()
                except ValueError as exc:
                    raise ClosureError(
                        f"external regular-file symlink is not an approved Python link: {source}"
                    ) from exc
                if (
                    relative_to_venv not in {"bin/python", "bin/python3", "bin/python3.12"}
                    or resolved != Path("/usr/bin/python3.12")
                ):
                    raise ClosureError(
                        f"external regular-file symlink is not an approved Python link: {source}"
                    )
                _copy_regular(resolved, destination)
        elif stat.S_ISDIR(resolved_metadata.st_mode):
            try:
                relative = resolved.relative_to(component_root.resolve(strict=True))
            except ValueError as exc:
                raise ClosureError(f"directory symlink escapes selected component: {source}") from exc
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target = os.path.relpath(destination_component_root / relative, destination.parent)
            os.symlink(target, destination)
        else:
            raise ClosureError(f"symlink resolves to unsafe object: {source}")
    else:
        raise ClosureError(f"source object cannot be copied: {source}")


def copy_selections(
    selections: Sequence[SourceItem], stage: Path, *, venv: Path, python_audit: dict[str, Any]
) -> None:
    for selection in sorted(selections, key=lambda item: item.destination.as_posix()):
        destination = stage.joinpath(*selection.destination.parts)
        _copy_item(
            selection.source,
            destination,
            component_root=selection.source,
            destination_component_root=destination,
            venv=venv,
            python_audit=python_audit,
        )
    placeholder = stage / "custom-addons" / "odoo-server19.conf"
    if os.path.lexists(placeholder):
        raise ClosureError("real Odoo configuration would enter the public image")
    placeholder.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    placeholder.write_bytes(PLACEHOLDER)
    os.chmod(placeholder, 0o000)
    os.chmod(placeholder.parent, 0o555)


def _assert_image_symlinks(stage: Path) -> None:
    root = stage.resolve(strict=True)
    for directory, names, files in os.walk(stage, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            target = os.readlink(path)
            if PurePosixPath(target).is_absolute():
                raise ClosureError(f"image contains absolute symlink: {path.relative_to(stage)}")
            resolved = path.resolve(strict=True)
            try:
                relative = path.relative_to(stage)
                component_root = (root / relative.parts[0]).resolve(strict=True)
                resolved.relative_to(component_root)
            except ValueError as exc:
                raise ClosureError(f"image symlink escapes closure: {path.relative_to(stage)}") from exc


def _image_payload_manifest(
    stage: Path, *, require_root_owner: bool = False
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    pending: list[tuple[Path, str]] = [(stage, ".")]
    while pending:
        path, relative = pending.pop()
        if relative in {"CLOSURE-MANIFEST.json"}:
            continue
        metadata = path.lstat()
        if require_root_owner and (metadata.st_uid != 0 or metadata.st_gid != 0):
            raise ClosureError(f"image member is not root-owned: {relative}")
        entry: dict[str, Any] = {
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": 0,
            "gid": 0,
        }
        if stat.S_ISDIR(metadata.st_mode):
            entry["kind"] = "directory"
            for child in os.scandir(path):
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                pending.append((Path(child.path), child_relative))
        elif stat.S_ISREG(metadata.st_mode):
            digest, size = _sha_file(path, maximum=MAX_SOURCE_BYTES)
            entry.update({"kind": "regular", "size": size, "sha256": digest})
        elif stat.S_ISLNK(metadata.st_mode):
            entry.update({"kind": "symlink", "target": os.readlink(path)})
        else:
            raise ClosureError("image staging tree contains unsafe object")
        entries.append(entry)
        if len(entries) > MAX_SOURCE_ENTRIES:
            raise ClosureError("image staging tree exceeds entry limit")
    entries.sort(key=lambda item: item["path"])
    return {"schema_version": 1, "entries": entries}


def _write_new(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        if hasattr(os, "fchown"):
            os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not hasattr(os, "fchmod"):
        os.chmod(path, mode)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory(path: Path, *, mode: int, uid: int, gid: int) -> None:
    if os.path.lexists(path):
        _mode_owner(path, uid=uid, gid=gid, mode=mode, directory=True, label=str(path))
        return
    path.mkdir(mode=mode, parents=False)
    os.chmod(path, mode)
    if hasattr(os, "chown"):
        os.chown(path, uid, gid)
    _fsync_directory(path.parent)


def _ensure_parent_chain(
    path: Path, *, final_mode: int, final_gid: int, test_mode: bool
) -> None:
    uid, gid = _require_root(test_mode=test_mode)
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise ClosureError(f"unsafe ancestor for dependency closure: {current}")
    for candidate in reversed(missing):
        candidate.mkdir(mode=0o755)
        os.chmod(candidate, final_mode if candidate == path else 0o755)
        if hasattr(os, "chown"):
            os.chown(candidate, uid, final_gid if candidate == path else gid)
        _fsync_directory(candidate.parent)
    _mode_owner(
        path,
        uid=uid,
        gid=final_gid,
        mode=final_mode,
        directory=True,
        label=str(path),
    )


def _lock(layout: Layout, *, test_mode: bool) -> tuple[int, Any]:
    uid, gid = _require_root(test_mode=test_mode)
    _ensure_parent_chain(layout.lock_parent, final_mode=0o755, final_gid=gid, test_mode=test_mode)
    descriptor = os.open(
        layout.lock,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    if hasattr(os, "fchown"):
        os.fchown(descriptor, uid, gid)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor, lambda: (fcntl.flock(descriptor, fcntl.LOCK_UN), os.close(descriptor))


def _binds(layout: Layout) -> list[dict[str, str]]:
    return [
        {
            "source": str(layout.mount_point / "odoo-server"),
            "destination": str(SOURCE_SERVER),
        },
        {
            "source": str(layout.mount_point / "odoo19-venv"),
            "destination": str(SOURCE_VENV),
        },
        {
            "source": str(layout.mount_point / "custom-addons"),
            "destination": str(SOURCE_CUSTOM),
        },
        {
            "source": str(layout.sealed_config),
            "destination": str(SOURCE_CONFIG),
        },
    ]


def _systemd(layout: Layout) -> dict[str, Any]:
    binds = _binds(layout)
    return {
        "execution_model": "single-supervisor-private-mount-namespace-v1",
        "private_mounts": True,
        "bind_read_only_paths": binds,
        "binding_phase": "root-supervisor-after-squashfs-mount",
        "supervisor_unit_properties": ["PrivateMounts=yes"],
        "child_execution": {
            "method": "direct-fork-exec",
            "systemd_run_forbidden": True,
            "credential_drop_required": True,
            "capabilities_zero_required": True,
            "no_new_privileges_required": True,
        },
    }


def _closure_manifest(
    *,
    expected: ExpectedIdentity,
    database_name: str,
    database_uuid: str,
    graph: dict[str, Any],
    mapping: list[dict[str, Any]],
    source_digest: str,
    external_manifest: dict[str, Any],
    python_audit: dict[str, Any],
    payload_manifest: dict[str, Any],
    config_sha256: str,
    system_python_sha256: str,
    loader_preload_sha256: str,
    loader_preload_identity: dict[str, Any],
) -> dict[str, Any]:
    names = [item["name"] for item in graph["modules"]]
    payload_mapping = _module_payload_mapping(payload_manifest, mapping)
    return {
        "schema_version": 1,
        "kind": "odoo_dependency_closure",
        "release_identity": expected.public(),
        "database_scope": {
            "database_name": database_name,
            "database_uuid": database_uuid,
        },
        "installed_modules": {
            "count": len(names),
            "names": names,
            "names_sha256": canonical_sha256(names),
            "database_graph_sha256": canonical_sha256(
                {"modules": graph["modules"], "dependencies": graph["dependencies"]}
            ),
            "module_mapping_sha256": canonical_sha256(mapping),
            "module_payload_mapping_sha256": canonical_sha256(payload_mapping),
            "resolver_precedence": ["builtin", "community", "custom"],
            "mapping": mapping,
            "payload_mapping": payload_mapping,
        },
        "source_manifest_sha256": source_digest,
        "external_runtime_manifest_sha256": canonical_sha256(external_manifest),
        "python_path_audit_sha256": canonical_sha256(python_audit),
        "payload_manifest_sha256": canonical_sha256(payload_manifest),
        "payload_entry_count": len(payload_manifest["entries"]),
        "sealed_config_sha256": config_sha256,
        "system_python_sha256": system_python_sha256,
        "loader_preload_sha256": loader_preload_sha256,
        "loader_preload": loader_preload_identity,
        "config_placeholder": {
            "path": "custom-addons/odoo-server19.conf",
            "mode": "0000",
            "sha256": hashlib.sha256(PLACEHOLDER).hexdigest(),
        },
    }


def _module_payload_mapping(
    payload_manifest: dict[str, Any], mapping: list[dict[str, Any]]
) -> list[dict[str, str]]:
    entries = payload_manifest.get("entries")
    if not isinstance(entries, list):
        raise ClosureError("image payload manifest entries are invalid")
    roots = {
        "builtin": "odoo-server/odoo/addons",
        "community": "odoo-server/addons",
        "custom": "custom-addons",
    }
    expected_directories: dict[str, set[str]] = {key: set() for key in roots}
    result: list[dict[str, str]] = []
    for item in mapping:
        if not isinstance(item, dict) or item.get("source") not in roots or not isinstance(item.get("name"), str):
            raise ClosureError("module mapping cannot be bound to image payload")
        source = item["source"]
        name = item["name"]
        prefix = f"{roots[source]}/{name}"
        selected = [
            entry
            for entry in entries
            if isinstance(entry, dict)
            and isinstance(entry.get("path"), str)
            and (entry["path"] == prefix or entry["path"].startswith(prefix + "/"))
        ]
        if not selected or not any(
            entry.get("path") == prefix and entry.get("kind") == "directory"
            for entry in selected
        ):
            raise ClosureError(f"installed module is absent from image payload: {name}")
        selected.sort(key=lambda entry: entry["path"])
        expected_directories[source].add(name)
        result.append(
            {
                "name": name,
                "destination": prefix,
                "payload_entries_sha256": canonical_sha256(selected),
            }
        )
    for source, root in roots.items():
        actual = {
            entry["path"].split("/")[-1]
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("kind") == "directory"
            and isinstance(entry.get("path"), str)
            and entry["path"].startswith(root + "/")
            and entry["path"].count("/") == root.count("/") + 1
        }
        if actual != expected_directories[source]:
            raise ClosureError(f"image {source} module set differs from database mapping")
    result.sort(key=lambda item: item["name"])
    return result


def _anchor_document(
    *,
    layout: Layout,
    expected: ExpectedIdentity,
    closure_manifest: dict[str, Any],
    image_sha256: str,
    source_before: str,
    source_after: str,
    external_manifest: dict[str, Any],
    config_sha256: str,
    mksquashfs_sha256: str,
    reproducible_image_sha256: str,
    system_python_sha256: str,
    loader_preload_sha256: str,
) -> dict[str, Any]:
    installed = closure_manifest["installed_modules"]
    return {
        "schema_version": 1,
        "kind": "odoo_dependency_closure_anchor",
        "release_identity": expected.public(),
        "database_scope": closure_manifest["database_scope"],
        "image": {
            "path": str(layout.image),
            "sha256": image_sha256,
            "filesystem_type": "squashfs",
            "all_root": True,
        },
        "mount_point": str(layout.mount_point),
        "closure_manifest_sha256": canonical_sha256(closure_manifest),
        "source_manifest_sha256_before": source_before,
        "source_manifest_sha256_after": source_after,
        "database_graph_sha256_before": installed["database_graph_sha256"],
        "database_graph_sha256_after": installed["database_graph_sha256"],
        "external_runtime_manifest_sha256": closure_manifest[
            "external_runtime_manifest_sha256"
        ],
        "external_runtime_paths": external_manifest["roots"],
        "python_path_audit_sha256": closure_manifest["python_path_audit_sha256"],
        "system_python_sha256": system_python_sha256,
        "loader_preload_sha256": loader_preload_sha256,
        "sealed_config": {
            "path": str(layout.sealed_config),
            "sha256": config_sha256,
            "mode": "0440",
        },
        "installed_modules": {
            "count": installed["count"],
            "names_sha256": installed["names_sha256"],
            "database_graph_sha256": installed["database_graph_sha256"],
            "module_mapping_sha256": installed["module_mapping_sha256"],
            "module_payload_mapping_sha256": installed[
                "module_payload_mapping_sha256"
            ],
            "resolver_precedence": installed["resolver_precedence"],
        },
        "mksquashfs_sha256": mksquashfs_sha256,
        "reproducibility": {
            "build_count": 2,
            "passed": True,
            "first_image_sha256": reproducible_image_sha256,
            "second_image_sha256": reproducible_image_sha256,
        },
        "systemd": _systemd(layout),
    }


def _publish_no_replace(
    temporary: Path, target: Path, *, mode: int, uid: int, gid: int
) -> None:
    os.chmod(temporary, mode)
    if hasattr(os, "chown"):
        os.chown(temporary, uid, gid)
    try:
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError as exc:
        raise ClosureError(f"immutable artifact already exists: {target}") from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    _fsync_directory(target.parent)


def _load_anchor(layout: Layout, *, uid: int, gid: int) -> tuple[dict[str, Any], str]:
    metadata = _mode_owner(
        layout.closure_anchor,
        uid=uid,
        gid=gid,
        mode=0o444,
        directory=False,
        label="closure anchor",
    )
    if metadata.st_nlink != 1:
        raise ClosureError("closure anchor has unsafe link count")
    payload = _read_file(layout.closure_anchor, maximum=MAX_JSON_BYTES)
    return _strict_object(payload, label="closure anchor"), hashlib.sha256(payload).hexdigest()


def _validate_anchor_shape(
    anchor: dict[str, Any],
    *,
    layout: Layout,
    expected: ExpectedIdentity,
    database_name: str,
    database_uuid: str,
    expected_config_sha256: str,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
) -> None:
    required = {
        "schema_version",
        "kind",
        "release_identity",
        "database_scope",
        "image",
        "mount_point",
        "closure_manifest_sha256",
        "source_manifest_sha256_before",
        "source_manifest_sha256_after",
        "database_graph_sha256_before",
        "database_graph_sha256_after",
        "external_runtime_manifest_sha256",
        "external_runtime_paths",
        "python_path_audit_sha256",
        "system_python_sha256",
        "loader_preload_sha256",
        "sealed_config",
        "installed_modules",
        "mksquashfs_sha256",
        "reproducibility",
        "systemd",
    }
    if (
        set(anchor) != required
        or not _schema_version_is_one(anchor.get("schema_version"))
        or anchor.get("kind") != "odoo_dependency_closure_anchor"
    ):
        raise ClosureError("closure anchor fields are invalid")
    if anchor["release_identity"] != expected.public() or anchor["database_scope"] != {
        "database_name": database_name,
        "database_uuid": database_uuid,
    }:
        raise ClosureError("closure anchor release/database identity mismatch")
    image = anchor.get("image")
    sealed = anchor.get("sealed_config")
    installed = anchor.get("installed_modules")
    if (
        not isinstance(image, dict)
        or image
        != {
            "path": str(layout.image),
            "sha256": image.get("sha256"),
            "filesystem_type": "squashfs",
            "all_root": True,
        }
        or not isinstance(image.get("sha256"), str)
        or HEX64.fullmatch(image["sha256"]) is None
        or anchor.get("mount_point") != str(layout.mount_point)
        or not isinstance(sealed, dict)
        or sealed
        != {
            "path": str(layout.sealed_config),
            "sha256": expected_config_sha256,
            "mode": "0440",
        }
        or not isinstance(installed, dict)
        or set(installed)
        != {
            "count",
            "names_sha256",
            "database_graph_sha256",
            "module_mapping_sha256",
            "module_payload_mapping_sha256",
            "resolver_precedence",
        }
        or installed.get("resolver_precedence") != ["builtin", "community", "custom"]
        or not isinstance(installed.get("count"), int)
        or installed["count"] <= 0
        or anchor.get("source_manifest_sha256_before")
        != anchor.get("source_manifest_sha256_after")
        or anchor.get("database_graph_sha256_before")
        != anchor.get("database_graph_sha256_after")
        or anchor.get("database_graph_sha256_before")
        != installed.get("database_graph_sha256")
        or anchor.get("systemd") != _systemd(layout)
        or anchor.get("system_python_sha256") != expected_system_python_sha256
        or anchor.get("loader_preload_sha256")
        != expected_loader_preload_sha256
        or anchor.get("reproducibility")
        != {
            "build_count": 2,
            "passed": True,
            "first_image_sha256": image.get("sha256") if isinstance(image, dict) else None,
            "second_image_sha256": image.get("sha256") if isinstance(image, dict) else None,
        }
    ):
        raise ClosureError("closure anchor invariant mismatch")
    for field in (
        "closure_manifest_sha256",
        "source_manifest_sha256_before",
        "source_manifest_sha256_after",
        "database_graph_sha256_before",
        "database_graph_sha256_after",
        "external_runtime_manifest_sha256",
        "python_path_audit_sha256",
        "system_python_sha256",
        "loader_preload_sha256",
        "mksquashfs_sha256",
    ):
        if not isinstance(anchor.get(field), str) or HEX64.fullmatch(anchor[field]) is None:
            raise ClosureError(f"closure anchor digest is invalid: {field}")
    for field in (
        "names_sha256",
        "database_graph_sha256",
        "module_mapping_sha256",
        "module_payload_mapping_sha256",
    ):
        if not isinstance(installed.get(field), str) or HEX64.fullmatch(installed[field]) is None:
            raise ClosureError(f"closure module digest is invalid: {field}")
    roots = anchor.get("external_runtime_paths")
    if (
        not isinstance(roots, list)
        or not roots
        or roots != sorted(set(roots))
        or any(not isinstance(path, str) or not path.startswith("/") for path in roots)
    ):
        raise ClosureError("external runtime path list is invalid")


def _allocated_bytes(path: Path) -> int:
    total = 0
    for directory, _names, files in os.walk(path, followlinks=False):
        metadata = Path(directory).lstat()
        total += getattr(metadata, "st_blocks", 0) * 512
        for name in files:
            total += getattr((Path(directory) / name).lstat(), "st_blocks", 0) * 512
    return total


def _capacity_gate(
    layout: Layout,
    *,
    stage_upper: int,
    image_upper: int,
    phase: str,
    test_mode: bool,
) -> None:
    if test_mode:
        return
    floor = 2 * 1024**3
    build_device = layout.build_parent.stat().st_dev
    image_device = layout.image_parent.stat().st_dev
    build_free = shutil.disk_usage(layout.build_parent).free
    image_free = shutil.disk_usage(layout.image_parent).free
    if phase == "before_stage":
        if build_device == image_device:
            required = stage_upper + image_upper + floor
            if build_free < required:
                raise ClosureError("insufficient free space for stage, image, and 2 GiB floor")
        elif build_free < stage_upper + floor or image_free < image_upper + floor:
            raise ClosureError("insufficient cross-filesystem closure build capacity")
    elif phase == "before_image":
        if image_free < image_upper + floor or build_free < floor:
            raise ClosureError("insufficient free space before SquashFS construction")
    elif phase in {"after_image", "before_publish"}:
        if build_free < floor or image_free < floor:
            raise ClosureError("closure build would violate the 2 GiB residual floor")
    else:
        raise ClosureError("unknown closure capacity-gate phase")


def _require_reproducible_images(first_sha256: str, second_sha256: str) -> None:
    if (
        not isinstance(first_sha256, str)
        or not isinstance(second_sha256, str)
        or HEX64.fullmatch(first_sha256) is None
        or HEX64.fullmatch(second_sha256) is None
        or first_sha256 != second_sha256
    ):
        raise ClosureError("two deterministic SquashFS builds differ")


def _require_discovery_unchanged(
    before: tuple[object, ...], after: tuple[object, ...], *, phase: str
) -> None:
    if before != after:
        raise ClosureError(f"dependency discovery changed {phase}")


def build(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path = Path("/"),
    script_path: Path = Path(__file__),
    test_mode: bool = False,
    graph: dict[str, Any] | None = None,
    native_roots: Sequence[Path] | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    service_gid: int | None = None,
) -> dict[str, Any]:
    uid, gid = _require_root(test_mode=test_mode)
    if not test_mode and (
        graph is not None or native_roots is not None or service_gid is not None
    ):
        raise ClosureError("production build rejects test-only dependency overrides")
    for label, value in (
        ("ldconfig.real", expected_ldconfig_sha256),
        ("Odoo config", expected_odoo_config_sha256),
    ):
        if not isinstance(value, str) or HEX64.fullmatch(value) is None:
            raise ClosureError(f"expected {label} SHA-256 is invalid")
    if DATABASE.fullmatch(expected_database_name) is None or DATABASE_UUID.fullmatch(expected_database_uuid) is None:
        raise ClosureError("expected database identity is invalid")
    layout = build_layout(root, expected)
    verify_release(layout, expected, script_path=script_path, test_mode=test_mode)
    system_python = _validate_system_python(
        expected_sha256=expected_system_python_sha256,
        root=root,
        test_mode=test_mode,
    )
    loader_preload = _validate_loader_preload(
        expected_sha256=expected_loader_preload_sha256,
        root=root,
        test_mode=test_mode,
    )
    if service_gid is None:
        try:
            service_gid = pwd.getpwnam("odoo").pw_gid
        except KeyError as exc:
            if test_mode:
                service_gid = gid
            else:
                raise ClosureError("odoo service account is unavailable") from exc
    _ensure_parent_chain(layout.image_parent, final_mode=0o755, final_gid=gid, test_mode=test_mode)
    _ensure_parent_chain(
        layout.closure_anchor.parent,
        final_mode=0o755,
        final_gid=gid,
        test_mode=test_mode,
    )
    _ensure_parent_chain(layout.mount_parent, final_mode=0o750, final_gid=service_gid, test_mode=test_mode)
    _ensure_parent_chain(layout.sealed_config_parent, final_mode=0o750, final_gid=service_gid, test_mode=test_mode)
    _ensure_parent_chain(layout.build_parent, final_mode=0o700, final_gid=gid, test_mode=test_mode)
    lock_fd, unlock = _lock(layout, test_mode=test_mode)
    del lock_fd
    try:
        existing = [
            os.path.lexists(layout.image),
            os.path.lexists(layout.sealed_config),
            os.path.lexists(layout.closure_anchor),
        ]
        if any(existing):
            if not all(existing):
                raise ClosureError("partial immutable closure artifacts already exist")
            anchor, anchor_raw = _load_anchor(layout, uid=uid, gid=gid)
            _validate_anchor_shape(
                anchor,
                layout=layout,
                expected=expected,
                database_name=expected_database_name,
                database_uuid=expected_database_uuid,
                expected_config_sha256=expected_odoo_config_sha256,
                expected_system_python_sha256=expected_system_python_sha256,
                expected_loader_preload_sha256=expected_loader_preload_sha256,
            )
            image_digest, _ = _sha_file(layout.image, maximum=MAX_SOURCE_BYTES)
            config_digest, _ = _sha_file(layout.sealed_config, maximum=MAX_CONFIG_BYTES)
            if image_digest != anchor["image"]["sha256"] or config_digest != expected_odoo_config_sha256:
                raise ClosureError("existing immutable closure artifact conflicts")
            return {
                "schema_version": 1,
                "status": "built",
                "already_exists": True,
                "release_identity": expected.public(),
                "closure_anchor_sha256": anchor_raw,
                "closure_image_sha256": image_digest,
                "closure_anchor_path": str(layout.closure_anchor),
                "closure_image_path": str(layout.image),
                "sealed_config_path": str(layout.sealed_config),
                "mount_point": str(layout.mount_point),
                "system_python_sha256": system_python["sha256"],
                "loader_preload_sha256": loader_preload["sha256"],
            }

        python_binary = _rooted(root, SYSTEM_PYTHON)
        python_stdlib = _rooted(root, PurePosixPath("/usr/lib/python3.12"))
        ld_cache = _rooted(root, PurePosixPath("/etc/ld.so.cache"))
        loader_preload_path = _rooted(root, LD_SO_PRELOAD)
        watch_roots = [
            layout.source_server,
            layout.source_venv,
            layout.source_custom,
            python_binary,
            python_stdlib,
            ld_cache,
            loader_preload_path,
            *[
                Path(item["path"])
                for item in loader_preload["symlink_chain"]
            ],
        ]
        stage: Path | None = None
        image_temporary: Path | None = None
        config_temporary: Path | None = None
        anchor_temporary: Path | None = None
        created: list[Path] = []
        try:
            with InotifyGuard(watch_roots, test_mode=test_mode) as guard:
                config_payload = _read_file(layout.source_config, maximum=MAX_CONFIG_BYTES)
                config_digest = hashlib.sha256(config_payload).hexdigest()
                if config_digest != expected_odoo_config_sha256:
                    raise ClosureError("live Odoo configuration digest drift detected")
                _parse_odoo_config(config_payload)
                graph_before = (
                    graph
                    if graph is not None
                    else query_database_graph(
                        database_name=expected_database_name,
                        database_uuid=expected_database_uuid,
                        runner=command_runner,
                        test_mode=test_mode,
                    )
                )
                if graph_before.get("database_name") != expected_database_name or graph_before.get("database_uuid") != expected_database_uuid:
                    raise ClosureError("supplied database graph identity mismatch")
                mapping, module_selections = resolve_installed_modules(layout, graph_before)
                selections = _core_selections(layout) + module_selections
                python_audit = audit_python_paths(layout.source_venv)

                def derive_native(
                    selected: Sequence[SourceItem], preload: dict[str, Any]
                ) -> list[Path]:
                    injected = [
                        Path(item["rooted_path"]) for item in preload["libraries"]
                    ]
                    if native_roots is not None:
                        return sorted(
                            dict.fromkeys(
                                [
                                    *[Path(path) for path in native_roots],
                                    *injected,
                                    *[path.resolve(strict=True) for path in injected],
                                ]
                            ),
                            key=str,
                        )
                    return _native_dependency_roots(
                        selected,
                        expected_ldconfig_sha256=expected_ldconfig_sha256,
                        injected_elfs=injected,
                        runtime_working_directory=layout.release_root,
                        test_mode=test_mode,
                    )

                preload_before = _validate_loader_preload(
                    expected_sha256=expected_loader_preload_sha256,
                    root=root,
                    test_mode=test_mode,
                )
                native_before = derive_native(selections, preload_before)
                external_roots = [
                    python_binary,
                    python_stdlib,
                    ld_cache,
                    loader_preload_path,
                    *native_before,
                ]
                guard.add_roots(native_before)
                source_before_document = source_manifest(selections, layout.source_config)
                source_before = canonical_sha256(source_before_document)
                external_before = external_runtime_manifest(
                    external_roots, trusted_uid=uid, trusted_gid=gid
                )
                _require_system_python_in_external_manifest(
                    external_before,
                    root=root,
                    expected_sha256=expected_system_python_sha256,
                    expected_uid=uid,
                    expected_gid=gid,
                )
                _require_loader_preload_in_external_manifest(
                    external_before, identity=preload_before
                )
                source_logical_bytes = sum(
                    item.get("size", 0) for item in source_before_document["entries"]
                )
                metadata_allowance = max(source_logical_bytes // 10, 64 * 1024 * 1024)
                stage_upper = source_logical_bytes + metadata_allowance
                image_upper = stage_upper
                _capacity_gate(
                    layout,
                    stage_upper=stage_upper,
                    image_upper=image_upper,
                    phase="before_stage",
                    test_mode=test_mode,
                )
                graph_pre_copy = (
                    graph
                    if graph is not None
                    else query_database_graph(
                        database_name=expected_database_name,
                        database_uuid=expected_database_uuid,
                        runner=command_runner,
                        test_mode=test_mode,
                    )
                )
                mapping_pre_copy, module_pre_copy = resolve_installed_modules(
                    layout, graph_pre_copy
                )
                selections_pre_copy = _core_selections(layout) + module_pre_copy
                audit_pre_copy = audit_python_paths(layout.source_venv)
                preload_pre_copy = _validate_loader_preload(
                    expected_sha256=expected_loader_preload_sha256,
                    root=root,
                    test_mode=test_mode,
                )
                native_pre_copy = derive_native(
                    selections_pre_copy, preload_pre_copy
                )
                _require_discovery_unchanged(
                    (
                        graph_before,
                        mapping,
                        selections,
                        python_audit,
                        preload_before,
                        native_before,
                    ),
                    (
                        graph_pre_copy,
                        mapping_pre_copy,
                        selections_pre_copy,
                        audit_pre_copy,
                        preload_pre_copy,
                        native_pre_copy,
                    ),
                    phase="before copy",
                )
                guard.assert_quiet()
                stage = Path(tempfile.mkdtemp(prefix=f".{expected.release}.", dir=layout.build_parent))
                os.chmod(stage, 0o700)
                copy_selections(
                    selections,
                    stage,
                    venv=layout.source_venv,
                    python_audit=python_audit,
                )
                _assert_no_python_cache(stage)
                _assert_image_symlinks(stage)
                os.chmod(stage, 0o755)
                source_after_document = source_manifest(selections, layout.source_config)
                source_after = canonical_sha256(source_after_document)
                external_after = external_runtime_manifest(
                    external_roots, trusted_uid=uid, trusted_gid=gid
                )
                config_after = _read_file(layout.source_config, maximum=MAX_CONFIG_BYTES)
                graph_after_copy = (
                    graph
                    if graph is not None
                    else query_database_graph(
                        database_name=expected_database_name,
                        database_uuid=expected_database_uuid,
                        runner=command_runner,
                        test_mode=test_mode,
                    )
                )
                mapping_after_copy, modules_after_copy = resolve_installed_modules(
                    layout, graph_after_copy
                )
                selections_after_copy = _core_selections(layout) + modules_after_copy
                audit_after_copy = audit_python_paths(layout.source_venv)
                preload_after_copy = _validate_loader_preload(
                    expected_sha256=expected_loader_preload_sha256,
                    root=root,
                    test_mode=test_mode,
                )
                native_after_copy = derive_native(
                    selections_after_copy, preload_after_copy
                )
                _require_discovery_unchanged(
                    (
                        source_before_document,
                        external_before,
                        config_payload,
                        graph_before,
                        mapping,
                        selections,
                        python_audit,
                        preload_before,
                        native_before,
                    ),
                    (
                        source_after_document,
                        external_after,
                        config_after,
                        graph_after_copy,
                        mapping_after_copy,
                        selections_after_copy,
                        audit_after_copy,
                        preload_after_copy,
                        native_after_copy,
                    ),
                    phase="during closure copy",
                )
                guard.assert_quiet()
                for name, document in (
                    ("SOURCE-MANIFEST.json", source_before_document),
                    ("EXTERNAL-RUNTIME-MANIFEST.json", external_before),
                    ("PYTHON-PATH-AUDIT.json", python_audit),
                ):
                    _write_new(stage / name, canonical_json(document) + b"\n", mode=0o444, uid=uid, gid=gid)
                payload_manifest = _image_payload_manifest(stage)
                closure_manifest = _closure_manifest(
                    expected=expected,
                    database_name=expected_database_name,
                    database_uuid=expected_database_uuid,
                    graph=graph_before,
                    mapping=mapping,
                    source_digest=source_before,
                    external_manifest=external_before,
                    python_audit=python_audit,
                    payload_manifest=payload_manifest,
                    config_sha256=config_digest,
                    system_python_sha256=expected_system_python_sha256,
                    loader_preload_sha256=expected_loader_preload_sha256,
                    loader_preload_identity=preload_before,
                )
                _write_new(
                    stage / "CLOSURE-MANIFEST.json",
                    canonical_json(closure_manifest) + b"\n",
                    mode=0o444,
                    uid=uid,
                    gid=gid,
                )
                if test_mode:
                    raise ClosureError("test mode cannot invoke or publish a real SquashFS build")
                _verified_program(MKSQUASHFS, label="mksquashfs", test_mode=False)
                mksquashfs_sha256, _ = _sha_file(MKSQUASHFS, maximum=64 * 1024 * 1024)
                actual_stage_bytes = _allocated_bytes(stage)
                image_upper = max(image_upper, actual_stage_bytes + metadata_allowance)

                def make_image(target: Path) -> None:
                    _capacity_gate(
                        layout,
                        stage_upper=stage_upper,
                        image_upper=image_upper,
                        phase="before_image",
                        test_mode=False,
                    )
                    process = command_runner(
                        [
                            str(MKSQUASHFS),
                            str(stage),
                            str(target),
                            "-noappend",
                            "-all-root",
                            "-no-xattrs",
                            "-no-exports",
                            "-no-progress",
                            "-comp",
                            "zstd",
                            "-processors",
                            "1",
                            "-mkfs-time",
                            "0",
                            "-all-time",
                            "0",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                        timeout=3600,
                        check=False,
                    )
                    if process.returncode != 0:
                        raise ClosureError("mksquashfs failed")
                    _capacity_gate(
                        layout,
                        stage_upper=stage_upper,
                        image_upper=image_upper,
                        phase="after_image",
                        test_mode=False,
                    )

                first_image = layout.image_parent / f".{expected.release}.{uuid.uuid4().hex}.first.squashfs"
                try:
                    make_image(first_image)
                    first_digest, _ = _sha_file(first_image, maximum=MAX_SOURCE_BYTES)
                finally:
                    try:
                        first_image.unlink()
                        _fsync_directory(first_image.parent)
                    except FileNotFoundError:
                        pass
                image_temporary = layout.image_parent / f".{expected.release}.{uuid.uuid4().hex}.squashfs"
                make_image(image_temporary)
                second_digest, _ = _sha_file(image_temporary, maximum=MAX_SOURCE_BYTES)
                _require_reproducible_images(first_digest, second_digest)
                source_final = source_manifest(selections, layout.source_config)
                external_final = external_runtime_manifest(
                    external_roots, trusted_uid=uid, trusted_gid=gid
                )
                config_final = _read_file(layout.source_config, maximum=MAX_CONFIG_BYTES)
                graph_final = (
                    graph
                    if graph is not None
                    else query_database_graph(
                        database_name=expected_database_name,
                        database_uuid=expected_database_uuid,
                        runner=command_runner,
                        test_mode=test_mode,
                    )
                )
                mapping_final, modules_final = resolve_installed_modules(
                    layout, graph_final
                )
                selections_final = _core_selections(layout) + modules_final
                audit_final = audit_python_paths(layout.source_venv)
                preload_final = _validate_loader_preload(
                    expected_sha256=expected_loader_preload_sha256,
                    root=root,
                    test_mode=test_mode,
                )
                native_final = derive_native(selections_final, preload_final)
                guard.assert_quiet()
                _require_discovery_unchanged(
                    (
                        source_before_document,
                        external_before,
                        config_payload,
                        graph_before,
                        mapping,
                        selections,
                        python_audit,
                        preload_before,
                        native_before,
                    ),
                    (
                        source_final,
                        external_final,
                        config_final,
                        graph_final,
                        mapping_final,
                        selections_final,
                        audit_final,
                        preload_final,
                        native_final,
                    ),
                    phase="before image publication",
                )
            image_digest, _ = _sha_file(image_temporary, maximum=MAX_SOURCE_BYTES)
            if image_digest != second_digest:
                raise ClosureError("second SquashFS image changed before publication")
            _capacity_gate(
                layout,
                stage_upper=stage_upper,
                image_upper=image_upper,
                phase="before_publish",
                test_mode=test_mode,
            )
            anchor = _anchor_document(
                layout=layout,
                expected=expected,
                closure_manifest=closure_manifest,
                image_sha256=image_digest,
                source_before=source_before,
                source_after=source_after,
                external_manifest=external_before,
                config_sha256=config_digest,
                mksquashfs_sha256=mksquashfs_sha256,
                reproducible_image_sha256=image_digest,
                system_python_sha256=expected_system_python_sha256,
                loader_preload_sha256=expected_loader_preload_sha256,
            )
            config_temporary = layout.sealed_config_parent / f".config.{uuid.uuid4().hex}"
            _write_new(config_temporary, config_payload, mode=0o440, uid=uid, gid=service_gid)
            _publish_no_replace(config_temporary, layout.sealed_config, mode=0o440, uid=uid, gid=service_gid)
            config_temporary = None
            created.append(layout.sealed_config)
            _publish_no_replace(image_temporary, layout.image, mode=0o444, uid=uid, gid=gid)
            image_temporary = None
            created.append(layout.image)
            anchor_payload = canonical_json(anchor) + b"\n"
            anchor_temporary = layout.closure_anchor.parent / f".closure-anchor.{uuid.uuid4().hex}"
            _write_new(anchor_temporary, anchor_payload, mode=0o444, uid=uid, gid=gid)
            _publish_no_replace(anchor_temporary, layout.closure_anchor, mode=0o444, uid=uid, gid=gid)
            anchor_temporary = None
            created.append(layout.closure_anchor)
            return {
                "schema_version": 1,
                "status": "built",
                "already_exists": False,
                "release_identity": expected.public(),
                "closure_anchor_sha256": hashlib.sha256(anchor_payload).hexdigest(),
                "closure_image_sha256": image_digest,
                "closure_anchor_path": str(layout.closure_anchor),
                "closure_image_path": str(layout.image),
                "sealed_config_path": str(layout.sealed_config),
                "mount_point": str(layout.mount_point),
                "system_python_sha256": system_python["sha256"],
                "loader_preload_sha256": loader_preload["sha256"],
            }
        except Exception:
            for path in reversed(created):
                try:
                    path.unlink()
                    _fsync_directory(path.parent)
                except OSError:
                    pass
            raise
        finally:
            for path in (image_temporary, config_temporary, anchor_temporary):
                if path is not None:
                    try:
                        path.unlink()
                    except OSError:
                        pass
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
    finally:
        unlock()


def _mountinfo_unescape(value: str) -> str:
    result = bytearray()
    index = 0
    encoded = value.encode("ascii", "strict")
    while index < len(encoded):
        if encoded[index] != 0x5C:
            result.append(encoded[index])
            index += 1
            continue
        if index + 3 >= len(encoded):
            raise ClosureError("mountinfo escape is truncated")
        digits = encoded[index + 1 : index + 4]
        if any(digit < 0x30 or digit > 0x37 for digit in digits):
            raise ClosureError("mountinfo escape is invalid")
        result.append(int(digits.decode("ascii"), 8))
        index += 4
    try:
        return os.fsdecode(bytes(result))
    except UnicodeError as exc:
        raise ClosureError("mountinfo path is invalid") from exc


def _mountinfo_rows(*, process: str = "self") -> list[dict[str, Any]]:
    if process not in {"self", "1"}:
        raise ClosureError("unsupported mount namespace selector")
    try:
        payload = Path(f"/proc/{process}/mountinfo").read_bytes()
    except OSError as exc:
        raise ClosureError("mount namespace cannot be inspected") from exc
    if not payload.endswith(b"\n"):
        raise ClosureError("mountinfo is truncated")
    rows: list[dict[str, Any]] = []
    for raw in payload.splitlines():
        try:
            fields = raw.decode("ascii").split(" ")
        except UnicodeError as exc:
            raise ClosureError("mountinfo is not ASCII") from exc
        if "-" not in fields:
            raise ClosureError("mountinfo row is invalid")
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 4:
            raise ClosureError("mountinfo row is incomplete")
        if (
            not fields[0].isdigit()
            or not fields[1].isdigit()
            or int(fields[0]) <= 0
            or int(fields[1]) <= 0
        ):
            raise ClosureError("mountinfo mount identity is invalid")
        rows.append(
            {
                "mount_id": int(fields[0]),
                "parent_id": int(fields[1]),
                "major_minor": fields[2],
                "mount_root": _mountinfo_unescape(fields[3]),
                "mount_point": _mountinfo_unescape(fields[4]),
                "mount_options": fields[5].split(","),
                "filesystem_type": fields[separator + 1],
                "mount_source": _mountinfo_unescape(fields[separator + 2]),
                "super_options": fields[separator + 3].split(","),
            }
        )
    return rows


def _namespace_identity(*, process: str) -> dict[str, int]:
    if process not in {"self", "1"}:
        raise ClosureError("unsupported mount namespace selector")
    try:
        metadata = Path(f"/proc/{process}/ns/mnt").stat()
    except OSError as exc:
        raise ClosureError("mount namespace identity cannot be inspected") from exc
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _affected_mount_points(layout: Layout) -> list[str]:
    return [str(layout.mount_point), *[item["destination"] for item in _binds(layout)]]


def _affected_mount_rows(layout: Layout, *, process: str) -> list[dict[str, Any]]:
    affected = set(_affected_mount_points(layout))
    return [row for row in _mountinfo_rows(process=process) if row["mount_point"] in affected]


def _loop_backings_for_image(image: Path) -> list[str]:
    expected = os.path.normpath(str(image))
    matches: list[str] = []
    try:
        candidates = sorted(Path("/sys/block").glob("loop*/loop/backing_file"), key=str)
    except OSError as exc:
        raise ClosureError("loop sysfs inventory cannot be inspected") from exc
    for backing_file in candidates:
        try:
            value = backing_file.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ClosureError("loop backing file cannot be inspected") from exc
        if not value or "(deleted)" in value:
            continue
        candidate = value if value.startswith("/") else "/" + value
        if os.path.normpath(candidate) == expected:
            matches.append(f"/dev/{backing_file.parts[-3]}")
    return matches


def _lifecycle_baseline(layout: Layout) -> dict[str, Any]:
    for path in [
        layout.image,
        layout.mount_parent,
        *map(Path, _affected_mount_points(layout)[1:]),
    ]:
        _require_no_symlink_ancestors(path)
    self_namespace = _namespace_identity(process="self")
    host_namespace = _namespace_identity(process="1")
    if self_namespace == host_namespace:
        raise ClosureError("closure lifecycle requires a private mount namespace")
    self_rows = _affected_mount_rows(layout, process="self")
    host_rows = _affected_mount_rows(layout, process="1")
    loops = _loop_backings_for_image(layout.image)
    if self_rows or host_rows or loops:
        raise ClosureError("closure lifecycle starts with an occupied mount or loop")
    return {
        "schema_version": 1,
        "self_mount_namespace": self_namespace,
        "host_mount_namespace": host_namespace,
        "affected_mount_points": _affected_mount_points(layout),
        "self_rows": self_rows,
        "host_rows": host_rows,
        "loop_devices": loops,
    }


def _run_mount_utility(
    command: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    failure: str,
) -> None:
    process = runner(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=120,
        check=False,
    )
    if process.returncode != 0:
        raise ClosureError(failure)


def _binding_observation(layout: Layout) -> list[dict[str, Any]]:
    rows = _mountinfo_rows(process="self")
    observations: list[dict[str, Any]] = []
    for binding in _binds(layout):
        source = Path(binding["source"])
        destination = Path(binding["destination"])
        _require_no_symlink_ancestors(source)
        _require_no_symlink_ancestors(destination)
        matching = [row for row in rows if row["mount_point"] == str(destination)]
        if len(matching) != 1:
            raise ClosureError("closure read-only bind is missing or ambiguous")
        row = matching[0]
        options = set(row["mount_options"])
        if "rw" in options or not {"ro", "nodev", "nosuid"}.issubset(options):
            raise ClosureError("closure bind is not strict read-only")
        try:
            source_metadata = source.stat()
            destination_metadata = destination.stat()
            filesystem = os.statvfs(destination)
        except OSError as exc:
            raise ClosureError("closure bind endpoint cannot be inspected") from exc
        if (source_metadata.st_dev, source_metadata.st_ino) != (
            destination_metadata.st_dev,
            destination_metadata.st_ino,
        ):
            raise ClosureError("closure bind target differs from its sealed source")
        if (filesystem.f_flag & getattr(os, "ST_RDONLY", 1)) == 0:
            raise ClosureError("closure bind statvfs is writable")
        observations.append(
            {
                "source": str(source),
                "destination": str(destination),
                "mount_id": row["mount_id"],
                "major_minor": row["major_minor"],
                "filesystem_type": row["filesystem_type"],
                "source_device": source_metadata.st_dev,
                "source_inode": source_metadata.st_ino,
                "read_only": True,
                "nodev": True,
                "nosuid": True,
            }
        )
    return observations


def _activate_bindings(
    layout: Layout,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> list[dict[str, Any]]:
    _verified_program(
        MOUNT,
        label="mount",
        test_mode=False,
        expected_mode=MOUNT_UTILITY_MODE,
    )
    if _affected_mount_rows(layout, process="1"):
        raise ClosureError("host PID 1 already exposes a closure lifecycle mount")
    for binding in _binds(layout):
        source = Path(binding["source"])
        destination = Path(binding["destination"])
        _require_no_symlink_ancestors(source)
        _require_no_symlink_ancestors(destination)
        try:
            source_metadata = source.lstat()
            destination_metadata = destination.lstat()
        except OSError as exc:
            raise ClosureError("closure bind endpoint is unavailable") from exc
        if source.is_symlink() or destination.is_symlink():
            raise ClosureError("closure bind endpoint cannot be a symlink")
        source_directory = stat.S_ISDIR(source_metadata.st_mode)
        if source_directory != stat.S_ISDIR(destination_metadata.st_mode) or (
            not source_directory
            and (
                not stat.S_ISREG(source_metadata.st_mode)
                or not stat.S_ISREG(destination_metadata.st_mode)
            )
        ):
            raise ClosureError("closure bind endpoint types differ")
        if any(
            row["mount_point"] == str(destination)
            for row in _mountinfo_rows(process="self")
        ):
            raise ClosureError("closure bind destination is already a mount point")
        _run_mount_utility(
            [str(MOUNT), "--bind", str(source), str(destination)],
            runner=runner,
            failure="closure bind mount failed",
        )
        _run_mount_utility(
            [
                str(MOUNT),
                "-o",
                "remount,bind,ro,nodev,nosuid",
                str(source),
                str(destination),
            ],
            runner=runner,
            failure="closure bind read-only remount failed",
        )
    return _binding_observation(layout)


def _unmount_exact(
    target: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> None:
    _verified_program(
        UMOUNT,
        label="umount",
        test_mode=False,
        expected_mode=MOUNT_UTILITY_MODE,
    )
    _run_mount_utility(
        [str(UMOUNT), str(target)],
        runner=runner,
        failure=f"closure unmount failed: {target}",
    )


def deactivate(
    layout: Layout,
    *,
    baseline: dict[str, Any],
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    """Reverse every lifecycle mount and prove the host and loop state are clean."""

    if (
        not _schema_version_is_one(baseline.get("schema_version"))
        or baseline.get("affected_mount_points") != _affected_mount_points(layout)
        or baseline.get("self_rows") != []
        or baseline.get("host_rows") != []
        or baseline.get("loop_devices") != []
    ):
        raise ClosureError("closure lifecycle cleanup baseline is invalid")
    failures: list[Exception] = []
    for target in [
        *[Path(item["destination"]) for item in reversed(_binds(layout))],
        layout.mount_point,
    ]:
        try:
            matches = [
                row
                for row in _mountinfo_rows(process="self")
                if row["mount_point"] == str(target)
            ]
            if len(matches) > 1:
                raise ClosureError(f"closure cleanup mount is ambiguous: {target}")
            if matches:
                _unmount_exact(target, runner=runner)
        except Exception as exc:
            failures.append(exc)
    deadline = time.monotonic() + 2.0
    loop_devices = _loop_backings_for_image(layout.image)
    while loop_devices and time.monotonic() < deadline:
        time.sleep(0.05)
        loop_devices = _loop_backings_for_image(layout.image)
    self_rows = _affected_mount_rows(layout, process="self")
    host_rows = _affected_mount_rows(layout, process="1")
    if failures or self_rows or host_rows or loop_devices:
        raise ClosureError("closure lifecycle cleanup left a mount or loop behind")
    self_namespace = _namespace_identity(process="self")
    host_namespace = _namespace_identity(process="1")
    if self_namespace != baseline["self_mount_namespace"] or host_namespace != baseline["host_mount_namespace"]:
        raise ClosureError("mount namespace identity changed during closure cleanup")
    return {
        "schema_version": 1,
        "status": "clean",
        "unmount_order": [
            *[item["destination"] for item in reversed(_binds(layout))],
            str(layout.mount_point),
        ],
        "self_mount_namespace": self_namespace,
        "host_mount_namespace": host_namespace,
        "remaining_self_mounts": [],
        "remaining_host_mounts": [],
        "remaining_loop_devices": [],
        "loop_autoclear_required": True,
    }


def _validate_loop_status(
    status: bytes | bytearray,
    *,
    image_metadata: os.stat_result | Any,
    expected_image_stat: os.stat_result | Any | None,
) -> dict[str, int | bool]:
    if len(status) < 56:
        raise ClosureError("loop device status is truncated")
    lo_device, lo_inode, _lo_rdevice, lo_offset, lo_sizelimit = struct.unpack_from(
        "=QQQQQ", status, 0
    )
    _lo_number, _lo_encrypt_type, _lo_key_size, lo_flags = struct.unpack_from(
        "=IIII", status, 40
    )
    if (
        lo_device != image_metadata.st_dev
        or lo_inode != image_metadata.st_ino
        or lo_offset != 0
        or lo_sizelimit != 0
        or lo_flags & 0x1 != 0x1  # LO_FLAGS_READ_ONLY
        or lo_flags & 0x4 != 0x4  # LO_FLAGS_AUTOCLEAR
        or (
            expected_image_stat is not None
            and (lo_device, lo_inode)
            != (expected_image_stat.st_dev, expected_image_stat.st_ino)
        )
    ):
        raise ClosureError("loop device is not bound to the current full image inode")
    return {
        "backing_image_device": lo_device,
        "backing_image_inode": lo_inode,
        "loop_offset": lo_offset,
        "loop_sizelimit": lo_sizelimit,
        "loop_read_only": True,
        "loop_autoclear": True,
    }


def _mount_observation(
    layout: Layout, *, expected_image_stat: os.stat_result | None = None
) -> dict[str, Any]:
    try:
        self_namespace = Path("/proc/self/ns/mnt").stat()
        host_namespace = Path("/proc/1/ns/mnt").stat()
        if (self_namespace.st_dev, self_namespace.st_ino) == (
            host_namespace.st_dev,
            host_namespace.st_ino,
        ):
            raise ClosureError("closure mount requires a systemd private mount namespace")
        payload = Path("/proc/self/mountinfo").read_bytes()
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError("host mount namespace cannot be inspected") from exc
    if not payload.endswith(b"\n"):
        raise ClosureError("mountinfo is truncated")
    matches: list[dict[str, Any]] = []
    for raw in payload.splitlines():
        try:
            fields = raw.decode("ascii").split(" ")
        except UnicodeError as exc:
            raise ClosureError("mountinfo is not ASCII") from exc
        if "-" not in fields:
            raise ClosureError("mountinfo row is invalid")
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 4:
            raise ClosureError("mountinfo row is incomplete")
        mount_point = _mountinfo_unescape(fields[4])
        if mount_point != str(layout.mount_point):
            continue
        matches.append(
            {
                "major_minor": fields[2],
                "mount_root": _mountinfo_unescape(fields[3]),
                "mount_point": mount_point,
                "mount_options": fields[5].split(","),
                "filesystem_type": fields[separator + 1],
                "mount_source": _mountinfo_unescape(fields[separator + 2]),
                "super_options": fields[separator + 3].split(","),
            }
        )
    if len(matches) != 1:
        raise ClosureError("closure mount is missing or ambiguous")
    observation = matches[0]
    observation["namespace_scope"] = "systemd-private"
    observation["self_mount_namespace"] = {
        "device": self_namespace.st_dev,
        "inode": self_namespace.st_ino,
    }
    observation["host_mount_namespace"] = {
        "device": host_namespace.st_dev,
        "inode": host_namespace.st_ino,
    }
    options = set(observation["mount_options"]) | set(observation["super_options"])
    if (
        observation["filesystem_type"] != "squashfs"
        or observation["mount_root"] != "/"
        or not {"ro", "nodev", "nosuid"}.issubset(options)
        or "rw" in options
        or re.fullmatch(r"[0-9]+:[0-9]+", observation["major_minor"]) is None
    ):
        raise ClosureError("closure mount is not a strict read-only SquashFS mount")
    source_text = observation["mount_source"]
    if (
        re.fullmatch(r"/dev/loop[0-9]+", source_text) is None
        or "(deleted)" in source_text
    ):
        raise ClosureError("closure mount source is not a canonical loop device")
    sysfs = Path("/sys/dev/block") / observation["major_minor"] / "loop/backing_file"
    try:
        backing_text = sysfs.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ClosureError("closure loop backing file cannot be verified") from exc
    if not backing_text:
        raise ClosureError("closure loop backing file is empty")
    backing = Path(backing_text if backing_text.startswith("/") else "/" + backing_text)
    try:
        if backing.resolve(strict=True) != layout.image.resolve(strict=True):
            raise ClosureError("closure loop device is backed by a different image")
    except OSError as exc:
        raise ClosureError("closure loop backing file cannot be resolved") from exc
    source = Path(source_text)
    if "(deleted)" in backing_text:
        raise ClosureError("closure mount source is not a canonical loop device")
    try:
        source_metadata = source.lstat()
        if not stat.S_ISBLK(source_metadata.st_mode):
            raise ClosureError("closure mount source is not a block device")
        major_minor = f"{os.major(source_metadata.st_rdev)}:{os.minor(source_metadata.st_rdev)}"
        if major_minor != observation["major_minor"]:
            raise ClosureError("loop device identity differs from mountinfo")
        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            status = bytearray(232)
            fcntl.ioctl(descriptor, 0x4C05, status, True)  # LOOP_GET_STATUS64
        finally:
            os.close(descriptor)
        image_metadata = layout.image.lstat()
    except ClosureError:
        raise
    except OSError as exc:
        raise ClosureError("loop device backing identity cannot be inspected") from exc
    loop_identity = _validate_loop_status(
        status,
        image_metadata=image_metadata,
        expected_image_stat=expected_image_stat,
    )
    observation["backing_image_path"] = str(layout.image)
    observation.update(loop_identity)
    return observation


def _mounted_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise ClosureError(f"{label} metadata is invalid")
    payload = _read_file(path, maximum=MAX_JSON_BYTES)
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise ClosureError(f"{label} is not canonical single-line JSON")
    document = _strict_object(payload, label=label)
    if payload != canonical_json(document) + b"\n":
        raise ClosureError(f"{label} bytes are not canonical")
    return document, canonical_sha256(document)


def _validate_external_document(
    document: dict[str, Any],
    *,
    root: Path = Path("/"),
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
) -> None:
    if (trusted_uid is None) != (trusted_gid is None):
        raise ClosureError("external runtime trusted owner is incomplete")
    if (
        set(document) != {"schema_version", "python_abi", "roots", "entries"}
        or not _schema_version_is_one(document.get("schema_version"))
        or document.get("python_abi") != "3.12"
        or not isinstance(document.get("roots"), list)
        or not isinstance(document.get("entries"), list)
        or document["roots"] != sorted(set(document["roots"]))
    ):
        raise ClosureError("external runtime manifest fields are invalid")
    required_roots = {
        str(_rooted(root, PurePosixPath("/usr/bin/python3.12"))),
        str(_rooted(root, PurePosixPath("/usr/lib/python3.12"))),
        str(_rooted(root, PurePosixPath("/etc/ld.so.cache"))),
        str(_rooted(root, LD_SO_PRELOAD)),
    }
    if not required_roots.issubset(set(document["roots"])):
        raise ClosureError("external runtime manifest omits a fixed runtime root")
    previous = ""
    entry_paths: set[str] = set()
    for entry in document["entries"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ClosureError("external runtime manifest entry is invalid")
        path = entry["path"]
        if not Path(path).is_absolute() or path <= previous:
            raise ClosureError("external runtime manifest paths are not canonical")
        previous = path
        entry_paths.add(path)
        common = {"path", "kind", "mode", "uid", "gid"}
        kind = entry.get("kind")
        expected_fields = (
            common
            if kind == "directory"
            else common | {"size", "sha256"}
            if kind == "regular"
            else common | {"target"}
            if kind == "symlink"
            else set()
        )
        if (
            not expected_fields
            or set(entry) != expected_fields
            or not isinstance(entry.get("mode"), str)
            or re.fullmatch(r"[0-7]{4}", entry["mode"]) is None
            or not isinstance(entry.get("uid"), int)
            or not isinstance(entry.get("gid"), int)
        ):
            raise ClosureError("external runtime manifest entry fields are invalid")
        if trusted_uid is not None and (
            entry["uid"] != trusted_uid
            or entry["gid"] != trusted_gid
            or (
                kind in {"directory", "regular"}
                and int(entry["mode"], 8) & 0o022
            )
        ):
            raise ClosureError("external runtime manifest metadata is untrusted")
        if kind == "regular" and (
            not isinstance(entry.get("size"), int)
            or entry["size"] < 0
            or not isinstance(entry.get("sha256"), str)
            or HEX64.fullmatch(entry["sha256"]) is None
        ):
            raise ClosureError("external runtime regular entry is invalid")
        if kind == "symlink" and not isinstance(entry.get("target"), str):
            raise ClosureError("external runtime symlink entry is invalid")
    if not set(document["roots"]).issubset(entry_paths):
        raise ClosureError("external runtime root is absent from its entry inventory")


def _require_system_python_in_external_manifest(
    document: dict[str, Any],
    *,
    root: Path,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
) -> None:
    path = str(_rooted(root, SYSTEM_PYTHON))
    matches = [entry for entry in document.get("entries", []) if entry.get("path") == path]
    if len(matches) != 1 or matches[0] != {
        "path": path,
        "mode": "0755",
        "uid": expected_uid,
        "gid": expected_gid,
        "kind": "regular",
        "size": matches[0].get("size") if matches else None,
        "sha256": expected_sha256,
    }:
        raise ClosureError("external runtime does not seal the fixed system Python")
    if (
        not isinstance(matches[0]["size"], int)
        or isinstance(matches[0]["size"], bool)
        or matches[0]["size"] <= 0
    ):
        raise ClosureError("external runtime system Python size is invalid")


def _require_loader_preload_in_external_manifest(
    document: dict[str, Any],
    *,
    identity: dict[str, Any],
) -> None:
    entries = {
        entry["path"]: entry
        for entry in document.get("entries", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    expected_file = {
        "path": identity["path"],
        "mode": "0644",
        "uid": identity["uid"],
        "gid": identity["gid"],
        "kind": "regular",
        "size": identity["size"],
        "sha256": identity["sha256"],
    }
    if entries.get(identity["path"]) != expected_file:
        raise ClosureError("external runtime does not seal ld.so.preload")
    for library in identity["libraries"]:
        rooted = entries.get(library["rooted_path"])
        resolved = entries.get(library["resolved_path"])
        if rooted is None or resolved is None or resolved.get("kind") != "regular":
            raise ClosureError("external runtime omits a loader preload library")


def _validate_closure_manifest(
    document: dict[str, Any],
    *,
    anchor: dict[str, Any],
    expected: ExpectedIdentity,
    database_name: str,
    database_uuid: str,
    expected_config_sha256: str,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    loader_preload_identity: dict[str, Any],
) -> None:
    if set(document) != {
        "schema_version",
        "kind",
        "release_identity",
        "database_scope",
        "installed_modules",
        "source_manifest_sha256",
        "external_runtime_manifest_sha256",
        "python_path_audit_sha256",
        "payload_manifest_sha256",
        "payload_entry_count",
        "sealed_config_sha256",
        "system_python_sha256",
        "loader_preload_sha256",
        "loader_preload",
        "config_placeholder",
    }:
        raise ClosureError("closure manifest fields are invalid")
    if (
        not _schema_version_is_one(document.get("schema_version"))
        or document.get("kind") != "odoo_dependency_closure"
        or document.get("release_identity") != expected.public()
        or document.get("database_scope")
        != {"database_name": database_name, "database_uuid": database_uuid}
        or document.get("source_manifest_sha256")
        != anchor["source_manifest_sha256_before"]
        or document.get("external_runtime_manifest_sha256")
        != anchor["external_runtime_manifest_sha256"]
        or document.get("python_path_audit_sha256")
        != anchor["python_path_audit_sha256"]
        or document.get("sealed_config_sha256") != expected_config_sha256
        or document.get("system_python_sha256")
        != expected_system_python_sha256
        or document.get("loader_preload_sha256")
        != expected_loader_preload_sha256
        or document.get("loader_preload") != loader_preload_identity
        or document.get("config_placeholder")
        != {
            "path": "custom-addons/odoo-server19.conf",
            "mode": "0000",
            "sha256": hashlib.sha256(PLACEHOLDER).hexdigest(),
        }
    ):
        raise ClosureError("closure manifest identity mismatch")
    installed = document.get("installed_modules")
    if (
        not isinstance(installed, dict)
        or set(installed)
        != {
            "count",
            "names",
            "names_sha256",
            "database_graph_sha256",
            "module_mapping_sha256",
            "module_payload_mapping_sha256",
            "resolver_precedence",
            "mapping",
            "payload_mapping",
        }
        or installed.get("count") != len(installed.get("names", []))
        or installed.get("names") != sorted(set(installed.get("names", [])))
        or installed.get("names_sha256") != canonical_sha256(installed["names"])
        or installed.get("mapping") != sorted(installed.get("mapping", []), key=lambda item: item.get("name", ""))
        or installed.get("module_mapping_sha256") != canonical_sha256(installed["mapping"])
        or installed.get("module_payload_mapping_sha256")
        != canonical_sha256(installed["payload_mapping"])
        or installed.get("resolver_precedence") != ["builtin", "community", "custom"]
        or {
            "count": installed.get("count"),
            "names_sha256": installed.get("names_sha256"),
            "database_graph_sha256": installed.get("database_graph_sha256"),
            "module_mapping_sha256": installed.get("module_mapping_sha256"),
            "module_payload_mapping_sha256": installed.get(
                "module_payload_mapping_sha256"
            ),
            "resolver_precedence": installed.get("resolver_precedence"),
        }
        != anchor["installed_modules"]
    ):
        raise ClosureError("closure installed-module identity mismatch")
    if (
        not isinstance(document.get("payload_entry_count"), int)
        or document["payload_entry_count"] <= 0
        or not isinstance(document.get("payload_manifest_sha256"), str)
        or HEX64.fullmatch(document["payload_manifest_sha256"]) is None
    ):
        raise ClosureError("closure payload identity is invalid")


def _derive_external_runtime(
    layout: Layout,
    *,
    root: Path,
    test_mode: bool,
    native_roots: Sequence[Path] | None,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    trusted_uid: int,
    trusted_gid: int,
) -> tuple[dict[str, Any], int, int]:
    selections = [
        SourceItem(layout.mount_point / "odoo-server", PurePosixPath("odoo-server"), "mounted"),
        SourceItem(layout.mount_point / "odoo19-venv", PurePosixPath("odoo19-venv"), "mounted"),
        SourceItem(layout.mount_point / "custom-addons", PurePosixPath("custom-addons"), "mounted"),
    ]
    regulars = list(_all_selected_regular_files(selections))
    elf_count = sum(1 for path in regulars if _is_elf(path))
    loader_preload = _validate_loader_preload(
        expected_sha256=expected_loader_preload_sha256,
        root=root,
        test_mode=test_mode,
    )
    injected = [Path(item["rooted_path"]) for item in loader_preload["libraries"]]
    if native_roots is None:
        native_roots = _native_dependency_roots(
            selections,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            injected_elfs=injected,
            runtime_working_directory=layout.release_root,
            test_mode=test_mode,
        )
    else:
        native_roots = sorted(
            dict.fromkeys(
                [
                    *[Path(path) for path in native_roots],
                    *injected,
                    *[path.resolve(strict=True) for path in injected],
                ]
            ),
            key=str,
        )
    fixed = [
        _rooted(root, SYSTEM_PYTHON),
        _rooted(root, PurePosixPath("/usr/lib/python3.12")),
        _rooted(root, PurePosixPath("/etc/ld.so.cache")),
        _rooted(root, LD_SO_PRELOAD),
    ]
    roots = sorted(dict.fromkeys([*fixed, *native_roots]), key=str)
    return (
        external_runtime_manifest(
            roots, trusted_uid=trusted_uid, trusted_gid=trusted_gid
        ),
        elf_count,
        len(roots) - len(fixed),
    )


def verify(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path = Path("/"),
    script_path: Path = Path(__file__),
    test_mode: bool = False,
    mount_observation: dict[str, Any] | None = None,
    native_roots: Sequence[Path] | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    service_gid: int | None = None,
    database_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    uid, gid = _require_root(test_mode=test_mode)
    if not test_mode and (
        mount_observation is not None
        or native_roots is not None
        or service_gid is not None
        or database_graph is not None
    ):
        raise ClosureError("production verify rejects test-only dependency overrides")
    for label, value in (
        ("ldconfig.real", expected_ldconfig_sha256),
        ("closure anchor", expected_closure_anchor_sha256),
        ("closure image", expected_closure_image_sha256),
        ("Odoo config", expected_odoo_config_sha256),
    ):
        if not isinstance(value, str) or HEX64.fullmatch(value) is None:
            raise ClosureError(f"expected {label} SHA-256 is invalid")
    if DATABASE.fullmatch(expected_database_name) is None or DATABASE_UUID.fullmatch(expected_database_uuid) is None:
        raise ClosureError("expected database identity is invalid")
    layout = build_layout(root, expected)
    system_python = _validate_system_python(
        expected_sha256=expected_system_python_sha256,
        root=root,
        test_mode=test_mode,
    )
    loader_preload = _validate_loader_preload(
        expected_sha256=expected_loader_preload_sha256,
        root=root,
        test_mode=test_mode,
    )
    release_identity = verify_release(
        layout, expected, script_path=script_path, test_mode=test_mode
    )
    if service_gid is None:
        try:
            service_gid = pwd.getpwnam("odoo").pw_gid
        except KeyError as exc:
            if test_mode:
                service_gid = gid
            else:
                raise ClosureError("odoo service account is unavailable") from exc
    anchor, anchor_raw_sha256 = _load_anchor(layout, uid=uid, gid=gid)
    if anchor_raw_sha256 != expected_closure_anchor_sha256:
        raise ClosureError("closure anchor raw digest mismatch")
    _validate_anchor_shape(
        anchor,
        layout=layout,
        expected=expected,
        database_name=expected_database_name,
        database_uuid=expected_database_uuid,
        expected_config_sha256=expected_odoo_config_sha256,
        expected_system_python_sha256=expected_system_python_sha256,
        expected_loader_preload_sha256=expected_loader_preload_sha256,
    )
    image_metadata = _mode_owner(
        layout.image,
        uid=uid,
        gid=gid,
        mode=0o444,
        directory=False,
        label="closure image",
    )
    if image_metadata.st_nlink != 1:
        raise ClosureError("closure image has unsafe link count")
    image_sha256, _ = _sha_file(layout.image, maximum=MAX_SOURCE_BYTES)
    if image_sha256 != expected_closure_image_sha256 or image_sha256 != anchor["image"]["sha256"]:
        raise ClosureError("closure image digest mismatch")
    sealed_metadata = _mode_owner(
        layout.sealed_config,
        uid=uid,
        gid=service_gid,
        mode=0o440,
        directory=False,
        label="sealed Odoo config",
    )
    if sealed_metadata.st_nlink != 1:
        raise ClosureError("sealed Odoo config has unsafe link count")
    sealed_sha256, _ = _sha_file(layout.sealed_config, maximum=MAX_CONFIG_BYTES)
    if sealed_sha256 != expected_odoo_config_sha256:
        raise ClosureError("sealed Odoo config digest mismatch")
    if mount_observation is None:
        mount_observation = _mount_observation(layout)
    if (
        mount_observation.get("filesystem_type") != "squashfs"
        or mount_observation.get("mount_point") != str(layout.mount_point)
        or mount_observation.get("backing_image_path") != str(layout.image)
    ):
        raise ClosureError("closure mount observation is invalid")

    closure, closure_sha256 = _mounted_json(
        layout.mount_point / "CLOSURE-MANIFEST.json", label="closure manifest"
    )
    if closure_sha256 != anchor["closure_manifest_sha256"]:
        raise ClosureError("closure manifest digest mismatch")
    _validate_closure_manifest(
        closure,
        anchor=anchor,
        expected=expected,
        database_name=expected_database_name,
        database_uuid=expected_database_uuid,
        expected_config_sha256=expected_odoo_config_sha256,
        expected_system_python_sha256=expected_system_python_sha256,
        expected_loader_preload_sha256=expected_loader_preload_sha256,
        loader_preload_identity=loader_preload,
    )
    graph_before = (
        database_graph
        if database_graph is not None
        else query_database_graph(
            database_name=expected_database_name,
            database_uuid=expected_database_uuid,
            runner=command_runner,
            test_mode=test_mode,
        )
    )
    graph_identity_before = canonical_sha256(
        {"modules": graph_before["modules"], "dependencies": graph_before["dependencies"]}
    )
    if (
        graph_before.get("database_name") != expected_database_name
        or graph_before.get("database_uuid") != expected_database_uuid
        or graph_identity_before
        != closure["installed_modules"]["database_graph_sha256"]
        or [item["name"] for item in graph_before["modules"]]
        != closure["installed_modules"]["names"]
    ):
        raise ClosureError("current database installed-module graph differs from closure")
    source_document, source_sha256 = _mounted_json(
        layout.mount_point / "SOURCE-MANIFEST.json", label="source manifest"
    )
    if (
        source_sha256 != closure["source_manifest_sha256"]
        or not _schema_version_is_one(source_document.get("schema_version"))
    ):
        raise ClosureError("source manifest digest mismatch")
    external_document, external_sha256 = _mounted_json(
        layout.mount_point / "EXTERNAL-RUNTIME-MANIFEST.json",
        label="external runtime manifest",
    )
    _validate_external_document(
        external_document, root=root, trusted_uid=uid, trusted_gid=gid
    )
    _require_system_python_in_external_manifest(
        external_document,
        root=root,
        expected_sha256=expected_system_python_sha256,
        expected_uid=uid,
        expected_gid=gid,
    )
    _require_loader_preload_in_external_manifest(
        external_document, identity=loader_preload
    )
    if external_sha256 != closure["external_runtime_manifest_sha256"]:
        raise ClosureError("external runtime manifest digest mismatch")
    python_document, python_sha256 = _mounted_json(
        layout.mount_point / "PYTHON-PATH-AUDIT.json", label="Python path audit"
    )
    if (
        python_sha256 != closure["python_path_audit_sha256"]
        or set(python_document)
        != {
            "schema_version",
            "accepted_pth",
            "excluded_editable_entries",
            "pyvenv",
            "python_path_escape_absent",
        }
        or not _schema_version_is_one(python_document.get("schema_version"))
        or python_document.get("python_path_escape_absent") is not True
    ):
        raise ClosureError("Python path audit identity mismatch")
    mounted_audit = audit_python_paths(layout.mount_point / "odoo19-venv")
    if (
        mounted_audit["excluded_editable_entries"]
        or mounted_audit["python_path_escape_absent"] is not True
        or mounted_audit["accepted_pth"] != python_document["accepted_pth"]
        or mounted_audit["pyvenv"]["source_sha256"]
        != python_document["pyvenv"]["normalized_sha256"]
        or mounted_audit["pyvenv"]["normalized_values"]
        != python_document["pyvenv"]["normalized_values"]
    ):
        raise ClosureError("mounted venv contains a Python path escape")
    _assert_image_symlinks(layout.mount_point)
    _assert_no_python_cache(layout.mount_point)
    placeholder = layout.mount_point / "custom-addons" / "odoo-server19.conf"
    placeholder_metadata = placeholder.lstat()
    placeholder_sha256, _ = _sha_file(placeholder, maximum=len(PLACEHOLDER))
    if (
        placeholder.is_symlink()
        or not stat.S_ISREG(placeholder_metadata.st_mode)
        or placeholder_metadata.st_uid != 0
        or placeholder_metadata.st_gid != 0
        or stat.S_IMODE(placeholder_metadata.st_mode) != 0
        or placeholder_sha256 != hashlib.sha256(PLACEHOLDER).hexdigest()
    ):
        raise ClosureError("image config placeholder is not fail-closed")
    payload_manifest = _image_payload_manifest(
        layout.mount_point, require_root_owner=not test_mode
    )
    if (
        canonical_sha256(payload_manifest) != closure["payload_manifest_sha256"]
        or len(payload_manifest["entries"]) != closure["payload_entry_count"]
        or _module_payload_mapping(
            payload_manifest, closure["installed_modules"]["mapping"]
        )
        != closure["installed_modules"]["payload_mapping"]
    ):
        raise ClosureError("mounted image payload differs from closure manifest")
    with InotifyGuard(
        [
            *[Path(path) for path in external_document["roots"]],
            *[Path(item["path"]) for item in loader_preload["symlink_chain"]],
        ],
        test_mode=test_mode,
    ) as external_guard:
        derived_external, elf_count, native_count = _derive_external_runtime(
            layout,
            root=root,
            test_mode=test_mode,
            native_roots=native_roots,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            trusted_uid=uid,
            trusted_gid=gid,
        )
        derived_external_after, elf_count_after, native_count_after = _derive_external_runtime(
            layout,
            root=root,
            test_mode=test_mode,
            native_roots=native_roots,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            trusted_uid=uid,
            trusted_gid=gid,
        )
        external_guard.assert_quiet()
    if (
        derived_external != external_document
        or derived_external_after != external_document
        or elf_count_after != elf_count
        or native_count_after != native_count
    ):
        raise ClosureError("external runtime derivation differs from sealed manifest")
    graph_after = (
        database_graph
        if database_graph is not None
        else query_database_graph(
            database_name=expected_database_name,
            database_uuid=expected_database_uuid,
            runner=command_runner,
            test_mode=test_mode,
        )
    )
    if graph_after != graph_before:
        raise ClosureError("database installed-module graph changed during verification")

    mount_public = {
        "mount_point": str(layout.mount_point),
        "filesystem_type": "squashfs",
        "read_only": True,
        "nodev": True,
        "nosuid": True,
        "backing_image_sha256": image_sha256,
        "namespace_scope": mount_observation.get("namespace_scope", "test-private"),
        "self_mount_namespace": mount_observation.get("self_mount_namespace", {}),
        "host_mount_namespace": mount_observation.get("host_mount_namespace", {}),
        "loop_device": mount_observation.get("mount_source", "test-loop"),
        "loop_backing_device": mount_observation.get("backing_image_device", image_metadata.st_dev),
        "loop_backing_inode": mount_observation.get("backing_image_inode", image_metadata.st_ino),
        "loop_offset": mount_observation.get("loop_offset", 0),
        "loop_sizelimit": mount_observation.get("loop_sizelimit", 0),
        "loop_read_only": mount_observation.get("loop_read_only", True),
        "loop_autoclear": mount_observation.get("loop_autoclear", True),
    }
    return {
        "schema_version": 1,
        "status": "verified",
        "release_identity": release_identity,
        "closure_identity": {
            "anchor_path": str(layout.closure_anchor),
            "anchor_sha256": anchor_raw_sha256,
            "image_path": str(layout.image),
            "image_sha256": image_sha256,
            "closure_manifest_sha256": closure_sha256,
            "source_manifest_sha256": source_sha256,
            "sealed_config_path": str(layout.sealed_config),
            "sealed_config_sha256": sealed_sha256,
            "system_python_sha256": system_python["sha256"],
            "loader_preload_sha256": loader_preload["sha256"],
            "loader_preload": loader_preload,
            "installed_modules_count": closure["installed_modules"]["count"],
            "installed_modules_sha256": closure["installed_modules"]["names_sha256"],
            "database_graph_sha256": closure["installed_modules"]["database_graph_sha256"],
            "module_mapping_sha256": closure["installed_modules"]["module_mapping_sha256"],
            "module_payload_mapping_sha256": closure["installed_modules"][
                "module_payload_mapping_sha256"
            ],
            "external_runtime_manifest_sha256": external_sha256,
            "external_runtime_manifest_path": str(
                layout.mount_point / "EXTERNAL-RUNTIME-MANIFEST.json"
            ),
            "external_runtime_paths": external_document["roots"],
            "external_runtime_derivation_method": "static-python-elf-dt-needed-loader-preload-plus-root-owned-ld-cache-v2",
            "external_runtime_entry_count": len(external_document["entries"]),
            "external_runtime_native_path_count": native_count,
            "closure_elf_count": elf_count,
        },
        "database_scope": {
            "database_name": expected_database_name,
            "database_uuid": expected_database_uuid,
        },
        "mount": mount_public,
        "systemd": _systemd(layout),
        "security": {
            "root_only": True,
            "image_all_root": True,
            "mount_read_only": True,
            "config_sealed_outside_image": True,
            "config_placeholder_fail_closed": True,
            "source_manifest_stable": True,
            "no_external_symlinks": True,
            "python_path_escape_absent": True,
            "system_python_exact_and_sealed": True,
            "system_python_isolated_no_site_required": True,
            "loop_autoclear": True,
            "loader_preload_is_root_os_trust_anchor": True,
            "runtime_open_trace_required_for_completion": True,
            "static_runtime_closure_complete": False,
            "promotion_eligible_from_static_verification": False,
        },
    }


def _preverify_mount_artifacts(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path,
    script_path: Path,
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> tuple[Layout, int, os.stat_result]:
    for label, value in (
        ("system Python", expected_system_python_sha256),
        ("ld.so.preload", expected_loader_preload_sha256),
        ("closure anchor", expected_closure_anchor_sha256),
        ("closure image", expected_closure_image_sha256),
        ("Odoo config", expected_odoo_config_sha256),
    ):
        if not isinstance(value, str) or HEX64.fullmatch(value) is None:
            raise ClosureError(f"expected {label} SHA-256 is invalid")
    layout = build_layout(root, expected)
    _validate_system_python(
        expected_sha256=expected_system_python_sha256,
        root=root,
        test_mode=False,
    )
    _validate_loader_preload(
        expected_sha256=expected_loader_preload_sha256,
        root=root,
        test_mode=False,
    )
    verify_release(layout, expected, script_path=script_path, test_mode=False)
    try:
        service_gid = pwd.getpwnam("odoo").pw_gid
    except KeyError as exc:
        raise ClosureError("odoo service account is unavailable") from exc
    anchor, raw_sha256 = _load_anchor(layout, uid=0, gid=0)
    if raw_sha256 != expected_closure_anchor_sha256:
        raise ClosureError("closure anchor raw digest mismatch before mount")
    _validate_anchor_shape(
        anchor,
        layout=layout,
        expected=expected,
        database_name=expected_database_name,
        database_uuid=expected_database_uuid,
        expected_config_sha256=expected_odoo_config_sha256,
        expected_system_python_sha256=expected_system_python_sha256,
        expected_loader_preload_sha256=expected_loader_preload_sha256,
    )
    image_metadata = _mode_owner(
        layout.image,
        uid=0,
        gid=0,
        mode=0o444,
        directory=False,
        label="closure image",
    )
    config_metadata = _mode_owner(
        layout.sealed_config,
        uid=0,
        gid=service_gid,
        mode=0o440,
        directory=False,
        label="sealed Odoo config",
    )
    if image_metadata.st_nlink != 1 or config_metadata.st_nlink != 1:
        raise ClosureError("mount artifact has unsafe hard-link count")
    image_descriptor = -1
    try:
        image_descriptor = os.open(
            layout.image,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
        )
        image_sha256, _image_size, image_open_stat = _sha_open_descriptor(
            image_descriptor, maximum=MAX_SOURCE_BYTES
        )
        if (
            image_open_stat.st_dev,
            image_open_stat.st_ino,
            image_open_stat.st_mode,
            image_open_stat.st_uid,
            image_open_stat.st_gid,
            image_open_stat.st_nlink,
            image_open_stat.st_size,
        ) != (
            image_metadata.st_dev,
            image_metadata.st_ino,
            image_metadata.st_mode,
            image_metadata.st_uid,
            image_metadata.st_gid,
            image_metadata.st_nlink,
            image_metadata.st_size,
        ):
            raise ClosureError("closure image changed while retaining pre-mount FD")
    except Exception:
        if image_descriptor >= 0:
            os.close(image_descriptor)
        raise
    config_sha256, _ = _sha_file(layout.sealed_config, maximum=MAX_CONFIG_BYTES)
    if (
        image_sha256 != expected_closure_image_sha256
        or image_sha256 != anchor["image"]["sha256"]
        or config_sha256 != expected_odoo_config_sha256
    ):
        os.close(image_descriptor)
        raise ClosureError("mount artifact digest mismatch before kernel mount")
    try:
        graph = query_database_graph(
            database_name=expected_database_name,
            database_uuid=expected_database_uuid,
            runner=command_runner,
            test_mode=False,
        )
        graph_sha256 = canonical_sha256(
            {"modules": graph["modules"], "dependencies": graph["dependencies"]}
        )
        if graph_sha256 != anchor["installed_modules"]["database_graph_sha256"]:
            raise ClosureError("current database graph differs before kernel mount")
        return layout, image_descriptor, image_open_stat
    except Exception:
        os.close(image_descriptor)
        raise


def mount(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path = Path("/"),
    script_path: Path = Path(__file__),
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    _lock_held: bool = False,
) -> dict[str, Any]:
    _require_root(test_mode=False)
    if Path(root) != Path("/"):
        raise ClosureError("production mount refuses redirected roots")
    layout = build_layout(root, expected)
    if _lock_held:
        unlock: Callable[[], object] = lambda: None
    else:
        _ensure_parent_chain(layout.lock_parent, final_mode=0o755, final_gid=0, test_mode=False)
        lock_fd, unlock = _lock(layout, test_mode=False)
        del lock_fd
    mounted_here = False
    image_descriptor = -1
    try:
        layout, image_descriptor, preverified_image_stat = _preverify_mount_artifacts(
            expected,
            expected_closure_anchor_sha256=expected_closure_anchor_sha256,
            expected_closure_image_sha256=expected_closure_image_sha256,
            expected_system_python_sha256=expected_system_python_sha256,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_odoo_config_sha256=expected_odoo_config_sha256,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
            root=root,
            script_path=script_path,
            command_runner=command_runner,
        )
        try:
            observation = _mount_observation(
                layout, expected_image_stat=preverified_image_stat
            )
        except ClosureError as exc:
            if "missing or ambiguous" not in str(exc):
                raise
            observation = None
        if observation is None:
            try:
                service_gid = pwd.getpwnam("odoo").pw_gid
            except KeyError as exc:
                raise ClosureError("odoo service account is unavailable") from exc
            _ensure_parent_chain(layout.mount_parent, final_mode=0o750, final_gid=service_gid, test_mode=False)
            if os.path.lexists(layout.mount_point):
                _mode_owner(
                    layout.mount_point,
                    uid=0,
                    gid=service_gid,
                    mode=0o750,
                    directory=True,
                    label="closure mount point",
                )
            else:
                layout.mount_point.mkdir(mode=0o750)
                os.chown(layout.mount_point, 0, service_gid)
            _verified_program(
                MOUNT,
                label="mount",
                test_mode=False,
                expected_mode=MOUNT_UTILITY_MODE,
            )
            process = command_runner(
                [
                    str(MOUNT),
                    "-t",
                    "squashfs",
                    "-o",
                    "loop,ro,nodev,nosuid",
                    str(layout.image),
                    str(layout.mount_point),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                timeout=120,
                check=False,
            )
            if process.returncode != 0:
                raise ClosureError("read-only SquashFS mount failed")
            mounted_here = True
            _mount_observation(
                layout, expected_image_stat=preverified_image_stat
            )
        return verify(
            expected,
            expected_closure_anchor_sha256=expected_closure_anchor_sha256,
            expected_closure_image_sha256=expected_closure_image_sha256,
            expected_system_python_sha256=expected_system_python_sha256,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            expected_odoo_config_sha256=expected_odoo_config_sha256,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
            root=root,
            script_path=script_path,
            command_runner=command_runner,
        )
    except Exception as original:
        if mounted_here:
            try:
                _verified_program(
                    UMOUNT,
                    label="umount",
                    test_mode=False,
                    expected_mode=MOUNT_UTILITY_MODE,
                )
                cleanup = command_runner(
                    [str(UMOUNT), str(layout.mount_point)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    timeout=120,
                    check=False,
                )
                if cleanup.returncode != 0:
                    raise ClosureError("failed closure mount could not be unmounted")
                mounted_here = False
                deadline = time.monotonic() + 2.0
                loops = _loop_backings_for_image(layout.image)
                while loops and time.monotonic() < deadline:
                    time.sleep(0.05)
                    loops = _loop_backings_for_image(layout.image)
                remaining = [
                    row
                    for row in _mountinfo_rows(process="self")
                    if row["mount_point"] == str(layout.mount_point)
                ]
                if remaining or loops:
                    raise ClosureError(
                        "failed closure mount retained a mount or loop device"
                    )
            except Exception as cleanup_error:
                raise ClosureError("failed closure mount cleanup failed closed") from cleanup_error
        raise original
    finally:
        if image_descriptor >= 0:
            os.close(image_descriptor)
        unlock()


def verify_active(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path = Path("/"),
    script_path: Path = Path(__file__),
    test_mode: bool = False,
    mount_observation: dict[str, Any] | None = None,
    native_roots: Sequence[Path] | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    service_gid: int | None = None,
    database_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify both the image and the four post-mount supervisor bindings."""

    result = verify(
        expected,
        expected_system_python_sha256=expected_system_python_sha256,
        expected_loader_preload_sha256=expected_loader_preload_sha256,
        expected_ldconfig_sha256=expected_ldconfig_sha256,
        expected_closure_anchor_sha256=expected_closure_anchor_sha256,
        expected_closure_image_sha256=expected_closure_image_sha256,
        expected_odoo_config_sha256=expected_odoo_config_sha256,
        expected_database_name=expected_database_name,
        expected_database_uuid=expected_database_uuid,
        root=root,
        script_path=script_path,
        test_mode=test_mode,
        mount_observation=mount_observation,
        native_roots=native_roots,
        command_runner=command_runner,
        service_gid=service_gid,
        database_graph=database_graph,
    )
    layout = build_layout(root, expected)
    bindings = _binding_observation(layout)
    if _affected_mount_rows(layout, process="1"):
        raise ClosureError("closure activation leaked into the host mount namespace")
    result["status"] = "active_verified"
    result["activation"] = {
        "execution_model": "single-supervisor-private-mount-namespace-v1",
        "bindings": bindings,
        "binding_count": 4,
        "config_binding_last": (
            bindings[-1].get("source") == str(layout.sealed_config)
            and bindings[-1].get("destination") == str(SOURCE_CONFIG)
        ),
        "host_mounts_absent": True,
        "direct_child_fork_exec_required": True,
        "systemd_run_forbidden": True,
    }
    if result["activation"]["config_binding_last"] is not True:
        raise ClosureError("sealed Odoo config is not the final activation binding")
    return result


@contextmanager
def activated_closure(
    expected: ExpectedIdentity,
    *,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_odoo_config_sha256: str,
    expected_database_name: str,
    expected_database_uuid: str,
    root: Path = Path("/"),
    script_path: Path = Path(__file__),
    command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> Iterator[dict[str, Any]]:
    """Own the complete mount/bind/verify/cleanup lifecycle in one supervisor."""

    _require_root(test_mode=False)
    if Path(root) != Path("/"):
        raise ClosureError("production activation refuses redirected roots")
    layout = build_layout(root, expected)
    _ensure_parent_chain(
        layout.lock_parent,
        final_mode=0o755,
        final_gid=0,
        test_mode=False,
    )
    lock_fd, unlock = _lock(layout, test_mode=False)
    del lock_fd
    baseline: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    body_failed = False
    try:
        baseline = _lifecycle_baseline(layout)
        mount(
            expected,
            expected_system_python_sha256=expected_system_python_sha256,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            expected_closure_anchor_sha256=expected_closure_anchor_sha256,
            expected_closure_image_sha256=expected_closure_image_sha256,
            expected_odoo_config_sha256=expected_odoo_config_sha256,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
            root=root,
            script_path=script_path,
            command_runner=command_runner,
            _lock_held=True,
        )
        _activate_bindings(layout, runner=command_runner)
        result = verify_active(
            expected,
            expected_system_python_sha256=expected_system_python_sha256,
            expected_loader_preload_sha256=expected_loader_preload_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            expected_closure_anchor_sha256=expected_closure_anchor_sha256,
            expected_closure_image_sha256=expected_closure_image_sha256,
            expected_odoo_config_sha256=expected_odoo_config_sha256,
            expected_database_name=expected_database_name,
            expected_database_uuid=expected_database_uuid,
            root=root,
            script_path=script_path,
            command_runner=command_runner,
        )
        result["lifecycle"] = {
            "lock_held_until_cleanup": True,
            "same_supervisor_namespace": True,
            "cleanup_required_before_success_anchor": True,
        }
        try:
            yield result
        except BaseException:
            body_failed = True
            raise
    finally:
        try:
            if baseline is not None:
                cleanup = deactivate(layout, baseline=baseline, runner=command_runner)
                if result is not None:
                    result["cleanup_receipt"] = cleanup
        except Exception as cleanup_error:
            if body_failed:
                raise ClosureError(
                    "closure lifecycle body and mandatory cleanup both failed"
                ) from cleanup_error
            raise
        finally:
            unlock()


def _identity_from_arguments(arguments: argparse.Namespace) -> ExpectedIdentity:
    return ExpectedIdentity(
        release=arguments.expected_release,
        version=arguments.expected_version,
        commit=arguments.expected_commit,
        manifest_sha256=arguments.expected_manifest_sha256,
        package_sha256=arguments.expected_package_sha256,
    )


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-system-python-sha256", required=True)
    parser.add_argument("--expected-ld-so-preload-sha256", required=True)
    parser.add_argument("--expected-ldconfig-sha256", required=True)
    parser.add_argument("--expected-odoo-config-sha256", required=True)
    parser.add_argument("--expected-database-name", required=True)
    parser.add_argument("--expected-database-uuid", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and verify the immutable Dev29 Odoo dependency closure"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="build two identical immutable images")
    _add_identity_arguments(build_parser)
    for name in ("mount", "verify", "verify-active"):
        child = commands.add_parser(name, help=f"{name} the exact immutable image")
        _add_identity_arguments(child)
        child.add_argument("--expected-closure-anchor-sha256", required=True)
        child.add_argument("--expected-closure-image-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        expected_system_python_sha256 = _expected_system_python_from_argv(
            raw_arguments
        )
        expected_loader_preload_sha256 = _expected_digest_from_argv(
            raw_arguments,
            option="--expected-ld-so-preload-sha256",
            label="ld.so.preload",
        )
        _validate_cli_interpreter(
            expected_system_python_sha256,
            expected_loader_preload_sha256,
        )
        expected_ldconfig_sha256 = _expected_digest_from_argv(
            raw_arguments,
            option="--expected-ldconfig-sha256",
            label="ldconfig.real",
        )
        arguments = _parser().parse_args(raw_arguments)
        expected = _identity_from_arguments(arguments)
        common = {
            "expected_system_python_sha256": expected_system_python_sha256,
            "expected_loader_preload_sha256": expected_loader_preload_sha256,
            "expected_ldconfig_sha256": expected_ldconfig_sha256,
            "expected_odoo_config_sha256": arguments.expected_odoo_config_sha256,
            "expected_database_name": arguments.expected_database_name,
            "expected_database_uuid": arguments.expected_database_uuid,
            "root": Path("/"),
            "script_path": Path(__file__).absolute(),
        }
        if arguments.command == "build":
            result = build(expected, **common)
        else:
            closure = {
                "expected_closure_anchor_sha256": arguments.expected_closure_anchor_sha256,
                "expected_closure_image_sha256": arguments.expected_closure_image_sha256,
            }
            if arguments.command == "mount":
                result = mount(expected, **common, **closure)
            elif arguments.command == "verify":
                result = verify(expected, **common, **closure)
            elif arguments.command == "verify-active":
                result = verify_active(expected, **common, **closure)
            else:  # pragma: no cover - argparse owns the closed command set.
                raise ClosureError("unsupported closure command")
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except ClosureError as exc:
        print(f"Odoo dependency closure rejected: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("Odoo dependency closure failed closed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
