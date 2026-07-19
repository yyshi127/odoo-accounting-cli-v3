#!/usr/bin/env python3
"""Fail-closed, side-load-only installer for immutable V3 release archives."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable

try:  # Import remains possible for platform-neutral contract tests.
    import pwd
except ImportError:  # pragma: no cover - Linux main() rejects this platform.
    pwd = None  # type: ignore[assignment]


PRODUCTION_INSTALL_ROOT = Path("/opt/odoo-accounting-cli-v3")
EXECUTABLE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
REQUIRED_MEMBERS = EXECUTABLE_MEMBERS | frozenset(
    {
        "VERSION",
        "deployment/install-release.py",
        "tools/verify_release.py",
        "src/odoo_accounting_cli_v3/release.py",
    }
)
VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
RENAME_NOREPLACE = 1
AT_FDCWD = -100
MAX_CHILD_OUTPUT_BYTES = 64 * 1024
CHILD_TIMEOUT_SECONDS = 60
CHILD_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_RELEASE_TREE_ENTRIES = 20_000
TAR_BLOCK_BYTES = 512
MAX_RAW_ARCHIVE_HEADERS = 2 * MAX_ARCHIVE_MEMBERS + 1
MAX_TAR_EXTENSION_BYTES = 64 * 1024
MAX_TAR_EXTENSION_TOTAL_BYTES = 16 * 1024 * 1024
MAX_CONSECUTIVE_TAR_EXTENSIONS = 2
MAX_TAR_TRAILING_ZERO_BYTES = 1024 * 1024
PUBLICATION_METADATA_BLOCKS_PER_OBJECT = 4
MIN_FREE_BYTES_AFTER_INSTALL = 2 * 1024 * 1024 * 1024
BROKER_HELP_STDOUT = (
    b"usage: odoo-accounting-cli-v3-broker --config ABSOLUTE_PATH\n"
)
EFFECT_FINALIZER_HELP_STDOUT = (
    b"usage: odoo-accounting-cli-v3-effect-finalizer --config ABSOLUTE_PATH\n"
)


class InstallError(RuntimeError):
    """The archive or target failed a side-load safety gate."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise InstallError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise InstallError(f"non-finite JSON value is forbidden: {value}")


def _load_json(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise InstallError(f"{label} must be a JSON object")
    return value


def _sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _sha256_path(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256_stream(stream)[0]


@dataclass(frozen=True)
class ExpectedIdentity:
    version: str
    commit: str
    release: str
    package_sha256: str
    manifest_sha256: str

    def validate(self) -> None:
        if VERSION_PATTERN.fullmatch(self.version) is None:
            raise InstallError("expected version is invalid")
        if COMMIT_PATTERN.fullmatch(self.commit) is None:
            raise InstallError("expected commit must be a full lowercase Git SHA-1")
        if SHA256_PATTERN.fullmatch(self.package_sha256) is None:
            raise InstallError("expected package SHA-256 is invalid")
        if SHA256_PATTERN.fullmatch(self.manifest_sha256) is None:
            raise InstallError("expected manifest SHA-256 is invalid")
        canonical_release = f"{self.version}-{self.commit[:12]}"
        if self.release != canonical_release:
            raise InstallError(
                "expected release must equal <version>-<full-commit-prefix12>"
            )

    @property
    def package_name(self) -> str:
        return f"odoo-accounting-cli-v3-{self.release}.tar.gz"

    @property
    def anchor(self) -> dict[str, str]:
        return {
            "commit": self.commit,
            "manifest_sha256": self.manifest_sha256,
            "package_sha256": self.package_sha256,
            "release": self.release,
        }


@dataclass(frozen=True)
class InstallLayout:
    root: Path
    owner_uid: int
    owner_gid: int
    test_mode: bool

    @property
    def packages(self) -> Path:
        return self.root / "packages"

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def anchors(self) -> Path:
        return self.root / "trusted-artifacts"

    @property
    def lock(self) -> Path:
        return self.root / ".install-release.lock"


@dataclass(frozen=True)
class ArchivePlan:
    manifest: dict[str, object]
    members: tuple[tarfile.TarInfo, ...]


class OwnedStaging:
    """Tracks only random, invocation-owned staging paths for safe cleanup."""

    def __init__(self) -> None:
        self._entries: list[tuple[Path, tuple[int, int], bool]] = []

    def add(self, path: Path, *, directory: bool) -> None:
        metadata = path.lstat()
        self.add_identity(
            path,
            identity=(metadata.st_dev, metadata.st_ino),
            directory=directory,
        )

    def add_identity(
        self,
        path: Path,
        *,
        identity: tuple[int, int],
        directory: bool,
    ) -> None:
        self._entries.append(
            (path, identity, directory)
        )

    def published(self, path: Path) -> None:
        self._entries = [item for item in self._entries if item[0] != path]

    def cleanup(self) -> None:
        for path, identity, is_directory in reversed(self._entries):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if path.name in {"", ".", ".."} or not path.name.startswith(".install-"):
                continue
            if (metadata.st_dev, metadata.st_ino) != identity or path.is_symlink():
                continue
            try:
                if is_directory and stat.S_ISDIR(metadata.st_mode):
                    for candidate in [path, *path.rglob("*")]:
                        current = candidate.lstat()
                        if candidate.is_symlink() or not (
                            stat.S_ISDIR(current.st_mode)
                            or stat.S_ISREG(current.st_mode)
                        ):
                            raise InstallError("unsafe object appeared in owned staging")
                    for directory in [path, *path.rglob("*")]:
                        if directory.is_dir() and not directory.is_symlink():
                            directory.chmod(0o700)
                    shutil.rmtree(path)
                elif not is_directory and stat.S_ISREG(metadata.st_mode):
                    path.unlink()
            except OSError:
                # Preserve evidence when identity-safe cleanup cannot be completed.
                pass
        self._entries.clear()


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


@contextmanager
def _defer_termination_signals() -> Iterable[None]:
    """Close the catchable signal window between creation and inode tracking."""

    deferred = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, deferred)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _assert_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    exact_mode: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError(f"required directory is missing: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_mode & 0o022
        or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)
    ):
        raise InstallError(f"directory is not trusted: {path}")


def _create_managed_directory(path: Path, *, uid: int, gid: int) -> None:
    previous_umask = os.umask(0)
    try:
        try:
            os.mkdir(path, 0o755)
        finally:
            os.umask(previous_umask)
    except FileExistsError:
        _assert_directory(path, uid=uid, gid=gid, exact_mode=0o755)
        return
    os.chown(path, uid, gid)
    os.chmod(path, 0o755)
    _assert_directory(path, uid=uid, gid=gid, exact_mode=0o755)
    _fsync_directory(path.parent)


def _layout(*, test_mode: bool, root_prefix: Path | None) -> InstallLayout:
    if sys.platform != "linux":
        raise InstallError("the side-load installer is Linux-only")
    if test_mode:
        if root_prefix is None or not root_prefix.is_absolute():
            raise InstallError("test mode requires an absolute --root-prefix")
        try:
            resolved_prefix = root_prefix.resolve(strict=True)
        except OSError as exc:
            raise InstallError("test mode root prefix must already exist") from exc
        if root_prefix != resolved_prefix:
            raise InstallError("test mode root prefix must be a canonical physical path")
        if resolved_prefix == Path("/") or os.path.samefile(resolved_prefix, Path("/")):
            raise InstallError("test mode root prefix may not be /")
        if os.geteuid() == 0 or os.getegid() == 0:
            raise InstallError("test mode must run as a non-root identity")
        try:
            prefix_metadata = resolved_prefix.lstat()
        except FileNotFoundError as exc:
            raise InstallError("test mode root prefix must already exist") from exc
        if (
            resolved_prefix.is_symlink()
            or not stat.S_ISDIR(prefix_metadata.st_mode)
            or prefix_metadata.st_uid != os.geteuid()
            or prefix_metadata.st_gid != os.getegid()
            or prefix_metadata.st_mode & 0o022
        ):
            raise InstallError("test mode root prefix is not a private owned directory")
        root = resolved_prefix / PRODUCTION_INSTALL_ROOT.relative_to("/")
        if root == PRODUCTION_INSTALL_ROOT:
            raise InstallError("test mode may not resolve to the production install root")
        return InstallLayout(root, os.geteuid(), os.getegid(), True)
    if root_prefix is not None:
        raise InstallError("--root-prefix is forbidden outside explicit test mode")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise InstallError("production installation must run as root:root")
    _assert_directory(Path("/opt"), uid=0, gid=0)
    return InstallLayout(PRODUCTION_INSTALL_ROOT, 0, 0, False)


def _prepare_layout(layout: InstallLayout) -> None:
    if layout.test_mode:
        prefix = layout.root.parents[1]
        opt = prefix / "opt"
        _create_managed_directory(
            opt, uid=layout.owner_uid, gid=layout.owner_gid
        )
        if os.path.samefile(opt, Path("/opt")):
            raise InstallError("test mode opt directory aliases production /opt")
        if _lexists(layout.root) and _lexists(PRODUCTION_INSTALL_ROOT) and os.path.samefile(
            layout.root, PRODUCTION_INSTALL_ROOT
        ):
            raise InstallError("test mode install root aliases the production install root")
    _create_managed_directory(
        layout.root, uid=layout.owner_uid, gid=layout.owner_gid
    )
    for path in (layout.packages, layout.releases, layout.anchors):
        _create_managed_directory(path, uid=layout.owner_uid, gid=layout.owner_gid)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_free_space(path: Path, additional_bytes: int, *, label: str) -> None:
    if additional_bytes < 0:
        raise InstallError(f"{label} size is invalid")
    free = shutil.disk_usage(path).free
    if free - additional_bytes < MIN_FREE_BYTES_AFTER_INSTALL:
        raise InstallError(
            f"{label} would breach the reserved filesystem free-space floor"
        )


def _release_allocation_budget(plan: ArchivePlan, target: Path) -> int:
    """Conservatively budget data blocks, directories, and directory entries."""

    filesystem = os.statvfs(target)
    block_size = filesystem.f_frsize or filesystem.f_bsize
    if block_size <= 0:
        raise InstallError("target filesystem reported an invalid block size")

    def allocated(size: int) -> int:
        return 0 if size == 0 else ((size + block_size - 1) // block_size) * block_size

    names = [_portable_member_name(member) for member in plan.members]
    directories = {
        parent.as_posix()
        for name in names
        for parent in PurePosixPath(name).parents
        if parent.as_posix() != "."
    }
    file_blocks = sum(
        allocated(member.size) for member in plan.members if member.isreg()
    )
    directory_blocks = block_size * (len(directories) + 1)
    entry_blocks = sum(
        allocated(len(name.encode("utf-8")) + 512) for name in names
    )
    return file_blocks + directory_blocks + entry_blocks


def _require_completed_staging_free_space(
    publication_objects: tuple[tuple[str, Path], ...],
) -> None:
    """Budget pending publication metadata once per actual filesystem."""

    filesystems: dict[int, tuple[list[str], Path, int]] = {}
    for label, path in publication_objects:
        device = path.stat().st_dev
        filesystem = os.statvfs(path)
        block_size = filesystem.f_frsize or filesystem.f_bsize
        if block_size <= 0:
            raise InstallError("publication filesystem reported an invalid block size")
        object_budget = block_size * PUBLICATION_METADATA_BLOCKS_PER_OBJECT
        if device in filesystems:
            labels, representative, budget = filesystems[device]
            labels.append(label)
            filesystems[device] = (labels, representative, budget + object_budget)
        else:
            filesystems[device] = ([label], path, object_budget)
    for labels, path, budget in filesystems.values():
        _require_free_space(
            path,
            budget,
            label=f"completed staging publication ({', '.join(labels)})",
        )


def _open_lock(layout: InstallLayout) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    created = False
    try:
        descriptor = os.open(layout.lock, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(layout.lock, flags, 0o600)
    try:
        if created:
            os.fchown(descriptor, layout.owner_uid, layout.owner_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync_directory(layout.root)
        opened = os.fstat(descriptor)
        current = layout.lock.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != layout.owner_uid
            or opened.st_gid != layout.owner_gid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or layout.lock.is_symlink()
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise InstallError("install lock is not a trusted single-link file")
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _close_lock(descriptor: int) -> None:
    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _validate_source_archive(path: Path, layout: InstallLayout) -> tuple[int, os.stat_result]:
    if not path.is_absolute():
        raise InstallError("archive path must be absolute")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise InstallError("archive could not be opened safely") from exc
    metadata = os.fstat(descriptor)
    try:
        current = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != layout.owner_uid
            or metadata.st_gid != layout.owner_gid
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > MAX_PACKAGE_BYTES
            or (metadata.st_dev, metadata.st_ino)
            != (current.st_dev, current.st_ino)
        ):
            raise InstallError("archive source is not a trusted single-link file")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _copy_archive_to_staging(
    source_fd: int,
    source_before: os.stat_result,
    destination: Path,
    layout: InstallLayout,
    expected_sha256: str,
    staging: OwnedStaging,
) -> tuple[int, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    with _defer_termination_signals():
        destination_fd = os.open(destination, flags, 0o400)
        identity = os.fstat(destination_fd)
        staging.add_identity(
            destination,
            identity=(identity.st_dev, identity.st_ino),
            directory=False,
        )
    digest = hashlib.sha256()
    total = 0
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise InstallError("short write while staging archive")
                view = view[written:]
        source_after = os.fstat(source_fd)
        if (
            (source_before.st_dev, source_before.st_ino, source_before.st_size)
            != (source_after.st_dev, source_after.st_ino, source_after.st_size)
            or source_before.st_mtime_ns != source_after.st_mtime_ns
        ):
            raise InstallError("archive source changed during stable copy")
        if total != source_before.st_size or digest.hexdigest() != expected_sha256:
            raise InstallError("archive does not match externally expected SHA-256")
        os.fchown(destination_fd, layout.owner_uid, layout.owner_gid)
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
    except BaseException:
        os.close(destination_fd)
        try:
            current = destination.lstat()
            if (
                not destination.is_symlink()
                and stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino)
                == (identity.st_dev, identity.st_ino)
            ):
                destination.unlink()
                _fsync_directory(destination.parent)
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(destination_fd)
    _fsync_directory(destination.parent)
    staged = destination.lstat()
    if (
        destination.is_symlink()
        or not stat.S_ISREG(staged.st_mode)
        or staged.st_uid != layout.owner_uid
        or staged.st_gid != layout.owner_gid
        or stat.S_IMODE(staged.st_mode) != 0o444
        or staged.st_nlink != 1
        or staged.st_size != total
        or staged.st_dev != destination.parent.stat().st_dev
        or (staged.st_dev, staged.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise InstallError("staged archive metadata mismatch")
    return staged.st_dev, staged.st_ino


def _hash_source_archive(
    descriptor: int, before: os.stat_result, expected_sha256: str
) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
        digest, size = _sha256_stream(stream)
    after = os.fstat(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or size != before.st_size
        or digest != expected_sha256
    ):
        raise InstallError("archive does not match externally expected SHA-256")


def _portable_member_name(member: tarfile.TarInfo) -> str:
    raw = member.name
    if member.isdir() and raw.endswith("/"):
        raw = raw[:-1]
    portable = PurePosixPath(raw)
    if (
        not raw
        or "\\" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
        or portable.is_absolute()
        or not portable.parts
        or any(part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in portable.parts)
        or portable.as_posix() != raw
        or len(raw.encode("utf-8")) > 4095
    ):
        raise InstallError(f"unsafe archive path: {member.name!r}")
    return raw


def _validate_manifest(
    manifest: dict[str, object], expected: ExpectedIdentity
) -> dict[str, dict[str, object]]:
    if set(manifest) != {
        "commit",
        "files",
        "manifest_sha256",
        "schema_version",
        "version",
    }:
        raise InstallError("release manifest fields are invalid")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise InstallError("release manifest schema is unsupported")
    if (
        manifest["version"] != expected.version
        or manifest["commit"] != expected.commit
        or manifest["manifest_sha256"] != expected.manifest_sha256
    ):
        raise InstallError("embedded manifest identity does not match external identity")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    calculated = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if calculated != expected.manifest_sha256:
        raise InstallError("embedded release manifest digest mismatch")
    files = manifest["files"]
    if (
        not isinstance(files, list)
        or not files
        or len(files) > MAX_ARCHIVE_MEMBERS
    ):
        raise InstallError("release manifest files must be a non-empty array")
    indexed: dict[str, dict[str, object]] = {}
    total_size = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise InstallError("release manifest file entry is invalid")
        path = item["path"]
        if not isinstance(path, str):
            raise InstallError("release manifest file path is invalid")
        probe = tarfile.TarInfo(path)
        portable = _portable_member_name(probe)
        if portable == "RELEASE-MANIFEST.json" or portable in indexed:
            raise InstallError("release manifest contains a duplicate/reserved path")
        if (
            not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] < 0
            or item["size"] > MAX_RELEASE_FILE_BYTES
            or not isinstance(item["sha256"], str)
            or SHA256_PATTERN.fullmatch(item["sha256"]) is None
        ):
            raise InstallError("release manifest file metadata is invalid")
        total_size += item["size"]
        if total_size > MAX_RELEASE_BYTES:
            raise InstallError("release manifest exceeds the total size limit")
        indexed[portable] = item
    missing = REQUIRED_MEMBERS - indexed.keys()
    if missing:
        raise InstallError(f"required release members are missing: {sorted(missing)}")
    return indexed


def _read_exact(stream: BinaryIO, size: int, *, label: str) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        chunk = stream.read(size - len(payload))
        if not chunk:
            raise InstallError(f"truncated {label}")
        payload.extend(chunk)
    return bytes(payload)


def _discard_exact(stream: BinaryIO, size: int, *, label: str) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise InstallError(f"truncated {label}")
        remaining -= len(chunk)


class _SingleGzipReader:
    """Bound decompression and reject bytes after the first gzip member."""

    def __init__(self, path: Path) -> None:
        self._raw = path.open("rb")
        self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._compressed = b""
        self._finished = False

    def __enter__(self) -> _SingleGzipReader:
        return self

    def __exit__(self, *_args: object) -> None:
        self._raw.close()

    def read(self, size: int) -> bytes:
        if size < 0:
            raise InstallError("unbounded gzip reads are forbidden")
        output = bytearray()
        while len(output) < size and not self._finished:
            if self._compressed:
                compressed = self._compressed
                self._compressed = b""
            else:
                compressed = self._raw.read(64 * 1024)
                if not compressed:
                    raise InstallError("truncated gzip member")
            try:
                decoded = self._decoder.decompress(
                    compressed,
                    size - len(output),
                )
            except zlib.error as exc:
                raise InstallError("archive has an invalid gzip member") from exc
            self._compressed = self._decoder.unconsumed_tail
            output.extend(decoded)
            if self._decoder.eof:
                if self._decoder.unused_data or self._compressed or self._raw.read(1):
                    raise InstallError("concatenated or trailing gzip data is forbidden")
                self._finished = True
        return bytes(output)


def _parse_tar_octal(field: bytes, *, label: str) -> int:
    if field and field[0] & 0x80:
        raise InstallError(f"base-256 {label} is forbidden in a release archive")
    raw = field.rstrip(b"\0 ").lstrip(b" ")
    if not raw:
        return 0
    if any(character < ord("0") or character > ord("7") for character in raw):
        raise InstallError(f"invalid tar {label}")
    return int(raw, 8)


def _validate_raw_tar_header(header: bytes) -> int:
    if len(header) != TAR_BLOCK_BYTES:
        raise InstallError("truncated tar header")
    expected_checksum = _parse_tar_octal(header[148:156], label="checksum")
    actual_checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if expected_checksum != actual_checksum:
        raise InstallError("invalid tar header checksum")
    return _parse_tar_octal(header[124:136], label="size")


def _decode_raw_tar_path(header: bytes) -> str:
    name = header[:100].split(b"\0", 1)[0]
    prefix = header[345:500].split(b"\0", 1)[0]
    raw = prefix + (b"/" if prefix and name else b"") + name
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("tar header path is not UTF-8") from exc


def _parse_pax_payload(payload: bytes) -> dict[str, object]:
    values: dict[str, object] = {}
    seen: set[str] = set()
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        if space < 0:
            raise InstallError("invalid PAX extension framing")
        raw_length = payload[offset:space]
        if not raw_length or len(raw_length) > 20 or any(
            character < ord("0") or character > ord("9")
            for character in raw_length
        ):
            raise InstallError("invalid PAX extension length")
        record_length = int(raw_length, 10)
        end = offset + record_length
        if record_length < 5 or end > len(payload) or payload[end - 1] != 0x0A:
            raise InstallError("invalid PAX extension framing")
        record = payload[space + 1 : end - 1]
        key, separator, value = record.partition(b"=")
        if not key or not separator:
            raise InstallError("invalid PAX extension field")
        try:
            decoded_key = key.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InstallError("PAX extension key is not UTF-8") from exc
        if decoded_key in seen:
            raise InstallError("duplicate PAX extension field")
        seen.add(decoded_key)
        if decoded_key.startswith("GNU.sparse."):
            raise InstallError("sparse PAX extensions are forbidden")
        if decoded_key == "hdrcharset" and value == b"BINARY":
            raise InstallError("binary PAX path encoding is forbidden")
        if decoded_key == "size":
            if (
                not value
                or len(value) > len(str(MAX_RELEASE_FILE_BYTES))
                or any(
                    character < ord("0") or character > ord("9")
                    for character in value
                )
            ):
                raise InstallError("invalid PAX size override")
            parsed_size = int(value, 10)
            if parsed_size > MAX_RELEASE_FILE_BYTES:
                raise InstallError("PAX size override exceeds the file limit")
            values[decoded_key] = parsed_size
        elif decoded_key == "path":
            try:
                values[decoded_key] = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InstallError("PAX path is not UTF-8") from exc
        offset = end
    return values


def _read_tar_extension(
    stream: BinaryIO,
    size: int,
    *,
    total_extension_bytes: int,
) -> tuple[bytes, int]:
    if size > MAX_TAR_EXTENSION_BYTES:
        raise InstallError("tar extension payload exceeds the per-header limit")
    total_extension_bytes += size
    if total_extension_bytes > MAX_TAR_EXTENSION_TOTAL_BYTES:
        raise InstallError("tar extension payloads exceed the total limit")
    payload = _read_exact(stream, size, label="tar extension payload")
    padding = (-size) % TAR_BLOCK_BYTES
    padding_payload = _read_exact(stream, padding, label="tar extension padding")
    if any(padding_payload):
        raise InstallError("tar extension padding must be zero")
    return payload, total_extension_bytes


def _preflight_archive(path: Path) -> None:
    """Bound raw gzip/tar structure before tarfile can materialize extensions."""

    raw_headers = 0
    extension_bytes = 0
    regular_bytes = 0
    manifest_bytes = 0
    pending_path: str | None = None
    pending_size: int | None = None
    consecutive_extensions = 0
    try:
        with _SingleGzipReader(path) as stream:
            while True:
                header = _read_exact(stream, TAR_BLOCK_BYTES, label="tar header")
                if header == bytes(TAR_BLOCK_BYTES):
                    second = _read_exact(
                        stream,
                        TAR_BLOCK_BYTES,
                        label="tar zero terminator",
                    )
                    if second != bytes(TAR_BLOCK_BYTES):
                        raise InstallError("tar archive has a single zero terminator")
                    if consecutive_extensions:
                        raise InstallError("tar archive ends with a dangling extension")
                    trailing = 0
                    while True:
                        chunk = stream.read(64 * 1024)
                        if not chunk:
                            return
                        trailing += len(chunk)
                        if (
                            trailing > MAX_TAR_TRAILING_ZERO_BYTES
                            or any(chunk)
                        ):
                            raise InstallError("tar archive has unsafe trailing data")

                raw_headers += 1
                if raw_headers > MAX_RAW_ARCHIVE_HEADERS:
                    raise InstallError("raw tar header count exceeds the safe limit")
                raw_size = _validate_raw_tar_header(header)
                member_type = header[156:157]

                if member_type in {b"x", b"g", b"L", b"K"}:
                    consecutive_extensions += 1
                    if consecutive_extensions > MAX_CONSECUTIVE_TAR_EXTENSIONS:
                        raise InstallError(
                            "consecutive tar extension chain exceeds the safe limit"
                        )
                    payload, extension_bytes = _read_tar_extension(
                        stream,
                        raw_size,
                        total_extension_bytes=extension_bytes,
                    )
                    if member_type in {b"x", b"L"} and (
                        pending_path is not None or pending_size is not None
                    ):
                        raise InstallError("stacked local tar extensions are forbidden")
                    if member_type in {b"x", b"g"}:
                        pax = _parse_pax_payload(payload)
                        if member_type == b"g" and (
                            "path" in pax or "size" in pax
                        ):
                            raise InstallError(
                                "global PAX path and size overrides are forbidden"
                            )
                        if member_type == b"x":
                            path_override = pax.get("path")
                            size_override = pax.get("size")
                            pending_path = (
                                path_override
                                if isinstance(path_override, str)
                                else None
                            )
                            pending_size = (
                                size_override
                                if isinstance(size_override, int)
                                else None
                            )
                    elif member_type == b"L":
                        raw_path, separator, remainder = payload.partition(b"\0")
                        if separator and any(remainder):
                            raise InstallError("GNU longname has non-zero trailing data")
                        try:
                            pending_path = raw_path.decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise InstallError("GNU longname is not UTF-8") from exc
                    continue

                if member_type not in {b"\0", b"0", b"5"}:
                    raise InstallError("unsafe raw archive member type")
                path_name = pending_path or _decode_raw_tar_path(header)
                effective_size = pending_size if pending_size is not None else raw_size
                if raw_size > MAX_RELEASE_FILE_BYTES:
                    raise InstallError("raw archive file size exceeds the file limit")
                if member_type == b"5":
                    if effective_size != 0:
                        raise InstallError("raw archive directory has data")
                elif path_name == "RELEASE-MANIFEST.json":
                    manifest_bytes += effective_size
                    if manifest_bytes > MAX_MANIFEST_BYTES:
                        raise InstallError("raw release manifest exceeds the size limit")
                else:
                    regular_bytes += effective_size
                    if regular_bytes > MAX_RELEASE_BYTES:
                        raise InstallError("raw regular content exceeds the total limit")
                if regular_bytes + manifest_bytes > MAX_RELEASE_BYTES + MAX_MANIFEST_BYTES:
                    raise InstallError("raw archive content exceeds the total limit")
                pending_path = None
                pending_size = None
                consecutive_extensions = 0
                _discard_exact(stream, effective_size, label="tar member payload")
                _discard_exact(
                    stream,
                    (-effective_size) % TAR_BLOCK_BYTES,
                    label="tar member padding",
                )
    except InstallError:
        raise
    except (OSError, EOFError) as exc:
        raise InstallError("archive is not a valid gzip tar package") from exc


def inspect_archive(path: Path, expected: ExpectedIdentity) -> ArchivePlan:
    _preflight_archive(path)
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members: list[tarfile.TarInfo] = []
            names: dict[str, tarfile.TarInfo] = {}
            files: dict[str, tarfile.TarInfo] = {}
            directories: set[str] = set()
            declared_file_bytes = 0
            while True:
                member = archive.next()
                if member is None:
                    break
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise InstallError("archive member count is outside the safe limit")
                name = _portable_member_name(member)
                if name in names:
                    raise InstallError(f"duplicate archive member: {name}")
                if member.sparse is not None:
                    raise InstallError(f"sparse archive member is forbidden: {name}")
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                ):
                    raise InstallError(f"archive member owner is not root:root: {name}")
                if member.isdir():
                    if member.size != 0:
                        raise InstallError(f"archive directory has data: {name}")
                    if stat.S_IMODE(member.mode) != 0o755:
                        raise InstallError(f"archive directory mode mismatch: {name}")
                    directories.add(name)
                elif member.isreg():
                    size_limit = (
                        MAX_MANIFEST_BYTES
                        if name == "RELEASE-MANIFEST.json"
                        else MAX_RELEASE_FILE_BYTES
                    )
                    if member.size < 0 or member.size > size_limit:
                        raise InstallError(f"archive file size limit exceeded: {name}")
                    declared_file_bytes += member.size
                    if declared_file_bytes > MAX_RELEASE_BYTES + MAX_MANIFEST_BYTES:
                        raise InstallError("archive declared content exceeds the total size limit")
                    expected_mode = 0o755 if name in EXECUTABLE_MEMBERS else 0o644
                    if stat.S_IMODE(member.mode) != expected_mode:
                        raise InstallError(f"archive file mode mismatch: {name}")
                    files[name] = member
                else:
                    raise InstallError(f"unsafe archive member type: {name}")
                names[name] = member
                members.append(member)
            if not members:
                raise InstallError("archive member count is outside the safe limit")
            manifest_member = files.get("RELEASE-MANIFEST.json")
            if manifest_member is None:
                raise InstallError("release manifest is missing or unreasonably large")
            manifest_stream = archive.extractfile(manifest_member)
            if manifest_stream is None:
                raise InstallError("release manifest could not be read")
            manifest = _load_json(manifest_stream.read(), label="release manifest")
            indexed = _validate_manifest(manifest, expected)
            if set(files) != set(indexed) | {"RELEASE-MANIFEST.json"}:
                raise InstallError("archive regular-file set does not match manifest")
            implied_directories = {
                PurePosixPath(name).parents[index].as_posix()
                for name in files
                for index in range(len(PurePosixPath(name).parents) - 1)
            }
            implied_directories.discard(".")
            if len(files) + len(implied_directories) > MAX_RELEASE_TREE_ENTRIES:
                raise InstallError("archive expands to too many filesystem entries")
            if not directories.issubset(implied_directories):
                raise InstallError("archive contains an unmanifested empty directory")
            file_names = set(files)
            for name in file_names:
                parents = set(PurePosixPath(name).parents)
                if any(parent.as_posix() in file_names for parent in parents):
                    raise InstallError("archive file is an ancestor of another member")
                if name != "RELEASE-MANIFEST.json":
                    item = indexed[name]
                    if files[name].size != item["size"]:
                        raise InstallError(f"archive/manifest size mismatch: {name}")
            return ArchivePlan(manifest=manifest, members=tuple(members))
    except (
        tarfile.TarError,
        OSError,
        EOFError,
        RecursionError,
        MemoryError,
        OverflowError,
    ) as exc:
        raise InstallError("archive is not a valid gzip tar package") from exc


def _manifest_file(plan: ArchivePlan, member: str) -> dict[str, object]:
    matches = [
        item
        for item in plan.manifest["files"]  # type: ignore[union-attr]
        if isinstance(item, dict) and item.get("path") == member
    ]
    if len(matches) != 1:
        raise InstallError(f"release manifest has no unique {member} entry")
    return matches[0]


def _validate_running_installer(plan: ArchivePlan, layout: InstallLayout) -> None:
    raw_path = Path(os.path.abspath(__file__))
    try:
        resolved_path = raw_path.resolve(strict=True)
        metadata = raw_path.lstat()
    except OSError as exc:
        raise InstallError("running installer could not be inspected") from exc
    if (
        raw_path != resolved_path
        or raw_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != layout.owner_uid
        or metadata.st_gid != layout.owner_gid
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise InstallError("running installer is not a trusted single-link file")
    for ancestor in raw_path.parents:
        ancestor_metadata = ancestor.lstat()
        test_shared_root = (
            layout.test_mode
            and ancestor_metadata.st_uid == 0
            and bool(ancestor_metadata.st_mode & stat.S_ISVTX)
        )
        permitted_owners = {0, layout.owner_uid} if layout.test_mode else {0}
        permitted_groups = {0, layout.owner_gid} if layout.test_mode else {0}
        if (
            ancestor.is_symlink()
            or not stat.S_ISDIR(ancestor_metadata.st_mode)
            or ancestor_metadata.st_uid not in permitted_owners
            or ancestor_metadata.st_gid not in permitted_groups
            or (ancestor_metadata.st_mode & 0o022 and not test_shared_root)
        ):
            raise InstallError("running installer ancestry is not trusted")
    item = _manifest_file(plan, "deployment/install-release.py")
    if (
        metadata.st_size != item["size"]
        or _sha256_path(raw_path) != item["sha256"]
    ):
        raise InstallError("running installer does not match the target release manifest")


def _mkdir_extraction_path(path: Path, *, uid: int, gid: int) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("archive path collides with a non-directory")
        return
    os.chown(path, uid, gid)
    os.chmod(path, 0o700)


def _extract_archive(
    archive_path: Path,
    plan: ArchivePlan,
    destination: Path,
    layout: InstallLayout,
) -> None:
    indexed = {item["path"]: item for item in plan.manifest["files"]}  # type: ignore[index]
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            by_name = {
                _portable_member_name(member): member for member in archive.getmembers()
            }
            for member in sorted(
                by_name.values(), key=lambda item: (len(PurePosixPath(_portable_member_name(item)).parts), _portable_member_name(item))
            ):
                name = _portable_member_name(member)
                parts = PurePosixPath(name).parts
                target = destination.joinpath(*parts)
                parent = destination
                for part in parts[:-1]:
                    parent /= part
                    _mkdir_extraction_path(
                        parent, uid=layout.owner_uid, gid=layout.owner_gid
                    )
                if member.isdir():
                    _mkdir_extraction_path(
                        target, uid=layout.owner_uid, gid=layout.owner_gid
                    )
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise InstallError(f"archive member could not be read: {name}")
                descriptor = os.open(
                    target,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                digest = hashlib.sha256()
                size = 0
                try:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        size += len(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise InstallError("short write while extracting release")
                            view = view[written:]
                    os.fchown(descriptor, layout.owner_uid, layout.owner_gid)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if name != "RELEASE-MANIFEST.json":
                    expected_item = indexed[name]
                    if size != expected_item["size"] or digest.hexdigest() != expected_item["sha256"]:
                        raise InstallError(f"extracted release file mismatch: {name}")
    except (
        tarfile.TarError,
        OSError,
        EOFError,
        RecursionError,
        MemoryError,
        OverflowError,
    ) as exc:
        if isinstance(exc, InstallError):
            raise
        raise InstallError("archive extraction failed") from exc


def _seal_release(root: Path, layout: InstallLayout) -> None:
    paths = [root, *root.rglob("*")]
    if any(path.is_symlink() for path in paths):
        raise InstallError("release staging contains a symlink")
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            os.chown(path, layout.owner_uid, layout.owner_gid)
            os.chmod(path, 0o555)
            _fsync_directory(path)
        elif stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(root).as_posix()
            os.chown(path, layout.owner_uid, layout.owner_gid)
            os.chmod(path, 0o555 if relative in EXECUTABLE_MEMBERS else 0o444)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        else:
            raise InstallError("release staging contains an unsafe object type")


def _tree_inventory(root: Path, layout: InstallLayout) -> dict[str, tuple[object, ...]]:
    inventory: dict[str, tuple[object, ...]] = {}
    for path in [root, *root.rglob("*")]:
        relative = "." if path == root else path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            raise InstallError(f"installed release symlink is forbidden: {relative}")
        if metadata.st_uid != layout.owner_uid or metadata.st_gid != layout.owner_gid:
            raise InstallError(f"installed release owner mismatch: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o555:
                raise InstallError(f"installed release directory mode mismatch: {relative}")
            inventory[relative] = ("directory", metadata.st_dev, metadata.st_ino, 0o555)
        elif stat.S_ISREG(metadata.st_mode):
            expected_mode = 0o555 if relative in EXECUTABLE_MEMBERS else 0o444
            if stat.S_IMODE(metadata.st_mode) != expected_mode or metadata.st_nlink != 1:
                raise InstallError(f"installed release file metadata mismatch: {relative}")
            inventory[relative] = (
                "file",
                metadata.st_dev,
                metadata.st_ino,
                expected_mode,
                metadata.st_size,
                _sha256_path(path),
            )
        else:
            raise InstallError(f"installed release object type is unsafe: {relative}")
    for member in EXECUTABLE_MEMBERS:
        if member not in inventory:
            raise InstallError(f"installed release executable is missing: {member}")
    return inventory


def _candidate_environment(root: Path) -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(root / "src"),
    }


def _candidate_preexec(layout: InstallLayout):
    identity: tuple[int, int] | None = None
    if not layout.test_mode:
        if pwd is None:  # pragma: no cover - guarded by Linux-only layout.
            raise InstallError("POSIX account lookup is unavailable")
        try:
            nobody = pwd.getpwnam("nobody")
        except KeyError as exc:
            raise InstallError("unprivileged verifier identity 'nobody' is missing") from exc
        if nobody.pw_uid == 0 or nobody.pw_gid == 0:
            raise InstallError("unprivileged verifier identity is unsafe")
        identity = (nobody.pw_uid, nobody.pw_gid)

    def prepare_candidate() -> None:
        import resource

        limits = (
            (resource.RLIMIT_AS, CHILD_ADDRESS_SPACE_BYTES),
            (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_CPU, 30),
            (resource.RLIMIT_FSIZE, MAX_CHILD_OUTPUT_BYTES),
            (resource.RLIMIT_NOFILE, 64),
        )
        for resource_id, requested in limits:
            _soft, hard = resource.getrlimit(resource_id)
            maximum = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
            resource.setrlimit(resource_id, (maximum, maximum))
        os.umask(0o077)
        if identity is not None:
            uid, gid = identity
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)

    return prepare_candidate


def _kill_candidate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise InstallError("candidate process group could not be reaped") from exc


def _run_candidate_command(
    command: list[str],
    *,
    root: Path,
    layout: InstallLayout,
    expected_stdout: bytes,
    label: str,
) -> None:
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd="/",
                env=_candidate_environment(root),
                close_fds=True,
                start_new_session=True,
                preexec_fn=_candidate_preexec(layout),
            )
            timed_out = False
            try:
                process.wait(timeout=CHILD_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                _kill_candidate_process_group(process)
            if timed_out:
                raise InstallError(f"{label} exceeded its execution deadline")
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
            stderr = stderr_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
    except InstallError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"{label} could not run safely") from exc
    if (
        process.returncode != 0
        or stdout != expected_stdout
        or stderr
        or len(stdout) > MAX_CHILD_OUTPUT_BYTES
        or len(stderr) > MAX_CHILD_OUTPUT_BYTES
    ):
        raise InstallError(f"{label} rejected the candidate")


def _verify_release_without_writes(
    root: Path, expected: ExpectedIdentity, layout: InstallLayout
) -> None:
    before = _tree_inventory(root, layout)
    version_path = root / "VERSION"
    try:
        version_lines = version_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise InstallError("installed VERSION could not be read") from exc
    if version_lines != [expected.version]:
        raise InstallError("installed VERSION does not match release identity")
    interpreter = Path(sys.executable) if layout.test_mode else Path("/usr/bin/python3")
    _run_candidate_command(
        [
            str(interpreter),
            "-B",
            str(root / "tools/verify_release.py"),
            str(root),
            expected.manifest_sha256,
        ],
        root=root,
        layout=layout,
        expected_stdout=f"verified {expected.version} {expected.commit}\n".encode(),
        label="extracted verify_release",
    )
    _run_candidate_command(
        [str(root / "bin/odoo-accounting-cli-v3-broker"), "--help"],
        root=root,
        layout=layout,
        expected_stdout=BROKER_HELP_STDOUT,
        label="frozen broker launcher",
    )
    _run_candidate_command(
        [
            str(root / "bin/odoo-accounting-cli-v3-effect-finalizer"),
            "--help",
        ],
        root=root,
        layout=layout,
        expected_stdout=EFFECT_FINALIZER_HELP_STDOUT,
        label="frozen effect-finalizer launcher",
    )
    after = _tree_inventory(root, layout)
    if after != before:
        raise InstallError("candidate verification changed the release tree")


def _validate_read_only_file(
    path: Path,
    layout: InstallLayout,
    *,
    expected_sha256: str | None = None,
) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError(f"installed file is missing: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != layout.owner_uid
        or metadata.st_gid != layout.owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise InstallError(f"installed file metadata mismatch: {path}")
    payload = path.read_bytes()
    if expected_sha256 is not None and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise InstallError(f"installed file digest mismatch: {path}")
    return payload


def _verify_complete_install(
    layout: InstallLayout, expected: ExpectedIdentity
) -> None:
    canonical_package = layout.packages / expected.package_name
    release_root = layout.releases / expected.release
    anchor_path = layout.anchors / f"{expected.release}.json"
    _validate_read_only_file(
        canonical_package, layout, expected_sha256=expected.package_sha256
    )
    anchor = _load_json(
        _validate_read_only_file(anchor_path, layout), label="external release anchor"
    )
    if anchor != expected.anchor:
        raise InstallError("external release anchor identity mismatch")
    _verify_release_without_writes(release_root, expected, layout)


def _existing_state(layout: InstallLayout, expected: ExpectedIdentity) -> str:
    paths = (
        layout.packages / expected.package_name,
        layout.releases / expected.release,
        layout.anchors / f"{expected.release}.json",
    )
    exists = tuple(_lexists(path) for path in paths)
    if not any(exists):
        return "absent"
    if not all(exists):
        raise InstallError("partial existing release is not eligible for idempotent install")
    _verify_complete_install(layout, expected)
    return "complete"


def _publish_file(staging: Path, destination: Path) -> None:
    before = staging.lstat()
    if staging.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise InstallError("file staging metadata is unsafe before publish")
    try:
        os.link(staging, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise InstallError(f"refusing to overwrite existing path: {destination}") from exc
    linked = destination.lstat()
    if (
        destination.is_symlink()
        or not stat.S_ISREG(linked.st_mode)
        or (linked.st_dev, linked.st_ino) != (before.st_dev, before.st_ino)
        or linked.st_nlink != 2
    ):
        raise InstallError("atomic file publication identity mismatch")
    _fsync_directory(destination.parent)
    staging.unlink()
    _fsync_directory(destination.parent)
    if destination.lstat().st_nlink != 1:
        raise InstallError("published file is not single-link")


def _rename_no_replace(source: Path, destination: Path) -> None:
    if source.parent != destination.parent:
        raise InstallError("release staging must share the final parent")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise InstallError("Linux renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == 17:
            raise InstallError(f"refusing to overwrite existing path: {destination}")
        raise InstallError(f"atomic release publication failed with errno {error}")
    _fsync_directory(destination.parent)


def _write_anchor_staging(
    path: Path,
    expected: ExpectedIdentity,
    layout: InstallLayout,
    staging: OwnedStaging,
) -> None:
    payload = (
        json.dumps(expected.anchor, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    with _defer_termination_signals():
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        identity = os.fstat(descriptor)
        staging.add_identity(
            path,
            identity=(identity.st_dev, identity.st_ino),
            directory=False,
        )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise InstallError("short write while staging external anchor")
            view = view[written:]
        os.fchown(descriptor, layout.owner_uid, layout.owner_gid)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            current = path.lstat()
            if (
                not path.is_symlink()
                and stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino)
                == (identity.st_dev, identity.st_ino)
            ):
                path.unlink()
                _fsync_directory(path.parent)
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    _fsync_directory(path.parent)
    if path.stat().st_dev != path.parent.stat().st_dev:
        raise InstallError("anchor staging is not on the final filesystem")


def install(
    archive: Path,
    expected: ExpectedIdentity,
    *,
    test_mode: bool = False,
    root_prefix: Path | None = None,
) -> dict[str, object]:
    expected.validate()
    if archive.name != expected.package_name:
        raise InstallError("archive filename does not match the expected release")
    layout = _layout(test_mode=test_mode, root_prefix=root_prefix)
    _prepare_layout(layout)
    lock_fd = _open_lock(layout)
    staging = OwnedStaging()
    source_fd: int | None = None
    try:
        state = _existing_state(layout, expected)
        source_fd, source_metadata = _validate_source_archive(archive, layout)
        if state == "complete":
            _hash_source_archive(source_fd, source_metadata, expected.package_sha256)
            installed_plan = inspect_archive(
                layout.packages / expected.package_name, expected
            )
            _validate_running_installer(installed_plan, layout)
            return {
                "already_installed": True,
                "commit": expected.commit,
                "manifest_sha256": expected.manifest_sha256,
                "package": str(layout.packages / expected.package_name),
                "package_sha256": expected.package_sha256,
                "release": expected.release,
                "version": expected.version,
            }
        transaction_id = uuid.uuid4().hex
        package_staging = layout.packages / (
            f".install-{expected.package_name}.{transaction_id}.staging"
        )
        release_staging = layout.releases / (
            f".install-{expected.release}.{transaction_id}.staging"
        )
        anchor_staging = layout.anchors / (
            f".install-{expected.release}.{transaction_id}.staging"
        )
        _require_free_space(
            layout.packages,
            source_metadata.st_size,
            label="package staging",
        )
        _copy_archive_to_staging(
            source_fd,
            source_metadata,
            package_staging,
            layout,
            expected.package_sha256,
            staging,
        )
        plan = inspect_archive(package_staging, expected)
        _validate_running_installer(plan, layout)
        release_size = _release_allocation_budget(plan, layout.releases)
        _require_free_space(
            layout.releases,
            release_size,
            label="release extraction",
        )
        with _defer_termination_signals():
            os.mkdir(release_staging, 0o700)
            release_identity = release_staging.lstat()
            staging.add_identity(
                release_staging,
                identity=(release_identity.st_dev, release_identity.st_ino),
                directory=True,
            )
        os.chown(release_staging, layout.owner_uid, layout.owner_gid)
        os.chmod(release_staging, 0o700)
        if release_staging.stat().st_dev != layout.releases.stat().st_dev:
            raise InstallError("release staging is not on the final filesystem")
        _extract_archive(package_staging, plan, release_staging, layout)
        _seal_release(release_staging, layout)
        _verify_release_without_writes(release_staging, expected, layout)
        if _sha256_path(package_staging) != expected.package_sha256:
            raise InstallError("staged package changed after archive verification")
        _write_anchor_staging(anchor_staging, expected, layout, staging)
        _require_completed_staging_free_space(
            (
                ("package hardlink", package_staging),
                ("release rename", release_staging),
                ("anchor hardlink", anchor_staging),
            )
        )

        canonical_package = layout.packages / expected.package_name
        release_root = layout.releases / expected.release
        anchor_path = layout.anchors / f"{expected.release}.json"
        _publish_file(package_staging, canonical_package)
        staging.published(package_staging)
        _rename_no_replace(release_staging, release_root)
        staging.published(release_staging)
        _publish_file(anchor_staging, anchor_path)
        staging.published(anchor_staging)
        _verify_complete_install(layout, expected)
        return {
            "already_installed": False,
            "commit": expected.commit,
            "manifest_sha256": expected.manifest_sha256,
            "package": str(canonical_package),
            "package_sha256": expected.package_sha256,
            "release": expected.release,
            "version": expected.version,
        }
    finally:
        try:
            if source_fd is not None:
                os.close(source_fd)
            staging.cleanup()
        finally:
            _close_lock(lock_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Side-load one immutable V3 archive; never route or start it."
    )
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--root-prefix", type=Path, help=argparse.SUPPRESS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    expected = ExpectedIdentity(
        version=arguments.expected_version,
        commit=arguments.expected_commit,
        release=arguments.expected_release,
        package_sha256=arguments.expected_package_sha256,
        manifest_sha256=arguments.expected_manifest_sha256,
    )
    previous_handlers: dict[int, object] = {}

    def interrupted(signum: int, _frame: object) -> None:
        raise InstallError(f"installation interrupted by signal {signum}")

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)
    try:
        result = install(
            arguments.archive,
            expected,
            test_mode=arguments.test_mode,
            root_prefix=arguments.root_prefix,
        )
    except (InstallError, OSError, ValueError) as exc:
        print(f"side-load failed: {exc}", file=sys.stderr)
        return 1
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
