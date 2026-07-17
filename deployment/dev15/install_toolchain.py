#!/usr/bin/env python3
"""Install the exact Dev15 read-evidence toolchain without changing routing."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


TOOLCHAIN_VERSION = "0.1.0.dev15-read-toolchain.2"
PRODUCTION_ROOT = Path("/opt/odoo-accounting-cli-v3")
TARGET_RELATIVE = Path("toolchains") / TOOLCHAIN_VERSION
APPLICATION = {
    "commit": "c4616386f921946cf43cde2de449d2938a837422",
    "manifest_sha256": (
        "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
    ),
    "package_sha256": (
        "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
    ),
    "registry_digest": (
        "ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b"
    ),
    "release": "0.1.0.dev15-c4616386f921",
    "version": "0.1.0.dev15",
}
MANIFEST_FILES = (
    "install_toolchain.py",
    "runtime_setup.py",
    "sign_read.py",
    "run_multicurrency_read.py",
    "multicurrency_sql_oracle.py",
    "verify_evidence.py",
    "read_plan.json",
)
CONTROL_FILES = (
    "README.md",
    "check_toolchain.py",
)
MANIFEST_NAME = "TOOLCHAIN-MANIFEST.json"
EXPECTED_FILES = frozenset({MANIFEST_NAME, *MANIFEST_FILES, *CONTROL_FILES})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
RENAME_NOREPLACE = 1
AT_FDCWD = -100


class ToolchainInstallError(RuntimeError):
    """The source or destination failed an immutable-install safety gate."""


@dataclass(frozen=True)
class _FileExpectation:
    name: str
    sha256: str
    size: int
    payload: bytes


@dataclass(frozen=True)
class _Layout:
    root: Path
    owner_uid: int
    owner_gid: int
    test_mode: bool

    @property
    def toolchains(self) -> Path:
        return self.root / "toolchains"

    @property
    def target(self) -> Path:
        return self.root / TARGET_RELATIVE


class _OwnedStage:
    """Remove only invocation-created objects whose inode is still ours."""

    def __init__(self, path: Path, identity: tuple[int, int]) -> None:
        self.path = path
        self.identity = identity
        self.files: list[tuple[Path, tuple[int, int]]] = []
        self.published = False

    def add_file(self, path: Path, identity: tuple[int, int]) -> None:
        self.files.append((path, identity))

    def cleanup(self) -> bool:
        if self.published:
            return False
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            return False
        if (
            self.path.name.startswith(".install-toolchain-")
            and not stat.S_ISLNK(current.st_mode)
            and stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == self.identity
        ):
            try:
                if os.name == "posix":
                    os.chmod(self.path, 0o700, follow_symlinks=False)
                else:
                    os.chmod(self.path, 0o700)
            except (NotImplementedError, OSError):
                return False
            for child, identity in reversed(self.files):
                try:
                    metadata = child.lstat()
                except FileNotFoundError:
                    continue
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == identity
                ):
                    try:
                        if os.name == "posix":
                            os.chmod(child, 0o600, follow_symlinks=False)
                        else:
                            os.chmod(child, 0o600)
                        changed = child.lstat()
                        if (changed.st_dev, changed.st_ino) != identity:
                            return False
                        child.unlink()
                    except OSError:
                        return False
                else:
                    return False
            try:
                after = self.path.lstat()
                if (after.st_dev, after.st_ino) == self.identity:
                    self.path.rmdir()
                    return True
            except OSError:
                return False
        return False


def _fail(condition: bool, message: str) -> None:
    if not condition:
        raise ToolchainInstallError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainInstallError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ToolchainInstallError(f"non-finite JSON value is forbidden: {value}")


def _load_json(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainInstallError(f"{label} is not strict UTF-8 JSON") from exc
    _fail(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _metadata_identity(metadata: os.stat_result) -> tuple[object, ...]:
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


def _canonical(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ToolchainInstallError(f"source directory cannot be resolved: {path}") from exc
    _fail(
        os.path.normcase(os.fspath(absolute)) == os.path.normcase(os.fspath(resolved)),
        "source directory must be a canonical path without symlinks",
    )
    return resolved


def _stable_read(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    source: bool,
) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ToolchainInstallError(f"missing toolchain file: {path.name}") from exc
    mode = stat.S_IMODE(before.st_mode)
    _fail(stat.S_ISREG(before.st_mode), f"toolchain file is not regular: {path.name}")
    _fail(before.st_nlink == 1, f"toolchain file must have one link: {path.name}")
    _fail(
        before.st_uid == owner_uid and before.st_gid == owner_gid,
        f"toolchain file owner mismatch: {path.name}",
    )
    if source:
        _fail(mode == 0o444, f"source toolchain file mode mismatch: {path.name}")
    else:
        _fail(mode == 0o444, f"installed toolchain file mode mismatch: {path.name}")
    _fail(before.st_size <= MAX_FILE_BYTES, f"toolchain file is too large: {path.name}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ToolchainInstallError(f"cannot safely open toolchain file: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        _fail(
            _metadata_identity(opened) == _metadata_identity(before),
            f"toolchain file changed while opening: {path.name}",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            _fail(total <= MAX_FILE_BYTES, f"toolchain file is too large: {path.name}")
        after = os.fstat(descriptor)
        _fail(
            _metadata_identity(after) == _metadata_identity(opened),
            f"toolchain file changed while reading: {path.name}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_source_directory(
    source: Path, *, owner_uid: int, owner_gid: int, test_mode: bool
) -> tuple[os.stat_result, dict[str, bytes]]:
    before = source.lstat()
    _fail(stat.S_ISDIR(before.st_mode), "source must be a directory")
    _fail(not stat.S_ISLNK(before.st_mode), "source directory cannot be a symlink")
    _fail(
        before.st_uid == owner_uid and before.st_gid == owner_gid,
        "source directory owner must be root:root",
    )
    _fail(
        (test_mode and os.name != "posix")
        or stat.S_IMODE(before.st_mode) == 0o700,
        "source directory mode must be 0700",
    )
    try:
        names = {entry.name for entry in os.scandir(source)}
    except OSError as exc:
        raise ToolchainInstallError("cannot enumerate source directory") from exc
    _fail(names == EXPECTED_FILES, "unexpected Dev15 toolchain file set")
    payloads = {
        name: _stable_read(
            source / name,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            source=True,
        )
        for name in sorted(EXPECTED_FILES)
    }
    after = source.lstat()
    _fail(
        _metadata_identity(after) == _metadata_identity(before),
        "source directory changed during verification",
    )
    _fail(
        {entry.name for entry in os.scandir(source)} == EXPECTED_FILES,
        "source directory changed during verification",
    )
    return before, payloads


def _parse_manifest(
    payloads: dict[str, bytes], *, expected_manifest_sha256: str
) -> tuple[_FileExpectation, ...]:
    _fail(
        isinstance(expected_manifest_sha256, str)
        and SHA256_PATTERN.fullmatch(expected_manifest_sha256) is not None,
        "expected toolchain manifest SHA-256 is invalid",
    )
    manifest_payload = payloads[MANIFEST_NAME]
    _fail(
        hashlib.sha256(manifest_payload).hexdigest() == expected_manifest_sha256,
        "toolchain manifest raw SHA-256 mismatch",
    )
    document = _load_json(manifest_payload, label="toolchain manifest")
    _fail(
        set(document)
        == {
            "application",
            "control_files",
            "files",
            "schema_version",
            "toolchain_version",
        },
        "toolchain manifest fields are invalid",
    )
    _fail(
        isinstance(document["schema_version"], int)
        and not isinstance(document["schema_version"], bool)
        and document["schema_version"] == 2,
        "toolchain manifest schema mismatch",
    )
    _fail(
        document["toolchain_version"] == TOOLCHAIN_VERSION,
        "toolchain manifest version mismatch",
    )
    _fail(document["application"] == APPLICATION, "toolchain application mismatch")
    expectations: list[_FileExpectation] = []
    total = 0
    for field, expected_names in (
        ("files", MANIFEST_FILES),
        ("control_files", CONTROL_FILES),
    ):
        entries = document[field]
        _fail(
            isinstance(entries, list)
            and all(isinstance(item, dict) for item in entries),
            f"toolchain manifest {field} are invalid",
        )
        _fail(
            tuple(item.get("name") for item in entries) == expected_names,
            f"toolchain manifest {field} order or set mismatch",
        )
        for entry in entries:
            _fail(
                set(entry) == {"name", "sha256", "size"},
                "toolchain manifest entry fields are invalid",
            )
            name = entry["name"]
            digest = entry["sha256"]
            size = entry["size"]
            _fail(
                isinstance(name, str)
                and isinstance(digest, str)
                and SHA256_PATTERN.fullmatch(digest) is not None
                and isinstance(size, int)
                and not isinstance(size, bool)
                and 0 < size <= MAX_FILE_BYTES,
                f"invalid toolchain manifest entry: {name!r}",
            )
            actual = payloads[name]
            _fail(len(actual) == size, f"toolchain file size mismatch: {name}")
            _fail(
                hashlib.sha256(actual).hexdigest() == digest,
                f"toolchain file SHA-256 mismatch: {name}",
            )
            total += len(actual)
            _fail(total <= MAX_TOTAL_BYTES, "toolchain payload exceeds the size limit")
            expectations.append(_FileExpectation(name, digest, size, actual))
    total += len(manifest_payload)
    _fail(total <= MAX_TOTAL_BYTES, "toolchain payload exceeds the size limit")
    expectations.append(
        _FileExpectation(
            MANIFEST_NAME,
            expected_manifest_sha256,
            len(manifest_payload),
            manifest_payload,
        )
    )
    return tuple(expectations)


def _verify_managed_directory(
    path: Path, *, owner_uid: int, owner_gid: int, modes: frozenset[int]
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ToolchainInstallError(f"managed directory is missing: {path}") from exc
    _fail(
        stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
        f"managed path is not a safe directory: {path}",
    )
    _fail(
        metadata.st_uid == owner_uid and metadata.st_gid == owner_gid,
        f"managed directory owner mismatch: {path}",
    )
    _fail(
        stat.S_IMODE(metadata.st_mode) in modes,
        f"managed directory mode mismatch: {path}",
    )
    return metadata


def _set_owner(path: Path, layout: _Layout) -> None:
    if not layout.test_mode:
        os.chown(path, layout.owner_uid, layout.owner_gid, follow_symlinks=False)


def _ensure_layout(layout: _Layout) -> None:
    test_allowed = frozenset({0o555, 0o700, 0o755, 0o777})
    if not layout.test_mode:
        _verify_managed_directory(
            layout.root.parent,
            owner_uid=layout.owner_uid,
            owner_gid=layout.owner_gid,
            modes=frozenset({0o555, 0o755}),
        )
    if not layout.root.exists():
        layout.root.mkdir(mode=0o700)
        _set_owner(layout.root, layout)
        os.chmod(layout.root, 0o700 if layout.test_mode else 0o755)
        _fsync_directory(layout.root, test_mode=layout.test_mode)
        _fsync_directory(layout.root.parent, test_mode=layout.test_mode)
    _verify_managed_directory(
        layout.root,
        owner_uid=layout.owner_uid,
        owner_gid=layout.owner_gid,
        modes=test_allowed if layout.test_mode else frozenset({0o755}),
    )
    if not layout.toolchains.exists():
        layout.toolchains.mkdir(mode=0o700)
        _set_owner(layout.toolchains, layout)
        if not layout.test_mode:
            os.chmod(layout.toolchains, 0o555)
        _fsync_directory(layout.toolchains, test_mode=layout.test_mode)
        _fsync_directory(layout.root, test_mode=layout.test_mode)
    _verify_managed_directory(
        layout.toolchains,
        owner_uid=layout.owner_uid,
        owner_gid=layout.owner_gid,
        modes=test_allowed if layout.test_mode else frozenset({0o555, 0o755}),
    )
    _fail(
        layout.root.stat().st_dev == layout.toolchains.stat().st_dev,
        "toolchain parent must be on the install-root filesystem",
    )


def _fsync_directory(path: Path, *, test_mode: bool) -> None:
    if test_mode and os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(
    path: Path, payload: bytes, *, layout: _Layout
) -> tuple[int, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    opened = os.fstat(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    try:
        _set_owner(path, layout)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            _fail(count > 0, f"short write while staging: {path.name}")
            written += count
        os.fsync(descriptor)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o444)
        elif layout.test_mode:
            os.chmod(path, 0o444)
        else:  # pragma: no cover - main() accepts POSIX only.
            raise ToolchainInstallError("fchmod is required in production")
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        _fail(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == layout.owner_uid
            and metadata.st_gid == layout.owner_gid
            and stat.S_IMODE(metadata.st_mode) == 0o444
            and metadata.st_size == len(payload),
            f"staged file metadata mismatch: {path.name}",
        )
    except BaseException:
        os.close(descriptor)
        try:
            current = path.lstat()
            if (
                stat.S_ISREG(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and (current.st_dev, current.st_ino) == identity
            ):
                if os.name == "posix":
                    os.chmod(path, 0o600, follow_symlinks=False)
                else:
                    os.chmod(path, 0o600)
                path.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)
    return metadata.st_dev, metadata.st_ino


def _publish_noreplace(source: Path, target: Path, *, test_mode: bool) -> bool:
    """Return False when target already exists; never replace it in production."""
    if test_mode:
        if target.exists() or target.is_symlink():
            return False
        os.rename(source, target)
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    _fail(renameat2 is not None, "renameat2 is required for no-replace publication")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(target),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        return False
    raise ToolchainInstallError(f"no-replace publication failed: errno {error}")


def _verify_target(
    target: Path,
    expectations: tuple[_FileExpectation, ...],
    *,
    layout: _Layout,
) -> None:
    try:
        before = target.lstat()
    except FileNotFoundError as exc:
        raise ToolchainInstallError("partial existing toolchain target") from exc
    _fail(
        stat.S_ISDIR(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_uid == layout.owner_uid
        and before.st_gid == layout.owner_gid
        and (
            (layout.test_mode and os.name != "posix")
            or stat.S_IMODE(before.st_mode) == 0o555
        ),
        "partial or unsafe existing toolchain target",
    )
    _fail(
        {entry.name for entry in os.scandir(target)} == EXPECTED_FILES,
        "partial existing toolchain target",
    )
    expected_by_name = {item.name: item for item in expectations}
    for name in sorted(EXPECTED_FILES):
        payload = _stable_read(
            target / name,
            owner_uid=layout.owner_uid,
            owner_gid=layout.owner_gid,
            source=False,
        )
        expected = expected_by_name[name]
        _fail(
            len(payload) == expected.size
            and hashlib.sha256(payload).hexdigest() == expected.sha256,
            f"installed toolchain content mismatch: {name}",
        )
    after = target.lstat()
    _fail(
        _metadata_identity(after) == _metadata_identity(before),
        "installed toolchain changed during verification",
    )


def _install(
    source: Path,
    *,
    install_root: Path,
    owner_uid: int,
    owner_gid: int,
    test_mode: bool,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    source = _canonical(source)
    _, payloads = _validate_source_directory(
        source,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        test_mode=test_mode,
    )
    expectations = _parse_manifest(
        payloads, expected_manifest_sha256=expected_manifest_sha256
    )
    layout = _Layout(install_root, owner_uid, owner_gid, test_mode)
    _ensure_layout(layout)

    if layout.target.exists() or layout.target.is_symlink():
        _verify_target(layout.target, expectations, layout=layout)
        already_installed = True
    else:
        stage_path = Path(
            tempfile.mkdtemp(prefix=".install-toolchain-", dir=layout.toolchains)
        )
        _set_owner(stage_path, layout)
        os.chmod(stage_path, 0o700)
        stage_metadata = stage_path.lstat()
        _fail(
            stat.S_ISDIR(stage_metadata.st_mode)
            and stage_metadata.st_uid == owner_uid
            and stage_metadata.st_gid == owner_gid
            and (
                (test_mode and os.name != "posix")
                or stat.S_IMODE(stage_metadata.st_mode) == 0o700
            )
            and stage_metadata.st_dev == layout.toolchains.stat().st_dev,
            "staging directory metadata mismatch",
        )
        owned = _OwnedStage(
            stage_path, (stage_metadata.st_dev, stage_metadata.st_ino)
        )
        try:
            by_name = {item.name: item for item in expectations}
            for name in sorted(EXPECTED_FILES):
                item = by_name[name]
                identity = _write_exclusive(
                    stage_path / name, item.payload, layout=layout
                )
                owned.add_file(stage_path / name, identity)
            _fsync_directory(stage_path, test_mode=test_mode)
            os.chmod(stage_path, 0o555)
            _fsync_directory(stage_path, test_mode=test_mode)
            staged = stage_path.lstat()
            _fail(
                (staged.st_dev, staged.st_ino) == owned.identity
                and (
                    (test_mode and os.name != "posix")
                    or stat.S_IMODE(staged.st_mode) == 0o555
                ),
                "staging directory changed before publication",
            )
            if _publish_noreplace(stage_path, layout.target, test_mode=test_mode):
                owned.published = True
                already_installed = False
                _fsync_directory(layout.toolchains, test_mode=test_mode)
            else:
                _verify_target(layout.target, expectations, layout=layout)
                already_installed = True
        finally:
            if owned.cleanup():
                _fsync_directory(layout.toolchains, test_mode=test_mode)
        _verify_target(layout.target, expectations, layout=layout)

    return {
        "already_installed": already_installed,
        "application": APPLICATION,
        "target": str(layout.target),
        "toolchain_manifest_sha256": expected_manifest_sha256,
        "toolchain_version": TOOLCHAIN_VERSION,
    }


def _install_for_test(
    source: Path, install_root: Path, expected_manifest_sha256: str
) -> dict[str, object]:
    """Private contract-test entry point; it never selects the production root."""
    metadata = source.lstat()
    return _install(
        source,
        install_root=install_root,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        test_mode=True,
        expected_manifest_sha256=expected_manifest_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("expected_manifest_sha256")
    arguments = parser.parse_args(argv)
    if SHA256_PATTERN.fullmatch(arguments.expected_manifest_sha256) is None:
        parser.error("expected_manifest_sha256 must be exactly 64 lowercase hex characters")
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise SystemExit("production installer requires Linux/POSIX")
    if os.geteuid() != 0:
        raise SystemExit("production installer must run as root")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SystemExit("production installer requires O_NOFOLLOW and O_DIRECTORY")
    source = _canonical(arguments.source_directory)
    try:
        source.relative_to(PRODUCTION_ROOT)
    except ValueError:
        pass
    else:
        raise SystemExit("upload source must be outside the production install root")
    result = _install(
        source,
        install_root=PRODUCTION_ROOT,
        owner_uid=0,
        owner_gid=0,
        test_mode=False,
        expected_manifest_sha256=arguments.expected_manifest_sha256,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
