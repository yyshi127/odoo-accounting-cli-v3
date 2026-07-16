"""Verify that the executing Odoo add-on belongs to one anchored V3 release.

This module intentionally uses only the Python standard library.  Odoo loads
the control add-on directly from the immutable release tree, so it cannot rely
on the separately imported CLI package to establish its own code identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


_ADDON_PREFIX = "odoo_addons/odoo_accounting_cli_v3_control/"
_SESSION_CLIENT_MEMBER = _ADDON_PREFIX + "models/session_client.py"
_ANCHOR_FIELDS = frozenset(
    {"commit", "manifest_sha256", "package_sha256", "release"}
)
_MANIFEST_FIELDS = frozenset(
    {"commit", "files", "manifest_sha256", "schema_version", "version"}
)
_MANIFEST_MEMBER_FIELDS = frozenset({"path", "sha256", "size"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z"
)
_MAX_ANCHOR_BYTES = 16 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_REGISTRY_BYTES = 16 * 1024 * 1024
_MAX_ADDON_MEMBER_BYTES = 16 * 1024 * 1024


class AddonReleaseBindingError(RuntimeError):
    """The executing add-on cannot be tied to one trusted V3 release."""


@dataclass(frozen=True, slots=True)
class VerifiedAddonRelease:
    """The independently derived route identity sent to the session issuer."""

    release_digest: str
    registry_digest: str
    release: str
    version: str
    commit: str


class _DuplicateJsonKey(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJsonKey("duplicate JSON member")
        value[key] = child
    return value


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON value")


def _strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise AddonReleaseBindingError(f"{label} is not strict JSON") from exc


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise AddonReleaseBindingError("release JSON is not canonicalizable") from exc


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _validate_file_metadata(
    metadata: os.stat_result,
    label: str,
    *,
    require_root_owner: bool,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (require_root_owner and metadata.st_uid != 0)
        or stat.S_IMODE(metadata.st_mode) & 0o222
    ):
        raise AddonReleaseBindingError(f"{label} is not an immutable trusted file")


def _read_trusted_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    require_root_owner: bool,
) -> bytes:
    """Read one non-link immutable inode and reject path replacement races."""

    try:
        before = path.lstat()
        if path.is_symlink():
            raise AddonReleaseBindingError(f"{label} must not be a symlink")
        _validate_file_metadata(
            before, label, require_root_owner=require_root_owner
        )
        if before.st_size > max_bytes:
            raise AddonReleaseBindingError(f"{label} exceeds its size limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        for name in ("O_CLOEXEC", "O_NOFOLLOW"):
            value = getattr(os, name, None)
            if value is None:
                if require_root_owner:
                    raise AddonReleaseBindingError(
                        f"{label} cannot be opened without link protection"
                    )
            else:
                flags |= value
        descriptor = os.open(path, flags)
    except AddonReleaseBindingError:
        raise
    except OSError as exc:
        raise AddonReleaseBindingError(f"{label} is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        _validate_file_metadata(
            opened, label, require_root_owner=require_root_owner
        )
        if not _same_file(before, opened):
            raise AddonReleaseBindingError(f"{label} changed while opening")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes or len(raw) != opened.st_size:
            raise AddonReleaseBindingError(f"{label} changed while reading")
        after_open = os.fstat(descriptor)
    except AddonReleaseBindingError:
        raise
    except OSError as exc:
        raise AddonReleaseBindingError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise AddonReleaseBindingError(f"{label} changed after reading") from exc
    if not _same_file(opened, after_open) or not _same_file(opened, after_path):
        raise AddonReleaseBindingError(f"{label} changed while reading")
    return raw


def _validate_directory(
    path: Path,
    label: str,
    *,
    require_root_owner: bool,
    immutable: bool,
) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AddonReleaseBindingError(f"{label} is unavailable") from exc
    _validate_directory_metadata(
        metadata,
        label,
        require_root_owner=require_root_owner,
        immutable=immutable,
    )
    if path.is_symlink() or resolved != path:
        raise AddonReleaseBindingError(f"{label} is not a trusted directory")


def _validate_directory_metadata(
    metadata: os.stat_result,
    label: str,
    *,
    require_root_owner: bool,
    immutable: bool,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (require_root_owner and metadata.st_uid != 0)
        or (immutable and mode & 0o222)
        or (not immutable and mode & 0o022)
    ):
        raise AddonReleaseBindingError(f"{label} is not a trusted directory")


def _validate_release_directories(
    release_root: Path,
    addon_root: Path,
    *,
    require_root_owner: bool,
) -> None:
    if require_root_owner:
        chain = tuple(reversed(release_root.parent.parents)) + (
            release_root.parent,
        )
        for ancestor in chain:
            _validate_directory(
                ancestor,
                "release ancestor",
                require_root_owner=True,
                immutable=False,
            )
    _validate_directory(
        release_root,
        "release root",
        require_root_owner=require_root_owner,
        immutable=True,
    )
    current = addon_root
    descendants: list[Path] = []
    while current != release_root:
        descendants.append(current)
        current = current.parent
    for directory in reversed(descendants):
        _validate_directory(
            directory,
            "add-on directory",
            require_root_owner=require_root_owner,
            immutable=True,
        )


def _manifest_members(manifest: object) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise AddonReleaseBindingError("release manifest fields are invalid")
    if manifest["schema_version"] != 1:
        raise AddonReleaseBindingError("release manifest schema is invalid")
    if (
        type(manifest["version"]) is not str
        or _VERSION.fullmatch(manifest["version"]) is None
        or type(manifest["commit"]) is not str
        or _COMMIT.fullmatch(manifest["commit"]) is None
        or type(manifest["manifest_sha256"]) is not str
        or _SHA256.fullmatch(manifest["manifest_sha256"]) is None
        or not isinstance(manifest["files"], list)
        or not manifest["files"]
    ):
        raise AddonReleaseBindingError("release manifest identity is invalid")
    members: dict[str, dict[str, Any]] = {}
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != _MANIFEST_MEMBER_FIELDS:
            raise AddonReleaseBindingError("release manifest member is invalid")
        portable = PurePosixPath(item.get("path", ""))
        path = item.get("path")
        if (
            type(path) is not str
            or not portable.parts
            or portable.is_absolute()
            or str(portable) != path
            or any(part in {"", ".", ".."} for part in portable.parts)
            or path in members
            or type(item.get("sha256")) is not str
            or _SHA256.fullmatch(item["sha256"]) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
        ):
            raise AddonReleaseBindingError("release manifest member is invalid")
        members[path] = item
    return members


def _assert_member(raw: bytes, member: dict[str, Any], label: str) -> None:
    if (
        len(raw) != member["size"]
        or hashlib.sha256(raw).hexdigest() != member["sha256"]
    ):
        raise AddonReleaseBindingError(f"{label} differs from the release manifest")


def verify_addon_release(
    module_file: str | os.PathLike[str],
    *,
    require_root_owner: bool = True,
) -> VerifiedAddonRelease:
    """Derive and verify the immutable release containing ``session_client``.

    ``require_root_owner=False`` exists only for hermetic non-root unit tests;
    the Odoo client never overrides the production default.
    """

    if type(require_root_owner) is not bool:
        raise AddonReleaseBindingError("release owner policy is invalid")
    if require_root_owner and (sys.platform != "linux" or os.name != "posix"):
        raise AddonReleaseBindingError("trusted add-on release requires Linux")
    try:
        supplied = Path(module_file)
        if not supplied.is_absolute():
            raise AddonReleaseBindingError("executing add-on path is not absolute")
        module_path = supplied.resolve(strict=True)
    except AddonReleaseBindingError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise AddonReleaseBindingError("executing add-on path is unavailable") from exc
    if supplied != module_path or supplied.is_symlink():
        raise AddonReleaseBindingError("executing add-on path is not canonical")
    try:
        release_root = module_path.parents[3]
    except IndexError as exc:
        raise AddonReleaseBindingError("executing add-on path is misplaced") from exc
    addon_root = release_root / "odoo_addons" / "odoo_accounting_cli_v3_control"
    expected_module = release_root.joinpath(*PurePosixPath(_SESSION_CLIENT_MEMBER).parts)
    if (
        release_root.parent.name != "releases"
        or module_path != expected_module
        or addon_root.resolve(strict=True) != addon_root
    ):
        raise AddonReleaseBindingError("executing add-on is outside a release")
    _validate_release_directories(
        release_root, addon_root, require_root_owner=require_root_owner
    )

    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_path = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    _validate_directory(
        anchor_path.parent,
        "external anchor directory",
        require_root_owner=require_root_owner,
        immutable=False,
    )
    manifest = _strict_json(
        _read_trusted_file(
            manifest_path,
            "release manifest",
            max_bytes=_MAX_MANIFEST_BYTES,
            require_root_owner=require_root_owner,
        ),
        "release manifest",
    )
    anchor = _strict_json(
        _read_trusted_file(
            anchor_path,
            "external release anchor",
            max_bytes=_MAX_ANCHOR_BYTES,
            require_root_owner=require_root_owner,
        ),
        "external release anchor",
    )
    members = _manifest_members(manifest)
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    calculated_manifest_digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if (
        not isinstance(anchor, dict)
        or set(anchor) != _ANCHOR_FIELDS
        or anchor["release"] != release_root.name
        or anchor["release"] != f"{manifest['version']}-{manifest['commit'][:12]}"
        or anchor["commit"] != manifest["commit"]
        or type(anchor["manifest_sha256"]) is not str
        or _SHA256.fullmatch(anchor["manifest_sha256"]) is None
        or type(anchor["package_sha256"]) is not str
        or _SHA256.fullmatch(anchor["package_sha256"]) is None
        or manifest["manifest_sha256"] != anchor["manifest_sha256"]
        or calculated_manifest_digest != anchor["manifest_sha256"]
    ):
        raise AddonReleaseBindingError(
            "release manifest does not match its external anchor"
        )

    expected_addon_members = {
        path: item for path, item in members.items() if path.startswith(_ADDON_PREFIX)
    }
    actual_addon_members: dict[str, Path] = {}
    try:
        addon_entries = tuple(addon_root.rglob("*"))
    except OSError as exc:
        raise AddonReleaseBindingError("add-on tree cannot be enumerated") from exc
    for path in addon_entries:
        relative = path.relative_to(release_root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AddonReleaseBindingError("add-on member is unavailable") from exc
        if stat.S_ISDIR(metadata.st_mode):
            _validate_directory(
                path,
                "add-on directory",
                require_root_owner=require_root_owner,
                immutable=True,
            )
        elif stat.S_ISREG(metadata.st_mode) and not path.is_symlink():
            actual_addon_members[relative] = path
        else:
            raise AddonReleaseBindingError("add-on tree contains a forbidden member")
    if (
        set(actual_addon_members) != set(expected_addon_members)
        or _SESSION_CLIENT_MEMBER not in actual_addon_members
    ):
        raise AddonReleaseBindingError("add-on file set differs from the release manifest")
    for relative, path in actual_addon_members.items():
        raw = _read_trusted_file(
            path,
            f"add-on member {relative}",
            max_bytes=_MAX_ADDON_MEMBER_BYTES,
            require_root_owner=require_root_owner,
        )
        _assert_member(raw, expected_addon_members[relative], "add-on member")

    registry_member_name = "registry/capabilities.json"
    registry_member = members.get(registry_member_name)
    if registry_member is None:
        raise AddonReleaseBindingError("release registry is absent from the manifest")
    _validate_directory(
        release_root / "registry",
        "capability registry directory",
        require_root_owner=require_root_owner,
        immutable=True,
    )
    registry_raw = _read_trusted_file(
        release_root / "registry" / "capabilities.json",
        "capability registry",
        max_bytes=_MAX_REGISTRY_BYTES,
        require_root_owner=require_root_owner,
    )
    _assert_member(registry_raw, registry_member, "capability registry")
    registry = _strict_json(registry_raw, "capability registry")
    if (
        not isinstance(registry, dict)
        or set(registry) != {"schema_version", "capabilities"}
        or registry["schema_version"] != 1
        or not isinstance(registry["capabilities"], list)
        or not registry["capabilities"]
    ):
        raise AddonReleaseBindingError("capability registry is invalid")
    # This is exactly registry.registry_digest(): the validated ordered list,
    # not the wrapper document or the registry file's presentation bytes.
    registry_digest = hashlib.sha256(
        _canonical_json(registry["capabilities"])
    ).hexdigest()
    return VerifiedAddonRelease(
        release_digest=anchor["manifest_sha256"],
        registry_digest=registry_digest,
        release=anchor["release"],
        version=manifest["version"],
        commit=manifest["commit"],
    )


__all__ = [
    "AddonReleaseBindingError",
    "VerifiedAddonRelease",
    "verify_addon_release",
]
