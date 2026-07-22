#!/usr/bin/python3 -I
"""Deterministically validate and atomically install Dev29 runtime-open policy."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


sys.dont_write_bytecode = True
INSTALL_PARENT = Path("/opt/odoo-accounting-cli-v3/runtime-open-manifests")
SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1"
INDEX_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-index.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SAFE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
MAX_RELEASE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_RELEASE_FILES = 20_000
MAX_LISTED_RELEASE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_LISTED_RELEASE_BYTES = 768 * 1024 * 1024
RUNTIME_TRACE_MEMBER = "deployment/dev29/runtime_open_trace.py"


class PolicyBuildError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PolicyBuildError("policy value is not canonical JSON") from exc


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise PolicyBuildError("JSON document has a duplicate key")
        result[key] = value
    return result


def _read_canonical(
    path: Path, expected_sha256: str, *, enforce_root: bool = False
) -> dict[str, Any]:
    if HEX64.fullmatch(expected_sha256) is None:
        raise PolicyBuildError("expected policy source digest is invalid")
    if enforce_root:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or metadata.st_nlink != 1
        ):
            raise PolicyBuildError("policy source identity is unsafe")
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise PolicyBuildError("policy source digest mismatch")
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise PolicyBuildError("policy source JSON is invalid") from exc
    if type(value) is not dict or payload != canonical_json(value) + b"\n":
        raise PolicyBuildError("policy source is not canonical JSON plus LF")
    return value


def expected_targets() -> tuple[str, ...]:
    positive = ("registry", "trial_balance", "ar_open_items", "ap_open_items", "multicurrency")
    financial = set(positive[1:])
    negative = (
        "acl_deny", "cross_company", "mixed_company", "wrong_database_uuid",
        "expired", "tamper_parameters", "replay",
    )
    targets = ["release-identity", "witness-pre", "boundary-probe"]
    for name in positive:
        targets.extend((f"positive-{name}-signer", f"positive-{name}-read"))
        if name in financial:
            targets.append(f"positive-{name}-oracle")
    for name in negative:
        if name != "replay":
            targets.append(f"negative-{name}-signer")
        targets.append(f"negative-{name}-read")
    targets.extend(("witness-post", "independent-verifier"))
    return tuple(targets)


def _load_runtime_module(payload: bytes, path: Path) -> Any:
    """Execute only the exact validator bytes already bound to the digest."""

    name = "_dev29_policy_runtime_trace"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(payload, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _write_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0),
        0o400,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PolicyBuildError("short policy file write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path, *, enforce_root: bool) -> None:
    if not enforce_root:
        if os.path.lexists(destination):
            raise FileExistsError(destination)
        os.rename(source, destination)
        return
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise PolicyBuildError("renameat2 is unavailable for atomic policy publication")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == 17:
            raise FileExistsError(destination)
        raise OSError(error, os.strerror(error))


def _verify_directory(path: Path, *, mode: int, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PolicyBuildError(f"{label} cannot be verified") from exc
    if (
        path.is_symlink()
        or path.resolve(strict=True) != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
    ):
        raise PolicyBuildError(f"{label} identity is unsafe")
    return metadata


def _prepare_install_parent(install_parent: Path, *, enforce_root: bool) -> None:
    if not enforce_root:
        if not install_parent.is_dir() or install_parent.is_symlink():
            raise PolicyBuildError("runtime-open policy parent is invalid")
        return
    if install_parent != INSTALL_PARENT:
        raise PolicyBuildError("runtime-open policy parent is not canonical")
    base = INSTALL_PARENT.parent
    _verify_directory(base, mode=0o755, label="runtime-open policy base")
    if not os.path.lexists(install_parent):
        try:
            os.mkdir(install_parent, 0o755)
        except FileExistsError:
            pass
        directory_fd = os.open(
            base,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    _verify_directory(
        install_parent, mode=0o755, label="runtime-open policy parent"
    )


def _hash_release_member(
    path: Path,
    expected_sha256: str,
    *,
    enforce_root: bool,
    label: str,
) -> bytes:
    if HEX64.fullmatch(expected_sha256) is None:
        raise PolicyBuildError(f"expected {label} digest is invalid")
    metadata = path.lstat()
    if (
        path.is_symlink()
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (
            enforce_root
            and (
                (metadata.st_uid, metadata.st_gid) != (0, 0)
                or stat.S_IMODE(metadata.st_mode) != 0o444
            )
        )
    ):
        raise PolicyBuildError(f"sealed {label} identity is unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        opened = os.fstat(descriptor)
        identity = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink")
        if any(getattr(metadata, field) != getattr(opened, field) for field in identity):
            raise PolicyBuildError(f"sealed {label} path changed while opening")
        if opened.st_size > MAX_RELEASE_MEMBER_BYTES:
            raise PolicyBuildError(f"sealed {label} is too large")
        chunks: list[bytes] = []
        remaining = MAX_RELEASE_MEMBER_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            raise PolicyBuildError(f"sealed {label} is too large")
        payload = b"".join(chunks)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(getattr(opened, field) != getattr(after_open, field) for field in stable)
        or any(getattr(opened, field) != getattr(after, field) for field in stable)
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise PolicyBuildError(f"sealed {label} digest differs")
    return payload


def _parse_release_manifest(
    payload: bytes,
    *,
    expected_release: str,
    runtime_payload: bytes,
) -> dict[str, dict[str, Any]]:
    """Validate the exact build_release.py manifest and bind the validator."""

    try:
        document = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PolicyBuildError(f"non-finite release manifest number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyBuildError("release manifest JSON is invalid") from exc
    if type(document) is not dict:
        raise PolicyBuildError("release manifest is not a JSON object")
    try:
        generated_payload = json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PolicyBuildError("release manifest value is invalid") from exc
    if payload != generated_payload:
        raise PolicyBuildError("release manifest is not in build format")

    files = document.get("files")
    if (
        set(document)
        != {"commit", "files", "manifest_sha256", "schema_version", "version"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or not isinstance(document.get("version"), str)
        or VERSION.fullmatch(document["version"]) is None
        or not isinstance(document.get("commit"), str)
        or HEX40.fullmatch(document["commit"]) is None
        or expected_release
        != f"{document['version']}-{document['commit'][:12]}"
        or not isinstance(document.get("manifest_sha256"), str)
        or HEX64.fullmatch(document["manifest_sha256"]) is None
        or type(files) is not list
        or not files
        or len(files) > MAX_RELEASE_FILES
    ):
        raise PolicyBuildError("release manifest identity is invalid")

    unsigned = {
        key: value for key, value in document.items() if key != "manifest_sha256"
    }
    try:
        semantic_payload = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PolicyBuildError("release manifest semantic value is invalid") from exc
    if hashlib.sha256(semantic_payload).hexdigest() != document["manifest_sha256"]:
        raise PolicyBuildError("release manifest semantic digest is invalid")

    indexed: dict[str, dict[str, Any]] = {}
    total_size = 0
    for item in files:
        name = item.get("path") if type(item) is dict else None
        portable = PurePosixPath(name) if isinstance(name, str) else None
        size = item.get("size") if type(item) is dict else None
        digest = item.get("sha256") if type(item) is dict else None
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size"}
            or portable is None
            or portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != name
            or "\\" in name
            or name == "RELEASE-MANIFEST.json"
            or name in indexed
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
            or type(size) is not int
            or size < 0
            or size > MAX_LISTED_RELEASE_MEMBER_BYTES
        ):
            raise PolicyBuildError("release manifest member is invalid")
        total_size += size
        if total_size > MAX_LISTED_RELEASE_BYTES:
            raise PolicyBuildError("release manifest member sizes are excessive")
        indexed[name] = item

    runtime_member = indexed.get(RUNTIME_TRACE_MEMBER)
    if (
        runtime_member is None
        or runtime_member["sha256"] != hashlib.sha256(runtime_payload).hexdigest()
        or runtime_member["size"] != len(runtime_payload)
    ):
        raise PolicyBuildError("release manifest runtime member is invalid")
    return indexed


def _verify_release_root(
    release_root: Path,
    release: str,
    *,
    expected_runtime_module_sha256: str,
    expected_release_manifest_sha256: str,
    enforce_root: bool,
) -> tuple[bytes, bytes]:
    expected = Path(f"/opt/odoo-accounting-cli-v3/releases/{release}")
    if enforce_root and release_root != expected:
        raise PolicyBuildError("runtime-open policy release root is not canonical")
    if enforce_root:
        _verify_directory(
            release_root, mode=0o555, label="sealed runtime-open release root"
        )
    elif not release_root.is_dir() or release_root.is_symlink():
        raise PolicyBuildError("sealed runtime-open release root is unsafe")
    runtime_member = release_root / "deployment" / "dev29" / "runtime_open_trace.py"
    runtime_payload = _hash_release_member(
        runtime_member,
        expected_runtime_module_sha256,
        enforce_root=enforce_root,
        label="runtime-open validator",
    )
    release_manifest_payload = _hash_release_member(
        release_root / "RELEASE-MANIFEST.json",
        expected_release_manifest_sha256,
        enforce_root=enforce_root,
        label="release manifest",
    )
    _parse_release_manifest(
        release_manifest_payload,
        expected_release=release,
        runtime_payload=runtime_payload,
    )
    return runtime_payload, release_manifest_payload


def build_policy(
    source: Mapping[str, Any],
    *,
    expected_source_sha256: str,
    expected_strace_sha256: str,
    expected_runtime_module_sha256: str,
    expected_release_manifest_sha256: str,
    release_root: Path,
    install_parent: Path = INSTALL_PARENT,
    enforce_root: bool = True,
) -> dict[str, Any]:
    source_payload = canonical_json(source) + b"\n"
    if (
        HEX64.fullmatch(expected_source_sha256) is None
        or hashlib.sha256(source_payload).hexdigest() != expected_source_sha256
    ):
        raise PolicyBuildError("runtime-open policy source digest mismatch")
    targets = source.get("targets") if type(source) is dict else None
    release = source.get("release") if type(source) is dict else None
    static = source.get("expected_static_closure_sha256") if type(source) is dict else None
    if (
        set(source)
        != {
            "schema_version", "scope", "release", "expected_strace_sha256",
            "expected_static_closure_sha256", "targets", "production_promotion_allowed",
            "expected_runtime_module_sha256", "expected_release_manifest_sha256",
        }
        or type(source.get("schema_version")) is not int
        or source.get("schema_version") != 1
        or source.get("scope") != SCOPE
        or not isinstance(release, str)
        or SAFE_NAME.fullmatch(release) is None
        or source.get("expected_strace_sha256") != expected_strace_sha256
        or source.get("expected_runtime_module_sha256")
        != expected_runtime_module_sha256
        or source.get("expected_release_manifest_sha256")
        != expected_release_manifest_sha256
        or HEX64.fullmatch(expected_strace_sha256) is None
        or not isinstance(static, str)
        or HEX64.fullmatch(static) is None
        or type(targets) is not list
        or source.get("production_promotion_allowed") is not False
    ):
        raise PolicyBuildError("runtime-open policy source identity is invalid")
    runtime_payload, release_manifest_payload = _verify_release_root(
        release_root,
        release,
        expected_runtime_module_sha256=expected_runtime_module_sha256,
        expected_release_manifest_sha256=expected_release_manifest_sha256,
        enforce_root=enforce_root,
    )
    runtime_member = release_root / "deployment" / "dev29" / "runtime_open_trace.py"
    release_manifest_member = release_root / "RELEASE-MANIFEST.json"
    runtime = _load_runtime_module(runtime_payload, runtime_member)
    index_entries: list[dict[str, str]] = []
    payloads: list[tuple[str, bytes]] = []
    ordered: list[str] = []
    for manifest in targets:
        target_id = manifest.get("target_id") if type(manifest) is dict else None
        if not isinstance(target_id, str) or SAFE_NAME.fullmatch(target_id) is None:
            raise PolicyBuildError("runtime-open policy target is invalid")
        payload = canonical_json(manifest) + b"\n"
        digest = hashlib.sha256(payload).hexdigest()
        watches = manifest.get("watch_roots")
        watch_sha256 = hashlib.sha256(canonical_json(tuple(watches or ()))).hexdigest()
        environment = manifest.get("environment")
        child_environment_sha256 = hashlib.sha256(
            canonical_json(environment)
        ).hexdigest()
        if (
            type(environment) is not dict
            or manifest.get("expected_child_environment_sha256")
            != child_environment_sha256
        ):
            raise PolicyBuildError(
                "runtime-open target child environment binding is invalid"
            )
        request = runtime.TraceRequest(
            release=release,
            target_id=target_id,
            expected_manifest_sha256=digest,
            expected_strace_sha256=expected_strace_sha256,
            expected_static_closure_sha256=static,
            expected_child_environment_sha256=child_environment_sha256,
            expected_watch_roots_sha256=watch_sha256,
        )
        runtime.validate_manifest_document(manifest, request)
        ordered.append(target_id)
        payloads.append((f"{target_id}.json", payload))
        index_entries.append(
            {
                "target_id": target_id,
                "manifest_sha256": digest,
                "watch_roots_sha256": watch_sha256,
                "child_environment_sha256": child_environment_sha256,
            }
        )
    if tuple(ordered) != expected_targets():
        raise PolicyBuildError("runtime-open policy target set or order is incomplete")
    index = {
        "schema_version": 1,
        "scope": INDEX_SCOPE,
        "release": release,
        "expected_strace_sha256": expected_strace_sha256,
        "expected_static_closure_sha256": static,
        "policy_source_sha256": expected_source_sha256,
        "runtime_module_sha256": expected_runtime_module_sha256,
        "release_manifest_sha256": expected_release_manifest_sha256,
        "targets": index_entries,
        "production_promotion_allowed": False,
    }
    index_payload = canonical_json(index) + b"\n"
    if (
        _hash_release_member(
            runtime_member,
            expected_runtime_module_sha256,
            enforce_root=enforce_root,
            label="runtime-open validator",
        )
        != runtime_payload
        or _hash_release_member(
            release_manifest_member,
            expected_release_manifest_sha256,
            enforce_root=enforce_root,
            label="release manifest",
        )
        != release_manifest_payload
    ):
        raise PolicyBuildError("sealed release members changed during policy build")
    destination = install_parent / release
    pending = install_parent / f".{release}.pending-{os.getpid()}"
    if enforce_root and (os.name != "posix" or os.geteuid() != 0):
        raise PolicyBuildError("runtime-open policy installation requires root")
    _prepare_install_parent(install_parent, enforce_root=enforce_root)
    if os.path.lexists(destination) or os.path.lexists(pending):
        raise PolicyBuildError("runtime-open policy release already exists")
    os.mkdir(pending, 0o700)
    try:
        for name, payload in payloads:
            _write_file(pending / name, payload)
        _write_file(pending / "INDEX.json", index_payload)
        if os.name == "posix":
            directory_fd = os.open(
                pending, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            os.chmod(pending, 0o555)
        _rename_noreplace(pending, destination, enforce_root=enforce_root)
        if os.name == "posix":
            parent_fd = os.open(
                install_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    except BaseException:
        if os.path.isdir(pending):
            if os.name == "posix":
                os.chmod(pending, 0o700)
            for child in pending.iterdir():
                if os.name == "posix":
                    os.chmod(child, 0o600)
                child.unlink()
            pending.rmdir()
        raise
    return {
        "schema_version": 1,
        "release": release,
        "source_sha256": expected_source_sha256,
        "index_sha256": hashlib.sha256(index_payload).hexdigest(),
        "target_count": len(index_entries),
        "installed_path": str(destination),
        "production_promotion_allowed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--expected-strace-sha256", required=True)
    parser.add_argument("--expected-runtime-module-sha256", required=True)
    parser.add_argument("--expected-release-manifest-sha256", required=True)
    parser.add_argument("--release-root", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        source = _read_canonical(
            arguments.source,
            arguments.expected_source_sha256,
            enforce_root=True,
        )
        result = build_policy(
            source,
            expected_source_sha256=arguments.expected_source_sha256,
            expected_strace_sha256=arguments.expected_strace_sha256,
            expected_runtime_module_sha256=(
                arguments.expected_runtime_module_sha256
            ),
            expected_release_manifest_sha256=(
                arguments.expected_release_manifest_sha256
            ),
            release_root=arguments.release_root,
        )
    except (OSError, PolicyBuildError) as exc:
        print(f"Dev29 runtime-open policy refused: {exc}", file=sys.stderr)
        return 2
    print(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
