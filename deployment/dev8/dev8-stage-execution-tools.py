#!/usr/bin/python3 -I
"""Stage the minimum dev8 tools needed by Odoo, execute them, and clean up."""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import signal
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


RELEASE = "0.1.0.dev8-bd21ca07c168"
UPLOAD_ROOT = Path("/root/odoo-accounting-cli-v3-dev8-upload")
PIPELINE_LOCK = Path("/opt/odoo-accounting-cli-v3/.dev8-pipeline.lock")
INSTALL_JOURNAL = Path("/opt/odoo-accounting-cli-v3/.dev8-install-transaction.json")
RUNTIME_JOURNAL = Path("/etc/odoo-accounting-cli-v3/.dev8-runtime-transaction.json")
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
MANIFEST_SHA256 = "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06"
REGISTRY_DIGEST = "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e"
PLAN_SHA256 = "c6dd18fc356bdbc26de43941656e9af62f639d06393ce87572e7a08e5759f2e5"
SOURCES = {
    "dev8-run-real-reads.sh": "de22f26a9e503581bc9d219322dc626f8830f81c6b06968963719e540f457ffd",
    "dev8-sign-read.py": "e94e610d480f7ba0736e315a46ca98a6507e82e88e1b35ac2ca6a31ff0592896",
    "dev8-launcher-isolation-gate.py": "9bb2a2596d639851df2567e5a8e9cef98f2c5849725946ecc72bb6b1cfbfa80e",
    "dev8-run-read-oracles.sh": "a69faa4d38341c5c9135c43e0f6308c3335eb65fb90b72f757b8a1e26d1af618",
    "dev6-trial-balance-sql-oracle.py": "7aa959361ac994f17cd871d33211bbef02ab816993ff87f088c82a6541cfcb9b",
    "dev6-ar-sql-oracle.py": "cdb49967d60af0aa416cadaeb61503847ddfeb4d111aa0e01335fe06b78499c6",
    "dev7-ap-sql-oracle.py": "ad54540725e8110ea1449586d0dcddb1d6c70b1e387f0e843b989aca6b70f1e5",
}
ORACLE_SOURCES = (
    "dev6-trial-balance-sql-oracle.py",
    "dev6-ar-sql-oracle.py",
    "dev7-ap-sql-oracle.py",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def acquire_pipeline_lock() -> tuple[int, dict[str, object]]:
    before = PIPELINE_LOCK.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and not PIPELINE_LOCK.is_symlink()
        and before.st_uid == 0
        and before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == 0o600
        and before.st_nlink == 1,
        "dev8 pipeline lock metadata is invalid",
    )
    descriptor = os.open(
        PIPELINE_LOCK,
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
            and stat.S_ISREG(opened.st_mode)
            and opened.st_uid == 0
            and opened.st_gid == 0
            and stat.S_IMODE(opened.st_mode) == 0o600
            and opened.st_nlink == 1,
            "dev8 pipeline lock changed while opening",
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        after = PIPELINE_LOCK.lstat()
        identity = (before.st_dev, before.st_ino)
        require(
            identity == (locked.st_dev, locked.st_ino) == (after.st_dev, after.st_ino)
            and stat.S_ISREG(after.st_mode)
            and not PIPELINE_LOCK.is_symlink()
            and after.st_uid == 0
            and after.st_gid == 0
            and stat.S_IMODE(after.st_mode) == 0o600
            and after.st_nlink == 1,
            "dev8 pipeline lock changed while acquiring",
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, {
        "path": str(PIPELINE_LOCK),
        "device": before.st_dev,
        "inode": before.st_ino,
        "uid": 0,
        "gid": 0,
        "mode": "0600",
        "nlink": 1,
        "regular": True,
        "not_symlink": True,
        "o_nofollow": True,
        "same_inode": True,
        "exclusive": True,
        "acquired": True,
    }


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate journal field: {key}")
        value[key] = item
    return value


def stable_fingerprint(value: os.stat_result) -> tuple[object, ...]:
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode), value.st_nlink,
    )


def secure_journal(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode) and not path.is_symlink()
        and before.st_uid == 0 and before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
        f"pipeline transaction journal metadata is invalid: {path}",
    )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require(stable_fingerprint(opened) == stable_fingerprint(before), f"pipeline journal changed while opening: {path}")
        chunks = []
        total = 0
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 16_384)
            if not chunk:
                break
            total += len(chunk)
            require(total <= 1_048_576, f"pipeline journal is too large: {path}")
            chunks.append(chunk)
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    require(
        stable_fingerprint(before) == stable_fingerprint(opened_after)
        == stable_fingerprint(after),
        f"pipeline journal changed while reading: {path}",
    )
    document = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(document, dict), f"pipeline journal is not an object: {path}")
    return document, {
        "path": str(path), "device": before.st_dev, "inode": before.st_ino,
        "uid": 0, "gid": 0, "mode": "0600", "nlink": 1,
        "regular": True, "not_symlink": True, "o_nofollow": True,
        "same_inode": True, "sha256": digest.hexdigest(),
    }


def current_identity(path: Path, kind: str) -> dict[str, object]:
    before = path.lstat()
    require(not path.is_symlink() and path.resolve(strict=True) == path, f"pipeline object path is unsafe: {path}")
    require(
        (kind == "file" and stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        or (kind == "directory" and stat.S_ISDIR(before.st_mode)),
        f"pipeline object type mismatch: {path}",
    )
    result: dict[str, object] = {
        "dev": before.st_dev, "ino": before.st_ino, "kind": kind,
        "uid": before.st_uid, "gid": before.st_gid,
        "mode": stat.S_IMODE(before.st_mode),
    }
    if kind == "file":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            require(stable_fingerprint(opened) == stable_fingerprint(before), f"pipeline object changed while opening: {path}")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
        require(
            stable_fingerprint(before) == stable_fingerprint(opened_after)
            == stable_fingerprint(after),
            f"pipeline object changed while reading: {path}",
        )
        result.update({"size": total, "sha256": digest.hexdigest()})
    return result


def validate_parent_records(
    document: dict[str, object],
    expected: dict[str, tuple[Path, set[tuple[int, int]], set[int] | None]],
) -> None:
    parents = document.get("parents")
    require(isinstance(parents, dict) and set(parents) == set(expected), "pipeline journal parent set mismatch")
    for label, (path, owners, modes) in expected.items():
        record = parents[label]
        identity = current_identity(path, "directory")
        require(
            isinstance(record, dict) and set(record) == {"path", "identity"}
            and record["path"] == str(path)
            and isinstance(record["identity"], dict)
            and set(record["identity"]) == {"dev", "ino", "kind", "uid", "gid", "mode"}
            and all(
                isinstance(record["identity"][field], int)
                and not isinstance(record["identity"][field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            and record["identity"] == identity
            and (int(identity["uid"]), int(identity["gid"])) in owners
            and not (int(identity["mode"]) & 0o022)
            and (modes is None or int(identity["mode"]) in modes),
            f"pipeline journal parent identity mismatch: {label}",
        )


def validate_object_records(
    document: dict[str, object],
    plans: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    objects = document.get("objects")
    require(isinstance(objects, dict) and set(objects) == set(plans), "pipeline journal object set mismatch")
    final: dict[str, dict[str, object]] = {}
    base_identity_fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
    for label, planned in plans.items():
        record = objects[label]
        require(
            isinstance(record, dict) and set(record) == set(planned)
            and canonical({**record, "identity": None}) == canonical(planned),
            f"pipeline journal object plan mismatch: {label}",
        )
        kind = str(planned["kind"])
        identity_fields = base_identity_fields | ({"size", "sha256"} if kind == "file" else set())
        recorded = record["identity"]
        require(
            isinstance(recorded, dict) and set(recorded) == identity_fields
            and all(
                isinstance(recorded[field], int) and not isinstance(recorded[field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            and int(recorded["dev"]) >= 0 and int(recorded["ino"]) >= 0
            and recorded["kind"] == kind
            and recorded["uid"] == planned["uid"] and recorded["gid"] == planned["gid"]
            and recorded["mode"] in planned["modes"]
            and (
                kind != "file"
                or (
                    isinstance(recorded["size"], int) and not isinstance(recorded["size"], bool)
                    and int(recorded["size"]) >= 0
                    and isinstance(recorded["sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", recorded["sha256"]) is not None
                )
            ),
            f"pipeline journal object identity mismatch: {label}",
        )
        path = Path(str(planned["path"]))
        if planned["unique"] is True:
            require(not os.path.lexists(path), f"completed pipeline retains staging object: {label}")
            continue
        observed = current_identity(path, kind)
        require(recorded == observed, f"pipeline final object identity mismatch: {label}")
        require(
            observed["uid"] == planned["uid"] and observed["gid"] == planned["gid"]
            and observed["mode"] in planned["modes"],
            f"pipeline final object metadata mismatch: {label}",
        )
        final[label] = {
            "path": str(path), "device": observed["dev"], "inode": observed["ino"],
            "kind": kind, "uid": planned["uid"], "gid": planned["gid"], "mode": f"{int(observed['mode']):04o}",
            "journal_identity_matched": True,
        }
    for label, planned in plans.items():
        source = planned["source"]
        if source is not None:
            require(
                objects[label]["identity"] == objects[source]["identity"],
                f"pipeline journal source identity mismatch: {label}",
            )
    return final


def object_plan(
    path: Path,
    kind: str,
    uid: int,
    gid: int,
    modes: list[int],
    unique: bool,
    source: str | None,
    *,
    unrecorded_owners: list[list[int]] | None = None,
    unrecorded_modes: list[int] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "path": str(path), "kind": kind, "uid": uid, "gid": gid,
        "modes": modes, "unique": unique, "source": source, "identity": None,
    }
    if unrecorded_owners is not None or unrecorded_modes is not None:
        require(unrecorded_owners is not None and unrecorded_modes is not None, "incomplete runtime object plan")
        result["unrecorded_owners"] = unrecorded_owners
        result["unrecorded_modes"] = unrecorded_modes
    return result


def validate_pipeline_transactions(odoo_uid: int, odoo_gid: int) -> dict[str, object]:
    install, install_journal = secure_journal(INSTALL_JOURNAL)
    runtime, runtime_journal = secure_journal(RUNTIME_JOURNAL)
    install_keys = {"schema_version", "kind", "release", "transaction_id", "state", "parents", "objects"}
    runtime_keys = install_keys | {"upstream_install_transaction_id", "upstream_install_identity_sha256"}
    install_id = install.get("transaction_id")
    runtime_id = runtime.get("transaction_id")
    require(
        set(install) == install_keys
        and isinstance(install.get("schema_version"), int) and not isinstance(install.get("schema_version"), bool)
        and install.get("schema_version") == 1
        and install.get("kind") == "install" and install.get("release") == RELEASE
        and install.get("state") == "completed" and isinstance(install_id, str)
        and re.fullmatch(r"[0-9a-f]{32}", install_id) is not None,
        "completed install transaction journal mismatch",
    )
    require(
        set(runtime) == runtime_keys
        and isinstance(runtime.get("schema_version"), int) and not isinstance(runtime.get("schema_version"), bool)
        and runtime.get("schema_version") == 1
        and runtime.get("kind") == "runtime" and runtime.get("release") == RELEASE
        and runtime.get("state") == "completed" and isinstance(runtime_id, str)
        and re.fullmatch(r"[0-9a-f]{32}", runtime_id) is not None
        and runtime.get("upstream_install_transaction_id") == install_id,
        "completed runtime transaction journal mismatch",
    )
    root = Path("/opt/odoo-accounting-cli-v3")
    releases = root / "releases"
    packages = root / "packages"
    anchors = root / "trusted-artifacts"
    package_name = f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
    validate_parent_records(
        install,
        {
            "root": (root, {(0, 0)}, None),
            "releases": (releases, {(0, 0)}, None),
            "packages": (packages, {(0, 0)}, None),
            "anchors": (anchors, {(0, 0)}, None),
        },
    )
    install_plans = {
        "package_staging": object_plan(packages / f".{package_name}.{install_id}.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "anchor_staging": object_plan(anchors / f".{RELEASE}.{install_id}.anchor.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "release_staging": object_plan(releases / f".{RELEASE}.{install_id}.release.staging", "directory", 0, 0, [0o555], True, None),
        "package": object_plan(packages / package_name, "file", 0, 0, [0o444], False, "package_staging"),
        "release": object_plan(releases / RELEASE, "directory", 0, 0, [0o555], False, "release_staging"),
        "anchor": object_plan(anchors / f"{RELEASE}.json", "file", 0, 0, [0o444], False, "anchor_staging"),
    }
    install_final = validate_object_records(install, install_plans)
    install_objects = install["objects"]
    require(
        install_objects["package"]["identity"]["size"] == 151492
        and install_objects["package"]["identity"]["sha256"] == PACKAGE_SHA256,
        "completed install package identity mismatch",
    )
    binding = {
        "anchor": install_objects["anchor"]["identity"],
        "install_transaction_id": install_id,
        "manifest_sha256": MANIFEST_SHA256,
        "package": install_objects["package"]["identity"],
        "registry_digest": REGISTRY_DIGEST,
        "release": install_objects["release"]["identity"],
    }
    binding_sha256 = sha256_bytes(canonical(binding))
    require(runtime.get("upstream_install_identity_sha256") == binding_sha256, "runtime journal upstream install identity mismatch")

    config_parent = Path("/etc/odoo-accounting-cli-v3")
    candidate_parent = Path("/var/lib/odoo-accounting-cli-v3/test/candidates")
    candidate_staging_parent = Path("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging")
    secret_parent = config_parent / "secrets/test"
    validate_parent_records(
        runtime,
        {
            "config_parent": (config_parent, {(0, 0)}, None),
            "candidate_parent": (candidate_parent, {(0, 0), (odoo_uid, odoo_gid)}, None),
            "candidate_staging_parent": (candidate_staging_parent, {(0, 0)}, {0o700}),
            "secret_parent": (secret_parent, {(0, 0), (0, odoo_gid)}, None),
        },
    )
    odoo_owner = [odoo_uid, odoo_gid]
    runtime_plans = {
        "config_staging": object_plan(config_parent / f".runtime-test-dev8.json.{runtime_id}.staging", "file", 0, 0, [0o644], True, None, unrecorded_owners=[[0, 0]], unrecorded_modes=[0o600, 0o644]),
        "candidate_staging": object_plan(candidate_staging_parent / f".{RELEASE}.{runtime_id}.candidate.staging", "directory", odoo_uid, odoo_gid, [0o700], True, None, unrecorded_owners=[[0, 0], odoo_owner], unrecorded_modes=[0o700]),
        "auth_staging": object_plan(secret_parent / f".dev8-auth.{runtime_id}.hmac.staging", "file", 0, odoo_gid, [0o640], True, None, unrecorded_owners=[[0, 0], [0, odoo_gid]], unrecorded_modes=[0o600, 0o640]),
        "receipt_staging": object_plan(secret_parent / f".dev8-receipt.{runtime_id}.hmac.staging", "file", 0, odoo_gid, [0o640], True, None, unrecorded_owners=[[0, 0], [0, odoo_gid]], unrecorded_modes=[0o600, 0o640]),
        "config": object_plan(config_parent / "runtime-test-dev8.json", "file", 0, 0, [0o644], False, "config_staging", unrecorded_owners=[[0, 0]], unrecorded_modes=[0o644]),
        "candidate": object_plan(candidate_parent / RELEASE, "directory", odoo_uid, odoo_gid, [0o700], False, "candidate_staging", unrecorded_owners=[odoo_owner], unrecorded_modes=[0o700]),
        "auth_secret": object_plan(secret_parent / "dev8-auth.hmac", "file", 0, odoo_gid, [0o640], False, "auth_staging", unrecorded_owners=[[0, odoo_gid]], unrecorded_modes=[0o640]),
        "receipt_secret": object_plan(secret_parent / "dev8-receipt.hmac", "file", 0, odoo_gid, [0o640], False, "receipt_staging", unrecorded_owners=[[0, odoo_gid]], unrecorded_modes=[0o640]),
    }
    runtime_final = validate_object_records(runtime, runtime_plans)
    return {
        "schema_version": 1,
        "install_journal": install_journal,
        "runtime_journal": runtime_journal,
        "install_transaction_id": install_id,
        "install_state": "completed",
        "runtime_transaction_id": runtime_id,
        "runtime_state": "completed",
        "runtime_upstream_install_transaction_id": install_id,
        "computed_install_identity_sha256": binding_sha256,
        "runtime_upstream_install_identity_sha256": binding_sha256,
        "install_final_objects": install_final,
        "runtime_final_objects": runtime_final,
        "staging_objects_absent": True,
        "all_checks_passed": True,
    }


def metadata(path: Path) -> dict[str, object]:
    value = path.lstat()
    return {
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "regular": stat.S_ISREG(value.st_mode),
        "not_symlink": not stat.S_ISLNK(value.st_mode),
        "device": value.st_dev,
        "inode": value.st_ino,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
    }


def validate_upload_root(odoo_uid: int) -> dict[str, object]:
    value = metadata(UPLOAD_ROOT)
    require(
        UPLOAD_ROOT.is_dir()
        and not UPLOAD_ROOT.is_symlink()
        and value["uid"] == 0
        and value["gid"] == 0
        and value["mode"] == "0700",
        "upload root must be root:root mode 0700",
    )
    root_meta = Path("/root").lstat()
    not_odoo_traversable = not bool(root_meta.st_mode & 0o001) and not bool(
        UPLOAD_ROOT.lstat().st_mode & 0o001
    )
    probe = subprocess.run(
        [
            "/usr/bin/sudo", "-n", "-u", "odoo", "-g", "odoo",
            "/usr/bin/test", "!", "-x", str(UPLOAD_ROOT),
        ],
        check=False,
        capture_output=True,
        timeout=20,
    )
    require(
        not_odoo_traversable and odoo_uid != 0 and probe.returncode == 0,
        "upload root is traversable by Odoo",
    )
    return {
        "path": str(UPLOAD_ROOT),
        "uid": 0,
        "gid": 0,
        "mode": "0700",
        "not_odoo_traversable": True,
    }


def validate_private_output(path: Path) -> None:
    require(path.is_absolute() and path.parent == Path("/tmp"), "output must be a direct /tmp child")
    require(not os.path.lexists(path), "output path already exists")
    os.mkdir(path, 0o700)
    value = path.lstat()
    require(
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o700
        and path.resolve(strict=True) == path,
        "root evidence directory metadata is invalid",
    )


def secure_write(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            require(written > 0, "output write did not progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def secure_read_source(path: Path, expected_sha256: str) -> tuple[int, dict[str, object]]:
    before = metadata(path)
    require(
        before["uid"] == 0
        and before["gid"] == 0
        and before["regular"] is True
        and before["not_symlink"] is True
        and before["nlink"] == 1
        and not (int(str(before["mode"]), 8) & 0o022),
        f"unsafe upload source: {path.name}",
    )
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    opened = os.fstat(descriptor)
    require(
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        == (before["device"], before["inode"], before["size"], before["mtime_ns"]),
        f"upload source changed while opening: {path.name}",
    )
    digest = hashlib.sha256()
    position = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, position)
        if not chunk:
            break
        digest.update(chunk)
        position += len(chunk)
    require(digest.hexdigest() == expected_sha256, f"upload source digest mismatch: {path.name}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor, before


def make_stage(prefix: str, odoo_gid: int) -> tuple[Path, tuple[int, int]]:
    raw = tempfile.mkdtemp(prefix=prefix, dir="/run")
    path = Path(raw)
    os.chown(path, 0, odoo_gid)
    os.chmod(path, 0o750)
    value = path.lstat()
    require(
        path.parent == Path("/run")
        and path.name.startswith(prefix)
        and stat.S_ISDIR(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == odoo_gid
        and stat.S_IMODE(value.st_mode) == 0o750,
        "staging directory metadata is invalid",
    )
    return path, (value.st_dev, value.st_ino)


def stage_file(
    source: Path,
    destination: Path,
    expected_sha256: str,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> tuple[dict[str, object], dict[str, object]]:
    source_fd, source_before = secure_read_source(source, expected_sha256)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    destination_fd = os.open(destination, flags, mode)
    try:
        os.fchown(destination_fd, uid, gid)
        os.fchmod(destination_fd, mode)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_fd, remaining)
                require(written > 0, "staged file write did not progress")
                remaining = remaining[written:]
        os.fsync(destination_fd)
        staged_open = os.fstat(destination_fd)
        source_after_open = os.fstat(source_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    source_after = metadata(source)
    source_identity = (
        source_before["device"],
        source_before["inode"],
        source_before["size"],
        source_before["mtime_ns"],
    )
    require(
        source_identity
        == (
            source_after_open.st_dev,
            source_after_open.st_ino,
            source_after_open.st_size,
            source_after_open.st_mtime_ns,
        )
        == (
            source_after["device"],
            source_after["inode"],
            source_after["size"],
            source_after["mtime_ns"],
        ),
        f"upload source changed during copy: {source.name}",
    )
    staged = metadata(destination)
    require(
        staged["uid"] == uid
        and staged["gid"] == gid
        and staged["mode"] == f"{mode:04o}"
        and staged["nlink"] == 1
        and staged["regular"] is True
        and staged["not_symlink"] is True
        and sha256_file(destination) == expected_sha256
        and (staged_open.st_dev, staged_open.st_ino) == (staged["device"], staged["inode"]),
        f"staged file metadata or digest mismatch: {source.name}",
    )
    public_source = {key: value for key, value in source_before.items() if key not in {"device", "inode", "mtime_ns"}}
    public_staged = {key: value for key, value in staged.items() if key not in {"device", "inode", "mtime_ns"}}
    public_staged.update({"path": str(destination), "sha256": expected_sha256})
    return public_source, public_staged


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(arguments: list[str], timeout: int) -> dict[str, object]:
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=10)
        exit_code = 124
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "output_sha256": sha256_bytes(stdout),
        "timed_out": timed_out,
        "process_group_reaped": process.poll() is not None,
    }


def safe_cleanup(path: Path | None, expected_parent: Path, prefix: str, identity: tuple[int, int] | None) -> bool:
    if path is None or not os.path.lexists(path):
        return True
    require(path.parent == expected_parent and path.name.startswith(prefix), "cleanup path escaped its scope")
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode):
        return False
    identity_unchanged = identity is None or (value.st_dev, value.st_ino) == identity
    if not identity_unchanged:
        return False
    require(stat.S_ISDIR(value.st_mode), "cleanup target is not a directory")
    shutil.rmtree(path)
    return not os.path.lexists(path)


def cleanup_fixed_file(path: Path, identity: tuple[int, int], expected_sha256: str) -> bool:
    if not os.path.lexists(path):
        return True
    require(path.parent == Path("/tmp") and path.name in ORACLE_SOURCES, "fixed oracle cleanup escaped its scope")
    value = path.lstat()
    if not (
        stat.S_ISREG(value.st_mode)
        and not stat.S_ISLNK(value.st_mode)
        and (value.st_dev, value.st_ino) == identity
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o444
        and value.st_nlink == 1
        and sha256_file(path) == expected_sha256
    ):
        return False
    os.unlink(path)
    return not os.path.lexists(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--read-plan", type=Path, required=True)
    parser.add_argument("--read-evidence", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "execution staging must run as root")
    pipeline_lock_fd, pipeline_lock_report = acquire_pipeline_lock()
    odoo = pwd.getpwnam("odoo")
    odoo_gid = grp.getgrnam("odoo").gr_gid
    require(odoo.pw_uid > 0 and odoo.pw_gid == odoo_gid, "Odoo identity is invalid")
    pipeline_transactions = validate_pipeline_transactions(odoo.pw_uid, odoo_gid)
    upload_report = validate_upload_root(odoo.pw_uid)
    require(args.read_plan == UPLOAD_ROOT / "dev8-read-plan.json", "read plan must be the root-private uploaded dev8 plan")
    plan_fd, _plan_meta = secure_read_source(args.read_plan, PLAN_SHA256)
    os.close(plan_fd)
    require(args.read_evidence.is_absolute() and args.read_evidence.parent == Path("/tmp"), "read evidence must be a direct /tmp child")
    require(not os.path.lexists(args.read_evidence), "read evidence path already exists")
    validate_private_output(args.output_directory)

    real_stage: Path | None = None
    real_identity: tuple[int, int] | None = None
    isolation_stage: Path | None = None
    isolation_identity: tuple[int, int] | None = None
    odoo_output: Path | None = None
    odoo_output_identity: tuple[int, int] | None = None
    stages: list[dict[str, object]] = []
    oracle_sources: list[dict[str, object]] = []
    oracle_fixed_identities: dict[str, tuple[int, int]] = {}
    real_result: dict[str, object] | None = None
    oracle_result: dict[str, object] | None = None
    isolation_result: dict[str, object] | None = None
    cleanup = {
        "real_read_stage_absent": False,
        "isolation_stage_absent": False,
        "odoo_output_absent": False,
        **{f"oracle_source_absent:{name}": False for name in ORACLE_SOURCES},
    }
    failure: str | None = None
    try:
        real_stage, real_identity = make_stage("dev8-real-read.", odoo_gid)
        runner_source, runner_staged = stage_file(
            UPLOAD_ROOT / "dev8-run-real-reads.sh",
            real_stage / "dev8-run-real-reads.sh",
            SOURCES["dev8-run-real-reads.sh"],
            uid=0,
            gid=0,
            mode=0o400,
        )
        signer_source, signer_staged = stage_file(
            UPLOAD_ROOT / "dev8-sign-read.py",
            real_stage / "dev8-sign-read.py",
            SOURCES["dev8-sign-read.py"],
            uid=0,
            gid=odoo_gid,
            mode=0o440,
        )
        real_result = run(
            [
                "/usr/bin/bash",
                str(real_stage / "dev8-run-real-reads.sh"),
                str(args.read_evidence),
                str(args.read_plan),
            ],
            600,
        )
        secure_write(args.output_directory / "real-read.stdout", real_result["stdout"])
        secure_write(args.output_directory / "real-read.stderr", real_result["stderr"])
        secure_write(args.output_directory / "real-read.exit", f"{real_result['exit_code']}\n".encode("ascii"))
        stages.extend(
            [
                {
                    "purpose": "real-read-runner",
                    "source_name": "dev8-run-real-reads.sh",
                    "source_sha256": SOURCES["dev8-run-real-reads.sh"],
                    "source_metadata": runner_source,
                    "staging_dir": {"path": str(real_stage), "parent": "/run", "uid": 0, "gid": odoo_gid, "mode": "0750", "random": True},
                    "staged_file": runner_staged,
                    "copy_guards": {"same_fd_source": True, "o_nofollow": True, "o_excl": True, "pre_post_source_identity_equal": True, "fsync": True},
                    "execution": {"uid": 0, "gid": 0, "exit_code": real_result["exit_code"], "output_sha256": real_result["output_sha256"], "timed_out": real_result["timed_out"], "process_group_reaped": real_result["process_group_reaped"]},
                },
                {
                    "purpose": "signer",
                    "source_name": "dev8-sign-read.py",
                    "source_sha256": SOURCES["dev8-sign-read.py"],
                    "source_metadata": signer_source,
                    "staging_dir": {"path": str(real_stage), "parent": "/run", "uid": 0, "gid": odoo_gid, "mode": "0750", "random": True},
                    "staged_file": signer_staged,
                    "copy_guards": {"same_fd_source": True, "o_nofollow": True, "o_excl": True, "pre_post_source_identity_equal": True, "fsync": True},
                    "execution": {"uid": odoo.pw_uid, "gid": odoo_gid, "exit_code": real_result["exit_code"], "output_sha256": sha256_file(args.read_evidence / "summary.json") if real_result["exit_code"] == 0 else None, "mechanism": "exact runner sudo -u odoo", "timed_out": real_result["timed_out"], "process_group_reaped": real_result["process_group_reaped"]},
                },
            ]
        )
        require(real_result["exit_code"] == 0 and real_result["stderr"] == b"", "real-read runner failed")

        oracle_runner_metadata, oracle_runner_staged = stage_file(
            UPLOAD_ROOT / "dev8-run-read-oracles.sh",
            real_stage / "dev8-run-read-oracles.sh",
            SOURCES["dev8-run-read-oracles.sh"],
            uid=0,
            gid=0,
            mode=0o400,
        )
        for source_name in ORACLE_SOURCES:
            fixed_path = Path("/tmp") / source_name
            require(not os.path.lexists(fixed_path), f"fixed oracle source path already exists: {fixed_path}")
            source_metadata, staged_metadata = stage_file(
                UPLOAD_ROOT / source_name,
                fixed_path,
                SOURCES[source_name],
                uid=0,
                gid=0,
                mode=0o444,
            )
            fixed = fixed_path.lstat()
            oracle_fixed_identities[source_name] = (fixed.st_dev, fixed.st_ino)
            oracle_sources.append(
                {
                    "purpose": f"oracle-source:{source_name}",
                    "source_name": source_name,
                    "source_sha256": SOURCES[source_name],
                    "source_metadata": source_metadata,
                    "staging_path": str(fixed_path),
                    "staged_file": staged_metadata,
                    "copy_guards": {
                        "same_fd_source": True,
                        "o_nofollow": True,
                        "o_excl": True,
                        "pre_post_source_identity_equal": True,
                        "fsync": True,
                    },
                    "execution": {
                        "uid": odoo.pw_uid,
                        "gid": odoo_gid,
                        "mechanism": "exact oracle runner root stages a second root:odoo 0440 copy under /run",
                    },
                }
            )
        oracle_result = run(
            [
                "/usr/bin/bash",
                str(real_stage / "dev8-run-read-oracles.sh"),
                str(args.read_evidence),
            ],
            600,
        )
        secure_write(args.output_directory / "read-oracles.stdout", oracle_result["stdout"])
        secure_write(args.output_directory / "read-oracles.stderr", oracle_result["stderr"])
        secure_write(args.output_directory / "read-oracles.exit", f"{oracle_result['exit_code']}\n".encode("ascii"))
        for item in oracle_sources:
            item["execution"].update(
                {
                    "exit_code": oracle_result["exit_code"],
                    "output_sha256": sha256_file(args.read_evidence / "read-oracles.audit.json")
                    if oracle_result["exit_code"] == 0
                    else None,
                    "timed_out": oracle_result["timed_out"],
                    "process_group_reaped": oracle_result["process_group_reaped"],
                }
            )
        require(oracle_result["exit_code"] == 0 and oracle_result["stderr"] == b"", "read-oracle runner failed")

        isolation_stage, isolation_identity = make_stage("dev8-launcher-isolation.", odoo_gid)
        isolation_source, isolation_staged = stage_file(
            UPLOAD_ROOT / "dev8-launcher-isolation-gate.py",
            isolation_stage / "dev8-launcher-isolation-gate.py",
            SOURCES["dev8-launcher-isolation-gate.py"],
            uid=0,
            gid=odoo_gid,
            mode=0o440,
        )
        raw_output = tempfile.mkdtemp(prefix="dev8-isolation-output.", dir="/tmp")
        odoo_output = Path(raw_output)
        os.chown(odoo_output, odoo.pw_uid, odoo_gid)
        os.chmod(odoo_output, 0o700)
        output_meta = odoo_output.lstat()
        odoo_output_identity = (output_meta.st_dev, output_meta.st_ino)
        isolation_report = odoo_output / "launcher-isolation.json"
        isolation_result = run(
            [
                "/usr/bin/sudo",
                "-n",
                "-u",
                "odoo",
                "-g",
                "odoo",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
                "/usr/bin/python3",
                "-I",
                str(isolation_stage / "dev8-launcher-isolation-gate.py"),
                "--output",
                str(isolation_report),
            ],
            120,
        )
        secure_write(args.output_directory / "launcher-isolation.stdout", isolation_result["stdout"])
        secure_write(args.output_directory / "launcher-isolation.stderr", isolation_result["stderr"])
        secure_write(args.output_directory / "launcher-isolation.exit", f"{isolation_result['exit_code']}\n".encode("ascii"))
        require(isolation_result["exit_code"] == 0 and isolation_result["stderr"] == b"", "launcher isolation gate failed")
        current_output_meta = odoo_output.lstat()
        require(
            (current_output_meta.st_dev, current_output_meta.st_ino) == odoo_output_identity,
            "Odoo output directory identity changed",
        )
        report_meta = metadata(isolation_report)
        require(
            report_meta["uid"] == odoo.pw_uid
            and report_meta["gid"] == odoo_gid
            and report_meta["mode"] == "0600"
            and report_meta["nlink"] == 1
            and report_meta["regular"] is True
            and report_meta["not_symlink"] is True,
            "Odoo launcher-isolation output metadata is invalid",
        )
        report_fd = os.open(isolation_report, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(report_fd)
            require((opened.st_dev, opened.st_ino) == (report_meta["device"], report_meta["inode"]), "isolation output changed while opening")
            chunks = []
            while True:
                chunk = os.read(report_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            report_payload = b"".join(chunks)
            opened_after = os.fstat(report_fd)
        finally:
            os.close(report_fd)
        report_after = metadata(isolation_report)
        require(
            (opened_after.st_dev, opened_after.st_ino, opened_after.st_size, opened_after.st_mtime_ns)
            == (report_meta["device"], report_meta["inode"], report_meta["size"], report_meta["mtime_ns"])
            == (report_after["device"], report_after["inode"], report_after["size"], report_after["mtime_ns"])
            and report_payload == isolation_result["stdout"],
            "isolation output changed while copying or differs from stdout",
        )
        secure_write(args.output_directory / "launcher-isolation.json", report_payload)
        stages.append(
            {
                "purpose": "launcher-isolation",
                "source_name": "dev8-launcher-isolation-gate.py",
                "source_sha256": SOURCES["dev8-launcher-isolation-gate.py"],
                "source_metadata": isolation_source,
                "staging_dir": {"path": str(isolation_stage), "parent": "/run", "uid": 0, "gid": odoo_gid, "mode": "0750", "random": True},
                "staged_file": isolation_staged,
                "copy_guards": {"same_fd_source": True, "o_nofollow": True, "o_excl": True, "pre_post_source_identity_equal": True, "fsync": True},
                "execution": {"uid": odoo.pw_uid, "gid": odoo_gid, "exit_code": isolation_result["exit_code"], "output_sha256": isolation_result["output_sha256"], "timed_out": isolation_result["timed_out"], "process_group_reaped": isolation_result["process_group_reaped"]},
            }
        )
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        for source_name in ORACLE_SOURCES:
            try:
                identity = oracle_fixed_identities.get(source_name)
                cleanup[f"oracle_source_absent:{source_name}"] = (
                    not os.path.lexists(Path("/tmp") / source_name)
                    if identity is None
                    else cleanup_fixed_file(
                        Path("/tmp") / source_name,
                        identity,
                        SOURCES[source_name],
                    )
                )
            except Exception as exc:
                cleanup[f"oracle_source_absent:{source_name}"] = False
                failure = failure or f"cleanup: {exc}"
        try:
            cleanup["real_read_stage_absent"] = safe_cleanup(real_stage, Path("/run"), "dev8-real-read.", real_identity)
        except Exception as exc:
            cleanup["real_read_stage_absent"] = False
            failure = failure or f"cleanup: {exc}"
        try:
            cleanup["isolation_stage_absent"] = safe_cleanup(isolation_stage, Path("/run"), "dev8-launcher-isolation.", isolation_identity)
        except Exception as exc:
            cleanup["isolation_stage_absent"] = False
            failure = failure or f"cleanup: {exc}"
        try:
            cleanup["odoo_output_absent"] = safe_cleanup(odoo_output, Path("/tmp"), "dev8-isolation-output.", odoo_output_identity)
        except Exception as exc:
            cleanup["odoo_output_absent"] = False
            failure = failure or f"cleanup: {exc}"

    all_passed = (
        failure is None
        and real_result is not None
        and real_result["exit_code"] == 0
        and real_result["timed_out"] is False
        and real_result["process_group_reaped"] is True
        and oracle_result is not None
        and oracle_result["exit_code"] == 0
        and oracle_result["timed_out"] is False
        and oracle_result["process_group_reaped"] is True
        and isolation_result is not None
        and isolation_result["exit_code"] == 0
        and isolation_result["timed_out"] is False
        and isolation_result["process_group_reaped"] is True
        and len(stages) == 3
        and all(cleanup.values())
    )
    for item in stages:
        item["cleanup"] = {
            "file_absent": cleanup["real_read_stage_absent"] if item["purpose"] in {"real-read-runner", "signer"} else cleanup["isolation_stage_absent"],
            "dir_absent": cleanup["real_read_stage_absent"] if item["purpose"] in {"real-read-runner", "signer"} else cleanup["isolation_stage_absent"],
        }
    for item in oracle_sources:
        source_name = str(item["source_name"])
        absent = cleanup[f"oracle_source_absent:{source_name}"]
        item["cleanup"] = {"file_absent": absent, "dir_absent": True}
    audit = {
        "schema_version": 1,
        "release": RELEASE,
        "pipeline_lock": pipeline_lock_report,
        "pipeline_transactions": pipeline_transactions,
        "upload_root": upload_report,
        "read_plan_sha256": PLAN_SHA256,
        "read_evidence": str(args.read_evidence),
        "stages": stages,
        "oracle": {
            "runner": {
                "source_name": "dev8-run-read-oracles.sh",
                "source_sha256": SOURCES["dev8-run-read-oracles.sh"],
                "source_metadata": {
                    key: value
                    for key, value in oracle_runner_metadata.items()
                    if key not in {"device", "inode", "mtime_ns"}
                }
                if oracle_result is not None
                else None,
                "staging_dir": {
                    "path": str(real_stage),
                    "parent": "/run",
                    "uid": 0,
                    "gid": odoo_gid,
                    "mode": "0750",
                    "random": True,
                }
                if oracle_result is not None
                else None,
                "staged_file": oracle_runner_staged if oracle_result is not None else None,
                "copy_guards": {
                    "same_fd_source": True,
                    "o_nofollow": True,
                    "o_excl": True,
                    "pre_post_source_identity_equal": True,
                    "fsync": True,
                }
                if oracle_result is not None
                else None,
                "execution": {
                    "uid": 0,
                    "gid": 0,
                    "exit_code": oracle_result["exit_code"] if oracle_result is not None else None,
                    "output_sha256": oracle_result["output_sha256"] if oracle_result is not None else None,
                    "timed_out": oracle_result["timed_out"] if oracle_result is not None else None,
                    "process_group_reaped": oracle_result["process_group_reaped"] if oracle_result is not None else None,
                },
                "cleanup": {
                    "file_absent": cleanup["real_read_stage_absent"],
                    "dir_absent": cleanup["real_read_stage_absent"],
                },
            },
            "sources": oracle_sources,
        },
        "source_hashes": SOURCES,
        "cleanup": cleanup,
        "failure": failure,
        "all_checks_passed": all_passed,
        "production_promotion_allowed": False,
    }
    secure_write(
        args.output_directory / "execution-staging-audit.json",
        json.dumps(audit, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    output_fd = os.open(args.output_directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
    fcntl.flock(pipeline_lock_fd, fcntl.LOCK_UN)
    os.close(pipeline_lock_fd)
    print(json.dumps(audit, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if not all_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
