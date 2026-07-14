#!/usr/bin/env bash
set -euo pipefail

release_id=0.1.0.dev8-bd21ca07c168
version=0.1.0.dev8
commit=bd21ca07c1689a42fbf903b91486269397b44733
package_name=odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz
package_sha=58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234
package_size=151492
manifest_sha=fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06
registry_sha=d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e
trusted_root=/opt/odoo-accounting-cli-v3
releases_directory=$trusted_root/releases
packages_directory=$trusted_root/packages
anchors_directory=$trusted_root/trusted-artifacts
release_root=$releases_directory/$release_id
canonical_package=$packages_directory/$package_name
anchor=$anchors_directory/$release_id.json
upload_directory=/root/odoo-accounting-cli-v3-dev8-upload
uploaded_package=$upload_directory/$package_name
uploaded_anchor=$upload_directory/$release_id.anchor.json
pipeline_lock=$trusted_root/.dev8-pipeline.lock
install_lock=$trusted_root/.dev8-install.lock
transaction_journal=$trusted_root/.dev8-install-transaction.json
install_succeeded=0

ensure_trusted_directory() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    test -d "$path"
    test ! -L "$path"
  else
    install -d -o root -g root -m 0755 "$path"
  fi
  test "$(stat -c '%U:%G' "$path")" = root:root
  test $((8#$(stat -c '%a' "$path") & 8#022)) -eq 0
}

prepare_install_lock() {
  local lock_path=$1
  local lock_name=$2
  python3 - "$lock_path" "$trusted_root" "$lock_name" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
parent = pathlib.Path(sys.argv[2])
expected_name = sys.argv[3]
parent_metadata = parent.lstat()
if (
    path.parent != parent
    or path.name != expected_name
    or expected_name not in {".dev8-pipeline.lock", ".dev8-install.lock"}
    or parent.resolve(strict=True) != parent
    or parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or parent_metadata.st_mode & 0o022
):
    raise SystemExit("install lock parent is not trusted")
descriptor = os.open(
    path,
    os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    os.fchown(descriptor, 0, 0)
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    opened = os.fstat(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != 0
        or opened.st_gid != 0
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        or path.is_symlink()
    ):
        raise SystemExit("install pipeline/stage lock metadata mismatch")
finally:
    os.close(descriptor)
PY
}

install_transaction() {
  local action=$1
  local label=${2:-}
  python3 - "$action" "$label" "$transaction_journal" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import uuid

action, label = sys.argv[1:3]
journal = pathlib.Path(sys.argv[3])
root = pathlib.Path("/opt/odoo-accounting-cli-v3")
releases = root / "releases"
packages = root / "packages"
anchors = root / "trusted-artifacts"
release_id = "0.1.0.dev8-bd21ca07c168"
package_name = "odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz"
journal_name = ".dev8-install-transaction.json"
labels = (
    "package_staging",
    "anchor_staging",
    "release_staging",
    "package",
    "release",
    "anchor",
)
parent_paths = {
    "root": root,
    "releases": releases,
    "packages": packages,
    "anchors": anchors,
}

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate journal field: {key}")
        value[key] = item
    return value

def validate_parent(path, expected_parent, expected_name):
    if path.parent != expected_parent or path.name != expected_name:
        raise RuntimeError(f"transaction path mismatch: {path}")
    metadata = expected_parent.lstat()
    if (
        expected_parent.resolve(strict=True) != expected_parent
        or expected_parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError(f"transaction parent is not trusted: {expected_parent}")

validate_parent(journal, root, journal_name)

def object_plan(transaction_id):
    package_stage_name = f".{package_name}.{transaction_id}.staging"
    anchor_stage_name = f".{release_id}.{transaction_id}.anchor.staging"
    release_stage_name = f".{release_id}.{transaction_id}.release.staging"
    return {
        "package_staging": {
            "path": str(packages / package_stage_name),
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "modes": [0o400, 0o444],
            "unique": True,
            "source": None,
            "identity": None,
        },
        "anchor_staging": {
            "path": str(anchors / anchor_stage_name),
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "modes": [0o400, 0o444],
            "unique": True,
            "source": None,
            "identity": None,
        },
        "release_staging": {
            "path": str(releases / release_stage_name),
            "kind": "directory",
            "uid": 0,
            "gid": 0,
            "modes": [0o555],
            "unique": True,
            "source": None,
            "identity": None,
        },
        "package": {
            "path": str(packages / package_name),
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "modes": [0o444],
            "unique": False,
            "source": "package_staging",
            "identity": None,
        },
        "release": {
            "path": str(releases / release_id),
            "kind": "directory",
            "uid": 0,
            "gid": 0,
            "modes": [0o555],
            "unique": False,
            "source": "release_staging",
            "identity": None,
        },
        "anchor": {
            "path": str(anchors / f"{release_id}.json"),
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "modes": [0o444],
            "unique": False,
            "source": "anchor_staging",
            "identity": None,
        },
    }

def encode(document):
    return (
        json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

def parent_identity(path):
    metadata = path.lstat()
    if (
        path.resolve(strict=True) != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError(f"transaction parent is not trusted: {path}")
    return {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "kind": "directory",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }

def write_document(document, *, create):
    import ctypes

    transaction_id = document["transaction_id"]
    temporary = root / f".{journal_name}.{transaction_id}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("transaction journal temporary path already exists")
    if not hasattr(os, "O_TMPFILE"):
        raise RuntimeError("anonymous transaction journal staging is unavailable")
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = os.open(
        root,
        os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
        0o600,
    )
    temporary_linked = False
    try:
        payload = encode(document)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while updating transaction journal")
            view = view[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        libc = ctypes.CDLL(None, use_errno=True)
        linkat = libc.linkat
        linkat.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        linkat.restype = ctypes.c_int
        if create:
            destination_name = journal.name
        else:
            destination_name = temporary.name
        if linkat(descriptor, b"", directory_fd, os.fsencode(destination_name), 0x1000) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), destination_name)
        if not create:
            temporary_linked = True
            os.replace(temporary, journal)
            temporary_linked = False
        os.fsync(directory_fd)
    finally:
        if temporary_linked:
            try:
                metadata = temporary.lstat()
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_uid == 0
                    and metadata.st_gid == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o600
                    and metadata.st_nlink == 1
                    and temporary.parent == root
                    and temporary.name == f".{journal_name}.{transaction_id}.tmp"
                ):
                    temporary.unlink()
            except FileNotFoundError:
                pass
        os.close(descriptor)
        os.close(directory_fd)

def expected_document(document):
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "kind",
        "release",
        "transaction_id",
        "state",
        "parents",
        "objects",
    }:
        raise RuntimeError("transaction journal fields are invalid")
    transaction_id = document.get("transaction_id")
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[0-9a-f]{32}", transaction_id):
        raise RuntimeError("transaction ID is invalid")
    expected = {
        "schema_version": 1,
        "kind": "install",
        "release": release_id,
        "transaction_id": transaction_id,
        "state": document.get("state"),
        "objects": object_plan(transaction_id),
    }
    if (
        not isinstance(document.get("schema_version"), int)
        or isinstance(document.get("schema_version"), bool)
        or document.get("schema_version") != 1
        or document.get("kind") != "install"
        or document.get("release") != release_id
        or document.get("state") not in {"active", "completed"}
    ):
        raise RuntimeError("transaction identity or state is invalid")
    parents = document.get("parents")
    if not isinstance(parents, dict) or set(parents) != set(parent_paths):
        raise RuntimeError("transaction parent records are invalid")
    for parent_label, parent_path in parent_paths.items():
        record = parents[parent_label]
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "identity"}
            or record["path"] != str(parent_path)
            or not isinstance(record["identity"], dict)
            or set(record["identity"])
            != {"dev", "ino", "kind", "uid", "gid", "mode"}
            or not all(
                isinstance(record["identity"][field], int)
                and not isinstance(record["identity"][field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            or record["identity"] != parent_identity(parent_path)
        ):
            raise RuntimeError(f"transaction parent identity mismatch: {parent_label}")
    objects = document.get("objects")
    if not isinstance(objects, dict) or set(objects) != set(labels):
        raise RuntimeError("transaction object plan is invalid")
    for object_label in labels:
        observed = objects[object_label]
        planned = expected["objects"][object_label]
        if not isinstance(observed, dict) or set(observed) != set(planned):
            raise RuntimeError(f"transaction object fields are invalid: {object_label}")
        identity = observed["identity"]
        observed_without_identity = {**observed, "identity": None}
        if encode(observed_without_identity) != encode(planned):
            raise RuntimeError(f"transaction object plan mismatch: {object_label}")
        identity_fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
        if planned["kind"] == "file":
            identity_fields |= {"size", "sha256"}
        if identity is not None and (
            not isinstance(identity, dict)
            or set(identity) != identity_fields
            or not all(
                isinstance(identity[field], int) and not isinstance(identity[field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            or identity["kind"] != planned["kind"]
            or identity["uid"] != planned["uid"]
            or identity["gid"] != planned["gid"]
            or identity["mode"] not in planned["modes"]
            or (
                planned["kind"] == "file"
                and (
                    not isinstance(identity["size"], int)
                    or isinstance(identity["size"], bool)
                    or identity["size"] < 0
                    or not isinstance(identity["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", identity["sha256"])
                )
            )
        ):
            raise RuntimeError(f"transaction object identity is invalid: {object_label}")
    if document["state"] == "completed":
        for object_label, planned in expected["objects"].items():
            source = planned["source"]
            if source is not None and objects[object_label]["identity"] != objects[source]["identity"]:
                raise RuntimeError(f"transaction object source identity mismatch: {object_label}")
    return expected

def load_document():
    descriptor = os.open(
        journal, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        current = journal.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or journal.is_symlink()
            or journal.resolve(strict=True) != journal
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise RuntimeError("transaction journal metadata mismatch")
        payload = b""
        while True:
            chunk = os.read(descriptor, 16_384)
            if not chunk:
                break
            payload += chunk
            if len(payload) > 1_048_576:
                raise RuntimeError("transaction journal is too large")
    finally:
        os.close(descriptor)
    document = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    expected_document(document)
    temporary = root / f".{journal_name}.{document['transaction_id']}.tmp"
    if temporary.exists() or temporary.is_symlink():
        temporary_descriptor = os.open(
            temporary, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            temporary_opened = os.fstat(temporary_descriptor)
            temporary_current = temporary.lstat()
            if (
                not stat.S_ISREG(temporary_opened.st_mode)
                or temporary.is_symlink()
                or temporary.resolve(strict=True) != temporary
                or temporary_opened.st_uid != 0
                or temporary_opened.st_gid != 0
                or stat.S_IMODE(temporary_opened.st_mode) != 0o600
                or temporary_opened.st_nlink != 1
                or (temporary_opened.st_dev, temporary_opened.st_ino)
                != (temporary_current.st_dev, temporary_current.st_ino)
            ):
                raise RuntimeError("transaction journal temporary metadata mismatch")
            temporary_payload = b""
            while True:
                chunk = os.read(temporary_descriptor, 16_384)
                if not chunk:
                    break
                temporary_payload += chunk
                if len(temporary_payload) > 1_048_576:
                    raise RuntimeError("transaction journal temporary is too large")
            temporary_document = json.loads(
                temporary_payload.decode("utf-8"), object_pairs_hook=reject_duplicates
            )
            expected_document(temporary_document)
            if temporary_document["transaction_id"] != document["transaction_id"]:
                raise RuntimeError("transaction journal temporary ID mismatch")
            final_current = temporary.lstat()
            if (final_current.st_dev, final_current.st_ino) != (
                temporary_opened.st_dev,
                temporary_opened.st_ino,
            ):
                raise RuntimeError("transaction journal temporary changed")
            temporary.unlink()
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(temporary_descriptor)
    return document

def file_fingerprint(value):
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode), value.st_nlink,
    )

def current_identity(path, plan):
    metadata = path.lstat()
    kind = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "other"
    )
    if (
        kind != plan["kind"]
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or metadata.st_uid != plan["uid"]
        or metadata.st_gid != plan["gid"]
        or stat.S_IMODE(metadata.st_mode) not in plan["modes"]
        or (kind == "file" and metadata.st_nlink != 1)
    ):
        raise RuntimeError(f"transaction object metadata mismatch: {path}")
    identity = {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "kind": kind,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }
    if kind == "file":
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            opened = os.fstat(descriptor)
            if file_fingerprint(opened) != file_fingerprint(metadata):
                raise RuntimeError(f"transaction object changed: {path}")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = path.lstat()
        if not (
            file_fingerprint(metadata)
            == file_fingerprint(opened_after)
            == file_fingerprint(current)
        ):
            raise RuntimeError(f"transaction object changed: {path}")
        identity["size"] = total
        identity["sha256"] = digest.hexdigest()
    return identity

def fsync_parent(path):
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def remove_tree(path, plan, expected_identity):
    observed = current_identity(path, plan)
    if expected_identity is not None and observed != expected_identity:
        raise RuntimeError(f"transaction directory identity mismatch: {path}")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RuntimeError("transaction recovery requires symlink-safe rmtree")
    for walk_root, directory_names, file_names in os.walk(path, followlinks=False):
        for child_name in [*directory_names, *file_names]:
            child = pathlib.Path(walk_root) / child_name
            child_metadata = child.lstat()
            if (
                child_metadata.st_uid != 0
                or child_metadata.st_gid != 0
                or not (
                    stat.S_ISDIR(child_metadata.st_mode)
                    or stat.S_ISREG(child_metadata.st_mode)
                )
            ):
                raise RuntimeError(f"unsafe transaction directory member: {child}")
    shutil.rmtree(path)
    fsync_parent(path)

if action == "create":
    if journal.exists() or journal.is_symlink():
        raise SystemExit("install transaction already exists")
    transaction_id = uuid.uuid4().hex
    document = {
        "schema_version": 1,
        "kind": "install",
        "release": release_id,
        "transaction_id": transaction_id,
        "state": "active",
        "parents": {
            parent_label: {
                "path": str(parent_path),
                "identity": parent_identity(parent_path),
            }
            for parent_label, parent_path in parent_paths.items()
        },
        "objects": object_plan(transaction_id),
    }
    write_document(document, create=True)
    print(transaction_id)
elif action == "record":
    if label not in labels:
        raise SystemExit("unknown install transaction object")
    document = load_document()
    if document["state"] != "active":
        raise SystemExit("cannot record a completed install transaction")
    plan = document["objects"][label]
    path = pathlib.Path(plan["path"])
    identity = current_identity(path, plan)
    source_label = plan["source"]
    if source_label is not None:
        source_identity = document["objects"][source_label]["identity"]
        if source_identity is None or identity != source_identity:
            raise SystemExit("published object is not the recorded staging inode")
    document["objects"][label]["identity"] = identity
    write_document(document, create=False)
elif action == "recover":
    if not journal.exists() and not journal.is_symlink():
        raise SystemExit(0)
    document = load_document()
    if document["state"] == "completed":
        for object_label in ("package", "release", "anchor"):
            plan = document["objects"][object_label]
            identity = plan["identity"]
            if identity is None or current_identity(pathlib.Path(plan["path"]), plan) != identity:
                raise SystemExit(f"completed install identity mismatch: {object_label}")
        for object_label in ("package_staging", "release_staging", "anchor_staging"):
            path = pathlib.Path(document["objects"][object_label]["path"])
            if path.exists() or path.is_symlink():
                raise SystemExit(f"completed install retains staging: {object_label}")
        print(f"completed_install_transaction={document['transaction_id']}")
        raise SystemExit(0)
    errors = []
    for object_label in (
        "anchor",
        "release",
        "package",
        "release_staging",
        "anchor_staging",
        "package_staging",
    ):
        plan = document["objects"][object_label]
        path = pathlib.Path(plan["path"])
        if not path.exists() and not path.is_symlink():
            continue
        identity = plan["identity"]
        if identity is None and plan["source"] is not None:
            identity = document["objects"][plan["source"]]["identity"]
        if identity is None and not plan["unique"]:
            errors.append(f"{object_label}: fixed path has no recorded source identity")
            continue
        try:
            observed = current_identity(path, plan)
            if identity is not None and observed != identity:
                raise RuntimeError("identity does not match transaction journal")
            if plan["kind"] == "directory":
                remove_tree(path, plan, identity)
            else:
                path.unlink()
                fsync_parent(path)
        except Exception as exc:
            errors.append(f"{object_label}: {exc}")
    if errors:
        raise SystemExit("install transaction recovery refused: " + "; ".join(errors))
    journal.unlink()
    fsync_parent(journal)
    print(f"recovered_install_transaction={document['transaction_id']}")
elif action == "commit":
    document = load_document()
    if document["state"] != "active":
        raise SystemExit("install transaction is already completed")
    for object_label in ("package", "release", "anchor"):
        plan = document["objects"][object_label]
        identity = plan["identity"]
        if identity is None:
            raise SystemExit(f"cannot commit without identity: {object_label}")
        current = current_identity(pathlib.Path(plan["path"]), plan)
        if current != identity:
            raise SystemExit(f"commit identity mismatch: {object_label}")
    for object_label in ("package_staging", "release_staging", "anchor_staging"):
        path = pathlib.Path(document["objects"][object_label]["path"])
        if path.exists() or path.is_symlink():
            raise SystemExit(f"cannot commit while staging exists: {object_label}")
    document["state"] = "completed"
    write_document(document, create=False)
elif action == "status":
    document = load_document()
    print(document["state"])
else:
    raise SystemExit("unknown install transaction action")
PY
}

create_stable_copy() {
  local source=$1
  local destination=$2
  local expected_sha=$3
  local expected_size=$4
  local expected_parent=$5
  local expected_name=$6
  python3 - "$source" "$destination" "$expected_sha" "$expected_size" \
    "$expected_parent" "$expected_name" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_sha = sys.argv[3]
expected_size = int(sys.argv[4]) if sys.argv[4] else None
expected_parent = pathlib.Path(sys.argv[5])
expected_name = sys.argv[6]
parent_metadata = expected_parent.lstat()
if (
    destination.parent != expected_parent
    or destination.name != expected_name
    or expected_parent.resolve(strict=True) != expected_parent
    or expected_parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or parent_metadata.st_mode & 0o022
):
    raise SystemExit("stable-copy destination parent is not trusted")
source_fd = os.open(
    source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
destination_created = False
destination_identity = None
try:
    source_metadata = os.fstat(source_fd)
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_uid != 0
        or source_metadata.st_gid != 0
        or source_metadata.st_nlink != 1
        or source_metadata.st_mode & 0o022
    ):
        raise SystemExit("uploaded source is not a root-managed single-link file")
    destination_fd = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    destination_created = True
    destination_identity = os.fstat(destination_fd)
    digest = hashlib.sha256()
    total = 0
    try:
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
                    raise OSError("short write while creating stable copy")
                view = view[written:]
        if expected_size is not None and total != expected_size:
            raise SystemExit("uploaded source size mismatch")
        if expected_sha and digest.hexdigest() != expected_sha:
            raise SystemExit("uploaded source digest mismatch")
        os.fchown(destination_fd, 0, 0)
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    metadata = destination.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or destination.is_symlink()
        or destination.resolve(strict=True) != destination
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
        or metadata.st_size != total
    ):
        raise SystemExit("stable-copy metadata mismatch")
    directory_fd = os.open(expected_parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except BaseException:
    if destination_created:
        try:
            metadata = destination.lstat()
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and destination.parent == expected_parent
                and destination.name == expected_name
                and destination_identity is not None
                and (metadata.st_dev, metadata.st_ino)
                == (destination_identity.st_dev, destination_identity.st_ino)
            ):
                destination.unlink()
                directory_fd = os.open(
                    expected_parent, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(source_fd)
PY
}

publish_staged_file() {
  local staging=$1
  local destination=$2
  local expected_parent=$3
  local staging_name=$4
  local destination_name=$5
  local expected_sha=$6
  local expected_size=$7
  python3 - "$staging" "$destination" "$expected_parent" "$staging_name" \
    "$destination_name" "$expected_sha" "$expected_size" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

staging = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_parent = pathlib.Path(sys.argv[3])
staging_name = sys.argv[4]
destination_name = sys.argv[5]
expected_sha = sys.argv[6]
expected_size = int(sys.argv[7]) if sys.argv[7] else None
parent_metadata = expected_parent.lstat()
if (
    staging.parent != expected_parent
    or destination.parent != expected_parent
    or staging.name != staging_name
    or destination.name != destination_name
    or expected_parent.resolve(strict=True) != expected_parent
    or expected_parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or parent_metadata.st_mode & 0o022
):
    raise SystemExit("atomic-publish parent or name mismatch")
descriptor = os.open(
    staging, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
destination_created = False
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or stat.S_IMODE(before.st_mode) != 0o444
        or before.st_nlink != 1
    ):
        raise SystemExit("atomic-publish staging metadata mismatch")
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    if expected_size is not None and total != expected_size:
        raise SystemExit("atomic-publish staging size mismatch")
    if expected_sha and digest.hexdigest() != expected_sha:
        raise SystemExit("atomic-publish staging digest mismatch")
    os.link(staging, destination, follow_symlinks=False)
    destination_created = True
    destination_metadata = destination.lstat()
    if (
        not stat.S_ISREG(destination_metadata.st_mode)
        or destination.is_symlink()
        or destination_metadata.st_uid != 0
        or destination_metadata.st_gid != 0
        or stat.S_IMODE(destination_metadata.st_mode) != 0o444
        or (destination_metadata.st_dev, destination_metadata.st_ino)
        != (before.st_dev, before.st_ino)
    ):
        raise SystemExit("atomic-publish destination metadata mismatch")
    staging.unlink()
    if destination.lstat().st_nlink != 1:
        raise SystemExit("atomic-publish destination link count mismatch")
    directory_fd = os.open(expected_parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    destination_created = False
except BaseException:
    if destination_created:
        try:
            metadata = destination.lstat()
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and destination.parent == expected_parent
                and destination.name == destination_name
                and (metadata.st_dev, metadata.st_ino)
                == (before.st_dev, before.st_ino)
            ):
                destination.unlink()
                directory_fd = os.open(
                    expected_parent, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(descriptor)
PY
}

rollback_install() {
  local original_status=$?
  trap - EXIT HUP INT TERM
  if [[ "$install_succeeded" = 1 ]]; then
    return 0
  fi
  set +e
  install_transaction recover
  local rollback_status=$?
  set -e
  if [[ "$rollback_status" -ne 0 ]]; then
    printf 'dev8 install failed with status %s; journal recovery failed\n' \
      "$original_status" >&2
    exit 97
  fi
  exit "$original_status"
}

verify_completed_install() {
  test ! -e "$trusted_root/current"
  test ! -L "$trusted_root/current"
  test -f "$canonical_package"
  test ! -L "$canonical_package"
  test "$(stat -c '%U:%G %a %s %h' "$canonical_package")" = \
    "root:root 444 $package_size 1"
  test "$(sha256sum "$canonical_package" | cut -d' ' -f1)" = "$package_sha"
  test -f "$anchor"
  test ! -L "$anchor"
  test "$(stat -c '%U:%G %a %h' "$anchor")" = "root:root 444 1"
  test -d "$release_root"
  test ! -L "$release_root"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release_root/src" \
    python3 -B "$release_root/tools/verify_release.py" "$release_root" "$manifest_sha"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release_root/src" \
  python3 -B - "$release_root" "$anchor" "$version" "$commit" \
    "$manifest_sha" "$package_sha" "$registry_sha" <<'PY'
import json
import pathlib
import stat
import sys

from odoo_accounting_cli_v3.registry import load_registry, registry_digest

root = pathlib.Path(sys.argv[1])
anchor_path = pathlib.Path(sys.argv[2])
version, commit, manifest_sha, package_sha, expected_registry = sys.argv[3:]
anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
if anchor != {
    "commit": commit,
    "manifest_sha256": manifest_sha,
    "package_sha256": package_sha,
    "release": root.name,
}:
    raise SystemExit("installed anchor identity mismatch")
manifest = json.loads((root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
if (
    manifest.get("version") != version
    or manifest.get("commit") != commit
    or manifest.get("manifest_sha256") != manifest_sha
):
    raise SystemExit("installed release identity mismatch")
observed_registry = registry_digest(load_registry(root / "registry/capabilities.json"))
if observed_registry != expected_registry:
    raise SystemExit("installed registry digest mismatch")
launcher = root / "bin/odoo-accounting-cli-v3"
for path in [root, *root.rglob("*")]:
    metadata = path.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"non-root installed release owner: {path.relative_to(root)}")
    if stat.S_ISDIR(metadata.st_mode):
        expected_mode = 0o555
    elif stat.S_ISREG(metadata.st_mode):
        expected_mode = 0o555 if path == launcher else 0o444
        if metadata.st_nlink != 1:
            raise SystemExit(f"linked installed release file: {path.relative_to(root)}")
    else:
        raise SystemExit(f"unsafe installed release path type: {path.relative_to(root)}")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise SystemExit(f"installed release mode mismatch: {path.relative_to(root)}")
print("completed_install_content_verified=true")
PY
}

test -d /opt
test ! -L /opt
ensure_trusted_directory "$trusted_root"
ensure_trusted_directory "$releases_directory"
ensure_trusted_directory "$packages_directory"
ensure_trusted_directory "$anchors_directory"
prepare_install_lock "$pipeline_lock" .dev8-pipeline.lock
exec {pipeline_lock_fd}<>"$pipeline_lock"
/usr/bin/flock --exclusive "$pipeline_lock_fd"
prepare_install_lock "$install_lock" .dev8-install.lock
exec {install_lock_fd}<>"$install_lock"
/usr/bin/flock --exclusive "$install_lock_fd"

if [[ -e "$transaction_journal" || -L "$transaction_journal" ]]; then
  transaction_state=$(install_transaction status)
  if [[ "$transaction_state" = completed ]]; then
    install_transaction recover
    verify_completed_install
    printf 'installed_release=%s\npackage_path=%s\npackage_sha256=%s\nmanifest_sha256=%s\nregistry_digest=%s\nalready_installed=true\n' \
      "$release_id" "$canonical_package" "$package_sha" "$manifest_sha" "$registry_sha"
    exit 0
  fi
  test "$transaction_state" = active
  install_transaction recover
fi

python3 - "$upload_directory" "$uploaded_package" "$uploaded_anchor" <<'PY'
import pathlib
import stat
import sys

upload = pathlib.Path(sys.argv[1])
root = pathlib.Path("/root")
root_metadata = root.lstat()
upload_metadata = upload.lstat()
if (
    upload.parent != root
    or upload.name != "odoo-accounting-cli-v3-dev8-upload"
    or root.resolve(strict=True) != root
    or root.is_symlink()
    or not stat.S_ISDIR(root_metadata.st_mode)
    or root_metadata.st_uid != 0
    or root_metadata.st_gid != 0
    or root_metadata.st_mode & 0o077
    or upload.resolve(strict=True) != upload
    or upload.is_symlink()
    or not stat.S_ISDIR(upload_metadata.st_mode)
    or upload_metadata.st_uid != 0
    or upload_metadata.st_gid != 0
    or stat.S_IMODE(upload_metadata.st_mode) != 0o700
):
    raise SystemExit("dev8 upload directory is not root-private")
for raw_path in sys.argv[2:]:
    path = pathlib.Path(raw_path)
    metadata = path.lstat()
    if (
        path.parent != upload
        or not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise SystemExit(f"uploaded artifact is not root-managed: {path}")
print("uploaded_artifact_metadata_verified=true")
PY

for target in "$release_root" "$canonical_package" "$anchor"; do
  test ! -e "$target"
  test ! -L "$target"
done
test ! -e "$trusted_root/current"
test ! -L "$trusted_root/current"

trap rollback_install EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

transaction_id=$(install_transaction create)
test "$transaction_id" != ""
canonical_package_staging=$packages_directory/.$package_name.$transaction_id.staging
anchor_staging=$anchors_directory/.$release_id.$transaction_id.anchor.staging
release_staging=$releases_directory/.$release_id.$transaction_id.release.staging
launcher=$release_staging/bin/odoo-accounting-cli-v3

create_stable_copy \
  "$uploaded_package" "$canonical_package_staging" "$package_sha" "$package_size" \
  "$packages_directory" ".$package_name.$transaction_id.staging"
install_transaction record package_staging
create_stable_copy \
  "$uploaded_anchor" "$anchor_staging" "" "" \
  "$anchors_directory" ".$release_id.$transaction_id.anchor.staging"
install_transaction record anchor_staging

python3 - "$canonical_package_staging" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
seen = set()
with tarfile.open(archive, "r:gz") as value:
    members = value.getmembers()
    for member in members:
        raw = member.name.rstrip("/") if member.isdir() else member.name
        path = pathlib.PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != raw
        ):
            raise SystemExit(f"unsafe archive path: {member.name!r}")
        normalized = path.as_posix()
        if normalized in seen:
            raise SystemExit(f"duplicate archive path: {normalized}")
        seen.add(normalized)
        if not (member.isdir() or member.isreg()):
            raise SystemExit(f"unsafe archive member type: {normalized}")
    if "RELEASE-MANIFEST.json" not in seen:
        raise SystemExit("release manifest is missing")
    if "bin/odoo-accounting-cli-v3" not in seen:
        raise SystemExit("canonical release launcher is missing")
print(f"archive_members_verified={len(seen)}")
PY

python3 - "$anchor_staging" <<'PY'
import json
import pathlib
import sys

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate anchor field: {key}")
        value[key] = item
    return value

anchor = json.loads(
    pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
expected = {
    "commit": "bd21ca07c1689a42fbf903b91486269397b44733",
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "release": "0.1.0.dev8-bd21ca07c168",
}
if anchor != expected:
    raise SystemExit("external anchor mismatch")
print("stable_anchor_verified=true")
PY

mkdir --mode=0555 "$release_staging"
chown root:root "$release_staging"
install_transaction record release_staging
tar --extract --gzip --file "$canonical_package_staging" \
  --directory "$release_staging" --no-same-owner --no-same-permissions
chown -R root:root "$release_staging"
find "$release_staging" -type d -exec chmod 0555 {} +
find "$release_staging" -type f -exec chmod 0444 {} +
chmod 0555 "$launcher"

PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release_staging/src" \
  python3 -B "$release_staging/tools/verify_release.py" \
  "$release_staging" "$manifest_sha"

PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release_staging/src" \
python3 - "$release_staging" "$version" "$commit" "$manifest_sha" "$registry_sha" <<'PY'
import json
import pathlib
import stat
import sys

from odoo_accounting_cli_v3.registry import load_registry, registry_digest

root = pathlib.Path(sys.argv[1])
version, commit, manifest_sha, expected_registry = sys.argv[2:]
manifest = json.loads((root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
if manifest.get("version") != version or manifest.get("commit") != commit:
    raise SystemExit("embedded release identity mismatch")
if manifest.get("manifest_sha256") != manifest_sha:
    raise SystemExit("embedded manifest digest mismatch")
observed_registry = registry_digest(load_registry(root / "registry/capabilities.json"))
if observed_registry != expected_registry:
    raise SystemExit("registry digest mismatch")
launcher = root / "bin/odoo-accounting-cli-v3"
for path in [root, *root.rglob("*")]:
    metadata = path.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"non-root release owner: {path.relative_to(root)}")
    if stat.S_ISDIR(metadata.st_mode):
        expected_mode = 0o555
    elif stat.S_ISREG(metadata.st_mode):
        expected_mode = 0o555 if path == launcher else 0o444
        if metadata.st_nlink != 1:
            raise SystemExit(f"linked release file: {path.relative_to(root)}")
    else:
        raise SystemExit(f"unsafe release path type: {path.relative_to(root)}")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise SystemExit(f"release mode mismatch: {path.relative_to(root)}")
print(f"release_files_verified={len(manifest['files'])}")
print(f"registry_digest={observed_registry}")
PY

publish_staged_file \
  "$canonical_package_staging" "$canonical_package" "$packages_directory" \
  ".$package_name.$transaction_id.staging" "$package_name" "$package_sha" "$package_size"
install_transaction record package

mv -T --no-clobber "$release_staging" "$release_root"
test ! -e "$release_staging"
test ! -L "$release_staging"
python3 - "$releases_directory" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if (
    path != pathlib.Path("/opt/odoo-accounting-cli-v3/releases")
    or path.resolve(strict=True) != path
    or path.is_symlink()
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_mode & 0o022
):
    raise SystemExit("release publish parent is not trusted")
descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
install_transaction record release

publish_staged_file \
  "$anchor_staging" "$anchor" "$anchors_directory" \
  ".$release_id.$transaction_id.anchor.staging" "$release_id.json" "" ""
install_transaction record anchor

test ! -e "$trusted_root/current"
test ! -L "$trusted_root/current"
test "$(stat -c '%U:%G %a %s %h' "$canonical_package")" = \
  "root:root 444 $package_size 1"
test "$(sha256sum "$canonical_package" | cut -d' ' -f1)" = "$package_sha"
PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release_root/src" \
  python3 -B "$release_root/tools/verify_release.py" "$release_root" "$manifest_sha"

verify_completed_install
/usr/bin/sync --file-system "$release_root" "$canonical_package" "$anchor"
install_transaction commit
install_succeeded=1
trap - EXIT HUP INT TERM
printf 'installed_release=%s\npackage_path=%s\npackage_sha256=%s\nmanifest_sha256=%s\nregistry_digest=%s\ntransaction_id=%s\n' \
  "$release_id" "$canonical_package" "$package_sha" "$manifest_sha" "$registry_sha" \
  "$transaction_id"
