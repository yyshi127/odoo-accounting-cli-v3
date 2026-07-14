#!/usr/bin/env bash
set -euo pipefail

release_id=0.1.0.dev8-bd21ca07c168
release=/opt/odoo-accounting-cli-v3/releases/$release_id
package_name=odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz
package=/opt/odoo-accounting-cli-v3/packages/$package_name
package_sha=58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234
package_size=151492
manifest_sha=fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06
candidate=/var/lib/odoo-accounting-cli-v3/test/candidates/$release_id
candidate_staging_parent=/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging
upload_directory=/root/odoo-accounting-cli-v3-dev8-upload
uploaded_config=$upload_directory/runtime-test-dev8.json
config=/etc/odoo-accounting-cli-v3/runtime-test-dev8.json
config_sha=a089d13a2418225e245d10cf76728ad6af31ce0b5fde9f5b14902c44eebe59b7
config_size=1438
auth_secret=/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac
receipt_secret=/etc/odoo-accounting-cli-v3/secrets/test/dev8-receipt.hmac
pipeline_lock=/opt/odoo-accounting-cli-v3/.dev8-pipeline.lock
runtime_lock=/etc/odoo-accounting-cli-v3/.dev8-runtime.lock
transaction_journal=/etc/odoo-accounting-cli-v3/.dev8-runtime-transaction.json
runtime_setup_succeeded=0

prepare_runtime_lock() {
  local lock_path=$1
  local lock_parent=$2
  local lock_name=$3
  python3 - "$lock_path" "$lock_parent" "$lock_name" <<'PY'
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
    or (str(parent), expected_name)
    not in {
        ("/opt/odoo-accounting-cli-v3", ".dev8-pipeline.lock"),
        ("/etc/odoo-accounting-cli-v3", ".dev8-runtime.lock"),
    }
    or parent.resolve(strict=True) != parent
    or parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or parent_metadata.st_mode & 0o022
):
    raise SystemExit("runtime lock parent is not trusted")
descriptor = os.open(
    path,
    os.O_RDWR
    | os.O_CREAT
    | os.O_CLOEXEC
    | getattr(os, "O_NOFOLLOW", 0),
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
        raise SystemExit("runtime pipeline/stage lock metadata mismatch")
finally:
    os.close(descriptor)
PY
}

prepare_candidate_staging_parent() {
  local action=$1
  python3 - "$candidate_staging_parent" "$action" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
action = sys.argv[2]
parent = pathlib.Path("/var/lib/odoo-accounting-cli-v3")
parent_metadata = parent.lstat()
if (
    path.parent != parent
    or path.name != "dev8-transaction-staging"
    or parent.resolve(strict=True) != parent
    or parent.is_symlink()
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or parent_metadata.st_uid != 0
    or parent_metadata.st_gid != 0
    or parent_metadata.st_mode & 0o022
):
    raise SystemExit("candidate staging base is not root-managed")
if action == "create":
    try:
        os.mkdir(path, 0o700)
        created = True
    except FileExistsError:
        created = False
    if created:
        os.chown(path, 0, 0)
        os.chmod(path, 0o700)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
elif action != "verify":
    raise SystemExit("candidate staging parent action is invalid")
metadata = path.lstat()
if (
    path.resolve(strict=True) != path
    or path.is_symlink()
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit("candidate staging parent metadata mismatch")
PY
}

# Runtime transaction helpers are defined below.
verify_completed_install_transaction() {
  python3 - /opt/odoo-accounting-cli-v3/.dev8-install-transaction.json <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

journal = pathlib.Path(sys.argv[1])
root = pathlib.Path("/opt/odoo-accounting-cli-v3")
release_id = "0.1.0.dev8-bd21ca07c168"
package_name = "odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz"

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate install-completion field: {key}")
        value[key] = item
    return value

def canonical(value):
    return json.dumps(
        value, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

def completion_file_fingerprint(value):
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode), value.st_nlink,
    )

def identity(path, kind, uid, gid, mode):
    metadata = path.lstat()
    if (
        path.is_symlink()
        or path.resolve(strict=True) != path
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or (kind == "file" and not stat.S_ISREG(metadata.st_mode))
        or (kind == "file" and metadata.st_nlink != 1)
        or (kind == "directory" and not stat.S_ISDIR(metadata.st_mode))
    ):
        raise SystemExit(f"install completion object metadata mismatch: {path}")
    result = {
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
            if completion_file_fingerprint(opened) != completion_file_fingerprint(metadata):
                raise SystemExit("install completion object changed")
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
        after = path.lstat()
        if not (
            completion_file_fingerprint(metadata)
            == completion_file_fingerprint(opened_after)
            == completion_file_fingerprint(after)
        ):
            raise SystemExit("install completion object changed")
        result["size"] = total
        result["sha256"] = digest.hexdigest()
    return result

descriptor = os.open(
    journal, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
try:
    opened = os.fstat(descriptor)
    current = journal.lstat()
    if (
        journal.parent != root
        or journal.name != ".dev8-install-transaction.json"
        or not stat.S_ISREG(opened.st_mode)
        or journal.is_symlink()
        or journal.resolve(strict=True) != journal
        or opened.st_uid != 0
        or opened.st_gid != 0
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise SystemExit("install completion journal metadata mismatch")
    payload = b""
    while True:
        chunk = os.read(descriptor, 16_384)
        if not chunk:
            break
        payload += chunk
        if len(payload) > 1_048_576:
            raise SystemExit("install completion journal is too large")
finally:
    os.close(descriptor)
document = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
if (
    not isinstance(document, dict)
    or set(document)
    != {
        "schema_version",
        "kind",
        "release",
        "transaction_id",
        "state",
        "parents",
        "objects",
    }
    or not isinstance(document["schema_version"], int)
    or isinstance(document["schema_version"], bool)
    or document["schema_version"] != 1
    or document["kind"] != "install"
    or document["release"] != release_id
    or document["state"] != "completed"
    or not isinstance(document["transaction_id"], str)
    or not re.fullmatch(r"[0-9a-f]{32}", document["transaction_id"])
):
    raise SystemExit("install completion journal identity mismatch")
transaction_id = document["transaction_id"]
releases = root / "releases"
packages = root / "packages"
anchors = root / "trusted-artifacts"
expected_parents = {
    "root": root,
    "releases": releases,
    "packages": packages,
    "anchors": anchors,
}
if not isinstance(document["parents"], dict) or set(document["parents"]) != set(
    expected_parents
):
    raise SystemExit("install completion parent records mismatch")
for label, path in expected_parents.items():
    record = document["parents"][label]
    mode = stat.S_IMODE(path.lstat().st_mode)
    if (
        not isinstance(record, dict)
        or set(record) != {"path", "identity"}
        or record["path"] != str(path)
        or not isinstance(record["identity"], dict)
        or set(record["identity"]) != {"dev", "ino", "kind", "uid", "gid", "mode"}
        or not all(
            isinstance(record["identity"][field], int)
            and not isinstance(record["identity"][field], bool)
            for field in ("dev", "ino", "uid", "gid", "mode")
        )
        or record["identity"] != identity(path, "directory", 0, 0, mode)
        or mode & 0o022
    ):
        raise SystemExit(f"install completion parent mismatch: {label}")
plans = {
    "package_staging": (
        packages / f".{package_name}.{transaction_id}.staging",
        "file",
        [0o400, 0o444],
        True,
        None,
    ),
    "anchor_staging": (
        anchors / f".{release_id}.{transaction_id}.anchor.staging",
        "file",
        [0o400, 0o444],
        True,
        None,
    ),
    "release_staging": (
        releases / f".{release_id}.{transaction_id}.release.staging",
        "directory",
        [0o555],
        True,
        None,
    ),
    "package": (packages / package_name, "file", [0o444], False, "package_staging"),
    "release": (releases / release_id, "directory", [0o555], False, "release_staging"),
    "anchor": (
        anchors / f"{release_id}.json",
        "file",
        [0o444],
        False,
        "anchor_staging",
    ),
}
objects = document["objects"]
if not isinstance(objects, dict) or set(objects) != set(plans):
    raise SystemExit("install completion object records mismatch")
for label, (path, kind, modes, unique, source) in plans.items():
    record = objects[label]
    planned = {
        "path": str(path), "kind": kind, "uid": 0, "gid": 0,
        "modes": modes, "unique": unique, "source": source, "identity": None,
    }
    identity_fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
    if kind == "file":
        identity_fields |= {"size", "sha256"}
    recorded = record.get("identity") if isinstance(record, dict) else None
    if (
        not isinstance(record, dict)
        or set(record) != set(planned)
        or canonical({**record, "identity": None}) != canonical(planned)
        or not isinstance(recorded, dict)
        or set(recorded) != identity_fields
        or not all(
            isinstance(recorded[field], int) and not isinstance(recorded[field], bool)
            for field in ("dev", "ino", "uid", "gid", "mode")
        )
        or recorded["kind"] != kind
        or recorded["uid"] != 0 or recorded["gid"] != 0
        or recorded["mode"] not in modes
        or (
            kind == "file"
            and (
                not isinstance(recorded["size"], int) or isinstance(recorded["size"], bool)
                or recorded["size"] < 0
                or not isinstance(recorded["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", recorded["sha256"])
            )
        )
    ):
        raise SystemExit(f"install completion object plan mismatch: {label}")
    if unique:
        if path.exists() or path.is_symlink():
            raise SystemExit(f"install completion retains staging: {label}")
    elif recorded != identity(path, kind, 0, 0, modes[0]):
        raise SystemExit(f"install completion identity mismatch: {label}")
for label, (_, _, _, _, source) in plans.items():
    if source is not None and objects[label]["identity"] != objects[source]["identity"]:
        raise SystemExit(f"install completion source mismatch: {label}")
package_identity = objects["package"]["identity"]
if (
    package_identity["size"] != 151492
    or package_identity["sha256"]
    != "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
):
    raise SystemExit("install completion package digest mismatch")
anchor_value = json.loads(
    pathlib.Path(plans["anchor"][0]).read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
if anchor_value != {
    "commit": "bd21ca07c1689a42fbf903b91486269397b44733",
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "release": release_id,
}:
    raise SystemExit("install completion anchor mismatch")
release = plans["release"][0]
manifest = json.loads(
    (release / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
if (
    manifest.get("version") != "0.1.0.dev8"
    or manifest.get("commit") != "bd21ca07c1689a42fbf903b91486269397b44733"
    or manifest.get("manifest_sha256")
    != "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06"
):
    raise SystemExit("install completion manifest mismatch")
expected_registry = "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e"
binding = {
    "anchor": objects["anchor"]["identity"],
    "install_transaction_id": transaction_id,
    "manifest_sha256": manifest["manifest_sha256"],
    "package": package_identity,
    "registry_digest": expected_registry,
    "release": objects["release"]["identity"],
}
binding_sha = hashlib.sha256(
    canonical(binding)
).hexdigest()
print(f"{transaction_id}:{binding_sha}")
PY
}

runtime_transaction() {
  local action=$1
  local label=$2
  local upstream_install_transaction_id=${3-}
  local upstream_install_identity_sha256=${4-}
  python3 - "$action" "$label" "$transaction_journal" \
    "$upstream_install_transaction_id" "$upstream_install_identity_sha256" <<'PY'
import ctypes
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import sys
import uuid

action, label = sys.argv[1:3]
journal = pathlib.Path(sys.argv[3])
upstream_install_transaction_id = sys.argv[4]
upstream_install_identity_sha256 = sys.argv[5]
release_id = "0.1.0.dev8-bd21ca07c168"
config_parent = pathlib.Path("/etc/odoo-accounting-cli-v3")
candidate_parent = pathlib.Path("/var/lib/odoo-accounting-cli-v3/test/candidates")
candidate_staging_parent = pathlib.Path(
    "/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging"
)
secret_parent = config_parent / "secrets/test"
config = config_parent / "runtime-test-dev8.json"
candidate = candidate_parent / release_id
auth_secret = secret_parent / "dev8-auth.hmac"
receipt_secret = secret_parent / "dev8-receipt.hmac"
journal_name = ".dev8-runtime-transaction.json"
odoo = pwd.getpwnam("odoo")
odoo_group = grp.getgrnam("odoo")
odoo_owner = [odoo.pw_uid, odoo_group.gr_gid]
labels = (
    "config_staging",
    "candidate_staging",
    "auth_staging",
    "receipt_staging",
    "config",
    "candidate",
    "auth_secret",
    "receipt_secret",
)
parent_paths = {
    "config_parent": config_parent,
    "candidate_parent": candidate_parent,
    "candidate_staging_parent": candidate_staging_parent,
    "secret_parent": secret_parent,
}

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate journal field: {key}")
        value[key] = item
    return value

def validate_journal_parent():
    metadata = config_parent.lstat()
    if (
        journal.parent != config_parent
        or journal.name != journal_name
        or config_parent.resolve(strict=True) != config_parent
        or config_parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError("runtime transaction parent is not trusted")

validate_journal_parent()

def parent_identity(parent_label, path):
    metadata = path.lstat()
    owner = [metadata.st_uid, metadata.st_gid]
    if parent_label == "config_parent":
        owner_allowed = owner == [0, 0]
    elif parent_label == "secret_parent":
        owner_allowed = metadata.st_uid == 0 and metadata.st_gid in {
            0,
            odoo_group.gr_gid,
        }
    elif parent_label == "candidate_staging_parent":
        owner_allowed = owner == [0, 0]
    else:
        owner_allowed = owner in ([0, 0], odoo_owner)
    if (
        path.resolve(strict=True) != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or not owner_allowed
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError(f"runtime transaction parent is not trusted: {path}")
    return {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "kind": "directory",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }

def object_plan(transaction_id):
    config_stage = config_parent / (
        f".runtime-test-dev8.json.{transaction_id}.staging"
    )
    candidate_stage = candidate_staging_parent / (
        f".{release_id}.{transaction_id}.candidate.staging"
    )
    auth_stage = secret_parent / f".dev8-auth.{transaction_id}.hmac.staging"
    receipt_stage = secret_parent / f".dev8-receipt.{transaction_id}.hmac.staging"

    def item(
        path,
        kind,
        uid,
        gid,
        modes,
        unique,
        source,
        unrecorded_owners,
        unrecorded_modes,
    ):
        return {
            "path": str(path),
            "kind": kind,
            "uid": uid,
            "gid": gid,
            "modes": modes,
            "unique": unique,
            "source": source,
            "unrecorded_owners": unrecorded_owners,
            "unrecorded_modes": unrecorded_modes,
            "identity": None,
        }

    return {
        "config_staging": item(
            config_stage,
            "file",
            0,
            0,
            [0o644],
            True,
            None,
            [[0, 0]],
            [0o600, 0o644],
        ),
        "candidate_staging": item(
            candidate_stage,
            "directory",
            odoo.pw_uid,
            odoo_group.gr_gid,
            [0o700],
            True,
            None,
            [[0, 0], odoo_owner],
            [0o700],
        ),
        "auth_staging": item(
            auth_stage,
            "file",
            0,
            odoo_group.gr_gid,
            [0o640],
            True,
            None,
            [[0, 0], [0, odoo_group.gr_gid]],
            [0o600, 0o640],
        ),
        "receipt_staging": item(
            receipt_stage,
            "file",
            0,
            odoo_group.gr_gid,
            [0o640],
            True,
            None,
            [[0, 0], [0, odoo_group.gr_gid]],
            [0o600, 0o640],
        ),
        "config": item(
            config,
            "file",
            0,
            0,
            [0o644],
            False,
            "config_staging",
            [[0, 0]],
            [0o644],
        ),
        "candidate": item(
            candidate,
            "directory",
            odoo.pw_uid,
            odoo_group.gr_gid,
            [0o700],
            False,
            "candidate_staging",
            [odoo_owner],
            [0o700],
        ),
        "auth_secret": item(
            auth_secret,
            "file",
            0,
            odoo_group.gr_gid,
            [0o640],
            False,
            "auth_staging",
            [[0, odoo_group.gr_gid]],
            [0o640],
        ),
        "receipt_secret": item(
            receipt_secret,
            "file",
            0,
            odoo_group.gr_gid,
            [0o640],
            False,
            "receipt_staging",
            [[0, odoo_group.gr_gid]],
            [0o640],
        ),
    }

def encode(document):
    return (
        json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

def file_fingerprint(value):
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode), value.st_nlink,
    )

def current_identity(path, plan, *, unrecorded=False):
    metadata = path.lstat()
    kind = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "other"
    )
    allowed_owners = (
        plan["unrecorded_owners"]
        if unrecorded
        else [[plan["uid"], plan["gid"]]]
    )
    allowed_modes = (
        plan["unrecorded_modes"] if unrecorded else plan["modes"]
    )
    if (
        kind != plan["kind"]
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or [metadata.st_uid, metadata.st_gid] not in allowed_owners
        or stat.S_IMODE(metadata.st_mode) not in allowed_modes
        or (kind == "file" and metadata.st_nlink != 1)
    ):
        raise RuntimeError(f"runtime transaction object metadata mismatch: {path}")
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
                raise RuntimeError(f"runtime transaction object changed: {path}")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 65_536)
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
            raise RuntimeError(f"runtime transaction object changed: {path}")
        identity["size"] = total
        identity["sha256"] = digest.hexdigest()
    return identity

def expected_document(document):
    required = {
        "schema_version",
        "kind",
        "release",
        "transaction_id",
        "upstream_install_transaction_id",
        "upstream_install_identity_sha256",
        "state",
        "parents",
        "objects",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise RuntimeError("runtime transaction journal fields are invalid")
    transaction_id = document.get("transaction_id")
    if (
        not isinstance(transaction_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
    ):
        raise RuntimeError("runtime transaction ID is invalid")
    if (
        not isinstance(document.get("schema_version"), int)
        or isinstance(document.get("schema_version"), bool)
        or document.get("schema_version") != 1
        or document.get("kind") != "runtime"
        or document.get("release") != release_id
        or not isinstance(document.get("upstream_install_transaction_id"), str)
        or not re.fullmatch(
            r"[0-9a-f]{32}", document["upstream_install_transaction_id"]
        )
        or not isinstance(document.get("upstream_install_identity_sha256"), str)
        or not re.fullmatch(
            r"[0-9a-f]{64}", document["upstream_install_identity_sha256"]
        )
        or document.get("state") not in {"active", "completed"}
    ):
        raise RuntimeError("runtime transaction identity is invalid")
    parents = document.get("parents")
    if not isinstance(parents, dict) or set(parents) != set(parent_paths):
        raise RuntimeError("runtime transaction parent records are invalid")
    for parent_label, path in parent_paths.items():
        record = parents[parent_label]
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "identity"}
            or record["path"] != str(path)
            or not isinstance(record["identity"], dict)
            or set(record["identity"]) != {"dev", "ino", "kind", "uid", "gid", "mode"}
            or not all(
                isinstance(record["identity"][field], int)
                and not isinstance(record["identity"][field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            or record["identity"] != parent_identity(parent_label, path)
        ):
            raise RuntimeError(
                f"runtime transaction parent identity mismatch: {parent_label}"
            )
    expected = object_plan(transaction_id)
    objects = document.get("objects")
    if not isinstance(objects, dict) or set(objects) != set(labels):
        raise RuntimeError("runtime transaction object plan is invalid")
    base_identity_fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
    for object_label in labels:
        observed = objects[object_label]
        planned = expected[object_label]
        if not isinstance(observed, dict) or set(observed) != set(planned):
            raise RuntimeError(
                f"runtime transaction object fields are invalid: {object_label}"
            )
        identity = observed["identity"]
        if encode({**observed, "identity": None}) != encode(planned):
            raise RuntimeError(
                f"runtime transaction object plan mismatch: {object_label}"
            )
        if identity is None:
            continue
        identity_fields = (
            base_identity_fields | {"size", "sha256"}
            if planned["kind"] == "file"
            else base_identity_fields
        )
        if (
            not isinstance(identity, dict)
            or set(identity) != identity_fields
            or identity["kind"] != planned["kind"]
            or identity["uid"] != planned["uid"]
            or identity["gid"] != planned["gid"]
            or identity["mode"] not in planned["modes"]
            or not all(
                isinstance(identity[field], int)
                and not isinstance(identity[field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
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
            raise RuntimeError(
                f"runtime transaction object identity is invalid: {object_label}"
            )
    if document["state"] == "completed":
        for object_label, planned in expected.items():
            source = planned["source"]
            if source is not None and objects[object_label]["identity"] != objects[source]["identity"]:
                raise RuntimeError(
                    f"runtime transaction object source identity mismatch: {object_label}"
                )

def write_document(document, *, create):
    transaction_id = document["transaction_id"]
    temporary = config_parent / f".{journal_name}.{transaction_id}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("runtime journal temporary path already exists")
    if not hasattr(os, "O_TMPFILE"):
        raise RuntimeError("anonymous runtime journal staging is unavailable")
    directory_fd = os.open(
        config_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    descriptor = os.open(
        config_parent, os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600
    )
    temporary_linked = False
    try:
        payload = encode(document)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while updating runtime journal")
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
        destination_name = journal.name if create else temporary.name
        if (
            linkat(
                descriptor,
                b"",
                directory_fd,
                os.fsencode(destination_name),
                0x1000,
            )
            != 0
        ):
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
                    and temporary.parent == config_parent
                    and temporary.name
                    == f".{journal_name}.{transaction_id}.tmp"
                ):
                    temporary.unlink()
            except FileNotFoundError:
                pass
        os.close(descriptor)
        os.close(directory_fd)

def read_document(path, expected_name):
    if path.parent != config_parent or path.name != expected_name:
        raise RuntimeError("runtime journal path mismatch")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise RuntimeError("runtime journal metadata mismatch")
        payload = b""
        while True:
            chunk = os.read(descriptor, 16_384)
            if not chunk:
                break
            payload += chunk
            if len(payload) > 1_048_576:
                raise RuntimeError("runtime journal is too large")
    finally:
        os.close(descriptor)
    return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)

def fsync_parent(path):
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def load_document():
    document = read_document(journal, journal_name)
    expected_document(document)
    temporary = config_parent / (
        f".{journal_name}.{document['transaction_id']}.tmp"
    )
    if temporary.exists() or temporary.is_symlink():
        temporary_document = read_document(temporary, temporary.name)
        expected_document(temporary_document)
        if temporary_document["transaction_id"] != document["transaction_id"]:
            raise RuntimeError("runtime journal temporary ID mismatch")
        temporary.unlink()
        fsync_parent(temporary)
    return document

def remove_tree(path, plan, identity, *, unrecorded):
    observed = current_identity(path, plan, unrecorded=unrecorded)
    if identity is not None and observed != identity:
        raise RuntimeError(f"runtime directory identity mismatch: {path}")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RuntimeError("runtime recovery requires symlink-safe rmtree")
    allowed_children = {
        (odoo.pw_uid, odoo_group.gr_gid),
    }
    if unrecorded:
        allowed_children.add((0, 0))
    for walk_root, directory_names, file_names in os.walk(path, followlinks=False):
        for child_name in [*directory_names, *file_names]:
            child = pathlib.Path(walk_root) / child_name
            child_metadata = child.lstat()
            if (
                (child_metadata.st_uid, child_metadata.st_gid)
                not in allowed_children
                or not (
                    stat.S_ISDIR(child_metadata.st_mode)
                    or stat.S_ISREG(child_metadata.st_mode)
                    or stat.S_ISLNK(child_metadata.st_mode)
                )
            ):
                raise RuntimeError(f"unsafe runtime directory member: {child}")
    shutil.rmtree(path)
    fsync_parent(path)

if action == "create":
    if journal.exists() or journal.is_symlink():
        raise SystemExit("runtime transaction already exists")
    transaction_id = uuid.uuid4().hex
    if not re.fullmatch(r"[0-9a-f]{32}", upstream_install_transaction_id):
        raise SystemExit("upstream install transaction ID is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", upstream_install_identity_sha256):
        raise SystemExit("upstream install identity digest is invalid")
    document = {
        "schema_version": 1,
        "kind": "runtime",
        "release": release_id,
        "transaction_id": transaction_id,
        "upstream_install_transaction_id": upstream_install_transaction_id,
        "upstream_install_identity_sha256": upstream_install_identity_sha256,
        "state": "active",
        "parents": {
            parent_label: {
                "path": str(path),
                "identity": parent_identity(parent_label, path),
            }
            for parent_label, path in parent_paths.items()
        },
        "objects": object_plan(transaction_id),
    }
    write_document(document, create=True)
    print(transaction_id)
elif action == "record":
    if label not in labels:
        raise SystemExit("unknown runtime transaction object")
    document = load_document()
    if document["state"] != "active":
        raise SystemExit("cannot record a completed runtime transaction")
    plan = document["objects"][label]
    identity = current_identity(pathlib.Path(plan["path"]), plan)
    source_label = plan["source"]
    if source_label is not None:
        source_identity = document["objects"][source_label]["identity"]
        if source_identity is None or identity != source_identity:
            raise SystemExit("runtime published object is not the staging identity")
    document["objects"][label]["identity"] = identity
    write_document(document, create=False)
elif action == "recover":
    if not journal.exists() and not journal.is_symlink():
        raise SystemExit(0)
    document = load_document()
    if document["state"] == "completed":
        for object_label in (
            "config",
            "candidate",
            "auth_secret",
            "receipt_secret",
        ):
            plan = document["objects"][object_label]
            identity = plan["identity"]
            if (
                identity is None
                or current_identity(pathlib.Path(plan["path"]), plan) != identity
            ):
                raise SystemExit(
                    f"completed runtime identity mismatch: {object_label}"
                )
        for object_label in (
            "config_staging",
            "candidate_staging",
            "auth_staging",
            "receipt_staging",
        ):
            path = pathlib.Path(document["objects"][object_label]["path"])
            if path.exists() or path.is_symlink():
                raise SystemExit(
                    f"completed runtime retains staging: {object_label}"
                )
        print(f"completed_runtime_transaction={document['transaction_id']}")
        raise SystemExit(0)
    errors = []
    for object_label in (
        "receipt_secret",
        "auth_secret",
        "candidate",
        "config",
        "receipt_staging",
        "auth_staging",
        "candidate_staging",
        "config_staging",
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
        unrecorded = identity is None
        try:
            observed = current_identity(path, plan, unrecorded=unrecorded)
            if identity is not None and observed != identity:
                raise RuntimeError("identity does not match runtime journal")
            if plan["kind"] == "directory":
                remove_tree(path, plan, identity, unrecorded=unrecorded)
            else:
                path.unlink()
                fsync_parent(path)
        except Exception as exc:
            errors.append(f"{object_label}: {exc}")
    if errors:
        raise SystemExit(
            "runtime transaction recovery refused: " + "; ".join(errors)
        )
    journal.unlink()
    fsync_parent(journal)
    print(f"recovered_runtime_transaction={document['transaction_id']}")
elif action == "commit":
    document = load_document()
    if document["state"] != "active":
        raise SystemExit("runtime transaction is already completed")
    for object_label in (
        "config",
        "candidate",
        "auth_secret",
        "receipt_secret",
    ):
        plan = document["objects"][object_label]
        identity = plan["identity"]
        if (
            identity is None
            or current_identity(pathlib.Path(plan["path"]), plan) != identity
        ):
            raise SystemExit(f"runtime commit identity mismatch: {object_label}")
    for object_label in (
        "config_staging",
        "candidate_staging",
        "auth_staging",
        "receipt_staging",
    ):
        path = pathlib.Path(document["objects"][object_label]["path"])
        if path.exists() or path.is_symlink():
            raise SystemExit(
                f"cannot commit runtime while staging exists: {object_label}"
            )
    document["state"] = "completed"
    write_document(document, create=False)
elif action == "status":
    document = load_document()
    if (
        upstream_install_transaction_id
        and (
            document["upstream_install_transaction_id"]
            != upstream_install_transaction_id
            or document["upstream_install_identity_sha256"]
            != upstream_install_identity_sha256
        )
    ):
        raise SystemExit("runtime upstream install transaction mismatch")
    print(document["state"])
else:
    raise SystemExit("unknown runtime transaction action")
PY
}

create_runtime_config_staging() {
  local staging=$1
  local staging_name=$2
  python3 - "$uploaded_config" "$staging" "$staging_name" \
    "$config_sha" "$config_size" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_name = sys.argv[3]
expected_sha = sys.argv[4]
expected_size = int(sys.argv[5])
source_parent = pathlib.Path("/root/odoo-accounting-cli-v3-dev8-upload")
destination_parent = pathlib.Path("/etc/odoo-accounting-cli-v3")
if (
    source.parent != source_parent
    or source.name != "runtime-test-dev8.json"
    or destination.parent != destination_parent
    or destination.name != expected_name
):
    raise SystemExit("runtime configuration staging path mismatch")
source_fd = os.open(
    source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
try:
    source_metadata = os.fstat(source_fd)
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_uid != 0
        or source_metadata.st_gid != 0
        or source_metadata.st_nlink != 1
        or source_metadata.st_mode & 0o022
    ):
        raise SystemExit("uploaded runtime config metadata mismatch")
    destination_fd = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > 65_536:
                raise SystemExit("uploaded runtime config is too large")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("short write while staging runtime config")
                view = view[written:]
        if total != expected_size or digest.hexdigest() != expected_sha:
            raise SystemExit("uploaded runtime config digest or size mismatch")
        os.fchown(destination_fd, 0, 0)
        os.fchmod(destination_fd, 0o644)
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
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_nlink != 1
        or metadata.st_size != expected_size
    ):
        raise SystemExit("staged runtime config metadata mismatch")
    directory_fd = os.open(destination_parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(source_fd)
PY
}

create_runtime_candidate_staging() {
  local staging=$1
  local staging_name=$2
  python3 - "$staging" "$staging_name" <<'PY'
import grp
import os
import pathlib
import pwd
import stat
import sys

path = pathlib.Path(sys.argv[1])
expected_name = sys.argv[2]
parent = pathlib.Path("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging")
odoo = pwd.getpwnam("odoo")
gid = grp.getgrnam("odoo").gr_gid
if path.parent != parent or path.name != expected_name:
    raise SystemExit("runtime candidate staging path mismatch")
os.mkdir(path, 0o700)
os.chown(path, odoo.pw_uid, gid)
os.chmod(path, 0o700)
metadata = path.lstat()
if (
    not stat.S_ISDIR(metadata.st_mode)
    or path.is_symlink()
    or path.resolve(strict=True) != path
    or metadata.st_uid != odoo.pw_uid
    or metadata.st_gid != gid
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit("runtime candidate staging metadata mismatch")
directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

create_runtime_secret_staging() {
  local path=$1
  local expected_name=$2
  python3 - "$path" "$expected_name" <<'PY'
import grp
import os
import pathlib
import secrets
import stat
import sys

path = pathlib.Path(sys.argv[1])
expected_name = sys.argv[2]
parent = pathlib.Path("/etc/odoo-accounting-cli-v3/secrets/test")
gid = grp.getgrnam("odoo").gr_gid
if path.parent != parent or path.name != expected_name:
    raise SystemExit("runtime secret staging path mismatch")
descriptor = os.open(
    path,
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_CLOEXEC
    | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    payload = (secrets.token_hex(24) + "\n").encode("ascii")
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while creating runtime secret")
        view = view[written:]
    os.fchown(descriptor, 0, gid)
    os.fchmod(descriptor, 0o640)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or path.is_symlink()
    or path.resolve(strict=True) != path
    or metadata.st_uid != 0
    or metadata.st_gid != gid
    or stat.S_IMODE(metadata.st_mode) != 0o640
    or metadata.st_nlink != 1
):
    raise SystemExit("runtime secret staging metadata mismatch")
directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

publish_runtime_staging() {
  local staging=$1
  local destination=$2
  local parent=$3
  local staging_name=$4
  local destination_name=$5
  local owner_kind=$6
  python3 - "$staging" "$destination" "$parent" "$staging_name" \
    "$destination_name" "$owner_kind" <<'PY'
import grp
import os
import pathlib
import stat
import sys

staging = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
parent = pathlib.Path(sys.argv[3])
staging_name = sys.argv[4]
destination_name = sys.argv[5]
owner_kind = sys.argv[6]
odoo_gid = grp.getgrnam("odoo").gr_gid
if owner_kind == "config":
    expected = (0, 0, 0o644)
elif owner_kind == "secret":
    expected = (0, odoo_gid, 0o640)
else:
    raise SystemExit("runtime publish owner kind is invalid")
if (
    staging.parent != parent
    or destination.parent != parent
    or staging.name != staging_name
    or destination.name != destination_name
):
    raise SystemExit("runtime publish path mismatch")
descriptor = os.open(
    staging, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
try:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode))
        != expected
        or opened.st_nlink != 1
    ):
        raise SystemExit("runtime publish staging metadata mismatch")
    os.link(staging, destination, follow_symlinks=False)
    published = destination.lstat()
    if (
        not stat.S_ISREG(published.st_mode)
        or destination.is_symlink()
        or (published.st_dev, published.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise SystemExit("runtime publish destination identity mismatch")
    staging.unlink()
    if destination.lstat().st_nlink != 1:
        raise SystemExit("runtime publish link count mismatch")
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(descriptor)
PY
}

rollback_runtime_setup() {
  local original_status=$?
  trap - EXIT HUP INT TERM
  if [[ "$runtime_setup_succeeded" = 1 ]]; then
    return 0
  fi
  set +e
  runtime_transaction recover ""
  local rollback_status=$?
  set -e
  if [[ "$rollback_status" -ne 0 ]]; then
    printf 'dev8 runtime setup failed with status %s; journal recovery failed\n' \
      "$original_status" >&2
    exit 98
  fi
  exit "$original_status"
}

verify_completed_runtime() {
  test ! -e /opt/odoo-accounting-cli-v3/current
  test ! -L /opt/odoo-accounting-cli-v3/current
  test -d "$release"
  test ! -L "$release"
  test -f "$package"
  test ! -L "$package"
  test "$(stat -c '%U:%G %a %s %h' "$package")" = \
    "root:root 444 $package_size 1"
  test "$(sha256sum "$package" | cut -d' ' -f1)" = "$package_sha"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
    python3 -B "$release/tools/verify_release.py" "$release" "$manifest_sha"
  test "$(stat -c '%U:%G %a %s %h' "$config")" = \
    "root:root 644 $config_size 1"
  test "$(sha256sum "$config" | cut -d' ' -f1)" = "$config_sha"
  test "$(stat -c '%U:%G %a %h' "$auth_secret")" = "root:odoo 640 1"
  test "$(stat -c '%U:%G %a %h' "$receipt_secret")" = "root:odoo 640 1"
  test "$(stat -c '%U:%G %a' "$candidate")" = "odoo:odoo 700"
  python3 - "$auth_secret" "$receipt_secret" <<'PY'
import grp
import os
import pathlib
import re
import stat
import sys

gid = grp.getgrnam("odoo").gr_gid
for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, 1024)
        if os.read(descriptor, 1):
            raise SystemExit("runtime secret is too large")
    finally:
        os.close(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        or opened.st_uid != 0
        or opened.st_gid != gid
        or stat.S_IMODE(opened.st_mode) != 0o640
        or opened.st_nlink != 1
        or not re.fullmatch(rb"[0-9a-f]{48}\n", payload)
    ):
        raise SystemExit(f"runtime secret verification failed: {path.name}")
print("dev8_runtime_secrets_verified=true")
PY
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
  python3 -B - "$config" <<'PY'
import sys

from odoo_accounting_cli_v3.odoo.runner import (
    _validate_canonical_package_binding,
    load_runtime_config,
)

config = load_runtime_config(sys.argv[1])
if (
    str(config.release_root)
    != "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168"
    or config.environment != "test"
    or config.capability_channel != "staged"
    or config.database_name != "odoo_test"
    or config.database_uuid != "19b09656-d10f-11f0-9065-00163e54a5ad"
):
    raise SystemExit("completed runtime config binding mismatch")
_validate_canonical_package_binding(config)
print("dev8_completed_runtime_binding_verified=true")
PY
}

prepare_runtime_lock \
  "$pipeline_lock" /opt/odoo-accounting-cli-v3 .dev8-pipeline.lock
exec {pipeline_lock_fd}<>"$pipeline_lock"
/usr/bin/flock --exclusive "$pipeline_lock_fd"
prepare_runtime_lock \
  "$runtime_lock" /etc/odoo-accounting-cli-v3 .dev8-runtime.lock
exec {runtime_lock_fd}<>"$runtime_lock"
/usr/bin/flock --exclusive "$runtime_lock_fd"

if [[ -e "$transaction_journal" || -L "$transaction_journal" ]]; then
  prepare_candidate_staging_parent verify
else
  prepare_candidate_staging_parent create
fi
install_binding=$(verify_completed_install_transaction)
install_transaction_id=${install_binding%%:*}
install_identity_sha=${install_binding#*:}
test "$install_transaction_id" != "$install_binding"
test "$install_identity_sha" != "$install_binding"
printf 'completed_install_journal_verified=%s\n' "$install_transaction_id"
test -d "$release"
test ! -L "$release"
test -f "$package"
test ! -L "$package"
test "$(stat -c '%U:%G %a %s %h' "$package")" = \
  "root:root 444 $package_size 1"
test "$(sha256sum "$package" | cut -d' ' -f1)" = "$package_sha"
test -d /etc/odoo-accounting-cli-v3
test ! -L /etc/odoo-accounting-cli-v3
test -d /etc/odoo-accounting-cli-v3/secrets/test
test ! -L /etc/odoo-accounting-cli-v3/secrets/test
test -d /var/lib/odoo-accounting-cli-v3/test/candidates
test ! -L /var/lib/odoo-accounting-cli-v3/test/candidates

if [[ -e "$transaction_journal" || -L "$transaction_journal" ]]; then
  transaction_state=$(
    runtime_transaction status "" "$install_transaction_id" "$install_identity_sha"
  )
  if [[ "$transaction_state" = completed ]]; then
    runtime_transaction recover ""
    verify_completed_runtime
    printf 'dev8_runtime_setup=passed\nrelease=%s\nconfig=%s\nalready_configured=true\n' \
      "$release_id" "$config"
    exit 0
  fi
  test "$transaction_state" = active
  runtime_transaction recover ""
fi

python3 - "$upload_directory" "$uploaded_config" <<'PY'
import pathlib
import stat
import sys

upload = pathlib.Path(sys.argv[1])
path = pathlib.Path(sys.argv[2])
root = pathlib.Path("/root")
root_metadata = root.lstat()
upload_metadata = upload.lstat()
metadata = path.lstat()
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
    or path.parent != upload
    or path.name != "runtime-test-dev8.json"
    or not stat.S_ISREG(metadata.st_mode)
    or path.is_symlink()
    or path.resolve(strict=True) != path
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_nlink != 1
    or metadata.st_mode & 0o022
):
    raise SystemExit("uploaded runtime config is not root-managed")
print("uploaded_runtime_metadata_verified=true")
PY
for target in "$candidate" "$config" "$auth_secret" "$receipt_secret"; do
  test ! -e "$target"
  test ! -L "$target"
done
test ! -e /opt/odoo-accounting-cli-v3/current
test ! -L /opt/odoo-accounting-cli-v3/current

PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
  python3 -B "$release/tools/verify_release.py" "$release" "$manifest_sha"
PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
python3 -B - "$release/registry/capabilities.json" <<'PY'
import sys

from odoo_accounting_cli_v3.registry import load_registry, registry_digest

observed = registry_digest(load_registry(sys.argv[1]))
expected = "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e"
if observed != expected:
    raise SystemExit("installed registry digest mismatch")
print(f"installed_registry_digest={observed}")
PY

trap rollback_runtime_setup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

transaction_id=$(
  runtime_transaction create "" "$install_transaction_id" "$install_identity_sha"
)
test "$transaction_id" != ""
config_staging=/etc/odoo-accounting-cli-v3/.runtime-test-dev8.json.$transaction_id.staging
candidate_staging=$candidate_staging_parent/.$release_id.$transaction_id.candidate.staging
auth_staging=/etc/odoo-accounting-cli-v3/secrets/test/.dev8-auth.$transaction_id.hmac.staging
receipt_staging=/etc/odoo-accounting-cli-v3/secrets/test/.dev8-receipt.$transaction_id.hmac.staging

create_runtime_config_staging \
  "$config_staging" ".runtime-test-dev8.json.$transaction_id.staging"
runtime_transaction record config_staging
publish_runtime_staging \
  "$config_staging" "$config" /etc/odoo-accounting-cli-v3 \
  ".runtime-test-dev8.json.$transaction_id.staging" runtime-test-dev8.json config
runtime_transaction record config
test "$(stat -c '%U:%G %a %s %h' "$config")" = \
  "root:root 644 $config_size 1"
test "$(sha256sum "$config" | cut -d' ' -f1)" = "$config_sha"

python3 - "$config" <<'PY'
import json
import pathlib
import sys

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate runtime field: {key}")
        value[key] = item
    return value

path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("runtime config must be a regular non-link file")
value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
expected = {
    "auth_key_id": "test-auth-2026-07-dev8",
    "auth_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac",
    "auth_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/0.1.0.dev8-bd21ca07c168/auth.sqlite3",
    "canonical_package_path": "/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz",
    "canonical_package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "capability_channel": "staged",
    "database_name": "odoo_test",
    "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
    "environment": "test",
    "instance_id": "odoo19@43.165.173.80",
    "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
    "odoo_bin_sha256": "e0fb7977c59f73e652805d169bcd1bffe41df7bbf0c39ce47e8ad32126529003",
    "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
    "odoo_config_sha256": "98a90d839e3ad16c32335057b27e33bc689cbccbb367350e31fbf41778ed70c3",
    "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
    "odoo_python_sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
    "receipt_key_id": "test-receipt-2026-07-dev8",
    "receipt_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/dev8-receipt.hmac",
    "receipt_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/0.1.0.dev8-bd21ca07c168/receipt.sqlite3",
    "release_root": "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168",
}
if value != expected:
    missing = sorted(set(expected) - set(value))
    extra = sorted(set(value) - set(expected))
    changed = sorted(key for key in set(value) & set(expected) if value[key] != expected[key])
    raise SystemExit(
        f"dev8 runtime config mismatch; missing={missing}, extra={extra}, changed={changed}"
    )
print("dev8_runtime_config_verified=true")
PY

PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
python3 -B - "$config" <<'PY'
import sys

from odoo_accounting_cli_v3.odoo.runner import (
    _validate_canonical_package_binding,
    load_runtime_config,
)

config = load_runtime_config(sys.argv[1])
if str(config.release_root) != "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168":
    raise SystemExit("release parser observed the wrong runtime release")
_validate_canonical_package_binding(config)
print("dev8_installed_runtime_binding_verified=true")
PY

create_runtime_candidate_staging \
  "$candidate_staging" ".$release_id.$transaction_id.candidate.staging"
runtime_transaction record candidate_staging
candidate_staging_device=$(stat -c '%d' "$candidate_staging_parent")
candidate_destination_device=$(
  stat -c '%d' /var/lib/odoo-accounting-cli-v3/test/candidates
)
test "$candidate_staging_device" = "$candidate_destination_device"
mv -T --no-clobber "$candidate_staging" "$candidate"
test ! -e "$candidate_staging"
test ! -L "$candidate_staging"
python3 - "$candidate_staging_parent" \
  /var/lib/odoo-accounting-cli-v3/test/candidates <<'PY'
import grp
import os
import pathlib
import pwd
import stat
import sys

source_parent = pathlib.Path(sys.argv[1])
destination_parent = pathlib.Path(sys.argv[2])
odoo = pwd.getpwnam("odoo")
odoo_gid = grp.getgrnam("odoo").gr_gid
expected = {
    source_parent: ("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging", {(0, 0)}),
    destination_parent: (
        "/var/lib/odoo-accounting-cli-v3/test/candidates",
        {(0, 0), (odoo.pw_uid, odoo_gid)},
    ),
}
metadata_by_path = {}
for path, (expected_path, owners) in expected.items():
    metadata = path.lstat()
    if (
        str(path) != expected_path
        or path.resolve(strict=True) != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) not in owners
        or metadata.st_mode & 0o022
    ):
        raise SystemExit("runtime candidate publish parent is not trusted")
    metadata_by_path[path] = metadata
if (
    metadata_by_path[source_parent].st_dev
    != metadata_by_path[destination_parent].st_dev
):
    raise SystemExit("runtime candidate publish parents are on different filesystems")
for path in (source_parent, destination_parent):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
runtime_transaction record candidate
test ! -L "$candidate"
test "$(stat -c '%U:%G %a' "$candidate")" = "odoo:odoo 700"
create_runtime_secret_staging \
  "$auth_staging" ".dev8-auth.$transaction_id.hmac.staging"
runtime_transaction record auth_staging
publish_runtime_staging \
  "$auth_staging" "$auth_secret" /etc/odoo-accounting-cli-v3/secrets/test \
  ".dev8-auth.$transaction_id.hmac.staging" dev8-auth.hmac secret
runtime_transaction record auth_secret
create_runtime_secret_staging \
  "$receipt_staging" ".dev8-receipt.$transaction_id.hmac.staging"
runtime_transaction record receipt_staging
publish_runtime_staging \
  "$receipt_staging" "$receipt_secret" /etc/odoo-accounting-cli-v3/secrets/test \
  ".dev8-receipt.$transaction_id.hmac.staging" dev8-receipt.hmac secret
runtime_transaction record receipt_secret

test ! -L "$config"
test ! -L "$auth_secret"
test ! -L "$receipt_secret"
test "$(stat -c '%U:%G %a' "$config")" = "root:root 644"
test "$(stat -c '%U:%G %a' "$auth_secret")" = "root:odoo 640"
test "$(stat -c '%U:%G %a' "$receipt_secret")" = "root:odoo 640"


test ! -e /opt/odoo-accounting-cli-v3/current
test ! -L /opt/odoo-accounting-cli-v3/current
test "$(stat -c '%U:%G %a %s %h' "$package")" = \
  "root:root 444 $package_size 1"
test "$(sha256sum "$package" | cut -d' ' -f1)" = "$package_sha"
PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
  python3 -B "$release/tools/verify_release.py" "$release" "$manifest_sha"
stat -c '%a %U:%G %s %n' \
  "$config" "$auth_secret" "$receipt_secret" "$candidate" "$package"
/usr/bin/sync --file-system "$candidate"
/usr/bin/sync --file-system "$config" "$auth_secret" "$receipt_secret"
verify_completed_runtime
runtime_transaction commit ""
runtime_setup_succeeded=1
trap - EXIT HUP INT TERM
printf 'dev8_runtime_setup=passed\nrelease=%s\nconfig=%s\ntransaction_id=%s\n' \
  "$release_id" "$config" "$transaction_id"
