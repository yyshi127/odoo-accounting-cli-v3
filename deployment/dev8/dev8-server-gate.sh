#!/usr/bin/env bash
set -euo pipefail

release_id=0.1.0.dev8-bd21ca07c168
release=/opt/odoo-accounting-cli-v3/releases/$release_id
launcher=$release/bin/odoo-accounting-cli-v3
package=/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz
package_sha=58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234
package_size=151492
manifest_sha=fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06
registry_sha=d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e
config=/etc/odoo-accounting-cli-v3/runtime-test-dev8.json
config_sha=a089d13a2418225e245d10cf76728ad6af31ce0b5fde9f5b14902c44eebe59b7
config_size=1438
pipeline_lock=/opt/odoo-accounting-cli-v3/.dev8-pipeline.lock
install_journal=/opt/odoo-accounting-cli-v3/.dev8-install-transaction.json
runtime_journal=/etc/odoo-accounting-cli-v3/.dev8-runtime-transaction.json
server_baseline=/root/odoo-accounting-cli-v3-dev8-upload/SERVER-BASELINE.json

prepare_pipeline_lock() {
  python3 - "$pipeline_lock" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
parent = pathlib.Path("/opt/odoo-accounting-cli-v3")
metadata = parent.lstat()
if (
    path.parent != parent
    or path.name != ".dev8-pipeline.lock"
    or parent.resolve(strict=True) != parent
    or parent.is_symlink()
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_mode & 0o022
):
    raise SystemExit("server-gate pipeline lock parent is not trusted")
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
        raise SystemExit("server-gate pipeline lock metadata mismatch")
finally:
    os.close(descriptor)
PY
}

verify_completed_transaction_journals() {
  python3 - "$install_journal" "$runtime_journal" <<'PY'
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import sys

release_id = "0.1.0.dev8-bd21ca07c168"
install_journal = pathlib.Path(sys.argv[1])
runtime_journal = pathlib.Path(sys.argv[2])
odoo = pwd.getpwnam("odoo")
odoo_gid = grp.getgrnam("odoo").gr_gid

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate completion-journal field: {key}")
        value[key] = item
    return value

def canonical(value):
    return json.dumps(
        value, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

def read_journal(path, parent, name):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            path.parent != parent
            or path.name != name
            or not stat.S_ISREG(opened.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise SystemExit(f"completion journal metadata mismatch: {name}")
        payload = b""
        while True:
            chunk = os.read(descriptor, 16_384)
            if not chunk:
                break
            payload += chunk
            if len(payload) > 1_048_576:
                raise SystemExit(f"completion journal is too large: {name}")
    finally:
        os.close(descriptor)
    return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)

def file_fingerprint(value):
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
        raise SystemExit(f"completion object metadata mismatch: {path}")
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
            if file_fingerprint(opened) != file_fingerprint(metadata):
                raise SystemExit(f"completion object changed: {path}")
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
            file_fingerprint(metadata)
            == file_fingerprint(opened_after)
            == file_fingerprint(after)
        ):
            raise SystemExit(f"completion object changed: {path}")
        result["size"] = total
        result["sha256"] = digest.hexdigest()
    return result

def verify_document(document, kind, parent_keys, object_keys):
    required = {
        "schema_version",
        "kind",
        "release",
        "transaction_id",
        "state",
        "parents",
        "objects",
    }
    if kind == "runtime":
        required.add("upstream_install_transaction_id")
        required.add("upstream_install_identity_sha256")
    if (
        not isinstance(document, dict)
        or set(document) != required
        or not isinstance(document["schema_version"], int)
        or isinstance(document["schema_version"], bool)
        or document["schema_version"] != 1
        or document["kind"] != kind
        or document["release"] != release_id
        or document["state"] != "completed"
        or not isinstance(document["transaction_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", document["transaction_id"])
        or not isinstance(document["parents"], dict)
        or set(document["parents"]) != set(parent_keys)
        or not isinstance(document["objects"], dict)
        or set(document["objects"]) != set(object_keys)
    ):
        raise SystemExit(f"{kind} completion journal identity mismatch")

def parent_identity(path, owners, modes):
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        path.resolve(strict=True) != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) not in owners
        or metadata.st_mode & 0o022
        or (modes is not None and mode not in modes)
    ):
        raise SystemExit(f"completion parent metadata mismatch: {path}")
    return {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "kind": "directory",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": mode,
    }

def verify_parent_records(document, specifications, kind):
    for label, (path, owners, modes) in specifications.items():
        record = document["parents"][label]
        observed = parent_identity(path, owners, modes)
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "identity"}
            or record["path"] != str(path)
            or not isinstance(record["identity"], dict)
            or set(record["identity"])
            != {"dev", "ino", "kind", "uid", "gid", "mode"}
            or not all(
                isinstance(record["identity"][field], int)
                and not isinstance(record["identity"][field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            or record["identity"] != observed
        ):
            raise SystemExit(f"{kind} completion parent mismatch: {label}")

def verify_object_records(document, plan, kind):
    identities = {}
    base_identity_fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
    for label, planned in plan.items():
        record = document["objects"][label]
        if (
            not isinstance(record, dict)
            or set(record) != set(planned)
            or canonical({**record, "identity": None}) != canonical(planned)
        ):
            raise SystemExit(f"{kind} completion object plan mismatch: {label}")
        recorded = record["identity"]
        identity_fields = (
            base_identity_fields | {"size", "sha256"}
            if planned["kind"] == "file"
            else base_identity_fields
        )
        if (
            not isinstance(recorded, dict)
            or set(recorded) != identity_fields
            or not all(
                isinstance(recorded[field], int)
                and not isinstance(recorded[field], bool)
                for field in ("dev", "ino", "uid", "gid", "mode")
            )
            or recorded["kind"] != planned["kind"]
            or recorded["uid"] != planned["uid"]
            or recorded["gid"] != planned["gid"]
            or recorded["mode"] not in planned["modes"]
            or (
                planned["kind"] == "file"
                and (
                    not isinstance(recorded["size"], int)
                    or isinstance(recorded["size"], bool)
                    or recorded["size"] < 0
                    or not isinstance(recorded["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", recorded["sha256"])
                )
            )
        ):
            raise SystemExit(f"{kind} completion object identity invalid: {label}")
        path = pathlib.Path(planned["path"])
        if planned["unique"]:
            if path.exists() or path.is_symlink():
                raise SystemExit(f"{kind} completion retains staging: {label}")
        else:
            observed = identity(
                path,
                planned["kind"],
                planned["uid"],
                planned["gid"],
                planned["modes"][0],
            )
            if recorded != observed:
                raise SystemExit(f"{kind} completion binding mismatch: {label}")
            identities[label] = observed
    for label, planned in plan.items():
        source = planned["source"]
        if source is not None and (
            document["objects"][label]["identity"]
            != document["objects"][source]["identity"]
        ):
            raise SystemExit(f"{kind} completion source mismatch: {label}")
    return identities

install = read_journal(
    install_journal,
    pathlib.Path("/opt/odoo-accounting-cli-v3"),
    ".dev8-install-transaction.json",
)
install_keys = {
    "package_staging",
    "anchor_staging",
    "release_staging",
    "package",
    "release",
    "anchor",
}
install_parent_specs = {
    "root": (pathlib.Path("/opt/odoo-accounting-cli-v3"), {(0, 0)}, None),
    "releases": (
        pathlib.Path("/opt/odoo-accounting-cli-v3/releases"),
        {(0, 0)},
        None,
    ),
    "packages": (
        pathlib.Path("/opt/odoo-accounting-cli-v3/packages"),
        {(0, 0)},
        None,
    ),
    "anchors": (
        pathlib.Path("/opt/odoo-accounting-cli-v3/trusted-artifacts"),
        {(0, 0)},
        None,
    ),
}
verify_document(install, "install", install_parent_specs, install_keys)
verify_parent_records(install, install_parent_specs, "install")
install_tx = install["transaction_id"]
install_paths = {
    "package": (
        pathlib.Path(
            "/opt/odoo-accounting-cli-v3/packages/"
            "odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz"
        ),
        "file",
        0,
        0,
        0o444,
    ),
    "release": (
        pathlib.Path(
            "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168"
        ),
        "directory",
        0,
        0,
        0o555,
    ),
    "anchor": (
        pathlib.Path(
            "/opt/odoo-accounting-cli-v3/trusted-artifacts/"
            "0.1.0.dev8-bd21ca07c168.json"
        ),
        "file",
        0,
        0,
        0o444,
    ),
}
install_staging = {
    "package_staging": pathlib.Path(
        "/opt/odoo-accounting-cli-v3/packages/"
        f".odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz.{install_tx}.staging"
    ),
    "anchor_staging": pathlib.Path(
        "/opt/odoo-accounting-cli-v3/trusted-artifacts/"
        f".0.1.0.dev8-bd21ca07c168.{install_tx}.anchor.staging"
    ),
    "release_staging": pathlib.Path(
        "/opt/odoo-accounting-cli-v3/releases/"
        f".0.1.0.dev8-bd21ca07c168.{install_tx}.release.staging"
    ),
}
install_plan = {
    "package_staging": {
        "path": str(install_staging["package_staging"]),
        "kind": "file",
        "uid": 0,
        "gid": 0,
        "modes": [0o400, 0o444],
        "unique": True,
        "source": None,
        "identity": None,
    },
    "anchor_staging": {
        "path": str(install_staging["anchor_staging"]),
        "kind": "file",
        "uid": 0,
        "gid": 0,
        "modes": [0o400, 0o444],
        "unique": True,
        "source": None,
        "identity": None,
    },
    "release_staging": {
        "path": str(install_staging["release_staging"]),
        "kind": "directory",
        "uid": 0,
        "gid": 0,
        "modes": [0o555],
        "unique": True,
        "source": None,
        "identity": None,
    },
    "package": {
        "path": str(install_paths["package"][0]),
        "kind": "file",
        "uid": 0,
        "gid": 0,
        "modes": [0o444],
        "unique": False,
        "source": "package_staging",
        "identity": None,
    },
    "release": {
        "path": str(install_paths["release"][0]),
        "kind": "directory",
        "uid": 0,
        "gid": 0,
        "modes": [0o555],
        "unique": False,
        "source": "release_staging",
        "identity": None,
    },
    "anchor": {
        "path": str(install_paths["anchor"][0]),
        "kind": "file",
        "uid": 0,
        "gid": 0,
        "modes": [0o444],
        "unique": False,
        "source": "anchor_staging",
        "identity": None,
    },
}
install_identities = verify_object_records(install, install_plan, "install")
if (
    install_identities["package"]["size"] != 151492
    or install_identities["package"]["sha256"]
    != "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
):
    raise SystemExit("install completion package digest mismatch")
anchor_value = json.loads(
    install_paths["anchor"][0].read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
if anchor_value != {
    "commit": "bd21ca07c1689a42fbf903b91486269397b44733",
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "release": release_id,
}:
    raise SystemExit("install completion anchor mismatch")
install_binding = {
    "anchor": install_identities["anchor"],
    "install_transaction_id": install_tx,
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package": install_identities["package"],
    "registry_digest": "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e",
    "release": install_identities["release"],
}
install_binding_sha = hashlib.sha256(
    json.dumps(
        install_binding, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
).hexdigest()

runtime = read_journal(
    runtime_journal,
    pathlib.Path("/etc/odoo-accounting-cli-v3"),
    ".dev8-runtime-transaction.json",
)
runtime_keys = {
    "config_staging",
    "candidate_staging",
    "auth_staging",
    "receipt_staging",
    "config",
    "candidate",
    "auth_secret",
    "receipt_secret",
}
runtime_parent_specs = {
    "config_parent": (
        pathlib.Path("/etc/odoo-accounting-cli-v3"),
        {(0, 0)},
        None,
    ),
    "candidate_parent": (
        pathlib.Path("/var/lib/odoo-accounting-cli-v3/test/candidates"),
        {(0, 0), (odoo.pw_uid, odoo_gid)},
        None,
    ),
    "candidate_staging_parent": (
        pathlib.Path("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging"),
        {(0, 0)},
        {0o700},
    ),
    "secret_parent": (
        pathlib.Path("/etc/odoo-accounting-cli-v3/secrets/test"),
        {(0, 0), (0, odoo_gid)},
        None,
    ),
}
verify_document(runtime, "runtime", runtime_parent_specs, runtime_keys)
verify_parent_records(runtime, runtime_parent_specs, "runtime")
if (
    runtime["upstream_install_transaction_id"] != install_tx
    or runtime["upstream_install_identity_sha256"] != install_binding_sha
):
    raise SystemExit("runtime journal is not bound to completed install transaction")
runtime_tx = runtime["transaction_id"]
runtime_paths = {
    "config": (
        pathlib.Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json"),
        "file",
        0,
        0,
        0o644,
    ),
    "candidate": (
        pathlib.Path(
            "/var/lib/odoo-accounting-cli-v3/test/candidates/"
            "0.1.0.dev8-bd21ca07c168"
        ),
        "directory",
        odoo.pw_uid,
        odoo_gid,
        0o700,
    ),
    "auth_secret": (
        pathlib.Path(
            "/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac"
        ),
        "file",
        0,
        odoo_gid,
        0o640,
    ),
    "receipt_secret": (
        pathlib.Path(
            "/etc/odoo-accounting-cli-v3/secrets/test/dev8-receipt.hmac"
        ),
        "file",
        0,
        odoo_gid,
        0o640,
    ),
}
runtime_staging = {
    "config_staging": pathlib.Path(
        "/etc/odoo-accounting-cli-v3/"
        f".runtime-test-dev8.json.{runtime_tx}.staging"
    ),
    "candidate_staging": pathlib.Path(
        "/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging/"
        f".0.1.0.dev8-bd21ca07c168.{runtime_tx}.candidate.staging"
    ),
    "auth_staging": pathlib.Path(
        "/etc/odoo-accounting-cli-v3/secrets/test/"
        f".dev8-auth.{runtime_tx}.hmac.staging"
    ),
    "receipt_staging": pathlib.Path(
        "/etc/odoo-accounting-cli-v3/secrets/test/"
        f".dev8-receipt.{runtime_tx}.hmac.staging"
    ),
}
odoo_owner = [odoo.pw_uid, odoo_gid]

def runtime_item(
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

runtime_plan = {
    "config_staging": runtime_item(
        runtime_staging["config_staging"],
        "file",
        0,
        0,
        [0o644],
        True,
        None,
        [[0, 0]],
        [0o600, 0o644],
    ),
    "candidate_staging": runtime_item(
        runtime_staging["candidate_staging"],
        "directory",
        odoo.pw_uid,
        odoo_gid,
        [0o700],
        True,
        None,
        [[0, 0], odoo_owner],
        [0o700],
    ),
    "auth_staging": runtime_item(
        runtime_staging["auth_staging"],
        "file",
        0,
        odoo_gid,
        [0o640],
        True,
        None,
        [[0, 0], [0, odoo_gid]],
        [0o600, 0o640],
    ),
    "receipt_staging": runtime_item(
        runtime_staging["receipt_staging"],
        "file",
        0,
        odoo_gid,
        [0o640],
        True,
        None,
        [[0, 0], [0, odoo_gid]],
        [0o600, 0o640],
    ),
    "config": runtime_item(
        runtime_paths["config"][0],
        "file",
        0,
        0,
        [0o644],
        False,
        "config_staging",
        [[0, 0]],
        [0o644],
    ),
    "candidate": runtime_item(
        runtime_paths["candidate"][0],
        "directory",
        odoo.pw_uid,
        odoo_gid,
        [0o700],
        False,
        "candidate_staging",
        [odoo_owner],
        [0o700],
    ),
    "auth_secret": runtime_item(
        runtime_paths["auth_secret"][0],
        "file",
        0,
        odoo_gid,
        [0o640],
        False,
        "auth_staging",
        [[0, odoo_gid]],
        [0o640],
    ),
    "receipt_secret": runtime_item(
        runtime_paths["receipt_secret"][0],
        "file",
        0,
        odoo_gid,
        [0o640],
        False,
        "receipt_staging",
        [[0, odoo_gid]],
        [0o640],
    ),
}
verify_object_records(runtime, runtime_plan, "runtime")
print(
    f"completed_transaction_journals_verified=true "
    f"install_transaction={install_tx} runtime_transaction={runtime_tx}"
)
PY
}

verify_package() {
  test -f "$package"
  test ! -L "$package"
  test "$(stat -c '%U:%G %a %s %h' "$package")" = "root:root 444 $package_size 1"
  test "$(sha256sum "$package" | cut -d' ' -f1)" = "$package_sha"
}

verify_release() {
  test -d "$release"
  test ! -L "$release"
  test -x "$launcher"
  test ! -L "$launcher"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
    python3 -B "$release/tools/verify_release.py" "$release" "$manifest_sha"
  python3 - "$release" <<'PY'
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
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
print("release_modes_verified=true")
PY
}

verify_runtime_config() {
  test -f "$config"
  test ! -L "$config"
  test "$(stat -c '%U:%G %a %s %h' "$config")" = \
    "root:root 644 $config_size 1"
  test "$(sha256sum "$config" | cut -d' ' -f1)" = "$config_sha"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH="$release/src" \
    python3 -B - "$config" "$release" "$package" "$package_sha" <<'PY'
import sys

from odoo_accounting_cli_v3.odoo.runner import (
    _validate_canonical_package_binding,
    load_runtime_config,
)

config = load_runtime_config(sys.argv[1])
_validate_canonical_package_binding(config)
expected_release = sys.argv[2]
expected_package = sys.argv[3]
expected_package_sha = sys.argv[4]
if str(config.release_root) != expected_release:
    raise SystemExit("runtime release_root mismatch")
if str(config.canonical_package_path) != expected_package:
    raise SystemExit("runtime canonical_package_path mismatch")
if config.canonical_package_sha256 != expected_package_sha:
    raise SystemExit("runtime canonical_package_sha256 mismatch")
if config.environment != "test" or config.capability_channel != "staged":
    raise SystemExit("runtime environment/channel mismatch")
for field in ("auth_secret_path", "auth_state_path", "receipt_secret_path", "receipt_state_path"):
    value = str(getattr(config, field))
    if "dev8" not in value and "0.1.0.dev8-bd21ca07c168" not in value:
        raise SystemExit(f"runtime {field} is not dev8-isolated")
print("runtime_package_binding_verified=true")
PY
}

verify_direct_launcher_identity() {
  sudo -u odoo env -i \
    HOME=/nonexistent \
    LANG=C.UTF-8 \
    PATH=/usr/bin:/bin \
    "$launcher" release identity | \
  python3 -I -B -c '
import json
import sys

document = json.load(sys.stdin)
expected = {
    "commit": "bd21ca07c1689a42fbf903b91486269397b44733",
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "registry_digest": "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e",
    "release": "0.1.0.dev8-bd21ca07c168",
    "verified": True,
    "version": "0.1.0.dev8",
}
if document != {"command": "release.identity", "data": expected, "ok": True}:
    raise SystemExit("direct launcher identity mismatch")
print("direct_launcher_identity_verified=true")
'
}

verify_isolation() {
  local phase=$1
  python3 -I -B - "$phase" "$server_baseline" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

phase = sys.argv[1]
baseline_path = pathlib.Path(sys.argv[2])
if phase not in {"pre", "post"}:
    raise SystemExit("isolation phase is invalid")

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate server-baseline field: {key}")
        value[key] = item
    return value

def fingerprint(value):
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid,
        f"{stat.S_IMODE(value.st_mode):04o}", value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )

baseline_before = baseline_path.lstat()
baseline_parent = baseline_path.parent.lstat()
if (
    baseline_path.parent != pathlib.Path("/root/odoo-accounting-cli-v3-dev8-upload")
    or baseline_path.name != "SERVER-BASELINE.json"
    or baseline_path.parent.resolve(strict=True) != baseline_path.parent
    or baseline_path.parent.is_symlink()
    or not stat.S_ISDIR(baseline_parent.st_mode)
    or baseline_parent.st_uid != 0
    or baseline_parent.st_gid != 0
    or stat.S_IMODE(baseline_parent.st_mode) != 0o700
    or baseline_path.is_symlink()
    or not stat.S_ISREG(baseline_before.st_mode)
    or baseline_before.st_uid != 0
    or baseline_before.st_gid != 0
    or baseline_before.st_nlink != 1
    or stat.S_IMODE(baseline_before.st_mode) & 0o022
):
    raise SystemExit("server baseline source metadata mismatch")
baseline_descriptor = os.open(
    baseline_path,
    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
)
try:
    baseline_opened = os.fstat(baseline_descriptor)
    if fingerprint(baseline_opened) != fingerprint(baseline_before):
        raise SystemExit("server baseline changed while opening")
    baseline_payload = b""
    while True:
        chunk = os.read(baseline_descriptor, 65_536)
        if not chunk:
            break
        baseline_payload += chunk
        if len(baseline_payload) > 1_048_576:
            raise SystemExit("server baseline is too large")
    baseline_opened_after = os.fstat(baseline_descriptor)
finally:
    os.close(baseline_descriptor)
baseline_after = baseline_path.lstat()
if not (
    fingerprint(baseline_before)
    == fingerprint(baseline_opened_after)
    == fingerprint(baseline_after)
):
    raise SystemExit("server baseline changed while reading")
baseline = json.loads(
    baseline_payload.decode("utf-8"), object_pairs_hook=reject_duplicates
)
baseline_keys = {
    "schema_version", "application_release", "captured_at", "hostname",
    "database_uuid", "services", "critical_files", "v3_paths_absent",
    "v3_unit_files", "v3_active_units", "production_dependency_metadata_safe",
    "production_promotion_allowed", "promotion_blockers",
}
if (
    not isinstance(baseline, dict)
    or set(baseline) != baseline_keys
    or not isinstance(baseline["schema_version"], int)
    or isinstance(baseline["schema_version"], bool)
    or baseline["schema_version"] != 1
    or baseline["application_release"] != "0.1.0.dev8-bd21ca07c168"
    or baseline["database_uuid"] != "19b09656-d10f-11f0-9065-00163e54a5ad"
    or baseline["production_dependency_metadata_safe"] is not False
    or baseline["production_promotion_allowed"] is not False
    or not isinstance(baseline["services"], list)
    or len(baseline["services"]) != 2
    or not isinstance(baseline["critical_files"], list)
    or len(baseline["critical_files"]) != 12
):
    raise SystemExit("server baseline identity mismatch")
expected_services = {item["unit"]: item for item in baseline["services"]}
if set(expected_services) != {"odoo19.service", "sudo-pi-agent-bridge.service"}:
    raise SystemExit("server baseline service set mismatch")

def run(*arguments):
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"isolation command failed: {arguments!r}; stderr={completed.stderr.strip()!r}"
        )
    return completed.stdout

def run_unit_listing(*arguments):
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    no_matches = (
        completed.returncode == 1
        and not completed.stdout.strip()
        and not completed.stderr.strip()
    )
    if completed.returncode != 0 and not no_matches:
        raise SystemExit(
            f"isolation unit listing failed: {arguments!r}; "
            f"returncode={completed.returncode}; stderr={completed.stderr.strip()!r}"
        )
    return completed.stdout

for unit, expected_service in expected_services.items():
    if (
        not isinstance(expected_service, dict)
        or set(expected_service)
        != {"unit", "active_state", "sub_state", "main_pid", "cmdline_sha256"}
        or expected_service["active_state"] != "active"
        or expected_service["sub_state"] != "running"
        or not isinstance(expected_service["main_pid"], int)
        or isinstance(expected_service["main_pid"], bool)
        or expected_service["main_pid"] <= 0
        or not isinstance(expected_service["cmdline_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_service["cmdline_sha256"])
    ):
        raise SystemExit(f"server baseline service entry mismatch: {unit}")
    expected_pid = expected_service["main_pid"]
    output = run(
        "/usr/bin/systemctl",
        "show",
        unit,
        "--property=ActiveState",
        "--property=SubState",
        "--property=MainPID",
    )
    properties = dict(
        line.split("=", 1) for line in output.splitlines() if "=" in line
    )
    observed_pid = int(properties.get("MainPID", "0") or "0")
    if (
        properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or observed_pid != expected_pid
    ):
        raise SystemExit(
            f"{phase} isolation service mismatch: {unit} pid={observed_pid} "
            f"active={properties.get('ActiveState')!r} "
            f"sub={properties.get('SubState')!r}"
        )
    process = pathlib.Path(f"/proc/{observed_pid}")
    if not process.is_dir():
        raise SystemExit(f"{phase} isolation process is unavailable: {unit}")
    cmdline = (process / "cmdline").read_bytes().replace(b"\0", b" ")
    if (
        hashlib.sha256(cmdline).hexdigest() != expected_service["cmdline_sha256"]
        or b"odoo-accounting-cli-v3" in cmdline
    ):
        raise SystemExit(f"{phase} isolation service unexpectedly references V3: {unit}")

critical_fields = {
    "path", "sha256", "device", "inode", "uid", "gid", "mode", "nlink",
    "size", "mtime_ns", "ctime_ns",
}
seen_critical = set()
unsafe_critical = []
for entry in baseline["critical_files"]:
    if not isinstance(entry, dict) or set(entry) != critical_fields:
        raise SystemExit("server baseline critical entry fields mismatch")
    raw_path = entry["path"]
    if (
        not isinstance(raw_path, str)
        or not raw_path.startswith("/mnt/odoo/odoo19/custom/")
        or raw_path in seen_critical
        or not isinstance(entry["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        or not isinstance(entry["mode"], str)
        or not re.fullmatch(r"0[0-7]{3}", entry["mode"])
        or any(
            not isinstance(entry[field], int) or isinstance(entry[field], bool)
            for field in ("device", "inode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
        )
        or entry["nlink"] != 1
    ):
        raise SystemExit(f"server baseline critical entry mismatch: {raw_path!r}")
    seen_critical.add(raw_path)
    if int(entry["mode"], 8) & 0o022:
        unsafe_critical.append(raw_path)
    path = pathlib.Path(raw_path)
    before = path.lstat()
    expected_metadata = (
        entry["device"], entry["inode"], entry["uid"], entry["gid"],
        entry["mode"], entry["nlink"], entry["size"], entry["mtime_ns"],
        entry["ctime_ns"],
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or fingerprint(before) != expected_metadata
    ):
        raise SystemExit(f"{phase} isolation critical path is unsafe: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if fingerprint(opened) != expected_metadata:
            raise SystemExit(f"{phase} isolation critical path changed: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        fingerprint(opened_after) != expected_metadata
        or fingerprint(after) != expected_metadata
        or digest.hexdigest() != entry["sha256"]
    ):
        raise SystemExit(f"{phase} isolation hash mismatch: {path}")
expected_blockers = [
    f"{entry['path']} is group/world writable ({entry['mode']})"
    for entry in baseline["critical_files"]
    if int(entry["mode"], 8) & 0o022
]
if (
    baseline["production_dependency_metadata_safe"] is not (not unsafe_critical)
    or baseline["promotion_blockers"] != expected_blockers
):
    raise SystemExit("server baseline production metadata flag mismatch")

current = pathlib.Path("/opt/odoo-accounting-cli-v3/current")
if os.path.lexists(current):
    raise SystemExit(f"{phase} isolation current route is present")

unit_files = run_unit_listing(
    "/usr/bin/systemctl",
    "list-unit-files",
    "--no-legend",
    "odoo-accounting-cli-v3*",
)
active_units = run_unit_listing(
    "/usr/bin/systemctl",
    "list-units",
    "--all",
    "--no-legend",
    "odoo-accounting-cli-v3*",
)
if unit_files.strip() or active_units.strip():
    raise SystemExit(f"{phase} isolation found a V3 systemd unit")

database_uuid = run(
    "/usr/bin/sudo",
    "-u",
    "postgres",
    "/usr/bin/env",
    "-i",
    "HOME=/var/lib/postgresql",
    "LANG=C.UTF-8",
    "PATH=/usr/bin:/bin",
    "psql",
    "--no-psqlrc",
    "--set=ON_ERROR_STOP=1",
    "--tuples-only",
    "--no-align",
    "--dbname=odoo_test",
    "--command=SELECT value FROM ir_config_parameter WHERE key = 'database.uuid';",
).strip()
if database_uuid != "19b09656-d10f-11f0-9065-00163e54a5ad":
    raise SystemExit(f"{phase} isolation database UUID mismatch: {database_uuid!r}")

print(
    f"dev8_isolation_{phase}=passed "
    f"odoo_pid={expected_services['odoo19.service']['main_pid']} "
    f"pi_pid={expected_services['sudo-pi-agent-bridge.service']['main_pid']} "
    f"critical_hashes={len(baseline['critical_files'])} "
    f"production_critical_metadata_safe="
    f"{str(baseline['production_dependency_metadata_safe']).lower()}"
)
PY
}

prepare_pipeline_lock
exec {pipeline_lock_fd}<>"$pipeline_lock"
/usr/bin/flock --exclusive "$pipeline_lock_fd"

verify_completed_transaction_journals
test ! -e /opt/odoo-accounting-cli-v3/current
test ! -L /opt/odoo-accounting-cli-v3/current
verify_isolation pre
verify_package
verify_release
verify_runtime_config
verify_direct_launcher_identity

release_bytecode=$(
  find "$release" -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo'
)
test -z "$release_bytecode"
test ! -e /opt/odoo-accounting-cli-v3/current
test ! -L /opt/odoo-accounting-cli-v3/current
verify_direct_launcher_identity
verify_runtime_config
verify_release
verify_package
verify_completed_transaction_journals
verify_isolation post
printf 'dev8_server_gate=passed\nrelease=%s\npackage_sha256=%s\nmanifest_sha256=%s\nregistry_digest=%s\nmutable_candidate_test_fixture_used=false\nserver_unit_test_source=github-ci-run-29319326192\nproduction_critical_metadata_safe=false\n' \
  "$release_id" "$package_sha" "$manifest_sha" "$registry_sha"
