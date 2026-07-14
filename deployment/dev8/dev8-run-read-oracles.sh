#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly release_id=0.1.0.dev8-bd21ca07c168
readonly trusted_root=/opt/odoo-accounting-cli-v3
readonly current_route="$trusted_root/current"
readonly odoo_python=/opt/odoo/odoo19/odoo19-venv/bin/python
readonly odoo_python_sha256=1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118
readonly host_python=/usr/bin/python3

readonly trial_source=/tmp/dev6-trial-balance-sql-oracle.py
readonly trial_sha256=7aa959361ac994f17cd871d33211bbef02ab816993ff87f088c82a6541cfcb9b
readonly ar_source=/tmp/dev6-ar-sql-oracle.py
readonly ar_sha256=cdb49967d60af0aa416cadaeb61503847ddfeb4d111aa0e01335fe06b78499c6
readonly ap_source=/tmp/dev7-ap-sql-oracle.py
readonly ap_sha256=ad54540725e8110ea1449586d0dcddb1d6c70b1e387f0e843b989aca6b70f1e5

usage() {
    echo "usage: $0 /tmp/DEV8_REAL_READ_EVIDENCE_DIR" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
    echo "dev8 read-oracle runner must execute as root" >&2
    exit 2
fi

requested_evidence=$1
if [[ "$requested_evidence" != /* || "$requested_evidence" == /tmp ]]; then
    echo "evidence directory must be an absolute direct child of /tmp" >&2
    exit 2
fi
if [[ ! -d "$requested_evidence" || -L "$requested_evidence" ]]; then
    echo "evidence path must be an existing non-symlink directory" >&2
    exit 2
fi
evidence=$(/usr/bin/realpath -e -- "$requested_evidence")
if [[ "$(/usr/bin/dirname -- "$evidence")" != /tmp ]]; then
    echo "resolved evidence directory must be a direct child of /tmp" >&2
    exit 2
fi
if [[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$evidence")" != "0:0:700" ]]; then
    echo "evidence directory must remain root:root mode 0700" >&2
    exit 2
fi

readonly read_names=(registry-list trial-balance ar-open-items ap-open-items)
readonly evidence_base_files=(read-plan.input.json identity.json summary.json)
for path in "${evidence_base_files[@]}"; do
    if [[ ! -f "$evidence/$path" || -L "$evidence/$path" ]]; then
        echo "required real-read evidence is unavailable: $path" >&2
        exit 2
    fi
done
for name in "${read_names[@]}"; do
    for suffix in parameters.json request.json response.json receipt.json stderr exit; do
        path="$evidence/$name.$suffix"
        if [[ ! -f "$path" || -L "$path" ]]; then
            echo "required real-read evidence is unavailable: $name.$suffix" >&2
            exit 2
        fi
    done
done

readonly new_outputs=(
    trial-balance.oracle.json trial-balance.oracle.stderr trial-balance.oracle.exit
    ar-open-items.oracle.json ar-open-items.oracle.stderr ar-open-items.oracle.exit
    ap-open-items.oracle.json ap-open-items.oracle.stderr ap-open-items.oracle.exit
    read-oracles.audit.json
)
for name in "${new_outputs[@]}"; do
    if [[ -e "$evidence/$name" || -L "$evidence/$name" ]]; then
        echo "refusing to overwrite oracle evidence: $name" >&2
        exit 2
    fi
done

if [[ ! -x "$odoo_python" ]]; then
    echo "the Odoo virtualenv Python is unavailable" >&2
    exit 1
fi
if [[ "$(/usr/bin/sha256sum -- "$odoo_python" | /usr/bin/cut -d' ' -f1)" != "$odoo_python_sha256" ]]; then
    echo "the Odoo virtualenv Python hash is not the dev8 runtime binding" >&2
    exit 1
fi
if [[ ! -x "$host_python" ]]; then
    echo "host Python is unavailable" >&2
    exit 1
fi

current_absent() {
    [[ ! -e "$current_route" && ! -L "$current_route" ]]
}

odoo_pid() {
    local value
    value=$(/usr/bin/systemctl show odoo19.service --property=MainPID --value)
    if [[ ! "$value" =~ ^[1-9][0-9]*$ || ! -d "/proc/$value" ]]; then
        echo "Odoo has no live MainPID" >&2
        return 1
    fi
    printf '%s\n' "$value"
}

if ! current_absent; then
    echo "the unpromoted dev8 boundary requires current to be absent" >&2
    exit 1
fi
pid_before=$(odoo_pid)

staging=""
cleanup() {
    if [[ -z "$staging" || "$staging" != /run/dev8-read-oracles.* ]]; then
        return
    fi
    if [[ -d "$staging" && ! -L "$staging" ]]; then
        local resolved
        resolved=$(/usr/bin/realpath -e -- "$staging" 2>/dev/null || true)
        if [[ -n "$resolved" && "$(/usr/bin/dirname -- "$resolved")" == /run ]]; then
            /usr/bin/rm -f -- \
                "$resolved/dev6-trial-balance-sql-oracle.py" \
                "$resolved/dev6-ar-sql-oracle.py" \
                "$resolved/dev7-ap-sql-oracle.py" \
                "$resolved/trial-balance.request.json" \
                "$resolved/trial-balance.response.json" \
                "$resolved/ar-open-items.response.json" \
                "$resolved/ap-open-items.request.json" \
                "$resolved/ap-open-items.response.json"
            /usr/bin/rmdir -- "$resolved" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT

staging=$(/usr/bin/mktemp -d -p /run dev8-read-oracles.XXXXXXXXXX)
if [[ -L "$staging" || "$(/usr/bin/dirname -- "$(/usr/bin/realpath -e -- "$staging")")" != /run ]]; then
    echo "oracle staging directory escaped /run" >&2
    exit 1
fi
/usr/bin/chown root:odoo -- "$staging"
/usr/bin/chmod 0750 -- "$staging"

"$host_python" -I -B - \
    "$staging" "$evidence" \
    "$trial_source" "$trial_sha256" dev6-trial-balance-sql-oracle.py \
    "$ar_source" "$ar_sha256" dev6-ar-sql-oracle.py \
    "$ap_source" "$ap_sha256" dev7-ap-sql-oracle.py <<'PY'
import grp
import hashlib
import os
import stat
import sys
from pathlib import Path


def write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        offset += os.write(descriptor, value[offset:])


def verified_copy(
    source: Path, destination: Path, expected: str | None, gid: int
) -> None:
    source_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    source_fd = os.open(source, source_flags)
    destination_fd = None
    created = False
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"oracle source is not regular: {source}")
        destination_fd = os.open(destination, destination_flags, 0o440)
        created = True
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            write_all(destination_fd, chunk)
        after = os.fstat(source_fd)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or (
            expected is not None and digest.hexdigest() != expected
        ):
            raise RuntimeError(f"source changed or has the wrong SHA-256: {source}")
        os.fchown(destination_fd, 0, gid)
        os.fchmod(destination_fd, 0o440)
        os.fsync(destination_fd)
    except BaseException:
        if destination_fd is not None:
            os.close(destination_fd)
            destination_fd = None
        if created:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


arguments = sys.argv[1:]
if len(arguments) != 11:
    raise SystemExit("internal oracle staging argument mismatch")
root = Path(arguments[0])
evidence = Path(arguments[1])
gid = grp.getgrnam("odoo").gr_gid
metadata = root.stat()
if (
    root.is_symlink()
    or not root.is_dir()
    or metadata.st_uid != 0
    or metadata.st_gid != gid
    or stat.S_IMODE(metadata.st_mode) != 0o750
):
    raise SystemExit("oracle staging directory is invalid")
for offset in range(2, len(arguments), 3):
    source = Path(arguments[offset])
    expected = arguments[offset + 1]
    name = arguments[offset + 2]
    if source.parent != Path("/tmp") or source.name != name:
        raise SystemExit("oracle source path is not the expected uploaded path")
    if len(expected) != 64 or expected.lower() != expected:
        raise SystemExit("oracle SHA-256 binding is invalid")
    verified_copy(source, root / name, expected, gid)

evidence_metadata = evidence.stat()
if (
    evidence.is_symlink()
    or not evidence.is_dir()
    or evidence.resolve().parent != Path("/tmp")
    or evidence_metadata.st_uid != 0
    or evidence_metadata.st_gid != 0
    or stat.S_IMODE(evidence_metadata.st_mode) != 0o700
):
    raise SystemExit("real-read evidence directory is invalid")
for name in (
    "trial-balance.request.json",
    "trial-balance.response.json",
    "ar-open-items.response.json",
    "ap-open-items.request.json",
    "ap-open-items.response.json",
):
    verified_copy(evidence / name, root / name, None, gid)
PY

set -o noclobber

run_oracle() {
    local name=$1
    local script=$2
    shift 2
    local report="$evidence/$name.oracle.json"
    local stderr_file="$evidence/$name.oracle.stderr"
    local exit_file="$evidence/$name.oracle.exit"
    local status

    set +e
    /usr/bin/sudo -n -u odoo /usr/bin/env -i \
        HOME=/nonexistent \
        LANG=C.UTF-8 \
        PATH=/usr/bin:/bin \
        PYTHONDONTWRITEBYTECODE=1 \
        PYTHONNOUSERSITE=1 \
        "$odoo_python" -I -B "$script" "$@" \
        > "$report" 2> "$stderr_file"
    status=$?
    set -e
    printf '%s\n' "$status" > "$exit_file"
    if [[ "$status" -ne 0 ]]; then
        echo "$name oracle failed with exit $status" >&2
        /usr/bin/cat -- "$stderr_file" >&2
        return "$status"
    fi
    if [[ -s "$stderr_file" ]]; then
        echo "$name oracle returned stderr despite a zero exit" >&2
        /usr/bin/cat -- "$stderr_file" >&2
        return 1
    fi
}

run_oracle \
    trial-balance \
    "$staging/dev6-trial-balance-sql-oracle.py" \
    "$staging/trial-balance.request.json" \
    "$staging/trial-balance.response.json"
run_oracle \
    ar-open-items \
    "$staging/dev6-ar-sql-oracle.py" \
    "$staging/ar-open-items.response.json"
run_oracle \
    ap-open-items \
    "$staging/dev7-ap-sql-oracle.py" \
    "$staging/ap-open-items.request.json" \
    "$staging/ap-open-items.response.json"

pid_after=$(odoo_pid)
if [[ "$pid_after" != "$pid_before" ]]; then
    echo "Odoo MainPID changed while the read-only oracles ran" >&2
    exit 1
fi
if ! current_absent; then
    echo "current appeared while the read-only oracles ran" >&2
    exit 1
fi

"$host_python" -I -B - \
    "$evidence" "$pid_before" "$pid_after" \
    "$staging/dev6-trial-balance-sql-oracle.py" \
    "$staging/dev6-ar-sql-oracle.py" \
    "$staging/dev7-ap-sql-oracle.py" \
    > "$evidence/read-oracles.audit.json" <<'PY'
import grp
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path


RELEASE_ID = "0.1.0.dev8-bd21ca07c168"
CURRENT = Path("/opt/odoo-accounting-cli-v3/current")
EXPECTED_RELEASE = {
    "commit": "bd21ca07c1689a42fbf903b91486269397b44733",
    "manifest_sha256": "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06",
    "package_sha256": "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234",
    "registry_digest": "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e",
    "release": RELEASE_ID,
    "verified": True,
    "version": "0.1.0.dev8",
}
EXPECTED_RUNTIME = {
    "capability_channel": "staged",
    "database_name": "odoo_test",
    "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
    "environment": "test",
    "instance_id": "odoo19@43.165.173.80",
}
CASES = {
    "registry-list": "acct.registry.list.v1",
    "trial-balance": "acct.gl.trial_balance.v1",
    "ar-open-items": "acct.ar.open_items.v1",
    "ap-open-items": "acct.ap.open_items.v1",
}
STAGED_IDS = [
    "acct.ap.open_items.v1",
    "acct.ar.open_items.v1",
    "acct.gl.trial_balance.v1",
    "acct.registry.list.v1",
]
CONTRACT_DIGESTS = {
    "acct.registry.list.v1": "61c85bfdea5b9ff08a9e85373c87387c6c807520646c7e67ff0073a8daec7453",
    "acct.gl.trial_balance.v1": "728b1487fae87472daef75bbcbeeedc280788c76781698f18d4d577a8e7b460a",
    "acct.ar.open_items.v1": "b1c648d292135f46ac6474195c67713b927e943c22650042c4f19cf50acea082",
    "acct.ap.open_items.v1": "dcfc39b9e850c6dbd2064a951ea2d017153f5376e5d3f8b22ecf41fe26a9973c",
}
ORACLE_HASHES = {
    "trial-balance": "7aa959361ac994f17cd871d33211bbef02ab816993ff87f088c82a6541cfcb9b",
    "ar-open-items": "cdb49967d60af0aa416cadaeb61503847ddfeb4d111aa0e01335fe06b78499c6",
    "ap-open-items": "ad54540725e8110ea1449586d0dcddb1d6c70b1e387f0e843b989aca6b70f1e5",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def load_bytes(path: Path) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        raise RuntimeError(f"unsafe evidence file metadata: {path.name}")
    return path.read_bytes()


def load_json(path: Path):
    return json.loads(
        load_bytes(path).decode("utf-8"),
        object_pairs_hook=reject_pairs,
        parse_constant=reject_constant,
    )


def canonical(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError("authentication timestamp is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeError("authentication timestamp lacks a timezone")
    return parsed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


root = Path(sys.argv[1])
pid_before = int(sys.argv[2])
pid_after = int(sys.argv[3])
oracle_paths = {
    "trial-balance": Path(sys.argv[4]),
    "ar-open-items": Path(sys.argv[5]),
    "ap-open-items": Path(sys.argv[6]),
}

root_metadata = root.lstat()
require(
    stat.S_ISDIR(root_metadata.st_mode)
    and root_metadata.st_uid == 0
    and root_metadata.st_gid == 0
    and stat.S_IMODE(root_metadata.st_mode) == 0o700
    and root.resolve().parent == Path("/tmp"),
    "evidence directory metadata or location is invalid",
)

staging_root = oracle_paths["trial-balance"].parent
staging_metadata = staging_root.lstat()
odoo_gid = grp.getgrnam("odoo").gr_gid
require(
    all(path.parent == staging_root for path in oracle_paths.values())
    and stat.S_ISDIR(staging_metadata.st_mode)
    and staging_metadata.st_uid == 0
    and staging_metadata.st_gid == odoo_gid
    and stat.S_IMODE(staging_metadata.st_mode) == 0o750
    and staging_root.resolve().parent == Path("/run")
    and staging_root.name.startswith("dev8-read-oracles."),
    "oracle staging directory identity is invalid",
)
staged_input_evidence = []
for name in (
    "trial-balance.request.json",
    "trial-balance.response.json",
    "ar-open-items.response.json",
    "ap-open-items.request.json",
    "ap-open-items.response.json",
):
    original = root / name
    staged = staging_root / name
    original_metadata = original.lstat()
    staged_metadata = staged.lstat()
    require(
        stat.S_ISREG(original_metadata.st_mode)
        and original_metadata.st_uid == 0
        and original_metadata.st_nlink == 1
        and not original_metadata.st_mode & 0o077,
        f"unsafe original oracle input metadata: {name}",
    )
    require(
        stat.S_ISREG(staged_metadata.st_mode)
        and staged_metadata.st_uid == 0
        and staged_metadata.st_gid == odoo_gid
        and staged_metadata.st_nlink == 1
        and stat.S_IMODE(staged_metadata.st_mode) == 0o440,
        f"unsafe staged oracle input metadata: {name}",
    )
    original_sha = hashlib.sha256(original.read_bytes()).hexdigest()
    staged_sha = hashlib.sha256(staged.read_bytes()).hexdigest()
    require(original_sha == staged_sha, f"staged oracle input differs from evidence: {name}")
    staged_input_evidence.append({"name": name, "sha256": original_sha})

plan = load_json(root / "read-plan.input.json")
expected_plan_keys = {"principal", "user_id", "company_id", "allowed_company_ids", "reads"}
require(isinstance(plan, dict) and set(plan) == expected_plan_keys, "read-plan fields are invalid")
require(isinstance(plan["reads"], dict) and set(plan["reads"]) == set(CASES), "read-plan cases are invalid")
require(isinstance(plan["principal"], str) and plan["principal"].strip(), "read-plan principal is invalid")
require(type(plan["user_id"]) is int and plan["user_id"] > 0, "read-plan user_id is invalid")
require(type(plan["company_id"]) is int and plan["company_id"] > 0, "read-plan company_id is invalid")
require(
    isinstance(plan["allowed_company_ids"], list)
    and plan["allowed_company_ids"]
    and all(type(value) is int and value > 0 for value in plan["allowed_company_ids"])
    and len(plan["allowed_company_ids"]) == len(set(plan["allowed_company_ids"]))
    and plan["company_id"] in plan["allowed_company_ids"],
    "read-plan allowed_company_ids are invalid",
)
expected_identity = {key: plan[key] for key in ("principal", "user_id", "company_id", "allowed_company_ids")}
require(load_json(root / "identity.json") == expected_identity, "identity evidence does not round-trip")

expected_context_keys = {
    "allowed_company_ids",
    "audience",
    "auth_expires_at",
    "auth_issued_at",
    "auth_key_id",
    "auth_request_digest",
    "auth_signature",
    "auth_signature_purpose",
    "auth_signature_version",
    "auth_token_id",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "odoo_instance_id",
    "principal",
    "user_id",
}
expected_receipt_keys = {
    "capability_id",
    "capability_channel",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "id",
    "observed_at",
    "odoo_instance_id",
    "record_count",
    "registry_digest",
    "release_digest",
    "request_digest",
    "result_digest",
    "signature",
    "signature_key_id",
    "signature_purpose",
    "signature_version",
    "user_id",
}

requests = {}
responses = {}
receipts = {}
token_ids = []
roundtrip_rows = []
for name, capability_id in CASES.items():
    parameters = plan["reads"][name]
    require(
        isinstance(parameters, dict) and parameters.get("company_id") == plan["company_id"],
        f"{name} parameters are not bound to the planned company",
    )
    require(load_json(root / f"{name}.parameters.json") == parameters, f"{name} parameter evidence changed")
    request = load_json(root / f"{name}.request.json")
    response = load_json(root / f"{name}.response.json")
    extracted_receipt = load_json(root / f"{name}.receipt.json")
    requests[name] = request
    responses[name] = response

    require(set(request) == {"capability_id", "context", "parameters"}, f"{name} request fields are invalid")
    require(request["capability_id"] == capability_id, f"{name} capability binding changed")
    require(request["parameters"] == parameters, f"{name} parameters did not round-trip")
    context = request["context"]
    require(isinstance(context, dict) and set(context) == expected_context_keys, f"{name} context fields are invalid")
    expected_context = {
        "allowed_company_ids": sorted(plan["allowed_company_ids"]),
        "audience": "odoo-accounting-cli-v3",
        "auth_key_id": "test-auth-2026-07-dev8",
        "auth_signature_purpose": "auth_context_v1",
        "auth_signature_version": 1,
        "company_id": plan["company_id"],
        "database_name": EXPECTED_RUNTIME["database_name"],
        "database_uuid": EXPECTED_RUNTIME["database_uuid"],
        "environment": EXPECTED_RUNTIME["environment"],
        "odoo_instance_id": EXPECTED_RUNTIME["instance_id"],
        "principal": plan["principal"],
        "user_id": plan["user_id"],
    }
    require(all(context.get(key) == value for key, value in expected_context.items()), f"{name} identity/context binding changed")
    expected_auth_digest = digest({"capability_id": capability_id, "parameters": parameters})
    require(context["auth_request_digest"] == expected_auth_digest, f"{name} authentication digest mismatch")
    require(isinstance(context["auth_signature"], str) and HEX64.fullmatch(context["auth_signature"]), f"{name} authentication signature shape is invalid")
    token_id = context["auth_token_id"]
    require(isinstance(token_id, str) and token_id.startswith("dev8-read-"), f"{name} token namespace is invalid")
    uuid.UUID(token_id.removeprefix("dev8-read-"))
    token_ids.append(token_id)
    issued = parse_timestamp(context["auth_issued_at"])
    expires = parse_timestamp(context["auth_expires_at"])
    require(expires - issued == timedelta(minutes=4), f"{name} authentication TTL is not four minutes")

    require(
        isinstance(response, dict)
        and set(response) == {"command", "data", "ok"}
        and response["ok"] is True
        and response["command"] == "read",
        f"{name} response envelope is invalid",
    )
    data = response["data"]
    require(
        isinstance(data, dict)
        and set(data) == {"capability_id", "release_identity", "result", "runtime"},
        f"{name} response data fields are invalid",
    )
    require(data["capability_id"] == capability_id, f"{name} response capability mismatch")
    require(data["release_identity"] == EXPECTED_RELEASE, f"{name} release identity mismatch")
    require(data["runtime"] == EXPECTED_RUNTIME, f"{name} runtime identity mismatch")
    result = data["result"]
    require(isinstance(result, dict) and isinstance(result.get("page"), dict), f"{name} result page is missing")
    receipt = result.get("receipt")
    require(isinstance(receipt, dict) and set(receipt) == expected_receipt_keys, f"{name} receipt fields are invalid")
    require(receipt == extracted_receipt, f"{name} extracted receipt differs from the response")
    receipts[name] = receipt
    expected_receipt_binding = {
        "capability_id": capability_id,
        "capability_channel": EXPECTED_RUNTIME["capability_channel"],
        "company_id": plan["company_id"],
        "database_name": EXPECTED_RUNTIME["database_name"],
        "database_uuid": EXPECTED_RUNTIME["database_uuid"],
        "environment": EXPECTED_RUNTIME["environment"],
        "odoo_instance_id": EXPECTED_RUNTIME["instance_id"],
        "record_count": result["page"]["total_count"],
        "registry_digest": EXPECTED_RELEASE["registry_digest"],
        "release_digest": EXPECTED_RELEASE["manifest_sha256"],
        "signature_key_id": "test-receipt-2026-07-dev8",
        "signature_purpose": "read_receipt_v2",
        "signature_version": 2,
        "user_id": plan["user_id"],
    }
    require(all(receipt.get(key) == value for key, value in expected_receipt_binding.items()), f"{name} receipt binding mismatch")
    require(isinstance(receipt["signature"], str) and HEX64.fullmatch(receipt["signature"]), f"{name} receipt signature shape is invalid")
    uuid.UUID(receipt["id"])
    parse_timestamp(receipt["observed_at"])
    request_digest = digest(
        {
            "auth_token_id": token_id,
            "capability_channel": EXPECTED_RUNTIME["capability_channel"],
            "capability_id": capability_id,
            "company_id": plan["company_id"],
            "database_name": EXPECTED_RUNTIME["database_name"],
            "database_uuid": EXPECTED_RUNTIME["database_uuid"],
            "environment": EXPECTED_RUNTIME["environment"],
            "odoo_instance_id": EXPECTED_RUNTIME["instance_id"],
            "parameters": parameters,
            "principal": plan["principal"],
            "registry_digest": EXPECTED_RELEASE["registry_digest"],
            "release_digest": EXPECTED_RELEASE["manifest_sha256"],
            "user_id": plan["user_id"],
        }
    )
    require(receipt["request_digest"] == request_digest, f"{name} receipt request digest mismatch")
    body = {key: value for key, value in result.items() if key != "receipt"}
    require(receipt["result_digest"] == digest(body), f"{name} receipt result digest mismatch")
    require(load_bytes(root / f"{name}.stderr") == b"", f"{name} launcher stderr is not empty")
    require(load_bytes(root / f"{name}.exit").decode("ascii").strip() == "0", f"{name} launcher exit is not zero")
    if name != "registry-list":
        require(result["page"].get("limit") == parameters["limit"], f"{name} page limit changed")
        require(result["page"].get("offset") == parameters["offset"], f"{name} page offset changed")
    roundtrip_rows.append(
        {
            "name": name,
            "capability_id": capability_id,
            "auth_token_id": token_id,
            "parameters_sha256": digest(parameters),
            "receipt_id": receipt["id"],
            "record_count": receipt["record_count"],
        }
    )

require(len(token_ids) == len(set(token_ids)) == 4, "read authentication tokens are not unique")

registry = responses["registry-list"]["data"]["result"]
require(set(registry) == {"capabilities", "page", "receipt"}, "registry result fields are invalid")
require(registry["page"] == {"count": 4, "total_count": 4}, "registry page is not exactly four")
descriptors = registry["capabilities"]
require(isinstance(descriptors, list) and [item.get("id") for item in descriptors] == STAGED_IDS, "registry staged IDs are not exact")
descriptor_keys = {
    "access",
    "approval_required",
    "business_description",
    "capability_channel",
    "company_scope",
    "contract_digest",
    "domain",
    "evidence_level",
    "id",
    "idempotency_required",
    "input_schema_json",
    "odoo_permissions",
    "output_schema_json",
    "recovery_method",
    "risk_level",
    "verification_method",
}
for descriptor in descriptors:
    require(isinstance(descriptor, dict) and set(descriptor) == descriptor_keys, "registry descriptor fields are invalid")
    require(descriptor["access"] == "read" and descriptor["capability_channel"] == "staged", "registry descriptor is not a staged read")
    require(descriptor["contract_digest"] == CONTRACT_DIGESTS[descriptor["id"]], "registry contract digest mismatch")
require(registry["receipt"]["record_count"] == 4, "registry receipt count is not exactly four")

summary = load_json(root / "summary.json")
expected_summary_rows = [
    {
        "name": row["name"],
        "capability_id": row["capability_id"],
        "auth_token_id": row["auth_token_id"],
        "receipt_id": row["receipt_id"],
        "record_count": row["record_count"],
    }
    for row in roundtrip_rows
]
require(summary == {"all_verified": True, "reads": expected_summary_rows}, "real-read summary does not match the four requests")

oracle_reports = {}
oracle_evidence = []
for name, script_path in oracle_paths.items():
    script_metadata = script_path.lstat()
    require(
        stat.S_ISREG(script_metadata.st_mode)
        and script_metadata.st_uid == 0
        and script_metadata.st_gid == odoo_gid
        and script_metadata.st_nlink == 1
        and stat.S_IMODE(script_metadata.st_mode) == 0o440,
        f"{name} staged oracle metadata is invalid",
    )
    script_sha = hashlib.sha256(script_path.read_bytes()).hexdigest()
    require(script_sha == ORACLE_HASHES[name], f"{name} staged oracle SHA-256 mismatch")
    report = load_json(root / f"{name}.oracle.json")
    oracle_reports[name] = report
    require(report.get("all_checks_passed") is True, f"{name} oracle checks did not all pass")
    require(report.get("transaction_isolation") == "repeatable read", f"{name} oracle isolation is not repeatable read")
    require(report.get("transaction_read_only") == "on", f"{name} oracle transaction is not read-only")
    require(report.get("rollback_completed") is True, f"{name} oracle rollback evidence is missing")
    checks = report.get("checks")
    require(isinstance(checks, dict) and checks and all(value is True for value in checks.values()), f"{name} oracle check details are incomplete")
    require(load_bytes(root / f"{name}.oracle.stderr") == b"", f"{name} oracle stderr is not empty")
    require(load_bytes(root / f"{name}.oracle.exit").decode("ascii").strip() == "0", f"{name} oracle exit is not zero")
    oracle_evidence.append(
        {
            "name": name,
            "script_sha256": script_sha,
            "all_checks_passed": True,
            "transaction_isolation": report["transaction_isolation"],
            "transaction_read_only": report["transaction_read_only"],
            "rollback_completed": report["rollback_completed"],
        }
    )

checks = {
    "exact_dev8_release_identity_on_four_reads": all(
        response["data"]["release_identity"] == EXPECTED_RELEASE
        for response in responses.values()
    ),
    "exact_staged_four_registry": [item["id"] for item in descriptors] == STAGED_IDS,
    "registry_page_and_receipt_count_four": registry["page"] == {"count": 4, "total_count": 4}
    and registry["receipt"]["record_count"] == 4,
    "four_request_parameter_context_roundtrip": len(roundtrip_rows) == 4,
    "three_exact_oracle_hashes": len(oracle_evidence) == 3,
    "five_staged_inputs_match_root_private_evidence": len(staged_input_evidence) == 5,
    "three_financial_oracles_passed": all(
        report["all_checks_passed"] is True for report in oracle_reports.values()
    ),
    "three_oracle_transactions_read_only": all(
        report["transaction_read_only"] == "on"
        and report["transaction_isolation"] == "repeatable read"
        and report["rollback_completed"] is True
        for report in oracle_reports.values()
    ),
    "odoo_pid_unchanged": pid_before > 0 and pid_after == pid_before,
    "current_absent": not os.path.lexists(CURRENT),
}
require(all(checks.values()), "final read-oracle audit checks did not all pass")

report = {
    "schema_version": 1,
    "release": RELEASE_ID,
    "evidence_directory": str(root),
    "database_name": EXPECTED_RUNTIME["database_name"],
    "capability_channel": EXPECTED_RUNTIME["capability_channel"],
    "registry": {
        "capability_ids": STAGED_IDS,
        "page": registry["page"],
        "receipt_id": registry["receipt"]["id"],
        "release_identity": EXPECTED_RELEASE,
    },
    "request_roundtrip": roundtrip_rows,
    "staged_inputs": staged_input_evidence,
    "oracles": oracle_evidence,
    "odoo_pid_before": pid_before,
    "odoo_pid_after": pid_after,
    "checks": checks,
    "all_checks_passed": True,
    "odoo_action_performed": False,
    "database_writes_permitted": False,
    "production_validated": False,
    "production_promotion_allowed": False,
}
print(json.dumps(report, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")))
PY

if ! current_absent; then
    echo "current appeared before the read-oracle audit completed" >&2
    exit 1
fi
if [[ "$(odoo_pid)" != "$pid_before" ]]; then
    echo "Odoo MainPID changed before the read-oracle audit completed" >&2
    exit 1
fi

cleanup
if [[ -e "$staging" || -L "$staging" ]]; then
    echo "oracle staging directory cleanup did not complete" >&2
    exit 1
fi
staging=""
trap - EXIT

echo "verified dev8 read-only oracle evidence: $evidence"
