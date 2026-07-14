#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly release=/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168
readonly launcher="$release/bin/odoo-accounting-cli-v3"
readonly runtime=/etc/odoo-accounting-cli-v3/runtime-test-dev8.json
readonly python=/usr/bin/python3

usage() {
    echo "usage: $0 /tmp/EMPTY_EVIDENCE_DIR READ_PLAN.json" >&2
    echo "READ_PLAN must bind principal/user/company/allowed_company_ids and parameters for all four reads." >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "dev8 evidence runner must execute as root" >&2
    exit 2
fi

requested_evidence=$1
plan=$2
if [[ "$requested_evidence" != /* || "$requested_evidence" == /tmp ]]; then
    echo "evidence directory must be an absolute child of /tmp" >&2
    exit 2
fi
if [[ ! -f "$plan" || -L "$plan" ]]; then
    echo "read plan must be a regular, non-symlink file" >&2
    exit 2
fi
if [[ ! -x "$launcher" || -L "$launcher" ]]; then
    echo "exact dev8 canonical launcher is unavailable" >&2
    exit 1
fi
if [[ ! -f "$runtime" || -L "$runtime" ]]; then
    echo "exact dev8 runtime configuration is unavailable" >&2
    exit 1
fi

if [[ -e "$requested_evidence" ]]; then
    if [[ ! -d "$requested_evidence" || -L "$requested_evidence" ]]; then
        echo "evidence path must be a non-symlink directory" >&2
        exit 2
    fi
else
    mkdir -m 0700 -- "$requested_evidence"
fi
evidence=$(/usr/bin/realpath -e -- "$requested_evidence")
if [[ "$(dirname -- "$evidence")" != /tmp ]]; then
    echo "resolved evidence directory must be a direct child of /tmp" >&2
    exit 2
fi
if [[ "$(/usr/bin/stat -c '%u:%g:%a' -- "$evidence")" != "0:0:700" ]]; then
    echo "evidence directory must be root:root mode 0700" >&2
    exit 2
fi
if [[ -n "$(/usr/bin/find "$evidence" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "evidence directory must be empty" >&2
    exit 2
fi

script_path=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
signer="$(dirname -- "$script_path")/dev8-sign-read.py"
if [[ ! -f "$signer" || -L "$signer" ]]; then
    echo "dev8 signer must be a sibling regular file" >&2
    exit 1
fi
sudo -n -u odoo test -r "$signer"

cp -- "$plan" "$evidence/read-plan.input.json"

"$python" -I - "$plan" "$evidence" <<'PY'
import json
import sys
from pathlib import Path


def reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


plan_path, evidence_path = map(Path, sys.argv[1:])
value = json.loads(
    plan_path.read_text(encoding="utf-8"),
    object_pairs_hook=reject_pairs,
    parse_constant=reject_constant,
)
expected_top = {"principal", "user_id", "company_id", "allowed_company_ids", "reads"}
if not isinstance(value, dict) or set(value) != expected_top:
    raise SystemExit(f"read plan keys must be exactly {sorted(expected_top)}")
if not isinstance(value["principal"], str) or not value["principal"].strip():
    raise SystemExit("principal must be a non-empty string")
if any(ord(char) < 32 for char in value["principal"]):
    raise SystemExit("principal must not contain control characters")
for name in ("user_id", "company_id"):
    if isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] <= 0:
        raise SystemExit(f"{name} must be a positive integer")
allowed = value["allowed_company_ids"]
if (
    not isinstance(allowed, list)
    or not allowed
    or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in allowed)
    or len(allowed) != len(set(allowed))
):
    raise SystemExit("allowed_company_ids must be unique positive integers")
if value["company_id"] not in allowed:
    raise SystemExit("bound company must be allowed")

cases = {
    "registry-list": "acct.registry.list.v1",
    "trial-balance": "acct.gl.trial_balance.v1",
    "ar-open-items": "acct.ar.open_items.v1",
    "ap-open-items": "acct.ap.open_items.v1",
}
reads = value["reads"]
if not isinstance(reads, dict) or set(reads) != set(cases):
    raise SystemExit(f"reads keys must be exactly {sorted(cases)}")
for name, capability_id in cases.items():
    parameters = reads[name]
    if not isinstance(parameters, dict):
        raise SystemExit(f"{name} parameters must be an object")
    if parameters.get("company_id") != value["company_id"]:
        raise SystemExit(f"{name} company_id must equal the bound company")
    (evidence_path / f"{name}.parameters.json").write_text(
        json.dumps(parameters, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

identity = {key: value[key] for key in ("principal", "user_id", "company_id", "allowed_company_ids")}
(evidence_path / "identity.json").write_text(
    json.dumps(identity, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

principal=$("$python" -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["principal"])' "$evidence/identity.json")
user_id=$("$python" -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["user_id"])' "$evidence/identity.json")
company_id=$("$python" -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["company_id"])' "$evidence/identity.json")
allowed_company_ids=$("$python" -I -c 'import json,sys; print(",".join(map(str,json.load(open(sys.argv[1], encoding="utf-8"))["allowed_company_ids"])))' "$evidence/identity.json")

run_read() {
    local name=$1
    local capability_id=$2
    local parameters request response receipt stderr_file exit_file status
    parameters=$(<"$evidence/${name}.parameters.json")
    request="$evidence/${name}.request.json"
    response="$evidence/${name}.response.json"
    receipt="$evidence/${name}.receipt.json"
    stderr_file="$evidence/${name}.stderr"
    exit_file="$evidence/${name}.exit"

    sudo -n -u odoo env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
        "$python" -I "$signer" \
        --capability-id "$capability_id" \
        --parameters-json "$parameters" \
        --principal "$principal" \
        --user-id "$user_id" \
        --company-id "$company_id" \
        --allowed-company-ids "$allowed_company_ids" \
        > "$request"

    set +e
    sudo -n -u odoo env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
        "$launcher" read --runtime-config "$runtime" \
        < "$request" > "$response" 2> "$stderr_file"
    status=$?
    set -e
    printf '%s\n' "$status" > "$exit_file"
    if [[ "$status" -ne 0 ]]; then
        echo "$name failed with exit $status; see $stderr_file" >&2
        return "$status"
    fi
    if [[ -s "$stderr_file" ]]; then
        echo "$name returned stderr despite a zero launcher exit; refusing the result" >&2
        return 1
    fi

    "$python" -I - "$request" "$response" "$receipt" "$capability_id" <<'PY'
import json
import re
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


request_path, response_path, receipt_path, expected_capability = sys.argv[1:]
request = load(request_path)
wire = load(response_path)
if wire.get("ok") is not True or wire.get("command") != "read":
    raise SystemExit("canonical launcher did not return a successful read envelope")
data = wire.get("data")
if not isinstance(data, dict) or data.get("capability_id") != expected_capability:
    raise SystemExit("response capability binding is missing or incorrect")
result = data.get("result")
receipt = result.get("receipt") if isinstance(result, dict) else None
if not isinstance(receipt, dict):
    raise SystemExit("verified receipt is missing")
context = request.get("context", {})
expected = {
    "capability_id": expected_capability,
    "company_id": context.get("company_id"),
    "user_id": context.get("user_id"),
    "environment": "test",
    "capability_channel": "staged",
    "signature_version": 2,
    "signature_purpose": "read_receipt_v2",
}
if any(receipt.get(key) != value for key, value in expected.items()):
    raise SystemExit("verified receipt identity or runtime binding is incorrect")
if not isinstance(receipt.get("id"), str) or not receipt["id"]:
    raise SystemExit("verified receipt ID is missing")
if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("signature", ""))):
    raise SystemExit("verified receipt signature is missing")
page = result.get("page")
if not isinstance(page, dict) or receipt.get("record_count") != page.get("total_count"):
    raise SystemExit("verified receipt record count does not match the result")
Path(receipt_path).write_text(
    json.dumps(receipt, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

run_read registry-list acct.registry.list.v1
run_read trial-balance acct.gl.trial_balance.v1
run_read ar-open-items acct.ar.open_items.v1
run_read ap-open-items acct.ap.open_items.v1

"$python" -I - "$evidence" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
names = ("registry-list", "trial-balance", "ar-open-items", "ap-open-items")
summary = {"all_verified": True, "reads": []}
for name in names:
    request = json.loads((root / f"{name}.request.json").read_text(encoding="utf-8"))
    receipt = json.loads((root / f"{name}.receipt.json").read_text(encoding="utf-8"))
    summary["reads"].append(
        {
            "name": name,
            "capability_id": request["capability_id"],
            "auth_token_id": request["context"]["auth_token_id"],
            "receipt_id": receipt["id"],
            "record_count": receipt["record_count"],
        }
    )
(root / "summary.json").write_text(
    json.dumps(summary, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

echo "verified dev8 read evidence: $evidence"
