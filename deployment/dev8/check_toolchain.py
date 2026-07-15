#!/usr/bin/env python3
"""Check the tracked dev8 deployment toolchain without importing server code."""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "TOOLCHAIN-MANIFEST.json"
RELEASE = "0.1.0.dev8-bd21ca07c168"
COMMIT = "bd21ca07c1689a42fbf903b91486269397b44733"
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
TOOLCHAIN_VERSION = "0.1.0.dev8-toolchain.12"
TOOLS = (
    "dev8-install.sh",
    "dev8-runtime-setup.sh",
    "dev8-server-gate.sh",
    "dev8-stage-execution-tools.py",
    "dev8-run-real-reads.sh",
    "dev8-sign-read.py",
    "dev8-launcher-isolation-gate.py",
    "dev8-run-read-oracles.sh",
    "dev6-trial-balance-sql-oracle.py",
    "dev6-ar-sql-oracle.py",
    "dev7-ap-sql-oracle.py",
    "dev8-persistence-audit.py",
    "dev8-runtime-dependency-inventory.py",
    "dev8-canonical-package-negative-gates.py",
    "dev8-freeze-evidence.py",
    "dev8-verify-frozen-evidence.py",
)
SERVER_BASELINE_NAME = "SERVER-BASELINE.json"
SERVICE_TRANSITION_NAME = "SERVER-SERVICE-TRANSITION.json"
PRIOR_EVIDENCE_DISPOSITION_NAME = "PRIOR-EVIDENCE-DISPOSITION.json"
MANIFEST_FILES = (
    *TOOLS,
    SERVER_BASELINE_NAME,
    SERVICE_TRANSITION_NAME,
    PRIOR_EVIDENCE_DISPOSITION_NAME,
)
CONTROL_FILES = {
    "README.md", "TOOLCHAIN-MANIFEST.json", "check_toolchain.py",
    SERVER_BASELINE_NAME, SERVICE_TRANSITION_NAME,
    PRIOR_EVIDENCE_DISPOSITION_NAME,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
BOOT_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
UTC_MICROSECONDS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
HEREDOC = re.compile(r"<<'(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)'\s*$")

BASELINE_SHA256 = "37b498ffce8f175813e866c534b6514142436d9c4dbf29216f1dab1c880c57e4"
BASELINE_SIZE = 5662
BASELINE_CAPTURED_AT = "2026-07-14T12:39:24Z"
SYSTEM_BOOT_ID = "9546f53a-2e02-476d-b579-1960c2bffc30"
EFFECTIVE_SERVICE_PIDS = {
    "odoo19.service": 2576660,
    "sudo-pi-agent-bridge.service": 2065799,
}
SERVICE_OBSERVATIONS = (
    {
        "observation_id": "service-observation-20260714T145014Z",
        "first_observed_at": "2026-07-14T14:50:14Z",
        "last_observed_at": "2026-07-14T14:53:29Z",
        "odoo_identity": {
            "effective_main_pid": 2316421,
            "exec_main_start_monotonic_usec": 10836291877098,
            "invocation_id": "5d50fca75f9043c0a7cacb8f9b853dbc",
            "proc_start_ticks": 1083629187,
        },
    },
    {
        "observation_id": "service-observation-20260715T001423Z",
        "first_observed_at": "2026-07-15T00:14:23Z",
        "last_observed_at": "2026-07-15T00:15:58Z",
        "odoo_identity": {
            "effective_main_pid": 2344733,
            "exec_main_start_monotonic_usec": 10840181608082,
            "invocation_id": "5b211eeb1dbd4f458396f6097b0f6623",
            "proc_start_ticks": 1084018160,
        },
    },
    {
        "observation_id": "service-observation-20260715T021109Z",
        "first_observed_at": "2026-07-15T02:11:09Z",
        "last_observed_at": "2026-07-15T02:13:44Z",
        "odoo_identity": {
            "effective_main_pid": 2576660,
            "exec_main_start_monotonic_usec": 10877336849089,
            "invocation_id": "ae54787981dd466db3b03ae6148b62bb",
            "proc_start_ticks": 1087733684,
        },
    },
)
PI_IDENTITY = {
    "effective_main_pid": 2065799,
    "exec_main_start_monotonic_usec": 7805455913314,
    "invocation_id": "5d393f016f7d4f56849543de03b83a9b",
    "proc_start_ticks": 780545590,
}
JOURNAL_RESTART_CYCLES = (
    ("2026-07-14T14:54:40.864133Z", "2026-07-14T14:54:44.223188Z"),
    ("2026-07-14T15:00:15.480601Z", "2026-07-14T15:00:18.317106Z"),
    ("2026-07-14T15:01:58.803407Z", "2026-07-14T15:02:05.840052Z"),
    ("2026-07-14T15:04:28.843964Z", "2026-07-14T15:04:36.451130Z"),
    ("2026-07-14T15:06:18.973566Z", "2026-07-14T15:08:54.104055Z"),
    ("2026-07-14T15:09:57.196883Z", "2026-07-14T15:10:09.568053Z"),
    ("2026-07-14T15:12:30.427274Z", "2026-07-14T15:15:20.058024Z"),
    ("2026-07-14T15:24:41.403921Z", "2026-07-14T15:24:50.648051Z"),
    ("2026-07-14T15:29:00.948715Z", "2026-07-14T15:29:11.025010Z"),
    ("2026-07-14T15:37:08.517076Z", "2026-07-14T15:37:23.592036Z"),
    ("2026-07-15T00:35:03.900349Z", "2026-07-15T00:35:19.231045Z"),
    ("2026-07-15T00:51:54.132437Z", "2026-07-15T00:52:11.030052Z"),
    ("2026-07-15T01:56:23.289706Z", "2026-07-15T01:56:38.833032Z"),
)
JOURNAL_SEGMENT_COUNTS = (10, 3)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON field: {key}")
        value[key] = item
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc_seconds(value: object, label: str) -> dt.datetime:
    require(
        isinstance(value, str) and UTC_SECONDS.fullmatch(value) is not None,
        f"{label} is not an exact UTC-second timestamp",
    )
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )


def parse_utc_microseconds(value: object, label: str) -> dt.datetime:
    require(
        isinstance(value, str) and UTC_MICROSECONDS.fullmatch(value) is not None,
        f"{label} is not an exact UTC-microsecond timestamp",
    )
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    )


def validate_service_snapshot(
    services: object,
    baseline_services: dict[str, dict[str, object]],
    expected_odoo_identity: dict[str, object],
    label: str,
) -> dict[str, int]:
    expected_units = ("odoo19.service", "sudo-pi-agent-bridge.service")
    service_fields = {
        "active_state", "baseline_main_pid", "cmdline_sha256",
        "effective_main_pid", "exec_main_start_monotonic_usec",
        "invocation_id", "proc_start_ticks", "sub_state", "transition",
        "unit",
    }
    require(
        isinstance(services, list)
        and len(services) == 2
        and all(isinstance(item, dict) for item in services)
        and [item.get("unit") for item in services] == list(expected_units),
        f"{label} service set mismatch",
    )
    effective_pids: dict[str, int] = {}
    for item in services:
        unit = item["unit"]
        baseline_service = baseline_services[unit]
        expected_identity = (
            expected_odoo_identity if unit == "odoo19.service" else PI_IDENTITY
        )
        expected_transition = "changed" if unit == "odoo19.service" else "unchanged"
        expected_item = {
            "active_state": "active",
            "baseline_main_pid": baseline_service["main_pid"],
            "cmdline_sha256": baseline_service["cmdline_sha256"],
            **expected_identity,
            "sub_state": "running",
            "transition": expected_transition,
            "unit": unit,
        }
        require(
            set(item) == service_fields
            and item == expected_item
            and isinstance(item["baseline_main_pid"], int)
            and not isinstance(item["baseline_main_pid"], bool)
            and isinstance(item["effective_main_pid"], int)
            and not isinstance(item["effective_main_pid"], bool)
            and isinstance(item["exec_main_start_monotonic_usec"], int)
            and not isinstance(item["exec_main_start_monotonic_usec"], bool)
            and isinstance(item["proc_start_ticks"], int)
            and not isinstance(item["proc_start_ticks"], bool)
            and HEX64.fullmatch(item["cmdline_sha256"]) is not None
            and HEX32.fullmatch(item["invocation_id"]) is not None,
            f"{label} identity mismatch: {unit}",
        )
        effective_pids[unit] = item["effective_main_pid"]
    return effective_pids


def validate_service_transition(
    transition: object,
    baseline_services: dict[str, dict[str, object]],
) -> dict[str, int]:
    require(
        isinstance(transition, dict)
        and set(transition)
        == {
            "actor_attribution", "application_release", "baseline",
            "classification", "history", "journal_transition_series",
            "maintenance_authorization_verified", "observation",
            "production_promotion_allowed", "production_write_authorized",
            "schema_version", "services", "system_boot_id",
        }
        and isinstance(transition["schema_version"], int)
        and not isinstance(transition["schema_version"], bool)
        and transition["schema_version"] == 2
        and transition["application_release"] == RELEASE
        and transition["actor_attribution"] == "unverified"
        and transition["classification"]
        == "out_of_band_service_transition_history_observed"
        and transition["maintenance_authorization_verified"] is False
        and transition["production_write_authorized"] is False
        and transition["production_promotion_allowed"] is False
        and isinstance(transition["system_boot_id"], str)
        and transition["system_boot_id"] == SYSTEM_BOOT_ID
        and BOOT_UUID.fullmatch(transition["system_boot_id"]) is not None,
        "service transition envelope mismatch",
    )
    require(
        transition["baseline"]
        == {
            "captured_at": BASELINE_CAPTURED_AT,
            "sha256": BASELINE_SHA256,
            "size": BASELINE_SIZE,
        }
        and isinstance(transition["baseline"].get("size"), int)
        and not isinstance(transition["baseline"]["size"], bool),
        "service transition baseline link mismatch",
    )

    history = transition["history"]
    require(
        isinstance(history, list)
        and len(history) == len(SERVICE_OBSERVATIONS)
        and all(isinstance(entry, dict) for entry in history),
        "service transition history mismatch",
    )
    history_ids: list[str] = []
    prior_last = parse_utc_seconds(BASELINE_CAPTURED_AT, "baseline capture")
    latest_pids: dict[str, int] = {}
    for index, (entry, expected) in enumerate(zip(history, SERVICE_OBSERVATIONS)):
        require(
            set(entry) == {"observation_id", "observation", "services"}
            and entry["observation_id"] == expected["observation_id"],
            f"service transition history entry mismatch: {index}",
        )
        history_ids.append(entry["observation_id"])
        observation = entry["observation"]
        require(
            isinstance(observation, dict)
            and set(observation) == {"first_observed_at", "last_observed_at"}
            and observation
            == {
                "first_observed_at": expected["first_observed_at"],
                "last_observed_at": expected["last_observed_at"],
            },
            f"service transition observation mismatch: {entry['observation_id']}",
        )
        first_observed = parse_utc_seconds(
            observation["first_observed_at"], f"history observation {index} first"
        )
        last_observed = parse_utc_seconds(
            observation["last_observed_at"], f"history observation {index} last"
        )
        require(
            first_observed > prior_last
            and (last_observed - first_observed).total_seconds() >= 60,
            f"service transition observation ordering mismatch: {entry['observation_id']}",
        )
        prior_last = last_observed
        latest_pids = validate_service_snapshot(
            entry["services"],
            baseline_services,
            expected["odoo_identity"],
            f"history observation {index}",
        )
    require(
        len(history_ids) == len(set(history_ids))
        and transition["observation"] == history[-1]["observation"]
        and transition["services"] == history[-1]["services"]
        and latest_pids == EFFECTIVE_SERVICE_PIDS,
        "service transition current projection mismatch",
    )

    series = transition["journal_transition_series"]
    require(
        isinstance(series, dict)
        and set(series)
        == {
            "from_observation_id", "intermediate_full_service_identities_available",
            "restart_cycle_count", "restart_cycles", "source",
            "to_observation_id", "unit",
        }
        and series["source"] == "systemd_journal_read_only"
        and series["unit"] == "odoo19.service"
        and series["from_observation_id"] == history_ids[0]
        and series["to_observation_id"] == history_ids[-1]
        and series["intermediate_full_service_identities_available"] is False
        and isinstance(series["restart_cycle_count"], int)
        and not isinstance(series["restart_cycle_count"], bool)
        and series["restart_cycle_count"] == len(JOURNAL_RESTART_CYCLES)
        and isinstance(series["restart_cycles"], list)
        and len(series["restart_cycles"]) == len(JOURNAL_RESTART_CYCLES),
        "journal transition series mismatch",
    )
    prior_cycle_end = parse_utc_seconds(
        history[0]["observation"]["last_observed_at"], "history zero last"
    )
    for cycle_number, (cycle, expected_times) in enumerate(
        zip(series["restart_cycles"], JOURNAL_RESTART_CYCLES), start=1
    ):
        stopping_at, started_at = expected_times
        require(
            isinstance(cycle, dict)
            and set(cycle) == {"cycle", "started_at", "stopping_at"}
            and isinstance(cycle["cycle"], int)
            and not isinstance(cycle["cycle"], bool)
            and cycle
            == {
                "cycle": cycle_number,
                "started_at": started_at,
                "stopping_at": stopping_at,
            },
            f"journal restart cycle mismatch: {cycle_number}",
        )
        stopping = parse_utc_microseconds(
            stopping_at, f"cycle {cycle_number} stopping"
        )
        started = parse_utc_microseconds(started_at, f"cycle {cycle_number} start")
        require(
            stopping > prior_cycle_end and started > stopping,
            f"journal restart cycle ordering mismatch: {cycle_number}",
        )
        prior_cycle_end = started
    require(
        len(JOURNAL_SEGMENT_COUNTS) == len(history) - 1
        and sum(JOURNAL_SEGMENT_COUNTS) == len(JOURNAL_RESTART_CYCLES),
        "journal transition segment count mismatch",
    )
    offset = 0
    for segment_index, cycle_count in enumerate(JOURNAL_SEGMENT_COUNTS):
        segment = series["restart_cycles"][offset : offset + cycle_count]
        require(segment, f"journal transition segment is empty: {segment_index}")
        segment_start = parse_utc_microseconds(
            segment[0]["stopping_at"], f"segment {segment_index} stopping"
        )
        segment_end = parse_utc_microseconds(
            segment[-1]["started_at"], f"segment {segment_index} started"
        )
        require(
            segment_start
            > parse_utc_seconds(
                history[segment_index]["observation"]["last_observed_at"],
                f"history {segment_index} last",
            )
            and segment_end
            < parse_utc_seconds(
                history[segment_index + 1]["observation"]["first_observed_at"],
                f"history {segment_index + 1} first",
            ),
            f"journal transition segment does not connect observations: {segment_index}",
        )
        offset += cycle_count
    return latest_pids


def validate_prior_evidence_disposition(
    disposition: object,
    invalidating_observation_id: str,
    invalidating_observation_last: str,
) -> dict[str, object]:
    expected = {
        "application_release": RELEASE,
        "final_verifier_passed": False,
        "invalidating_service_observation_id": invalidating_observation_id,
        "prior_evidence": {
            "anchor_path":
            "/var/lib/odoo-accounting-cli-v3/evidence-anchors/"
            "0.1.0.dev8-bd21ca07c168.json",
            "anchor_sha256":
            "429d02227cd2d4e35df84d9d0de25ad8f0be7081d8c4cae4d63366dab27b80d6",
            "anchor_size": 1120,
            "evidence_checksum_manifest_sha256":
            "0bb87449e070523cabf0967a26dbe04dc8f0c4da3bc1c490618429517320485e",
            "evidence_metadata_sha256":
            "0320acebc25ca47590b6898d7630814beb0e1e7c453632c876a63f8c813f00be",
            "evidence_path":
            "/var/lib/odoo-accounting-cli-v3/evidence/"
            "0.1.0.dev8-bd21ca07c168",
            "toolchain_version": "0.1.0.dev8-toolchain.8",
        },
        "production_promotion_allowed": False,
        "reason_code": "baseline_service_pid_changed_before_final_verification",
        "recorded_at": invalidating_observation_last,
        "schema_version": 1,
        "status": "retained_nonfinal",
    }
    require(
        isinstance(disposition, dict)
        and disposition == expected
        and isinstance(disposition["schema_version"], int)
        and not isinstance(disposition["schema_version"], bool)
        and disposition["final_verifier_passed"] is False
        and disposition["production_promotion_allowed"] is False,
        "prior evidence disposition mismatch",
    )
    return disposition


def literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                return ast.literal_eval(node.value)
    raise RuntimeError(f"missing literal assignment {name}: {path}")


def compile_python_heredocs(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    compiled = 0
    index = 0
    while index < len(lines):
        match = HEREDOC.search(lines[index].rstrip("\r\n"))
        if match is None:
            index += 1
            continue
        delimiter = match.group("delimiter")
        start = index + 1
        end = start
        while end < len(lines) and lines[end].rstrip("\r\n") != delimiter:
            end += 1
        require(end < len(lines), f"unterminated heredoc at {path}:{index + 1}")
        if delimiter == "PY":
            compile("".join(lines[start:end]), f"{path}:{start + 1}", "exec")
            compiled += 1
        index = end + 1
    return compiled


def main() -> None:
    actual_files = {path.name for path in ROOT.iterdir() if path.is_file()}
    require(actual_files == set(TOOLS) | CONTROL_FILES, "deployment/dev8 file set is not exact")

    document = json.loads(
        MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )
    require(
        isinstance(document, dict)
        and set(document)
        == {
            "schema_version",
            "toolchain_version",
            "application_release",
            "application_commit",
            "application_package_sha256",
            "source_directory",
            "files",
        },
        "toolchain manifest fields are not exact",
    )
    require(
        isinstance(document["schema_version"], int)
        and not isinstance(document["schema_version"], bool)
        and document["schema_version"] == 1
        and document["toolchain_version"] == TOOLCHAIN_VERSION
        and document["application_release"] == RELEASE
        and document["application_commit"] == COMMIT
        and document["application_package_sha256"] == PACKAGE_SHA256
        and document["source_directory"] == "deployment/dev8",
        "toolchain manifest identity mismatch",
    )
    entries = document["files"]
    require(isinstance(entries, list) and len(entries) == len(MANIFEST_FILES), "tool manifest count mismatch")
    require(
        [entry.get("name") for entry in entries if isinstance(entry, dict)] == list(MANIFEST_FILES),
        "tool manifest order or names mismatch",
    )
    for entry in entries:
        require(
            isinstance(entry, dict) and set(entry) == {"name", "sha256", "size"},
            "tool manifest entry fields are not exact",
        )
        name = entry["name"]
        size = entry["size"]
        expected_hash = entry["sha256"]
        path = ROOT / name
        require(
            isinstance(size, int)
            and not isinstance(size, bool)
            and size == path.stat().st_size
            and isinstance(expected_hash, str)
            and HEX64.fullmatch(expected_hash) is not None
            and expected_hash == sha256(path),
            f"tool manifest digest or size mismatch: {name}",
        )

    baseline_path = ROOT / SERVER_BASELINE_NAME
    require(
        baseline_path.stat().st_size == BASELINE_SIZE
        and sha256(baseline_path) == BASELINE_SHA256,
        "server baseline bytes changed",
    )
    baseline = json.loads(
        baseline_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    require(
        isinstance(baseline, dict)
        and set(baseline)
        == {
            "schema_version", "application_release", "captured_at", "hostname",
            "database_uuid", "services", "critical_files", "v3_paths_absent",
            "v3_unit_files", "v3_active_units", "production_dependency_metadata_safe",
            "production_promotion_allowed", "promotion_blockers",
        }
        and isinstance(baseline["schema_version"], int)
        and not isinstance(baseline["schema_version"], bool)
        and baseline["schema_version"] == 1
        and baseline["application_release"] == RELEASE
        and baseline["captured_at"] == BASELINE_CAPTURED_AT
        and baseline["database_uuid"] == "19b09656-d10f-11f0-9065-00163e54a5ad"
        and baseline["production_dependency_metadata_safe"] is False
        and baseline["production_promotion_allowed"] is False,
        "server baseline envelope mismatch",
    )
    services = baseline["services"]
    require(
        isinstance(services, list)
        and [(item.get("unit"), item.get("main_pid")) for item in services]
        == [("odoo19.service", 2257341), ("sudo-pi-agent-bridge.service", 2065799)],
        "server baseline service identity mismatch",
    )
    critical_files = baseline["critical_files"]
    require(
        isinstance(critical_files, list) and len(critical_files) == 12
        and len({item.get("path") for item in critical_files}) == 12
        and [item["path"] for item in critical_files if int(item["mode"], 8) & 0o022]
        == ["/mnt/odoo/odoo19/custom/addons/sudo_ai_bot/__manifest__.py"],
        "server baseline critical metadata mismatch",
    )

    baseline_services = {item["unit"]: item for item in services}
    transition = json.loads(
        (ROOT / SERVICE_TRANSITION_NAME).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    effective_pids = validate_service_transition(transition, baseline_services)

    disposition = json.loads(
        (ROOT / PRIOR_EVIDENCE_DISPOSITION_NAME).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    validate_prior_evidence_disposition(
        disposition,
        transition["history"][0]["observation_id"],
        transition["history"][0]["observation"]["last_observed_at"],
    )

    for name in ("dev8-freeze-evidence.py", "dev8-verify-frozen-evidence.py"):
        require(tuple(literal_assignment(ROOT / name, "TOOL_FILES")) == TOOLS, f"TOOL_FILES mismatch: {name}")

    python_files = [ROOT / name for name in TOOLS if name.endswith(".py")]
    for path in python_files:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    heredoc_count = sum(
        compile_python_heredocs(ROOT / name) for name in TOOLS if name.endswith(".sh")
    )
    require(heredoc_count > 0, "no embedded Python heredocs were checked")

    runtime_gate = (ROOT / "dev8-runtime-setup.sh").read_text(encoding="utf-8")
    server_gate = (ROOT / "dev8-server-gate.sh").read_text(encoding="utf-8")
    for forbidden in ("test-venv", "test-checkout", "pip install", "python3.12"):
        require(forbidden not in runtime_gate and forbidden not in server_gate, f"mutable test fixture returned: {forbidden}")
    require("mutable_candidate_test_fixture_used=false" in server_gate, "mutable fixture marker is missing")
    require("server_unit_test_source=github-ci-run-29319326192" in server_gate, "CI source marker is missing")
    require("production_critical_metadata_safe=false" in server_gate, "production metadata blocker marker is missing")
    install_gate = (ROOT / "dev8-install.sh").read_text(encoding="utf-8")
    require("root_metadata.st_mode & 0o022" in install_gate, "upload parent write guard is missing")
    require("root_metadata.st_mode & 0o007" in install_gate, "upload parent other-access guard is missing")
    require("upload_not_traversable_by_odoo=true" in install_gate, "Odoo upload traversal probe is missing")
    require("root_metadata.st_mode & 0o022" in runtime_gate, "runtime upload parent write guard is missing")
    require("root_metadata.st_mode & 0o007" in runtime_gate, "runtime upload parent other-access guard is missing")
    require("runtime_upload_not_traversable_by_odoo=true" in runtime_gate, "runtime Odoo upload traversal probe is missing")
    require(
        "load_registry(pathlib.Path(sys.argv[1]))" in runtime_gate,
        "runtime registry path conversion is missing",
    )
    for name in ("dev8-server-gate.sh", "dev8-freeze-evidence.py", "dev8-verify-frozen-evidence.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        require(source.count("run_unit_listing(") >= 3, f"systemd no-match listing gate is missing: {name}")
        require("completed.returncode == 1" in source, f"systemd no-match exit contract is missing: {name}")

    print(
        json.dumps(
            {
                "toolchain_version": TOOLCHAIN_VERSION,
                "tool_count": len(TOOLS),
                "manifest_file_count": len(MANIFEST_FILES),
                "upload_file_count": len(MANIFEST_FILES) + 7,
                "effective_service_pids": effective_pids,
                "python_file_count": len(python_files),
                "embedded_python_blocks": heredoc_count,
                "all_checks_passed": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
