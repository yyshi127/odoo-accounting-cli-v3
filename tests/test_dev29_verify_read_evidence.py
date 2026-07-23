from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEV29 = ROOT / "deployment" / "dev29"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


suite = load_module("dev29_suite_for_independence", DEV29 / "run_read_suite.py")
verifier = load_module("dev29_verify_read_evidence", DEV29 / "verify_read_evidence.py")

VERSION = "0.1.0.dev29"
COMMIT = "a1234567890bcdef1234567890abcdef12345678"
RELEASE = f"{VERSION}-{COMMIT[:12]}"
EXPECTED = {
    "release": RELEASE,
    "version": VERSION,
    "commit": COMMIT,
    "manifest_sha256": "b" * 64,
    "package_sha256": "c" * 64,
}


def plan() -> dict:
    return json.loads((DEV29 / "read_plan.json").read_text("utf-8"))


def _valid_state_delta_fixture():
    started = "2026-07-20T00:00:00Z"
    finished = "2026-07-20T00:20:00Z"
    runtime = {"auth_state_path": "/state/auth.db", "receipt_state_path": "/state/receipt.db"}
    requests = {}
    receipts = {}
    for index, name in enumerate(verifier.POSITIVE_NAMES):
        request = {
            "context": {
                "auth_token_id": f"token-{index:02d}",
                "auth_issued_at": "2026-07-19T23:59:00Z",
                "auth_expires_at": "2026-07-20T00:10:00Z",
                "principal": {"user_id": index + 1, "company_id": 1},
            },
            "parameters": {"case": name},
        }
        request_digest = hashlib.sha256(verifier.canonical_json(request)).hexdigest()
        observed = f"2026-07-20T00:01:{index:02d}Z"
        requests[name] = request
        receipts[name] = {
            "id": f"receipt-{index:02d}",
            "request_digest": request_digest,
            "observed_at": observed,
            "capability_id": f"capability.{name}",
            "capability_channel": "read",
            "company_id": 1,
            "environment": "sandbox",
            "database_name": "sandbox",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "odoo_instance_id": "instance-1",
            "registry_digest": "1" * 64,
            "release_digest": "2" * 64,
            "result_digest": "3" * 64,
            "user_id": index + 1,
        }
    requests["acl_deny"] = {
        "context": {
            "auth_token_id": "token-99",
            "auth_issued_at": "2026-07-19T23:59:00Z",
            "auth_expires_at": "2026-07-20T00:10:00Z",
            "principal": {"user_id": 99, "company_id": 1},
        },
        "parameters": {"case": "acl_deny"},
    }
    token_requests = [requests[name] for name in verifier.POSITIVE_NAMES] + [
        requests["acl_deny"]
    ]
    token_rows = sorted(
        (
            {
                "token_id": request["context"]["auth_token_id"],
                "request_digest": hashlib.sha256(
                    verifier.canonical_json(request)
                ).hexdigest(),
                "expires_at": request["context"]["auth_expires_at"],
                "consumed_at": f"2026-07-20T00:00:{20 + index:02d}Z",
            }
            for index, request in enumerate(token_requests)
        ),
        key=lambda row: row["token_id"],
    )
    receipt_rows = sorted(
        (
            {
                "receipt_id": receipt["id"],
                "request_digest": receipt["request_digest"],
                "observed_at": receipt["observed_at"],
                "consumed_at": f"2026-07-20T00:02:{index:02d}Z",
            }
            for index, receipt in enumerate(receipts.values())
        ),
        key=lambda row: row["receipt_id"],
    )
    previous = "a" * 64
    audit_rows = []
    for index, name in enumerate(verifier.POSITIVE_NAMES):
        receipt = receipts[name]
        request = requests[name]
        payload = {
            "auth_token_id": request["context"]["auth_token_id"],
            "capability_id": receipt["capability_id"],
            "capability_channel": receipt["capability_channel"],
            "company_id": receipt["company_id"],
            "environment": receipt["environment"],
            "database_name": receipt["database_name"],
            "database_uuid": receipt["database_uuid"],
            "odoo_instance_id": receipt["odoo_instance_id"],
            "principal": request["context"]["principal"],
            "receipt": receipt,
            "receipt_id": receipt["id"],
            "registry_digest": receipt["registry_digest"],
            "release_digest": receipt["release_digest"],
            "request_digest": receipt["request_digest"],
            "result_digest": receipt["result_digest"],
            "user_id": receipt["user_id"],
        }
        row = {
            "sequence": 31 + index,
            "event_id": f"read:{receipt['id']}",
            "event_type": "read.verified",
            "operation_id": None,
            "occurred_at": receipt["observed_at"],
            "payload_json": verifier.canonical_json(payload).decode("utf-8"),
            "previous_hash": previous,
            "event_hash": "",
        }
        row["event_hash"] = verifier._audit_hash(row)
        previous = row["event_hash"]
        audit_rows.append(row)
    before = {
        "schema_version": 1,
        "auth": {
            "path": runtime["auth_state_path"],
            "queries": {"count": [{"value": 10}], "selected_tokens": []},
        },
        "receipt": {
            "path": runtime["receipt_state_path"],
            "queries": {
                "receipt_count": [{"value": 20}],
                "audit_count": [{"value": 30}],
                "selected_receipts": [],
                "audit_delta": [],
                "audit_head": [{"sequence": 30, "event_hash": "a" * 64}],
            },
        },
    }
    after = {
        "schema_version": 1,
        "auth": {
            "path": runtime["auth_state_path"],
            "queries": {"count": [{"value": 16}], "selected_tokens": token_rows},
        },
        "receipt": {
            "path": runtime["receipt_state_path"],
            "queries": {
                "receipt_count": [{"value": 25}],
                "audit_count": [{"value": 35}],
                "selected_receipts": receipt_rows,
                "audit_delta": audit_rows,
                "audit_head": [
                    {
                        "sequence": audit_rows[-1]["sequence"],
                        "event_hash": audit_rows[-1]["event_hash"],
                    }
                ],
            },
        },
    }
    return before, after, requests, receipts, runtime, started, finished


def _rehash_state_audit(before, after):
    previous = before["receipt"]["queries"]["audit_head"][0]["event_hash"]
    rows = after["receipt"]["queries"]["audit_delta"]
    for row in rows:
        row["previous_hash"] = previous
        row["event_hash"] = verifier._audit_hash(row)
        previous = row["event_hash"]
    after["receipt"]["queries"]["audit_head"] = [
        {"sequence": rows[-1]["sequence"], "event_hash": rows[-1]["event_hash"]}
    ]


def test_release_member_mode_policy_matches_the_builder_whitelist() -> None:
    expected = frozenset(
        {
            "bin/odoo-accounting-cli-v3",
            "bin/odoo-accounting-cli-v3-broker",
            "bin/odoo-accounting-cli-v3-effect-finalizer",
            "deployment/dev9/run-private-mount-gate.sh",
        }
    )
    assert verifier.EXECUTABLE_RELEASE_MEMBERS == expected
    assert all(
        verifier._expected_release_member_mode(name) == 0o555
        for name in expected
    )
    assert verifier._expected_release_member_mode("VERSION") == 0o444
    assert verifier._expected_release_member_mode(str(verifier.TRACE_RELATIVE)) == 0o444


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
@pytest.mark.parametrize(
    ("name", "drifted_mode"),
    [
        ("VERSION", 0o555),
        ("bin/odoo-accounting-cli-v3", 0o444),
    ],
)
def test_release_member_mode_policy_rejects_execution_bit_drift(
    tmp_path: Path, name: str, drifted_mode: int
) -> None:
    member = tmp_path / "member"
    member.write_bytes(b"sealed\n")
    member.chmod(drifted_mode)
    with pytest.raises(
        verifier.EvidenceVerificationError, match="metadata is invalid"
    ):
        verifier.stable_read(
            member,
            label="release member mode drift",
            allowed_modes=frozenset(
                {verifier._expected_release_member_mode(name)}
            ),
        )


def test_bootstrap_release_manifest_rejects_boolean_schema_after_digest_rebinding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = dict(EXPECTED)
    root = tmp_path / expected["release"]
    verifier_path = root.joinpath(*verifier.VERIFIER_RELATIVE.parts)
    verifier_path.parent.mkdir(parents=True)
    verifier_path.write_bytes(b"# sealed verifier\n")
    unsigned = {
        "schema_version": True,
        "version": expected["version"],
        "commit": expected["commit"],
        "files": [],
    }
    expected["manifest_sha256"] = hashlib.sha256(
        verifier.canonical_json(unsigned)
    ).hexdigest()
    manifest = {**unsigned, "manifest_sha256": expected["manifest_sha256"]}
    (root / "RELEASE-MANIFEST.json").write_bytes(
        verifier.canonical_json(manifest) + b"\n"
    )
    trust = tmp_path / "trust"
    trust.mkdir()
    (trust / f'{expected["release"]}.json').write_bytes(
        verifier.canonical_json(
            {
                "commit": expected["commit"],
                "manifest_sha256": expected["manifest_sha256"],
                "package_sha256": expected["package_sha256"],
                "release": expected["release"],
            }
        )
        + b"\n"
    )
    monkeypatch.setattr(verifier, "RELEASE_PARENT", tmp_path)
    monkeypatch.setattr(verifier, "TRUST_PARENT", trust)
    monkeypatch.setattr(verifier, "__file__", str(verifier_path))
    monkeypatch.setattr(verifier, "_safe_root_chain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        verifier,
        "stable_read",
        lambda path, **_kwargs: Path(path).read_bytes(),
    )
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="installed release manifest identity mismatch",
    ):
        verifier.bootstrap_verify_release(expected)


@pytest.mark.parametrize(
    "category",
    ["plan", "state-before", "state-after", "financial-oracle"],
)
def test_external_envelopes_reject_boolean_schema_versions(category: str) -> None:
    if category == "plan":
        document = plan()
        document["schema_version"] = True
        with pytest.raises(
            verifier.EvidenceVerificationError, match="read plan envelope"
        ):
            verifier.validate_plan(document)
        return
    if category in {"state-before", "state-after"}:
        before, after, requests, receipts, configuration, started, finished = (
            _valid_state_delta_fixture()
        )
        (before if category == "state-before" else after)["schema_version"] = True
        with pytest.raises(
            verifier.EvidenceVerificationError,
            match="SQLite state snapshot binding is invalid",
        ):
            verifier.validate_state_delta(
                before,
                after,
                requests=requests,
                receipts=receipts,
                runtime=configuration,
                suite_started_at=started,
                observed_not_after=finished,
            )
        return
    report, case, request, response, planned, witness = _financial_oracle_fixture()
    report["schema_version"] = True
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="financial Oracle evidence is invalid",
    ):
        verifier.validate_oracle_report(
            report,
            case=case,
            request=request,
            response=response,
            plan=planned,
            runtime=runtime(),
            witness=witness,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "before_selected_nonempty",
        "duplicate_token",
        "unordered_tokens",
        "token_after_expiry",
        "receipt_after_expiry",
        "audit_sequence_gap",
        "duplicate_event_id",
        "audit_payload_field_deleted",
        "audit_occurred_at_drift",
        "post_head_mismatch",
    ],
)
def test_independent_state_delta_rejects_structural_and_temporal_mutations(mutation):
    before, after, requests, receipts, runtime, started, finished = (
        _valid_state_delta_fixture()
    )
    valid = verifier.validate_state_delta(
        before,
        after,
        requests=requests,
        receipts=receipts,
        runtime=runtime,
        suite_started_at=started,
        observed_not_after=finished,
    )
    assert valid["all_checks_passed"] is True
    before = deepcopy(before)
    after = deepcopy(after)
    if mutation == "before_selected_nonempty":
        before["auth"]["queries"]["selected_tokens"] = [
            deepcopy(after["auth"]["queries"]["selected_tokens"][0])
        ]
    elif mutation == "duplicate_token":
        rows = after["auth"]["queries"]["selected_tokens"]
        rows[1]["token_id"] = rows[0]["token_id"]
    elif mutation == "unordered_tokens":
        after["auth"]["queries"]["selected_tokens"].reverse()
    elif mutation == "token_after_expiry":
        after["auth"]["queries"]["selected_tokens"][0]["consumed_at"] = (
            "2026-07-20T00:11:00Z"
        )
    elif mutation == "receipt_after_expiry":
        after["receipt"]["queries"]["selected_receipts"][0]["consumed_at"] = (
            "2026-07-20T00:11:00Z"
        )
    elif mutation == "audit_sequence_gap":
        after["receipt"]["queries"]["audit_delta"][2]["sequence"] += 1
        _rehash_state_audit(before, after)
    elif mutation == "duplicate_event_id":
        rows = after["receipt"]["queries"]["audit_delta"]
        rows[1]["event_id"] = rows[0]["event_id"]
        _rehash_state_audit(before, after)
    elif mutation == "audit_payload_field_deleted":
        row = after["receipt"]["queries"]["audit_delta"][0]
        payload = json.loads(row["payload_json"])
        del payload["user_id"]
        row["payload_json"] = verifier.canonical_json(payload).decode("utf-8")
        _rehash_state_audit(before, after)
    elif mutation == "audit_occurred_at_drift":
        after["receipt"]["queries"]["audit_delta"][0]["occurred_at"] = (
            "2026-07-20T00:03:00Z"
        )
        _rehash_state_audit(before, after)
    else:
        after["receipt"]["queries"]["audit_head"][0]["event_hash"] = "f" * 64
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.validate_state_delta(
            before,
            after,
            requests=requests,
            receipts=receipts,
            runtime=runtime,
            suite_started_at=started,
            observed_not_after=finished,
        )


def test_expired_negative_must_predate_suite_start():
    request = {"context": {"auth_expires_at": "2026-07-19T23:59:59Z"}}
    verifier.validate_expired_negative_time(
        request, suite_started_at="2026-07-20T00:00:00Z"
    )
    for invalid in (
        "2026-07-20T00:00:00Z",
        "2026-07-20T00:00:01Z",
    ):
        changed = deepcopy(request)
        changed["context"]["auth_expires_at"] = invalid
        with pytest.raises(
            verifier.EvidenceVerificationError, match="not expired before"
        ):
            verifier.validate_expired_negative_time(
                changed, suite_started_at="2026-07-20T00:00:00Z"
            )


def test_independent_verifier_requeries_live_systemd_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = 4242
    unit = "odoo-accounting-cli-v3-dev29-proof.service"
    cgroup = "/system.slice/odoo-accounting-cli-v3-dev29-proof.service"
    runtime = {
        "auth_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/x/auth/state.db",
        "receipt_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/x/receipt/state.db",
    }
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    capabilities = [
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
    ]
    writable = [
        "/var/lib/odoo-accounting-cli-v3/evidence",
        "/var/lib/odoo-accounting-cli-v3/evidence-private",
        "/var/lib/odoo-accounting-cli-v3/runtime-open-trace",
        "/var/lib/odoo-accounting-cli-v3/evidence-anchors",
        "/opt/odoo-accounting-cli-v3/dependencies",
        str(Path(runtime["auth_state_path"]).parent),
        str(Path(runtime["receipt_state_path"]).parent),
        "/var/lib/odoo-accounting-cli-v3-broker",
        "/run/odoo-accounting-cli-v3-dev29",
    ]
    live_argv = [
        verifier.CLOSURE_PYTHON,
        "-I",
        "-S",
        str(
            verifier.RELEASE_PARENT
            / RELEASE
            / "deployment/dev29/run_read_evidence.py"
        ),
        "supervise",
    ]
    properties = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Type": "exec",
        "User": "root",
        "Group": "root",
        "MainPID": str(parent),
        "ControlGroup": cgroup,
        "InvocationID": "a" * 32,
        "ExecStart": "{/usr/bin/python3.12 ; argv[]=/usr/bin/python3.12 -I -S ;}",
        "WorkingDirectory": str(verifier.RELEASE_PARENT / RELEASE),
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "PrivateMounts": "yes",
        "PrivateTmp": "yes",
        "PrivateNetwork": "yes",
        "NoNewPrivileges": "yes",
        "ProtectControlGroups": "yes",
        "KillMode": "control-group",
        "RuntimeMaxUSec": "1h",
        "TimeoutStopUSec": "30s",
        "UMask": "0077",
        "ReadWritePaths": " ".join(verifier.shlex.quote(item) for item in writable),
        "Environment": " ".join(f"{key}={value}" for key, value in environment.items()),
        "CapabilityBoundingSet": " ".join(capabilities),
    }
    systemctl = {
        "path": "/usr/bin/systemctl",
        "sha256": "b" * 64,
        "size": 123,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
    }
    execution = {
        "method": "open-fd-ptrace-exec-v1",
        "file": systemctl,
        "pinned_device": 1,
        "pinned_inode": 2,
        "proc_exe_device": 1,
        "proc_exe_inode": 2,
        "ptrace_exitkill_set": True,
        "ptrace_exec_stop_verified": True,
        "ptrace_detached_before_communicate": True,
        "parent_death_signal": "SIGKILL",
        "parent_identity_checked": True,
        "security_capability_absent": True,
        "child_reaped": True,
        "all_checks_passed": True,
    }
    outer = {
        "schema_version": 1,
        "unit": unit,
        "supervisor_pid": parent,
        "systemctl": systemctl,
        "systemctl_execution": execution,
        "properties": properties,
        "proc": {
            "argv": live_argv,
            "argv_sha256": hashlib.sha256(
                verifier.canonical_json(live_argv)
            ).hexdigest(),
            "cgroup": cgroup,
        },
        "expected_environment": environment,
        "read_write_paths": writable,
        "read_only_paths": ["/run/odoo-accounting-cli-v3-dev29-leases"],
        "capability_bounding_set": capabilities,
        "all_checks_passed": True,
    }
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def read_bytes(path: Path):
        if path.as_posix() == f"/proc/{parent}/cmdline":
            return b"\0".join(item.encode() for item in live_argv) + b"\0"
        return original_read_bytes(path)

    def read_text(path: Path, *args, **kwargs):
        if path.as_posix() == f"/proc/{parent}/cgroup":
            return f"0::{cgroup}\n"
        return original_read_text(path, *args, **kwargs)

    observed = {}

    def live_query(observed_unit: str, *, expected_sha256: str):
        observed["unit"] = observed_unit
        observed["sha256"] = expected_sha256
        return deepcopy(properties), deepcopy(execution)

    monkeypatch.setattr(verifier.os, "getppid", lambda: parent)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(verifier, "_query_systemctl_properties", live_query)
    verifier.validate_outer_unit(outer, runtime=runtime, release=RELEASE)
    assert observed == {"unit": unit, "sha256": "b" * 64}

    drifted = deepcopy(properties)
    drifted["ProtectSystem"] = "full"
    monkeypatch.setattr(
        verifier,
        "_query_systemctl_properties",
        lambda *_args, **_kwargs: (drifted, deepcopy(execution)),
    )
    with pytest.raises(
        verifier.EvidenceVerificationError, match="live systemd properties drifted"
    ):
        verifier.validate_outer_unit(outer, runtime=runtime, release=RELEASE)


def runtime() -> dict:
    fixed = plan()["runtime"]
    state = f"/var/lib/odoo-accounting-cli-v3/test/candidates/{RELEASE}"
    secrets = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE}"
    return {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        **fixed,
        "release_root": f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}",
        "canonical_package_path": (
            f"/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-{RELEASE}.tar.gz"
        ),
        "canonical_package_sha256": "c" * 64,
        "auth_state_path": f"{state}/auth/state.sqlite3",
        "receipt_state_path": f"{state}/receipt/state.sqlite3",
        "auth_key_id": "test-auth-dev29-unit",
        "receipt_key_id": "test-receipt-dev29-unit",
        "auth_secret_path": f"{secrets}/auth.hmac",
        "receipt_secret_path": f"{secrets}/receipt.hmac",
    }


def request_for_case(case: dict) -> dict:
    configuration = runtime()
    return {
        "capability_id": case["capability_id"],
        "parameters": deepcopy(case["parameters"]),
        "context": {
            "principal": case["principal"],
            "user_id": case["user_id"],
            "company_id": case["company_id"],
            "allowed_company_ids": case["allowed_company_ids"],
            "odoo_instance_id": configuration["instance_id"],
            "database_name": configuration["database_name"],
            "database_uuid": configuration["database_uuid"],
            "environment": configuration["environment"],
            "audience": "odoo-accounting-cli-v3",
            "auth_key_id": configuration["auth_key_id"],
            "auth_token_id": "dev29-read-11111111-1111-4111-8111-111111111111",
            "auth_issued_at": "2026-07-20T00:00:00Z",
            "auth_expires_at": "2026-07-20T00:05:00Z",
            "auth_request_digest": "1" * 64,
            "auth_signature": "2" * 64,
            "auth_signature_purpose": "read-request-context",
            "auth_signature_version": 1,
        },
    }


def test_verifier_has_no_dynamic_or_private_suite_helper_dependency(monkeypatch):
    source = (DEV29 / "verify_read_evidence.py").read_text("utf-8")
    assert "_load_runner" not in source
    assert "runner._" not in source

    def poison(*_args, **_kwargs):
        raise AssertionError("suite helper must not be called by verifier")

    monkeypatch.setattr(suite, "_validate_signed_selection", poison)
    monkeypatch.setattr(suite, "_strict_negative", poison)
    case = plan()["cases"][0]
    verifier.validate_signed_selection(
        request_for_case(case),
        base_case=case,
        selected_identity=case,
        runtime=runtime(),
        mutation=None,
    )


def test_independent_request_validator_rejects_parameter_and_identity_drift():
    case = plan()["cases"][1]
    request = request_for_case(case)
    verifier.validate_signed_selection(
        request,
        base_case=case,
        selected_identity=case,
        runtime=runtime(),
        mutation=None,
    )
    changed = deepcopy(request)
    changed["parameters"]["date_to"] = "2026-12-30"
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.validate_signed_selection(
            changed,
            base_case=case,
            selected_identity=case,
            runtime=runtime(),
            mutation=None,
        )


def boundary_response() -> dict:
    release_identity = {**EXPECTED, "registry_digest": "f" * 64, "verified": True}
    database = {
        "backend_pid": 123,
        "name": "odoo_test",
        "uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
    }
    transaction = {
        "idle_after_rollback": True,
        "isolation": "repeatable read",
        "read_only": True,
    }
    evidence = {
        "schema_version": "odoo-accounting-cli-v3.read-boundary-evidence.v1",
        "database": {"before": database, "after": deepcopy(database)},
        "checks": {
            "backend_pid_unchanged": True,
            "database_name_unchanged": True,
            "database_uuid_unchanged": True,
            "relation_filenode_unchanged": True,
            "relation_oid_unchanged": True,
            "relation_row_count_unchanged": True,
        },
        "relation": {
            "schema": "public",
            "name": "ir_config_parameter",
            "before": {"filenode": 100, "oid": 200, "row_count": 10},
            "after": {"filenode": 100, "oid": 200, "row_count": 10},
        },
        "successful_transactions": {
            "before": {**transaction, "marker_sha256": "1" * 64},
            "after": {**transaction, "marker_sha256": "2" * 64},
        },
        "write_probe": {
            "idle_after_rollback": True,
            "rejected": True,
            "sqlstate": "25006",
            "statement_id": "ir-config-parameter-noop-update-v1",
        },
        "drift_probes": {
            name: {
                "canary_sha256": str(index) * 64,
                "idle_after_cleanup": True,
                "rejected": True,
                "result_released": False,
            }
            for index, name in enumerate(
                ("hidden_commit", "hidden_rollback", "rollback_hook_reopen"), start=3
            )
        },
    }
    configuration = runtime()
    return {
        "command": "evidence.read-boundary",
        "ok": True,
        "data": {
            "evidence": evidence,
            "release_identity": release_identity,
            "runtime": {
                key: configuration[key]
                for key in (
                    "capability_channel",
                    "database_name",
                    "database_uuid",
                    "environment",
                    "instance_id",
                )
            },
        },
    }


def test_d11_validation_is_independent_strict_and_rejects_released_canary():
    response = boundary_response()
    verifier.validate_boundary_response(
        response,
        runtime=runtime(),
        release_identity=response["data"]["release_identity"],
    )
    changed = deepcopy(response)
    changed["data"]["evidence"]["drift_probes"]["hidden_commit"][
        "result_released"
    ] = True
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.validate_boundary_response(
            changed,
            runtime=runtime(),
            release_identity=response["data"]["release_identity"],
        )


def _make_bundle(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(verifier, "EVIDENCE_PARENT", tmp_path)
    evidence = tmp_path / "dev29-unit-evidence"
    evidence.mkdir()
    files = verifier.expected_bundle_files()
    for name in files:
        path = evidence.joinpath(*Path(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    release_identity = {**EXPECTED, "registry_digest": "f" * 64, "verified": True}
    entries = []
    for name in sorted(files):
        payload = evidence.joinpath(*Path(name).parts).read_bytes()
        entries.append(
            {"path": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        )
    manifest = {
        "schema_version": 1,
        "bundle_type": "odoo-accounting-cli-v3.dev29.read-suite-evidence",
        "evidence_name": evidence.name,
        "evidence_path": str(evidence),
        "release_identity": release_identity,
        "closure_identity": {"image_sha256": "e" * 64},
        "closure_verification_sha256": "9" * 64,
        "plan_sha256": "1" * 64,
        "runtime_sha256": "2" * 64,
        "runtime_open_trace_sha256": hashlib.sha256(
            (evidence / "runtime-open-trace.json").read_bytes()
        ).hexdigest(),
        "runtime_open_trace_private": {
            "schema_version": 1,
            "manifest_sha256": "3" * 64,
            "trace_count": 1,
            "tree_identity_sha256": "4" * 64,
            "production_promotion_allowed": False,
        },
        "positive_cases": list(verifier.POSITIVE_NAMES),
        "financial_oracle_cases": list(verifier.FINANCIAL_NAMES),
        "negative_cases": list(verifier.NEGATIVE_NAMES),
        "auth_token_ids": {
            name: f"dev29-read-{index:032d}"
            for index, name in enumerate((*verifier.POSITIVE_NAMES, *verifier.NEGATIVE_NAMES), 1)
        },
        "receipt_ids": {
            name: f"receipt-{index}" for index, name in enumerate(verifier.POSITIVE_NAMES, 1)
        },
        "production_promotion_allowed": False,
        "files": entries,
    }
    payload = verifier.canonical_json(manifest) + b"\n"
    (evidence / "BUNDLE-MANIFEST.json").write_bytes(payload)
    return evidence, hashlib.sha256(payload).hexdigest()


def test_bundle_loader_requires_exact_file_set_and_hashes(tmp_path: Path, monkeypatch):
    evidence, digest = _make_bundle(tmp_path, monkeypatch)
    documents, manifest, observed = verifier.load_bundle(
        evidence,
        expected=EXPECTED,
        expected_bundle_manifest_sha256=digest,
        enforce_root=False,
    )
    assert set(documents) == verifier.expected_bundle_files()
    assert observed == digest
    assert manifest["production_promotion_allowed"] is False
    member = evidence / sorted(verifier.expected_bundle_files())[0]
    member.write_bytes(b"tampered")
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.load_bundle(
            evidence,
            expected=EXPECTED,
            expected_bundle_manifest_sha256=digest,
            enforce_root=False,
        )


def test_dependency_validator_rejects_attacker_self_reported_root_and_none_path_exploit():
    mount = f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"
    closure = {
        "mount": {"mount_point": mount},
        "closure_identity": {
            "sealed_config_path": (
                f"/etc/odoo-accounting-cli-v3/dependencies/{RELEASE}/odoo-server19.conf"
            ),
            "anchor_path": (
                f"/opt/odoo-accounting-cli-v3/dependency-anchors/{RELEASE}.json"
            ),
            "image_path": (
                f"/opt/odoo-accounting-cli-v3/dependency-images/{RELEASE}.squashfs"
            ),
            "external_runtime_paths": [
                "/etc/ld.so.cache",
                "/usr/bin/python3.12",
                "/usr/lib/python3.12",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
            ],
        },
    }
    roots = verifier.expected_dependency_roots(
        runtime=runtime(),
        expected=EXPECTED,
        closure=closure,
        external_runtime_paths=closure["closure_identity"]["external_runtime_paths"],
    )
    root_documents = []
    for index, root in enumerate(roots):
        entries = [
            {
                "path": None if index == 0 else ".",
                "kind": "directory",
                "uid": 0,
                "gid": 0,
                "mode": "0555",
            }
        ]
        root_documents.append(
            {
                "root": str(root),
                "entry_count": 1,
                "manifest_sha256": hashlib.sha256(
                    verifier.canonical_json(entries)
                ).hexdigest(),
                "entries": entries,
            }
        )
    document = {
        "schema_version": 1,
        "algorithm": "canonical-json-complete-lstat-tree-sha256-v1",
        "root_count": len(root_documents),
        "entry_count": len(root_documents),
        "roots": root_documents,
        "combined_sha256": hashlib.sha256(
            verifier.canonical_json(root_documents)
        ).hexdigest(),
    }
    with pytest.raises(
        verifier.EvidenceVerificationError, match="dependency entry schema"
    ):
        verifier.validate_dependency_document(
            document,
            runtime=runtime(),
            expected=EXPECTED,
            closure=closure,
            external_runtime_paths=closure["closure_identity"]["external_runtime_paths"],
            verify_live_files=False,
        )

    attacker_root = deepcopy(document)
    attacker_root["roots"][0]["root"] = "/attacker-chosen-only-root"
    attacker_root["combined_sha256"] = hashlib.sha256(
        verifier.canonical_json(attacker_root["roots"])
    ).hexdigest()
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.validate_dependency_document(
            attacker_root,
            runtime=runtime(),
            expected=EXPECTED,
            closure=closure,
            external_runtime_paths=closure["closure_identity"]["external_runtime_paths"],
            verify_live_files=False,
        )


def test_external_runtime_rejects_self_consistent_omitted_actual_elf_dependency(
    monkeypatch,
):
    roots = ["/etc/ld.so.cache", "/usr/bin/python3.12", "/usr/lib/python3.12"]
    entries = [
        {
            "path": "/etc/ld.so.cache",
            "kind": "regular",
            "mode": "0644",
            "uid": 0,
            "gid": 0,
            "size": 1,
            "sha256": "1" * 64,
        },
        {
            "path": "/usr/bin/python3.12",
            "kind": "regular",
            "mode": "0755",
            "uid": 0,
            "gid": 0,
            "size": 1,
            "sha256": "2" * 64,
        },
        {
            "path": "/usr/lib/python3.12",
            "kind": "directory",
            "mode": "0755",
            "uid": 0,
            "gid": 0,
        },
    ]
    manifest = {
        "schema_version": 1,
        "python_abi": "3.12",
        "roots": roots,
        "entries": entries,
    }
    payload = verifier.canonical_json(manifest) + b"\n"
    closure = {
        "mount": {"mount_point": f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"},
        "closure_identity": {
            "external_runtime_manifest_path": "/sealed/EXTERNAL-RUNTIME-MANIFEST.json",
            "external_runtime_manifest_sha256": hashlib.sha256(
                verifier.canonical_json(manifest)
            ).hexdigest(),
            "external_runtime_paths": roots,
            "external_runtime_entry_count": len(entries),
            "external_runtime_native_path_count": 0,
            "external_runtime_derivation_method": (
                "python-elf-dt-needed-plus-root-owned-ld-cache-v1"
            ),
            "closure_elf_count": 1,
        },
    }
    monkeypatch.setattr(verifier, "stable_read", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(
        verifier,
        "independently_derive_external_runtime",
        lambda _closure, *, expected_ldconfig_sha256: (
            [*roots, "/usr/lib/x86_64-linux-gnu/libc.so.6"],
            1,
            1,
        ),
    )
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="omits an independently derived dependency",
    ):
        verifier.validate_external_runtime_manifest(
            closure, verify_live_files=True, expected_ldconfig_sha256="6" * 64
        )


def test_external_runtime_rejects_self_consistent_omitted_stdlib_file(monkeypatch):
    roots = ["/etc/ld.so.cache", "/usr/bin/python3.12", "/usr/lib/python3.12"]
    entries = [
        {
            "path": "/etc/ld.so.cache",
            "kind": "regular",
            "mode": "0644",
            "uid": 0,
            "gid": 0,
            "size": 1,
            "sha256": "1" * 64,
        },
        {
            "path": "/usr/bin/python3.12",
            "kind": "regular",
            "mode": "0755",
            "uid": 0,
            "gid": 0,
            "size": 1,
            "sha256": "2" * 64,
        },
        {
            "path": "/usr/lib/python3.12",
            "kind": "directory",
            "mode": "0755",
            "uid": 0,
            "gid": 0,
        },
    ]
    manifest = {
        "schema_version": 1,
        "python_abi": "3.12",
        "roots": roots,
        "entries": entries,
    }
    payload = verifier.canonical_json(manifest) + b"\n"
    closure = {
        "mount": {"mount_point": f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"},
        "closure_identity": {
            "external_runtime_manifest_path": "/sealed/EXTERNAL-RUNTIME-MANIFEST.json",
            "external_runtime_manifest_sha256": hashlib.sha256(
                verifier.canonical_json(manifest)
            ).hexdigest(),
            "external_runtime_paths": roots,
            "external_runtime_entry_count": len(entries),
            "external_runtime_native_path_count": 0,
            "external_runtime_derivation_method": (
                "python-elf-dt-needed-plus-root-owned-ld-cache-v1"
            ),
            "closure_elf_count": 1,
        },
    }
    live_manifest = deepcopy(manifest)
    live_manifest["entries"].append(
        {
            "path": "/usr/lib/python3.12/os.py",
            "kind": "regular",
            "mode": "0644",
            "uid": 0,
            "gid": 0,
            "size": 1,
            "sha256": "3" * 64,
        }
    )
    monkeypatch.setattr(verifier, "stable_read", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(
        verifier,
        "independently_derive_external_runtime",
        lambda _closure, *, expected_ldconfig_sha256: (roots, 1, 0),
    )
    monkeypatch.setattr(
        verifier,
        "independently_snapshot_external_manifest",
        lambda _roots: live_manifest,
    )
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="omits or changes a live dependency entry",
    ):
        verifier.validate_external_runtime_manifest(
            closure, verify_live_files=True, expected_ldconfig_sha256="6" * 64
        )


def test_verifier_is_validate_only_and_has_no_anchor_publication_api():
    assert not hasattr(verifier, "write_external_anchor")
    arguments = verifier._parser().parse_args(
        [
            "--evidence-dir", "/tmp/evidence",
            "--expected-bundle-manifest-sha256", "1" * 64,
            "--expected-release", EXPECTED["release"],
            "--expected-version", EXPECTED["version"],
            "--expected-commit", EXPECTED["commit"],
            "--expected-manifest-sha256", EXPECTED["manifest_sha256"],
            "--expected-package-sha256", EXPECTED["package_sha256"],
            "--expected-closure-anchor-sha256", "2" * 64,
            "--expected-closure-image-sha256", "3" * 64,
            "--expected-system-python-sha256", "4" * 64,
            "--expected-ld-so-preload-sha256", "5" * 64,
                "--expected-ldconfig-sha256", "6" * 64,
                "--expected-runtime-open-index-sha256", "7" * 64,
                "--expected-strace-sha256", "8" * 64,
        ]
    )
    assert arguments.validate_only is False


def test_verifier_cli_requires_bundle_and_closure_external_digests():
    destinations = {action.dest for action in verifier._parser()._actions}
    assert {
        "expected_bundle_manifest_sha256",
        "expected_closure_anchor_sha256",
        "expected_closure_image_sha256",
        "expected_system_python_sha256",
        "expected_ldconfig_sha256",
    } <= destinations


def test_loader_stat_identity_ignores_atime_but_rejects_content_metadata_drift():
    values = {
        "st_dev": 1,
        "st_ino": 2,
        "st_nlink": 1,
        "st_size": 1_051_280,
        "st_mtime_ns": 3,
        "st_ctime_ns": 4,
        "st_mode": stat.S_IFREG | 0o755,
        "st_uid": 0,
        "st_gid": 0,
        "st_atime_ns": 5,
    }
    baseline = SimpleNamespace(**values)
    atime_changed = SimpleNamespace(**{**values, "st_atime_ns": 999})
    mtime_changed = SimpleNamespace(**{**values, "st_mtime_ns": 999})
    ctime_changed = SimpleNamespace(**{**values, "st_ctime_ns": 999})
    assert verifier._loader_stat_identity(baseline) == verifier._loader_stat_identity(
        atime_changed
    )
    assert verifier._loader_stat_identity(baseline) != verifier._loader_stat_identity(
        mtime_changed
    )
    assert verifier._loader_stat_identity(baseline) != verifier._loader_stat_identity(
        ctime_changed
    )


def test_loader_cache_rejects_invalid_external_digest_before_open():
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="loader-cache reader digest is invalid",
    ):
        verifier._independent_loader_cache("not-a-sha256")


def test_loader_ptrace_exitkill_option_is_applied(monkeypatch: pytest.MonkeyPatch):
    calls = []

    class Library:
        def ptrace(self, request, pid, address, options):
            calls.append((request, pid, address, options.value))
            return 0

    monkeypatch.setattr(verifier.ctypes, "CDLL", lambda *_args, **_kwargs: Library())
    verifier._ptrace_set_exitkill(1234)
    assert calls == [
        (verifier.PTRACE_SETOPTIONS, 1234, None, verifier.PTRACE_O_EXITKILL)
    ]


def test_systemctl_preexec_sets_parent_death_before_ptrace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class Library:
        def prctl(self, option, signal_number, arg3, arg4, arg5):
            calls.append(("prctl", option, signal_number, arg3, arg4, arg5))
            return 0

        def ptrace(self, request, pid, address, options):
            calls.append(("ptrace", request, pid, address, options))
            return 0

    monkeypatch.setattr(verifier.ctypes, "CDLL", lambda *_args, **_kwargs: Library())
    monkeypatch.setattr(verifier.os, "getppid", lambda: 4321)
    verifier._ptrace_traceme_with_parent_death(4321)
    assert calls == [
        ("prctl", verifier.PR_SET_PDEATHSIG, verifier.SIGKILL, 0, 0, 0),
        ("ptrace", 0, 0, None, None),
    ]


def test_systemctl_file_capability_xattr_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        verifier.os, "getxattr", lambda *_args: b"capability", raising=False
    )
    with pytest.raises(
        verifier.EvidenceVerificationError, match="has file capabilities"
    ):
        verifier._reject_systemctl_file_capabilities(7)


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux ptrace and prctl")
def test_parent_death_signal_remains_effective_after_ptrace_detach() -> None:
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    supervisor = os.fork()
    if supervisor == 0:
        try:
            os.close(ready_read)
            os.close(release_write)
            expected_parent = os.getpid()
            child = subprocess.Popen(
                ["/usr/bin/sleep", "30"],
                preexec_fn=lambda: verifier._ptrace_traceme_with_parent_death(
                    expected_parent
                ),
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            waited, status = os.waitpid(child.pid, os.WUNTRACED)
            if (
                waited != child.pid
                or not os.WIFSTOPPED(status)
                or os.WSTOPSIG(status) != verifier.signal.SIGTRAP
            ):
                os._exit(121)
            verifier._ptrace_set_exitkill(child.pid)
            verifier._ptrace_detach(child.pid)
            os.write(ready_write, f"{child.pid}\n".encode("ascii"))
            if os.read(release_read, 1) != b"x":
                os._exit(122)
            os._exit(0)
        except BaseException:
            os._exit(123)
    os.close(ready_write)
    os.close(release_read)
    raw_pid = os.read(ready_read, 64)
    assert raw_pid.endswith(b"\n")
    child_pid = int(raw_pid)
    os.write(release_write, b"x")
    os.close(release_write)
    os.close(ready_read)
    waited, status = os.waitpid(supervisor, 0)
    assert waited == supervisor and os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    deadline = time.monotonic() + 5
    proc = Path(f"/proc/{child_pid}")

    def dead() -> bool:
        if not proc.exists():
            return True
        try:
            return (proc / "stat").read_text("ascii").split()[2] == "Z"
        except (FileNotFoundError, ProcessLookupError, IndexError):
            return True

    while not dead() and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        assert dead()
    finally:
        try:
            os.kill(child_pid, verifier.SIGKILL)
        except ProcessLookupError:
            pass


def test_loader_cleanup_kills_and_reaps_when_ptrace_detach_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    class Process:
        pid = 4321
        returncode = None

        def wait(self):
            events.append(("wait", self.pid))
            self.returncode = -verifier.SIGKILL

    monkeypatch.setattr(
        verifier,
        "_ptrace_detach",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("detach failed")),
    )
    monkeypatch.setattr(
        verifier.os,
        "kill",
        lambda pid, signum: events.append(("kill", pid, signum)),
    )
    process = Process()
    verifier._kill_and_reap_loader_process(process, traced=True)
    assert events == [
        ("kill", process.pid, verifier.SIGKILL),
        ("wait", process.pid),
    ]


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root-owned temporary executables and ptrace",
)
def test_loader_cache_rejects_wrong_hash_and_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = Path(verifier.CLOSURE_LDCONFIG)
    if not source.exists():
        pytest.skip("fixed ldconfig.real is unavailable")
    tool = tmp_path / "ldconfig.real"
    replacement = tmp_path / "replacement"
    shutil.copyfile(source, tool)
    shutil.copyfile("/usr/bin/false", replacement)
    tool.chmod(0o755)
    replacement.chmod(0o755)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    real_popen = subprocess.Popen
    monkeypatch.setattr(verifier, "CLOSURE_LDCONFIG", str(tool))
    monkeypatch.setattr(
        verifier.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("wrong digest must be rejected before execution")
        ),
    )
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]
    with pytest.raises(verifier.EvidenceVerificationError, match="identity drifted"):
        verifier._independent_loader_cache(wrong)

    observed = {}

    def replace_path_then_execute(*args, **kwargs):
        os.replace(replacement, tool)
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        return process

    monkeypatch.setattr(verifier.subprocess, "Popen", replace_path_then_execute)
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match=(
            "executed unpinned bytes|identity drifted|"
            "changed across pinned execution"
        ),
    ):
        verifier._independent_loader_cache(digest)
    assert observed["process"].returncode is not None


def test_loader_executed_bytes_are_bound_by_proc_exe_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"verified loader bytes\n"
    executable = tmp_path / "ldconfig.real"
    executable.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    real_open = os.open

    def open_proc_exe(path, flags, *args, **kwargs):
        if str(path) == "/proc/321/exe":
            return real_open(executable, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(verifier.os, "open", open_proc_exe)
    verifier._verify_executed_loader_bytes(321, digest)

    executable.write_bytes(b"different executed bytes\n")
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="executed unpinned bytes",
    ):
        verifier._verify_executed_loader_bytes(321, digest)


@pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or os.environ.get("DEV29_REAL_LDCONFIG_TEST") != "1",
    reason="set DEV29_REAL_LDCONFIG_TEST=1 on the Linux root gate",
)
def test_loader_cache_real_linux_pinned_execution():
    path = Path(verifier.CLOSURE_LDCONFIG)
    if not path.exists():
        pytest.skip("fixed ldconfig.real is unavailable")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    cache = verifier._independent_loader_cache(digest)
    assert cache
    assert any(name.startswith("libc.so") for name in cache)


def test_verifier_binds_fixed_isolated_system_python_identity():
    expected_sha256 = "a" * 64
    evidence = {
        "schema_version": 1,
        "path": "/usr/bin/python3.12",
        "sha256": expected_sha256,
        "size": 6_000_000,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
        "root_owned": True,
        "one_link_regular": True,
        "resolved_executable": "/usr/bin/python3.12",
        "isolated": True,
        "no_site": True,
    }
    verifier._validate_closure_python(evidence, expected_sha256=expected_sha256)
    for key, changed_value in (
        ("sha256", "b" * 64),
        ("resolved_executable", "/usr/bin/python3"),
        ("isolated", False),
        ("no_site", False),
    ):
        changed = deepcopy(evidence)
        changed[key] = changed_value
        with pytest.raises(verifier.EvidenceVerificationError):
            verifier._validate_closure_python(
                changed,
                expected_sha256=expected_sha256,
            )


def _financial_oracle_fixture():
    planned = plan()
    case = next(item for item in planned["cases"] if item["name"] == "trial_balance")
    request = request_for_case(case)
    body = {"page": {"total_count": 2}}
    response = {
        "data": {
            "result": {**body, "receipt": {"id": "receipt-1"}},
            "release_identity": {**EXPECTED, "verified": True},
        }
    }
    database = {
        "current_database": planned["database"]["name"],
        "current_user": planned["database"]["current_user"],
        "database_uuid": planned["database"]["uuid"],
        "server_version_num": planned["database"]["server_version_num"],
        "system_identifier": planned["database"]["system_identifier"],
        "postmaster_started_at": "2026-07-20T00:00:00+00:00",
    }
    endpoint = {
        "kind": "unix_socket",
        "requested_directory": planned["database"]["unix_socket_directory"],
        "socket_path": planned["database"]["unix_socket_path"],
    }
    relations = [
        {"name": item["name"], "schema_sha256": f"{index:x}" * 64}
        for index, item in enumerate(planned["witness"]["relations"], 1)
    ]
    expected_metrics = {
        key: item
        for key, item in case["expected"].items()
        if key != "historical_source"
    }
    check_names = {
        "business_result",
        *(f"golden_{key}" for key in expected_metrics),
        "signed_receipt_binding",
        "nonempty_business_result",
    }
    report = {
        "schema_version": 1,
        "command": "verify",
        "case": case["name"],
        "capability_id": case["capability_id"],
        "all_checks_passed": True,
        "checks": {name: True for name in check_names},
        "database": database,
        "endpoint": endpoint,
        "relation_schema_sha256": {
            item["name"]: item["schema_sha256"] for item in relations
        },
        "access": {
            "user_id": case["user_id"],
            "company_id": case["company_id"],
            "company_member": True,
            "required_group": "account.group_account_readonly",
            "required_group_member": True,
        },
        "parameters_sha256": hashlib.sha256(
            verifier.canonical_json(request["parameters"])
        ).hexdigest(),
        "business_result_sha256": hashlib.sha256(
            verifier.canonical_json(body)
        ).hexdigest(),
        "oracle_metrics_sha256": hashlib.sha256(
            verifier.canonical_json(expected_metrics)
        ).hexdigest(),
        "record_count": 2,
        "release_identity_sha256": hashlib.sha256(
            verifier.canonical_json(response["data"]["release_identity"])
        ).hexdigest(),
        "fixture_gaps": [],
        "odoo_action_performed": False,
        "database_writes_permitted": False,
        "production_validated": False,
        "transaction": {
            "final_status": "IDLE",
            "isolation": "repeatable read",
            "read_only": "on",
            "rollback_completed": True,
        },
        "oracle_python": {
            "path": runtime()["odoo_python"],
            "sha256": runtime()["odoo_python_sha256"],
            "isolated": True,
        },
    }
    witness = {"database": database, "endpoint": endpoint, "relations": relations}
    return report, case, request, response, planned, witness


def test_oracle_report_is_exactly_bound_and_rejects_forged_true_checks():
    report, case, request, response, planned, witness = _financial_oracle_fixture()
    verifier.validate_oracle_report(
        report,
        case=case,
        request=request,
        response=response,
        plan=planned,
        runtime=runtime(),
        witness=witness,
    )
    mutations = (
        lambda value: value.__setitem__("unexpected", True),
        lambda value: value.__setitem__("checks", {"anything": True}),
        lambda value: value["database"].__setitem__("database_uuid", "wrong"),
        lambda value: value["endpoint"].__setitem__("socket_path", "/tmp/fake"),
        lambda value: value["relation_schema_sha256"].pop(next(iter(value["relation_schema_sha256"]))),
        lambda value: value.__setitem__("oracle_metrics_sha256", "f" * 64),
        lambda value: value["transaction"].__setitem__("rollback_completed", False),
        lambda value: value["oracle_python"].__setitem__("isolated", False),
    )
    for mutate in mutations:
        changed = deepcopy(report)
        mutate(changed)
        with pytest.raises(verifier.EvidenceVerificationError):
            verifier.validate_oracle_report(
                changed,
                case=case,
                request=request,
                response=response,
                plan=planned,
                runtime=runtime(),
                witness=witness,
            )


def test_independent_auth_and_receipt_match_production_vectors_and_resist_monkeypatch(
    monkeypatch,
):
    from odoo_accounting_cli_v3 import auth, receipts

    configuration = runtime()
    case = plan()["cases"][1]
    secret_auth = b"A" * 32
    secret_receipt = b"R" * 32
    issued = datetime(2026, 7, 20, tzinfo=timezone.utc)
    context = auth.sign_request_context(
        auth_token_id="dev29-read-trial_balance-11111111-1111-4111-8111-111111111111",
        principal=case["principal"],
        odoo_instance_id=configuration["instance_id"],
        database_name=configuration["database_name"],
        database_uuid=configuration["database_uuid"],
        user_id=case["user_id"],
        company_id=case["company_id"],
        allowed_company_ids=frozenset(case["allowed_company_ids"]),
        environment=configuration["environment"],
        capability_id=case["capability_id"],
        parameters=case["parameters"],
        issued_at=issued,
        expires_at=issued + timedelta(minutes=4),
        key_id=configuration["auth_key_id"],
        secret=secret_auth,
    )
    request = {
        "capability_id": case["capability_id"],
        "context": {**auth.context_payload(context), "auth_signature": context.auth_signature},
        "parameters": deepcopy(case["parameters"]),
    }
    verifier.verify_auth_request(
        request,
        auth_secret=secret_auth,
        runtime=configuration,
        expect_content_match=True,
    )

    body = {"page": {"total_count": 1}}
    release_identity = {
        **EXPECTED,
        "registry_digest": "f" * 64,
        "verified": True,
    }
    receipt = receipts.create_read_receipt(
        receipt_id="receipt-independent-vector",
        capability_id=case["capability_id"],
        parameters=case["parameters"],
        result_body=body,
        auth_token_id=request["context"]["auth_token_id"],
        principal=case["principal"],
        odoo_instance_id=configuration["instance_id"],
        database_name=configuration["database_name"],
        database_uuid=configuration["database_uuid"],
        company_id=case["company_id"],
        user_id=case["user_id"],
        registry_digest=release_identity["registry_digest"],
        release_digest=release_identity["manifest_sha256"],
        environment=configuration["environment"],
        capability_channel=configuration["capability_channel"],
        record_count=1,
        observed_at=issued + timedelta(minutes=1),
        key_id=configuration["receipt_key_id"],
        secret=secret_receipt,
    )
    response = {"data": {"result": {**body, "receipt": receipt}}}
    assert verifier.verify_receipt(
        request,
        response,
        receipt_secret=secret_receipt,
        runtime=configuration,
        release_identity=release_identity,
    ) == receipt

    monkeypatch.setattr(auth, "verify_request_context", lambda *_args, **_kwargs: True)
    changed_request = deepcopy(request)
    changed_request["context"]["principal"] = "attacker"
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.verify_auth_request(
            changed_request,
            auth_secret=secret_auth,
            runtime=configuration,
            expect_content_match=True,
        )
    changed_response = deepcopy(response)
    changed_response["data"]["result"]["receipt"]["record_count"] = 2
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.verify_receipt(
            request,
            changed_response,
            receipt_secret=secret_receipt,
            runtime=configuration,
            release_identity=release_identity,
        )


def test_independent_registry_digest_matches_production_and_rejects_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from odoo_accounting_cli_v3.registry import load_registry, registry_digest

    monkeypatch.setattr(
        verifier, "stable_read", lambda path, **_kwargs: Path(path).read_bytes()
    )
    registry_path = ROOT / "registry" / "capabilities.json"
    assert verifier.independent_registry_digest(registry_path) == registry_digest(
        load_registry(registry_path)
    )
    document = json.loads(registry_path.read_text("utf-8"))
    document["capabilities"][0]["input_schema"]["additionalProperties"] = True
    changed = tmp_path / "capabilities.json"
    changed.write_bytes(verifier.canonical_json(document) + b"\n")
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.independent_registry_digest(changed)

    source = (DEV29 / "verify_read_evidence.py").read_text("utf-8")
    assert "from odoo_accounting_cli_v3" not in source
    assert "_load_exact_core" not in source


def _installed_runtime_open_policy_fixture(
    destination: Path,
    *,
    release: str,
    runtime_sha256: str,
    release_manifest_sha256: str,
) -> tuple[dict, str]:
    static_sha256 = "2" * 64
    manifest_documents = []
    index_targets = []
    for target_id in verifier.expected_runtime_trace_targets():
        role = verifier._expected_trace_role(target_id)
        environment = verifier._expected_child_environment(role)
        environment_sha256 = hashlib.sha256(
            verifier.canonical_json(environment)
        ).hexdigest()
        watch_roots = ["/dev", "/opt", "/usr"]
        watch_roots_sha256 = hashlib.sha256(
            verifier.canonical_json(tuple(watch_roots))
        ).hexdigest()
        document = {
            "schema_version": 1,
            "scope": verifier.TRACE_MANIFEST_SCOPE,
            "release": release,
            "target_id": target_id,
            "role": role,
            "working_directory": f"/opt/odoo-accounting-cli-v3/releases/{release}",
            "environment": environment,
            "bootstrap_argv": ["/usr/bin/python3.12", "-I", "bootstrap.py"],
            "final_argv": ["/usr/bin/python3.12", "-I", "command.py"],
            "allowed_paths": ["/proc/self/exe", "/usr/bin/python3.12"],
            "path_access_policy": [
                {
                    "path": "/proc/self/exe",
                    "role": role,
                    "classification": "process-view",
                    "allowed_access": ["metadata", "read"],
                    "create_suffixes": [],
                    "delta_verifier": None,
                    "delta_contract_sha256": None,
                    "allow_success": True,
                    "allowed_errnos": [],
                    "failure_guard": None,
                },
                {
                    "path": "/usr/bin/python3.12",
                    "role": role,
                    "classification": "immutable",
                    "allowed_access": ["execute", "metadata", "read"],
                    "create_suffixes": [],
                    "delta_verifier": None,
                    "delta_contract_sha256": None,
                    "allow_success": True,
                    "allowed_errnos": [],
                    "failure_guard": None,
                }
            ],
            "watch_roots": watch_roots,
            "expected_static_closure_sha256": static_sha256,
            "expected_child_environment_sha256": environment_sha256,
            "expected_watch_roots_sha256": watch_roots_sha256,
            "expected_returncodes": [0],
        }
        payload = verifier.canonical_json(document) + b"\n"
        (destination / f"{target_id}.json").write_bytes(payload)
        manifest_documents.append(document)
        index_targets.append(
            {
                "target_id": target_id,
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                "watch_roots_sha256": watch_roots_sha256,
                "child_environment_sha256": environment_sha256,
            }
        )
    source = {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1",
        "release": release,
        "expected_strace_sha256": "1" * 64,
        "expected_static_closure_sha256": static_sha256,
        "expected_runtime_module_sha256": runtime_sha256,
        "expected_release_manifest_sha256": release_manifest_sha256,
        "targets": manifest_documents,
        "production_promotion_allowed": False,
    }
    source_sha256 = hashlib.sha256(
        verifier.canonical_json(source) + b"\n"
    ).hexdigest()
    return (
        {
            "schema_version": 1,
            "scope": verifier.TRACE_INDEX_SCOPE,
            "release": release,
            "expected_strace_sha256": "1" * 64,
            "expected_static_closure_sha256": static_sha256,
            "policy_source_sha256": source_sha256,
            "runtime_module_sha256": runtime_sha256,
            "release_manifest_sha256": release_manifest_sha256,
            "targets": index_targets,
            "production_promotion_allowed": False,
        },
        source_sha256,
    )


def _runtime_release_manifest(
    *, runtime_sha256: str, runtime_size: int
) -> dict:
    unsigned = {
        "schema_version": 1,
        "version": EXPECTED["version"],
        "commit": EXPECTED["commit"],
        "files": [
            {
                "path": str(verifier.TRACE_RELATIVE),
                "sha256": runtime_sha256,
                "size": runtime_size,
            }
        ],
    }
    return {
        **unsigned,
        "manifest_sha256": hashlib.sha256(
            verifier.canonical_json(unsigned)
        ).hexdigest(),
    }


def _synchronize_policy_source_digest(
    destination: Path, index: dict
) -> None:
    source = {
        "schema_version": 1,
        "scope": verifier.TRACE_POLICY_SOURCE_SCOPE,
        "release": index["release"],
        "expected_strace_sha256": index["expected_strace_sha256"],
        "expected_static_closure_sha256": index[
            "expected_static_closure_sha256"
        ],
        "expected_runtime_module_sha256": index["runtime_module_sha256"],
        "expected_release_manifest_sha256": index[
            "release_manifest_sha256"
        ],
        "targets": [
            json.loads((destination / f"{target_id}.json").read_bytes())
            for target_id in verifier.expected_runtime_trace_targets()
        ],
        "production_promotion_allowed": False,
    }
    index["policy_source_sha256"] = hashlib.sha256(
        verifier.canonical_json(source) + b"\n"
    ).hexdigest()


def test_runtime_open_index_binds_policy_environment_and_exact_release_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_root = tmp_path / "release"
    runtime_path = release_root.joinpath(*verifier.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    runtime_payload = (DEV29 / "runtime_open_trace.py").read_bytes()
    runtime_path.write_bytes(runtime_payload)
    runtime_sha256 = hashlib.sha256(runtime_payload).hexdigest()
    release_manifest = _runtime_release_manifest(
        runtime_sha256=runtime_sha256,
        runtime_size=len(runtime_payload),
    )
    release_manifest_payload = verifier.canonical_json(release_manifest) + b"\n"
    (release_root / "RELEASE-MANIFEST.json").write_bytes(
        release_manifest_payload
    )
    index_parent = tmp_path / "indices"
    destination = index_parent / EXPECTED["release"]
    destination.mkdir(parents=True)
    index, source_sha256 = _installed_runtime_open_policy_fixture(
        destination,
        release=EXPECTED["release"],
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=hashlib.sha256(
            release_manifest_payload
        ).hexdigest(),
    )

    def install(document: dict) -> str:
        payload = verifier.canonical_json(document) + b"\n"
        (destination / verifier.TRACE_INDEX_NAME).write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    monkeypatch.setattr(verifier, "TRACE_INDEX_PARENT", index_parent)
    digest = install(index)
    observed, targets, verified_runtime_payload = verifier._read_runtime_trace_index(
        EXPECTED,
        root=release_root,
        release_manifest=release_manifest,
        expected_sha256=digest,
        expected_strace_sha256="1" * 64,
        enforce_root=False,
    )
    assert observed["policy_source_sha256"] == source_sha256
    assert targets["independent-verifier"]["child_environment_sha256"] == (
        index["targets"][-1]["child_environment_sha256"]
    )
    assert verified_runtime_payload == runtime_payload

    boolean_index_schema = deepcopy(index)
    boolean_index_schema["schema_version"] = True
    with pytest.raises(
        verifier.EvidenceVerificationError, match="index identity"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(boolean_index_schema),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    first_target = verifier.expected_runtime_trace_targets()[0]
    first_manifest_path = destination / f"{first_target}.json"
    first_manifest_payload = first_manifest_path.read_bytes()
    boolean_target_manifest = json.loads(first_manifest_payload)
    boolean_target_manifest["schema_version"] = True
    boolean_target_payload = (
        verifier.canonical_json(boolean_target_manifest) + b"\n"
    )
    first_manifest_path.write_bytes(boolean_target_payload)
    boolean_target_index = deepcopy(index)
    boolean_target_index["targets"][0]["manifest_sha256"] = hashlib.sha256(
        boolean_target_payload
    ).hexdigest()
    _synchronize_policy_source_digest(destination, boolean_target_index)
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest identity"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(boolean_target_index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    first_manifest_path.write_bytes(first_manifest_payload)

    arbitrary_source_digest = deepcopy(index)
    arbitrary_source_digest["policy_source_sha256"] = "3" * 64
    with pytest.raises(
        verifier.EvidenceVerificationError, match="policy source digest"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(arbitrary_source_digest),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    extra = destination / "unapproved.json"
    extra.write_bytes(b"{}\n")
    with pytest.raises(
        verifier.EvidenceVerificationError, match="installed file set"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    extra.unlink()

    first_manifest = json.loads(first_manifest_payload)
    first_manifest["target_id"] = "different-target"
    changed_target_payload = verifier.canonical_json(first_manifest) + b"\n"
    first_manifest_path.write_bytes(changed_target_payload)
    changed_target = deepcopy(index)
    changed_target["targets"][0]["manifest_sha256"] = hashlib.sha256(
        changed_target_payload
    ).hexdigest()
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest identity"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(changed_target),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    first_manifest_path.write_bytes(first_manifest_payload)

    first_manifest_path.write_bytes(b"{}\n")
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest digest"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    first_manifest_path.write_bytes(first_manifest_payload)

    wrong_environment_binding = deepcopy(index)
    wrong_environment_binding["targets"][0]["child_environment_sha256"] = (
        "7" * 64
    )
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest identity"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(wrong_environment_binding),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    wrong_watch_binding = deepcopy(index)
    wrong_watch_binding["targets"][0]["watch_roots_sha256"] = "8" * 64
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest identity"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(wrong_watch_binding),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    watched_process_view_manifest = json.loads(first_manifest_payload)
    watched_process_view_manifest["watch_roots"] = sorted(
        [*watched_process_view_manifest["watch_roots"], "/proc/self"]
    )
    watched_process_view_manifest["expected_watch_roots_sha256"] = hashlib.sha256(
        verifier.canonical_json(tuple(watched_process_view_manifest["watch_roots"]))
    ).hexdigest()
    watched_process_view_payload = (
        verifier.canonical_json(watched_process_view_manifest) + b"\n"
    )
    first_manifest_path.write_bytes(watched_process_view_payload)
    watched_process_view_index = deepcopy(index)
    watched_process_view_index["targets"][0]["manifest_sha256"] = hashlib.sha256(
        watched_process_view_payload
    ).hexdigest()
    watched_process_view_index["targets"][0]["watch_roots_sha256"] = (
        watched_process_view_manifest["expected_watch_roots_sha256"]
    )
    _synchronize_policy_source_digest(destination, watched_process_view_index)
    with pytest.raises(
        verifier.EvidenceVerificationError, match="non-immutable path is watched"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(watched_process_view_index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    first_manifest_path.write_bytes(first_manifest_payload)

    writable_process_view_manifest = json.loads(first_manifest_payload)
    for policy in writable_process_view_manifest["path_access_policy"]:
        if policy["path"] == "/proc/self/exe":
            policy["allowed_access"] = ["metadata", "read", "write"]
            break
    writable_process_view_payload = (
        verifier.canonical_json(writable_process_view_manifest) + b"\n"
    )
    first_manifest_path.write_bytes(writable_process_view_payload)
    writable_process_view_index = deepcopy(index)
    writable_process_view_index["targets"][0]["manifest_sha256"] = hashlib.sha256(
        writable_process_view_payload
    ).hexdigest()
    _synchronize_policy_source_digest(destination, writable_process_view_index)
    with pytest.raises(
        verifier.EvidenceVerificationError, match="access policy is unsafe"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(writable_process_view_index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )
    first_manifest_path.write_bytes(first_manifest_payload)

    missing_environment = deepcopy(index)
    del missing_environment["targets"][0]["child_environment_sha256"]
    with pytest.raises(
        verifier.EvidenceVerificationError, match="index target"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(missing_environment),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    wrong_runtime = deepcopy(index)
    wrong_runtime["runtime_module_sha256"] = "7" * 64
    with pytest.raises(
        verifier.EvidenceVerificationError, match="release member binding"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=release_manifest,
            expected_sha256=install(wrong_runtime),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    wrong_size_manifest = _runtime_release_manifest(
        runtime_sha256=runtime_sha256,
        runtime_size=len(runtime_payload) + 1,
    )
    wrong_size_payload = verifier.canonical_json(wrong_size_manifest) + b"\n"
    (release_root / "RELEASE-MANIFEST.json").write_bytes(wrong_size_payload)
    wrong_size_index, _ = _installed_runtime_open_policy_fixture(
        destination,
        release=EXPECTED["release"],
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=hashlib.sha256(wrong_size_payload).hexdigest(),
    )
    with pytest.raises(
        verifier.EvidenceVerificationError, match="release member binding"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=wrong_size_manifest,
            expected_sha256=install(wrong_size_index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )

    wrong_member_manifest = _runtime_release_manifest(
        runtime_sha256="4" * 64,
        runtime_size=len(runtime_payload),
    )
    wrong_member_payload = (
        verifier.canonical_json(wrong_member_manifest) + b"\n"
    )
    (release_root / "RELEASE-MANIFEST.json").write_bytes(
        wrong_member_payload
    )
    wrong_member_index, _ = _installed_runtime_open_policy_fixture(
        destination,
        release=EXPECTED["release"],
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=hashlib.sha256(
            wrong_member_payload
        ).hexdigest(),
    )
    with pytest.raises(
        verifier.EvidenceVerificationError, match="release member binding"
    ):
        verifier._read_runtime_trace_index(
            EXPECTED,
            root=release_root,
            release_manifest=wrong_member_manifest,
            expected_sha256=install(wrong_member_index),
            expected_strace_sha256="1" * 64,
            enforce_root=False,
        )


def test_runtime_module_executes_index_verified_bytes_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_root = tmp_path / "release"
    runtime_path = release_root.joinpath(*verifier.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    runtime_payload = (DEV29 / "runtime_open_trace.py").read_bytes()
    runtime_path.write_bytes(runtime_payload)
    runtime_sha256 = hashlib.sha256(runtime_payload).hexdigest()
    release_manifest = _runtime_release_manifest(
        runtime_sha256=runtime_sha256,
        runtime_size=len(runtime_payload),
    )
    release_manifest_payload = verifier.canonical_json(release_manifest) + b"\n"
    (release_root / "RELEASE-MANIFEST.json").write_bytes(
        release_manifest_payload
    )
    index_parent = tmp_path / "indices"
    destination = index_parent / EXPECTED["release"]
    destination.mkdir(parents=True)
    index, _ = _installed_runtime_open_policy_fixture(
        destination,
        release=EXPECTED["release"],
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=hashlib.sha256(
            release_manifest_payload
        ).hexdigest(),
    )
    index_payload = verifier.canonical_json(index) + b"\n"
    (destination / verifier.TRACE_INDEX_NAME).write_bytes(index_payload)
    monkeypatch.setattr(verifier, "TRACE_INDEX_PARENT", index_parent)
    _, _, verified_runtime_payload = verifier._read_runtime_trace_index(
        EXPECTED,
        root=release_root,
        release_manifest=release_manifest,
        expected_sha256=hashlib.sha256(index_payload).hexdigest(),
        expected_strace_sha256="1" * 64,
        enforce_root=False,
    )

    before_inode = runtime_path.stat().st_ino
    replacement_path = runtime_path.with_name("runtime_open_trace.replacement.py")
    replacement_path.write_bytes(
        b"raise AssertionError('replacement executed')\n"
    )
    replacement_inode = replacement_path.stat().st_ino
    assert replacement_inode != before_inode
    os.replace(replacement_path, runtime_path)
    assert runtime_path.stat().st_ino == replacement_inode
    assert runtime_path.stat().st_ino != before_inode
    module = verifier._load_runtime_trace_module(
        release_root,
        expected_sha256=runtime_sha256,
        verified_payload=verified_runtime_payload,
        enforce_root=False,
    )
    assert module.TraceRequest.__dataclass_fields__.keys() >= {
        "expected_child_environment_sha256"
    }


def test_runtime_open_module_executes_only_the_digest_bound_bytes(tmp_path: Path) -> None:
    runtime_path = tmp_path.joinpath(*verifier.TRACE_RELATIVE.parts)
    runtime_path.parent.mkdir(parents=True)
    payload = (DEV29 / "runtime_open_trace.py").read_bytes()
    runtime_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    module = verifier._load_runtime_trace_module(
        tmp_path, expected_sha256=digest, enforce_root=False
    )
    assert module.TraceRequest.__dataclass_fields__.keys() >= {
        "expected_child_environment_sha256"
    }
    with pytest.raises(
        verifier.EvidenceVerificationError, match="parser digest differs"
    ):
        verifier._load_runtime_trace_module(
            tmp_path, expected_sha256="0" * 64, enforce_root=False
        )


def _runtime_trace_receipt_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict, dict, dict]:
    expected_index_sha256 = "1" * 64
    expected_strace_sha256 = "2" * 64
    static_sha256 = "3" * 64
    policy_source_sha256 = "4" * 64
    runtime_module_sha256 = "5" * 64
    release_manifest_sha256 = "6" * 64
    target_ids = verifier.suite_runtime_trace_targets()
    manifests = {}
    targets = {}
    private_entries = {}
    receipts = []
    for target_id in target_ids:
        manifest_sha256 = hashlib.sha256(target_id.encode("utf-8")).hexdigest()
        policy_sha256 = hashlib.sha256(
            f"policy:{target_id}".encode("utf-8")
        ).hexdigest()
        trace_sha256 = hashlib.sha256(
            f"trace:{target_id}".encode("utf-8")
        ).hexdigest()
        path_set_sha256 = hashlib.sha256(
            f"paths:{target_id}".encode("utf-8")
        ).hexdigest()
        role = verifier._expected_trace_role(target_id)
        manifests[target_id] = {"role": role}
        targets[target_id] = {
            "target_id": target_id,
            "manifest_sha256": manifest_sha256,
            "watch_roots_sha256": "7" * 64,
            "child_environment_sha256": "8" * 64,
        }
        private_entries[target_id] = {
            "path": str(tmp_path / f"{target_id}.strace"),
            "expected_leader_pid": 100,
            "sha256": trace_sha256,
        }
        receipts.append(
            {
                "schema_version": 1,
                "scope": verifier.TRACE_MANIFEST_SCOPE,
                "target_id": target_id,
                "role": role,
                "manifest_sha256": manifest_sha256,
                "policy_sha256": policy_sha256,
                "watch_roots_sha256": "7" * 64,
                "child_environment_sha256": "8" * 64,
                "static_closure_sha256": static_sha256,
                "dynamic_namespace_receipt_sha256": "9" * 64,
                "canonical_path_count": 1,
                "canonical_path_set_sha256": path_set_sha256,
                "trace_sha256": trace_sha256,
                "production_promotion_allowed": False,
            }
        )
    index = {
        "expected_static_closure_sha256": static_sha256,
        "policy_source_sha256": policy_source_sha256,
        "runtime_module_sha256": runtime_module_sha256,
        "release_manifest_sha256": release_manifest_sha256,
    }
    private_summary = {"sealed": True}
    receipt_set = {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.dev29.runtime-open-receipts.v1",
        "release": EXPECTED["release"],
        "index_sha256": expected_index_sha256,
        "expected_strace_sha256": expected_strace_sha256,
        "expected_static_closure_sha256": static_sha256,
        "policy_source_sha256": policy_source_sha256,
        "runtime_module_sha256": runtime_module_sha256,
        "release_manifest_sha256": release_manifest_sha256,
        "receipts": receipts,
        "private_sidecar": private_summary,
        "production_promotion_allowed": False,
    }
    documents = {
        "runtime-open-trace.json": verifier.canonical_json(receipt_set) + b"\n"
    }
    bundle_manifest = {
        "evidence_path": str(tmp_path / "proof"),
        "runtime_open_trace_sha256": hashlib.sha256(
            documents["runtime-open-trace.json"]
        ).hexdigest(),
        "runtime_open_trace_private": private_summary,
    }
    monkeypatch.setattr(
        verifier,
        "_read_runtime_trace_index",
        lambda *_args, **_kwargs: (index, targets, b"verified runtime module"),
    )
    monkeypatch.setattr(
        verifier,
        "_load_private_runtime_trace_sidecar",
        lambda *_args, **_kwargs: private_entries,
    )

    def validate_manifest(target_id, *_args, **_kwargs):
        return (
            manifests[target_id],
            hashlib.sha256(f"policy:{target_id}".encode("utf-8")).hexdigest(),
        )

    monkeypatch.setattr(
        verifier, "_validate_runtime_trace_manifest", validate_manifest
    )

    def validate_trace_file(_path, _manifest, *, expected_leader_pid):
        assert expected_leader_pid == 100
        target_id = _manifest["target_id"]
        receipt = next(
            item for item in receipts if item["target_id"] == target_id
        )
        return SimpleNamespace(
            document=lambda: {
                "canonical_path_count": receipt["canonical_path_count"],
                "canonical_path_set_sha256": receipt[
                    "canonical_path_set_sha256"
                ],
                "trace_sha256": receipt["trace_sha256"],
            }
        )

    fake_module = SimpleNamespace(
        TraceRequest=lambda **kwargs: SimpleNamespace(**kwargs),
        load_trace_manifest=lambda request: (
            {"target_id": request.target_id},
            {},
        ),
        validate_trace_file=validate_trace_file,
    )
    monkeypatch.setattr(
        verifier, "_load_runtime_trace_module", lambda *_args, **_kwargs: fake_module
    )
    arguments = {
        "root": tmp_path,
        "release_manifest": {},
        "expected_index_sha256": expected_index_sha256,
        "expected_strace_sha256": expected_strace_sha256,
    }
    verifier.validate_runtime_open_trace(
        documents,
        bundle_manifest,
        EXPECTED,
        **arguments,
    )
    return receipt_set, bundle_manifest, arguments


@pytest.mark.parametrize(
    ("layer", "message"),
    (
        ("receipt_set", "receipt set"),
        ("receipt", "trace receipt"),
    ),
)
def test_runtime_open_schema_versions_reject_booleans_after_digest_rebinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    layer: str,
    message: str,
) -> None:
    receipt_set, bundle_manifest, arguments = _runtime_trace_receipt_fixture(
        tmp_path, monkeypatch
    )
    changed = deepcopy(receipt_set)
    if layer == "receipt_set":
        changed["schema_version"] = True
    else:
        changed["receipts"][0]["schema_version"] = True
    documents = {
        "runtime-open-trace.json": verifier.canonical_json(changed) + b"\n"
    }
    rebound_bundle = deepcopy(bundle_manifest)
    rebound_bundle["runtime_open_trace_sha256"] = hashlib.sha256(
        documents["runtime-open-trace.json"]
    ).hexdigest()
    with pytest.raises(verifier.EvidenceVerificationError, match=message):
        verifier.validate_runtime_open_trace(
            documents,
            rebound_bundle,
            EXPECTED,
            **arguments,
        )


def test_private_runtime_sidecar_rejects_residual_seal_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_name = "proof"
    target_id = "release-identity"
    sidecar = tmp_path / evidence_name
    sidecar.mkdir()
    trace_path = sidecar / f"{target_id}.strace"
    trace_payload = b"trace\n"
    trace_path.write_bytes(trace_payload)
    metadata = trace_path.stat()
    entry = {
        "target_id": target_id,
        "manifest_sha256": "1" * 64,
        "expected_leader_pid": 1234,
        "path": str(trace_path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mode": "0400",
        "sha256": hashlib.sha256(trace_payload).hexdigest(),
    }
    document = {
        "schema_version": 1,
        "sidecar_type": "odoo-accounting-cli-v3.dev29.private-runtime-open.v1",
        "release": EXPECTED["release"],
        "evidence_name": evidence_name,
        "entries": [entry],
        "production_promotion_allowed": False,
    }
    manifest_payload = verifier.canonical_json(document) + b"\n"
    (sidecar / "MANIFEST.json").write_bytes(manifest_payload)
    identity = {
        key: entry[key]
        for key in ("target_id", "device", "inode", "size", "sha256")
    }
    summary = {
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "trace_count": 1,
        "tree_identity_sha256": hashlib.sha256(
            verifier.canonical_json([identity])
        ).hexdigest(),
        "production_promotion_allowed": False,
    }
    monkeypatch.setattr(verifier, "PRIVATE_EVIDENCE_PARENT", tmp_path)
    verifier._load_private_runtime_trace_sidecar(
        evidence_name,
        EXPECTED["release"],
        summary,
        (target_id,),
        enforce_root=False,
    )
    for field in ("schema_version", "trace_count"):
        invalid_summary = deepcopy(summary)
        invalid_summary[field] = True
        with pytest.raises(
            verifier.EvidenceVerificationError, match="summary is invalid"
        ):
            verifier._load_private_runtime_trace_sidecar(
                evidence_name,
                EXPECTED["release"],
                invalid_summary,
                (target_id,),
                enforce_root=False,
            )

    invalid_document = deepcopy(document)
    invalid_document["schema_version"] = True
    invalid_manifest_payload = verifier.canonical_json(invalid_document) + b"\n"
    (sidecar / "MANIFEST.json").write_bytes(invalid_manifest_payload)
    invalid_manifest_summary = deepcopy(summary)
    invalid_manifest_summary["manifest_sha256"] = hashlib.sha256(
        invalid_manifest_payload
    ).hexdigest()
    with pytest.raises(
        verifier.EvidenceVerificationError, match="manifest is invalid"
    ):
        verifier._load_private_runtime_trace_sidecar(
            evidence_name,
            EXPECTED["release"],
            invalid_manifest_summary,
            (target_id,),
            enforce_root=False,
        )
    (sidecar / "MANIFEST.json").write_bytes(manifest_payload)

    (sidecar / f".{target_id}.seal.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(
        verifier.EvidenceVerificationError, match="sidecar member set"
    ):
        verifier._load_private_runtime_trace_sidecar(
            evidence_name,
            EXPECTED["release"],
            summary,
            (target_id,),
            enforce_root=False,
        )
