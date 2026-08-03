from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import stat
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

import odoo_accounting_cli_v3.read_evidence_index as evidence_index_module
from odoo_accounting_cli_v3.read_evidence_index import (
    ARTIFACT_SCHEMA,
    ATTESTATION_KEYS_SCHEMA,
    ATTESTATION_SCHEMA,
    EVIDENCE_INDEX_SCHEMA,
    REQUIRED_EVIDENCE_KINDS,
    SOURCE_BUNDLE_SCHEMA,
    TRUST_ANCHOR_SCHEMA,
    ReadEvidenceIndexError,
    canonical_json_bytes,
    create_read_evidence_attestation,
    verify_read_evidence_index,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt


IDENTITY = {
    "commit": "1" * 40,
    "manifest_sha256": "2" * 64,
    "package_sha256": "3" * 64,
    "registry_digest": "4" * 64,
    "release": "0.1.0.dev262-111111111111",
    "verified": True,
    "version": "0.1.0.dev262",
}
CAPABILITY_CONTRACTS = {
    "acct.gl.trial_balance.v1": "5" * 64,
    "acct.tax.report_read.v1": "6" * 64,
}
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
RECEIPT_KEY_ID = "test-read-receipt:dev262"
RECEIPT_SECRET = hashlib.sha256(b"test-read-receipt-secret").digest()
COLLECTED_AT = datetime(2026, 8, 3, 3, 0, tzinfo=timezone.utc)
COLLECTED_AT_TEXT = "2026-08-03T03:00:00Z"
SOURCE_BUNDLE_ID = "dev262-real-read-source"

SCOPE = {
    "allowed_company_ids": [1],
    "capability_channel": "staged",
    "company_id": 1,
    "database_name": "odoo_test",
    "database_uuid": DATABASE_UUID,
    "environment": "test",
    "odoo_instance_id": "odoo19@43.165.173.80",
    "principal": "pi:test-user-2",
    "receipt_key_id": RECEIPT_KEY_ID,
    "registry_digest": IDENTITY["registry_digest"],
    "release_digest": IDENTITY["manifest_sha256"],
    "user_id": 2,
}

SECURITY_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)
READ_EVENT_ORDER = (
    "user_input",
    "capability_selected",
    "clarification_completed",
    "material_parameters_finalized",
    "cli_input",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
)


@dataclass
class EvidenceFixture:
    index_path: Path
    index: dict[str, object]
    evidence_parent: Path
    evidence_source_parent: Path
    source_parent: Path
    source_root: Path
    source_manifest_path: Path
    source_manifest: dict[str, object]
    attestation_keys_parent: Path
    keys_path: Path
    keys: dict[str, object]
    trusted_artifact_parent: Path
    anchor_path: Path
    anchor: dict[str, object]
    runtime_path: Path
    runtime: dict[str, object]
    receipt_secret_path: Path
    attestation_secrets: dict[str, bytes]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> bytes:
    raw = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    if os.name == "posix":
        path.chmod(0o600)
    return raw


def _write_private_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    if os.name == "posix":
        path.chmod(0o600)


def _release_root() -> str:
    return str(
        (
            Path("/opt/odoo-accounting-cli-v3/releases")
            / IDENTITY["release"]
        ).resolve()
    )


def _authority_document() -> tuple[dict[str, object], dict[str, bytes]]:
    secrets = {
        kind: hashlib.sha256(f"test-read-evidence-{kind}".encode()).digest()
        for kind in REQUIRED_EVIDENCE_KINDS
    }
    return (
        {
            "keys": [
                {
                    "authority_id": f"test-authority:{kind}",
                    "evidence_kind": kind,
                    "key_id": f"test-key:{kind}",
                    "secret_base64": base64.b64encode(secrets[kind]).decode(
                        "ascii"
                    ),
                }
                for kind in REQUIRED_EVIDENCE_KINDS
            ],
            "schema_version": ATTESTATION_KEYS_SCHEMA,
        },
        secrets,
    )


def _runtime_config(tmp_path: Path, receipt_secret_path: Path) -> dict[str, object]:
    runtime_root = (tmp_path / "runtime-inputs").resolve()

    def runtime_path(name: str) -> str:
        return str((runtime_root / name).resolve())

    return {
        "auth_key_id": "test-read-auth:dev262",
        "auth_secret_path": runtime_path("auth.hmac"),
        "auth_state_path": runtime_path("auth-state.sqlite3"),
        "canonical_package_path": runtime_path("canonical-package.tar.gz"),
        "canonical_package_sha256": IDENTITY["package_sha256"],
        "capability_channel": SCOPE["capability_channel"],
        "database_name": SCOPE["database_name"],
        "database_uuid": SCOPE["database_uuid"],
        "environment": SCOPE["environment"],
        "gcov_state_path": runtime_path("gcov-state.sqlite3"),
        "instance_id": SCOPE["odoo_instance_id"],
        "odoo_bin": runtime_path("odoo-bin"),
        "odoo_bin_sha256": "7" * 64,
        "odoo_config": runtime_path("odoo.conf"),
        "odoo_config_sha256": "8" * 64,
        "odoo_python": runtime_path("python3"),
        "odoo_python_sha256": "9" * 64,
        "receipt_key_id": RECEIPT_KEY_ID,
        "receipt_secret_path": str(receipt_secret_path),
        "receipt_state_path": runtime_path("receipt-state.sqlite3"),
        "release_root": _release_root(),
    }


def _parameters(capability_id: str) -> dict[str, object]:
    return {
        "company_id": SCOPE["company_id"],
        "date_to": "2026-07-31",
        "include_draft": False,
        "limit": 100,
        "request_marker": capability_id,
    }


def _result_body(capability_id: str) -> dict[str, object]:
    return {
        "capability_id": capability_id,
        "company_id": SCOPE["company_id"],
        "currency": {"code": "USD", "id": 1},
        "lines": [
            {
                "account_code": "1000",
                "balance": "125.00",
                "id": 101,
            }
        ],
        "page": {
            "limit": 100,
            "offset": 0,
            "returned_count": 1,
            "total_count": 1,
        },
    }


def _create_receipt(
    *,
    capability_id: str,
    kind: str,
    parameters: dict[str, object],
    result_body: dict[str, object],
    auth_token_id: str,
    observed_at: datetime = COLLECTED_AT,
    record_count: int | None = None,
) -> dict[str, object]:
    return create_read_receipt(
        receipt_id=f"receipt:{capability_id}:{kind}",
        capability_id=capability_id,
        parameters=parameters,
        result_body=result_body,
        auth_token_id=auth_token_id,
        principal=SCOPE["principal"],
        odoo_instance_id=SCOPE["odoo_instance_id"],
        database_name=SCOPE["database_name"],
        database_uuid=SCOPE["database_uuid"],
        company_id=SCOPE["company_id"],
        user_id=SCOPE["user_id"],
        registry_digest=SCOPE["registry_digest"],
        release_digest=SCOPE["release_digest"],
        environment=SCOPE["environment"],
        capability_channel=SCOPE["capability_channel"],
        record_count=(
            result_body["page"]["total_count"]
            if record_count is None
            else record_count
        ),
        observed_at=observed_at,
        key_id=RECEIPT_KEY_ID,
        secret=RECEIPT_SECRET,
    )


def _read_case(capability_id: str, kind: str) -> dict[str, object]:
    parameters = _parameters(capability_id)
    result_body = _result_body(capability_id)
    auth_token_id = f"auth:{capability_id}:{kind}"
    return {
        "auth_token_id": auth_token_id,
        "case_id": f"case:{capability_id}:{kind}",
        "parameters": parameters,
        "receipt": _create_receipt(
            capability_id=capability_id,
            kind=kind,
            parameters=parameters,
            result_body=result_body,
            auth_token_id=auth_token_id,
        ),
        "result_body": result_body,
    }


def _oracle_witness(oracle_result: dict[str, object]) -> dict[str, object]:
    state_sha256 = hashlib.sha256(b"database-state-before-and-after").hexdigest()
    return {
        "company_id": SCOPE["company_id"],
        "database_name": SCOPE["database_name"],
        "database_uuid": SCOPE["database_uuid"],
        "isolation_level": "repeatable_read",
        "oracle_result_sha256": _json_sha256(oracle_result),
        "post_state_sha256": state_sha256,
        "pre_state_sha256": state_sha256,
        "query_sha256": hashlib.sha256(b"independent-sql-query").hexdigest(),
        "rolled_back": True,
        "row_stream_sha256": hashlib.sha256(b"independent-row-stream").hexdigest(),
        "transaction_read_only": True,
        "write_statement_count": 0,
    }


def _payload(kind: str, capability_id: str) -> dict[str, object]:
    if kind == "live_odoo":
        return {"cases": [_read_case(capability_id, kind)]}
    if kind == "accounting_oracle":
        case = _read_case(capability_id, kind)
        oracle_result = deepcopy(case["result_body"])
        return {
            "cases": [
                {
                    **case,
                    "oracle_result": oracle_result,
                    "postgresql_witness": _oracle_witness(oracle_result),
                }
            ]
        }
    if kind == "pi_e2e":
        read_case = _read_case(capability_id, kind)
        return {
            "cases": [
                {
                    "assistant_result_sha256": _json_sha256(
                        read_case["result_body"]
                    ),
                    "audit_receipt_sha256": _json_sha256(read_case["receipt"]),
                    "auth_token_id": read_case["auth_token_id"],
                    "case_id": read_case["case_id"],
                    "cli_parameters": read_case["parameters"],
                    "collected_parameters": deepcopy(read_case["parameters"]),
                    "event_order": list(READ_EVENT_ORDER),
                    "natural_language_request": "请读取并核对这项会计数据",
                    "receipt": read_case["receipt"],
                    "result_body": read_case["result_body"],
                    "selected_capability_id": capability_id,
                }
            ]
        }
    if kind == "security_negative":
        return {
            "cases": [
                {
                    "case_id": case_id,
                    "exit_code": 6,
                    "expected_error_code": error_code,
                    "observed_error_code": error_code,
                    "odoo_effect": "none",
                    "odoo_write_count": 0,
                    "postgresql_write_count": 0,
                    "receipt_count": 0,
                    "request_sha256": hashlib.sha256(
                        f"{capability_id}:{case_id}:request".encode()
                    ).hexdigest(),
                    "response_sha256": hashlib.sha256(
                        f"{capability_id}:{case_id}:response".encode()
                    ).hexdigest(),
                }
                for case_id, error_code in SECURITY_CASES
            ]
        }
    if kind == "release_identity":
        return {
            "canonical_package_sha256": IDENTITY["package_sha256"],
            "capability_contract_sha256": CAPABILITY_CONTRACTS[capability_id],
            "commit": IDENTITY["commit"],
            "registry_digest": IDENTITY["registry_digest"],
            "release": IDENTITY["release"],
            "release_manifest_identity_sha256": IDENTITY["manifest_sha256"],
            "release_root": _release_root(),
            "version": IDENTITY["version"],
        }
    raise AssertionError(f"unsupported evidence kind: {kind}")


def _verification_summary(kind: str, payload: dict[str, object]) -> dict[str, object]:
    cases = payload.get("cases")
    case_count = (
        1
        if kind == "release_identity"
        else len(cases)
        if isinstance(cases, list)
        else 0
    )
    receipt_count = (
        len(cases)
        if kind in {"accounting_oracle", "live_odoo", "pi_e2e"}
        and isinstance(cases, list)
        else 0
    )
    return {
        "independent_verifier_proven": False,
        "legacy_structural_case_count": case_count,
        "legacy_structural_checks_passed": True,
        "legacy_structural_receipt_count": receipt_count,
        "postgresql_read_proven": False,
        "postgresql_write_absence_proven": False,
        "real_odoo_read_proven": False,
        "real_odoo_write_absence_proven": False,
    }


def _authority_binding(kind: str) -> dict[str, object]:
    return {
        "authority_id": f"test-authority:{kind}",
        "evidence_kind": kind,
        "key_id": f"test-key:{kind}",
        "verifier_id": f"test-verifier:{kind}:v2",
        "verifier_sha256": hashlib.sha256(
            f"test-verifier-source:{kind}".encode()
        ).hexdigest(),
    }


def _claims(
    artifact: dict[str, object],
    *,
    artifact_sha256: str,
    source_bundle_manifest_sha256: str,
    collected_at: str,
) -> dict[str, object]:
    kind = artifact["evidence_kind"]
    authority = _authority_binding(kind)
    summary = _verification_summary(kind, artifact["payload"])
    return {
        "artifact_sha256": artifact_sha256,
        "authority_id": authority["authority_id"],
        "capability_contract_sha256": artifact[
            "capability_contract_sha256"
        ],
        "capability_id": artifact["capability_id"],
        "commit": IDENTITY["commit"],
        "evidence_kind": kind,
        "manifest_sha256": IDENTITY["manifest_sha256"],
        "observed_at": collected_at,
        "package_sha256": IDENTITY["package_sha256"],
        "registry_digest": IDENTITY["registry_digest"],
        "release": IDENTITY["release"],
        "scope_sha256": _json_sha256(artifact["scope"]),
        "source_bundle_manifest_sha256": source_bundle_manifest_sha256,
        "verification_summary_sha256": _json_sha256(summary),
        "verifier_id": authority["verifier_id"],
        "verifier_sha256": authority["verifier_sha256"],
        "version": IDENTITY["version"],
    }


def _build_bundle(tmp_path: Path) -> EvidenceFixture:
    evidence_parent = (tmp_path / "evidence").resolve()
    evidence_root = evidence_parent / "run-dev262"
    evidence_source_parent = (tmp_path / "evidence-sources").resolve()
    source_parent = evidence_source_parent / IDENTITY["release"]
    source_root = source_parent / SOURCE_BUNDLE_ID
    attestation_keys_parent = (tmp_path / "attestation-keys").resolve()
    keys_path = (
        attestation_keys_parent
        / IDENTITY["release"]
        / "attestation-keys.json"
    )
    trusted_artifact_parent = (tmp_path / "trusted-artifacts").resolve()
    anchor_path = (
        trusted_artifact_parent / f"{IDENTITY['release']}.read-evidence.json"
    )
    runtime_path = (tmp_path / "runtime" / "read-runtime.json").resolve()
    receipt_secret_path = (tmp_path / "runtime" / "receipt.hmac").resolve()
    for directory in (
        evidence_root,
        source_root,
        keys_path.parent,
        trusted_artifact_parent,
        runtime_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            directory.chmod(0o700)

    _write_private_bytes(receipt_secret_path, RECEIPT_SECRET)
    runtime = _runtime_config(tmp_path, receipt_secret_path)
    runtime_raw = _write_json(runtime_path, runtime)
    keys, attestation_secrets = _authority_document()
    keys_raw = _write_json(keys_path, keys)

    source_entries: list[dict[str, object]] = []
    payloads: dict[tuple[str, str], tuple[str, str, dict[str, object]]] = {}
    for capability_id in sorted(CAPABILITY_CONTRACTS):
        for kind in REQUIRED_EVIDENCE_KINDS:
            payload = _payload(kind, capability_id)
            relative = f"artifacts/{capability_id}/{kind}.json"
            member_path = source_root.joinpath(*relative.split("/"))
            member_raw = _write_json(member_path, payload)
            member_sha256 = _sha256(member_raw)
            source_entries.append(
                {
                    "path": relative,
                    "sha256": member_sha256,
                    "size": len(member_raw),
                }
            )
            payloads[(capability_id, kind)] = (
                relative,
                member_sha256,
                payload,
            )
    source_manifest = {
        "bundle_id": SOURCE_BUNDLE_ID,
        "collected_at": COLLECTED_AT_TEXT,
        "collector_id": "test-real-read-collector:v1",
        "collector_sha256": hashlib.sha256(
            b"test-real-read-collector-source"
        ).hexdigest(),
        "files": sorted(source_entries, key=lambda item: item["path"]),
        "release_identity": deepcopy(IDENTITY),
        "schema_version": SOURCE_BUNDLE_SCHEMA,
        "scope": deepcopy(SCOPE),
    }
    source_manifest_path = source_root / "BUNDLE-MANIFEST.json"
    source_manifest_raw = _write_json(source_manifest_path, source_manifest)
    source_manifest_sha256 = _sha256(source_manifest_raw)

    anchor = {
        "attestation_keys_path": str(keys_path),
        "attestation_keys_sha256": _sha256(keys_raw),
        "authorities": [
            _authority_binding(kind) for kind in REQUIRED_EVIDENCE_KINDS
        ],
        "read_runtime_config_path": str(runtime_path),
        "read_runtime_config_sha256": _sha256(runtime_raw),
        "release_identity": deepcopy(IDENTITY),
        "schema_version": TRUST_ANCHOR_SCHEMA,
        "scope": deepcopy(SCOPE),
        "source_parent": str(source_parent),
    }
    _write_json(anchor_path, anchor)

    capabilities: list[dict[str, object]] = []
    for capability_id, contract_sha256 in sorted(CAPABILITY_CONTRACTS.items()):
        capability_root = evidence_root / capability_id
        capability_root.mkdir()
        evidence: list[dict[str, str]] = []
        for kind in REQUIRED_EVIDENCE_KINDS:
            relative, member_sha256, payload = payloads[(capability_id, kind)]
            artifact = {
                "capability_contract_sha256": contract_sha256,
                "capability_id": capability_id,
                "evidence_kind": kind,
                "payload": payload,
                "release_identity": deepcopy(IDENTITY),
                "schema_version": ARTIFACT_SCHEMA,
                "scope": deepcopy(SCOPE),
                "source": {
                    "bundle_id": SOURCE_BUNDLE_ID,
                    "bundle_manifest_path": str(source_manifest_path),
                    "bundle_manifest_sha256": source_manifest_sha256,
                    "evidence_member_path": relative,
                    "evidence_member_sha256": member_sha256,
                },
            }
            artifact_path = capability_root / f"{kind}.artifact.json"
            artifact_raw = _write_json(artifact_path, artifact)
            artifact_sha256 = _sha256(artifact_raw)
            claims = _claims(
                artifact,
                artifact_sha256=artifact_sha256,
                source_bundle_manifest_sha256=source_manifest_sha256,
                collected_at=COLLECTED_AT_TEXT,
            )
            attestation = create_read_evidence_attestation(
                claims,
                key_id=f"test-key:{kind}",
                secret=attestation_secrets[kind],
            )
            assert attestation["schema_version"] == ATTESTATION_SCHEMA
            attestation_path = capability_root / f"{kind}.attestation.json"
            attestation_raw = _write_json(attestation_path, attestation)
            evidence.append(
                {
                    "artifact_path": str(artifact_path),
                    "artifact_sha256": artifact_sha256,
                    "attestation_path": str(attestation_path),
                    "attestation_sha256": _sha256(attestation_raw),
                    "evidence_kind": kind,
                }
            )
        capabilities.append(
            {
                "capability_id": capability_id,
                "evidence": evidence,
                "scope": deepcopy(SCOPE),
            }
        )
    index = {
        "capabilities": capabilities,
        "evidence_root": str(evidence_root),
        "release_identity": deepcopy(IDENTITY),
        "schema_version": EVIDENCE_INDEX_SCHEMA,
    }
    index_path = evidence_root / "read-evidence-index.json"
    _write_json(index_path, index)
    return EvidenceFixture(
        index_path=index_path,
        index=index,
        evidence_parent=evidence_parent,
        evidence_source_parent=evidence_source_parent,
        source_parent=source_parent,
        source_root=source_root,
        source_manifest_path=source_manifest_path,
        source_manifest=source_manifest,
        attestation_keys_parent=attestation_keys_parent,
        keys_path=keys_path,
        keys=keys,
        trusted_artifact_parent=trusted_artifact_parent,
        anchor_path=anchor_path,
        anchor=anchor,
        runtime_path=runtime_path,
        runtime=runtime,
        receipt_secret_path=receipt_secret_path,
        attestation_secrets=attestation_secrets,
    )


def _verify(
    fixture: EvidenceFixture, *, require_root_owner: bool = False
) -> dict[str, object]:
    return verify_read_evidence_index(
        fixture.index_path,
        expected_release_identity=IDENTITY,
        expected_capability_contracts=CAPABILITY_CONTRACTS,
        require_root_owner=require_root_owner,
        evidence_parent=fixture.evidence_parent,
        attestation_keys_parent=fixture.attestation_keys_parent,
        evidence_source_parent=fixture.evidence_source_parent,
        trusted_artifact_parent=fixture.trusted_artifact_parent,
    )


def _rewrite_index(fixture: EvidenceFixture) -> None:
    _write_json(fixture.index_path, fixture.index)


def _capability(
    fixture: EvidenceFixture, capability_id: str | None = None
) -> dict[str, object]:
    selected = capability_id or sorted(CAPABILITY_CONTRACTS)[0]
    return next(
        item
        for item in fixture.index["capabilities"]
        if item["capability_id"] == selected
    )


def _entry(
    fixture: EvidenceFixture,
    kind: str,
    capability_id: str | None = None,
) -> dict[str, str]:
    return next(
        item
        for item in _capability(fixture, capability_id)["evidence"]
        if item["evidence_kind"] == kind
    )


def _source_member_path(
    fixture: EvidenceFixture, capability_id: str, kind: str
) -> Path:
    return fixture.source_root / "artifacts" / capability_id / f"{kind}.json"


def _store_artifact(
    fixture: EvidenceFixture,
    capability_id: str,
    kind: str,
    artifact: dict[str, object],
) -> None:
    entry = _entry(fixture, kind, capability_id)
    artifact_raw = _write_json(Path(entry["artifact_path"]), artifact)
    artifact_sha256 = _sha256(artifact_raw)
    entry["artifact_sha256"] = artifact_sha256
    claims = _claims(
        artifact,
        artifact_sha256=artifact_sha256,
        source_bundle_manifest_sha256=artifact["source"][
            "bundle_manifest_sha256"
        ],
        collected_at=fixture.source_manifest["collected_at"],
    )
    attestation = create_read_evidence_attestation(
        claims,
        key_id=f"test-key:{kind}",
        secret=fixture.attestation_secrets[kind],
    )
    attestation_raw = _write_json(Path(entry["attestation_path"]), attestation)
    entry["attestation_sha256"] = _sha256(attestation_raw)


def _reseal_all_artifacts(fixture: EvidenceFixture) -> None:
    manifest_raw = _write_json(
        fixture.source_manifest_path, fixture.source_manifest
    )
    manifest_sha256 = _sha256(manifest_raw)
    for capability in fixture.index["capabilities"]:
        capability_id = capability["capability_id"]
        for evidence in capability["evidence"]:
            kind = evidence["evidence_kind"]
            member_path = _source_member_path(fixture, capability_id, kind)
            member_raw = member_path.read_bytes()
            payload = _read_json(member_path)
            artifact = _read_json(Path(evidence["artifact_path"]))
            artifact["payload"] = payload
            artifact["source"]["bundle_manifest_sha256"] = manifest_sha256
            artifact["source"]["evidence_member_sha256"] = _sha256(member_raw)
            _store_artifact(fixture, capability_id, kind, artifact)
    _rewrite_index(fixture)


def _replace_payload(
    fixture: EvidenceFixture,
    kind: str,
    payload: dict[str, object],
    capability_id: str | None = None,
) -> None:
    selected = capability_id or sorted(CAPABILITY_CONTRACTS)[0]
    member_path = _source_member_path(fixture, selected, kind)
    member_raw = _write_json(member_path, payload)
    relative = member_path.relative_to(fixture.source_root).as_posix()
    manifest_entry = next(
        item
        for item in fixture.source_manifest["files"]
        if item["path"] == relative
    )
    manifest_entry.update(
        {"sha256": _sha256(member_raw), "size": len(member_raw)}
    )
    _reseal_all_artifacts(fixture)


def _rewrite_anchor(fixture: EvidenceFixture) -> None:
    _write_json(fixture.anchor_path, fixture.anchor)


def _rewrite_keys_and_pin(fixture: EvidenceFixture) -> None:
    keys_raw = _write_json(fixture.keys_path, fixture.keys)
    fixture.anchor["attestation_keys_sha256"] = _sha256(keys_raw)
    _rewrite_anchor(fixture)


def test_verifier_api_does_not_accept_a_caller_selected_keys_file():
    parameters = inspect.signature(verify_read_evidence_index).parameters

    assert "attestation_keys_path" not in parameters
    assert "trust_anchor_path" not in parameters


def test_read_evidence_index_audits_strict_v2_without_opening_goal_gate(
    tmp_path: Path,
):
    fixture = _build_bundle(tmp_path)

    report = _verify(fixture)

    assert report["external_read_evidence_verified"] is False
    assert report["goal_evidence_admissible"] is False
    assert report["legacy_v2_structural_audit_verified"] is True
    assert report["blockers"] == [
        "legacy HMAC read evidence v2 is not admissible for Goal evidence; "
        "SSHSIG v3 with active admission and raw verifier evidence is required"
    ]
    assert report["verified_capability_count"] == 0
    assert report["structurally_audited_capability_count"] == len(
        CAPABILITY_CONTRACTS
    )
    assert report["required_evidence_kinds"] == list(REQUIRED_EVIDENCE_KINDS)
    assert [item["capability_id"] for item in report["capabilities"]] == sorted(
        CAPABILITY_CONTRACTS
    )
    assert all(item["verified"] is False for item in report["capabilities"])
    assert all(
        item["legacy_structural_audit_verified"] is True
        and item["verified_evidence_kinds"] == []
        and item["structurally_audited_evidence_kinds"]
        == list(REQUIRED_EVIDENCE_KINDS)
        for item in report["capabilities"]
    )
    assert report["scope"] == SCOPE
    assert report["production_promotion_allowed"] is False
    assert report["real_odoo_write_performed"] is False
    assert "secret" not in json.dumps(report).lower()


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda index: index["capabilities"].pop(),
            "capability IDs/order do not match",
        ),
        (
            lambda index: index["capabilities"][0]["evidence"].pop(),
            "evidence kinds/order do not match",
        ),
        (
            lambda index: index["capabilities"].reverse(),
            "capability IDs/order do not match",
        ),
        (
            lambda index: index["capabilities"][0]["evidence"].reverse(),
            "evidence kinds/order do not match",
        ),
    ],
)
def test_read_evidence_index_rejects_inventory_drift(
    tmp_path: Path, mutation, message: str
):
    fixture = _build_bundle(tmp_path)
    mutation(fixture.index)
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match=message):
        _verify(fixture)


def test_read_evidence_index_rejects_release_identity_drift(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.index["release_identity"]["commit"] = "f" * 40
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="release identity"):
        _verify(fixture)


def test_read_evidence_index_rejects_artifact_digest_tampering(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    artifact_path = Path(
        fixture.index["capabilities"][0]["evidence"][0]["artifact_path"]
    )
    artifact_path.write_bytes(b"{}\n")

    with pytest.raises(ReadEvidenceIndexError, match="artifact digest mismatch"):
        _verify(fixture)


def test_read_evidence_index_rejects_empty_artifact_even_when_resigned(
    tmp_path: Path,
):
    fixture = _build_bundle(tmp_path)
    evidence = _entry(fixture, "live_odoo")
    artifact_raw = _write_json(Path(evidence["artifact_path"]), {})
    artifact_sha256 = _sha256(artifact_raw)
    evidence["artifact_sha256"] = artifact_sha256
    old_attestation = _read_json(Path(evidence["attestation_path"]))
    old_attestation["claims"]["artifact_sha256"] = artifact_sha256
    attestation = create_read_evidence_attestation(
        old_attestation["claims"],
        key_id="test-key:live_odoo",
        secret=fixture.attestation_secrets["live_odoo"],
    )
    attestation_raw = _write_json(Path(evidence["attestation_path"]), attestation)
    evidence["attestation_sha256"] = _sha256(attestation_raw)
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="artifact.*fields|artifact.*schema"):
        _verify(fixture)


def test_read_evidence_index_rejects_attestation_signature_tampering(
    tmp_path: Path,
):
    fixture = _build_bundle(tmp_path)
    evidence = fixture.index["capabilities"][0]["evidence"][0]
    attestation_path = Path(evidence["attestation_path"])
    attestation = _read_json(attestation_path)
    attestation["signature"] = "0" * 64
    raw = _write_json(attestation_path, attestation)
    evidence["attestation_sha256"] = _sha256(raw)
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="signature mismatch"):
        _verify(fixture)


def test_read_evidence_index_rejects_cross_purpose_key(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    evidence = fixture.index["capabilities"][0]["evidence"][0]
    attestation_path = Path(evidence["attestation_path"])
    attestation = _read_json(attestation_path)
    wrong_kind = next(
        kind
        for kind in REQUIRED_EVIDENCE_KINDS
        if kind != evidence["evidence_kind"]
    )
    attestation["key_id"] = f"test-key:{wrong_kind}"
    raw = _write_json(attestation_path, attestation)
    evidence["attestation_sha256"] = _sha256(raw)
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="purpose|signature"):
        _verify(fixture)


def test_read_evidence_index_rejects_reused_authority_secret(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.keys["keys"][1]["secret_base64"] = fixture.keys["keys"][0][
        "secret_base64"
    ]
    _rewrite_keys_and_pin(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="secrets must be unique"):
        _verify(fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_name", "other_database"),
        ("database_uuid", "00000000-0000-0000-0000-000000000001"),
        ("company_id", 2),
        ("allowed_company_ids", [1, 2]),
        ("user_id", 7),
        ("principal", "pi:other-user"),
        ("odoo_instance_id", "odoo19@other-host"),
        ("environment", "sandbox"),
        ("capability_channel", "enabled"),
    ],
)
def test_resigned_cross_scope_artifact_is_rejected_by_release_anchor(
    tmp_path: Path, field: str, value: object
):
    fixture = _build_bundle(tmp_path)
    capability_id = sorted(CAPABILITY_CONTRACTS)[0]
    evidence = _entry(fixture, "release_identity", capability_id)
    artifact = _read_json(Path(evidence["artifact_path"]))
    artifact["scope"][field] = value
    _capability(fixture, capability_id)["scope"][field] = value
    if field == "company_id":
        artifact["scope"]["allowed_company_ids"] = [value]
        _capability(fixture, capability_id)["scope"][
            "allowed_company_ids"
        ] = [value]
    _store_artifact(fixture, capability_id, "release_identity", artifact)
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="scope|binding|anchor"):
        _verify(fixture)


def test_release_derived_anchor_rejects_wrong_keys_digest(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.anchor["attestation_keys_sha256"] = "0" * 64
    _rewrite_anchor(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="key.*digest"):
        _verify(fixture)


def test_release_derived_anchor_rejects_noncanonical_keys_path(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    wrong_path = fixture.keys_path.with_name("caller-selected-keys.json")
    _write_private_bytes(wrong_path, fixture.keys_path.read_bytes())
    fixture.anchor["attestation_keys_path"] = str(wrong_path)
    fixture.anchor["attestation_keys_sha256"] = _sha256(wrong_path.read_bytes())
    _rewrite_anchor(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="key path.*release-canonical"):
        _verify(fixture)


def test_release_derived_anchor_rejects_runtime_digest_tampering(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.runtime["receipt_key_id"] = "tampered-receipt-key"
    _write_json(fixture.runtime_path, fixture.runtime)

    with pytest.raises(ReadEvidenceIndexError, match="runtime.*digest"):
        _verify(fixture)


def test_release_derived_anchor_rejects_repinned_runtime_scope_drift(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.runtime["database_uuid"] = "00000000-0000-0000-0000-000000000001"
    runtime_raw = _write_json(fixture.runtime_path, fixture.runtime)
    fixture.anchor["read_runtime_config_sha256"] = _sha256(runtime_raw)
    _rewrite_anchor(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="runtime.*trusted scope"):
        _verify(fixture)


def test_source_bundle_member_tampering_is_rejected(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    member_path = _source_member_path(
        fixture, sorted(CAPABILITY_CONTRACTS)[0], "live_odoo"
    )
    _write_json(member_path, {})

    with pytest.raises(ReadEvidenceIndexError, match="source bundle member.*mismatch"):
        _verify(fixture)


def test_source_bundle_manifest_tampering_is_rejected(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.source_manifest["collector_sha256"] = "f" * 64
    _write_json(fixture.source_manifest_path, fixture.source_manifest)

    with pytest.raises(ReadEvidenceIndexError, match="source bundle manifest digest"):
        _verify(fixture)


def test_source_bundle_manifest_digest_is_rejected_before_tree_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fixture = _build_bundle(tmp_path)
    fixture.source_manifest["collector_sha256"] = "f" * 64
    _write_json(fixture.source_manifest_path, fixture.source_manifest)
    tree_scan = Mock(side_effect=AssertionError("tree scan must not run"))
    monkeypatch.setattr(evidence_index_module, "_source_tree_files", tree_scan)

    with pytest.raises(ReadEvidenceIndexError, match="source bundle manifest digest"):
        _verify(fixture)

    tree_scan.assert_not_called()


def test_source_bundle_aggregate_cache_limit_is_checked_before_tree_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fixture = _build_bundle(tmp_path)
    monkeypatch.setattr(
        evidence_index_module, "_MAX_SOURCE_CACHE_BYTES", 1, raising=False
    )
    tree_scan = Mock(side_effect=AssertionError("tree scan must not run"))
    monkeypatch.setattr(evidence_index_module, "_source_tree_files", tree_scan)

    with pytest.raises(ReadEvidenceIndexError, match="aggregate cache size"):
        _verify(fixture)

    tree_scan.assert_not_called()


@pytest.mark.parametrize(
    "left,right",
    [
        (True, 1),
        (False, 0),
        (1, 1.0),
        ({"value": True}, {"value": 1}),
    ],
)
def test_evidence_value_comparison_preserves_json_types(left, right):
    assert evidence_index_module._canonical_json_equal(left, right) is False


def test_exact_directory_check_stops_after_the_first_excess_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    consumed = 0

    class Entry:
        def __init__(self, name: str):
            self.name = name

    def entries():
        nonlocal consumed
        for index in range(10_000):
            consumed += 1
            yield Entry(f"entry-{index}")

    monkeypatch.setattr(evidence_index_module.os, "scandir", lambda _path: entries())

    with pytest.raises(ReadEvidenceIndexError, match="file set is not exact"):
        evidence_index_module._exact_directory_entries(
            tmp_path, {"expected"}, "bounded directory"
        )

    assert consumed == 2


def test_source_bundle_rejects_unexpected_empty_directory(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    (fixture.source_root / "unexpected-empty").mkdir()

    with pytest.raises(ReadEvidenceIndexError, match="source bundle tree is not exact"):
        _verify(fixture)


def test_source_bundle_rejects_member_changed_after_cache_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fixture = _build_bundle(tmp_path)
    original = evidence_index_module._validate_artifact
    changed = False

    def mutate_after_first_validation(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            member = _source_member_path(
                fixture,
                sorted(CAPABILITY_CONTRACTS)[0],
                REQUIRED_EVIDENCE_KINDS[0],
            )
            member.write_bytes(member.read_bytes() + b" ")
        return result

    monkeypatch.setattr(
        evidence_index_module, "_validate_artifact", mutate_after_first_validation
    )

    with pytest.raises(ReadEvidenceIndexError, match="source bundle changed"):
        _verify(fixture)


def test_source_bundle_rejects_manifest_changed_after_cache_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fixture = _build_bundle(tmp_path)
    original = evidence_index_module._validate_artifact
    changed = False

    def mutate_after_first_validation(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            fixture.source_manifest_path.write_bytes(
                fixture.source_manifest_path.read_bytes() + b" "
            )
        return result

    monkeypatch.setattr(
        evidence_index_module, "_validate_artifact", mutate_after_first_validation
    )

    with pytest.raises(ReadEvidenceIndexError, match="source bundle changed"):
        _verify(fixture)


@pytest.mark.parametrize(
    "kind,mutation",
    [
        ("live_odoo", lambda payload: payload.pop("cases")),
        (
            "accounting_oracle",
            lambda payload: payload["cases"][0].pop("postgresql_witness"),
        ),
        ("security_negative", lambda payload: payload.pop("cases")),
        (
            "release_identity",
            lambda payload: payload.pop("canonical_package_sha256"),
        ),
        ("pi_e2e", lambda payload: payload["cases"][0].pop("receipt")),
    ],
)
def test_each_v2_artifact_kind_rejects_missing_payload_fields(
    tmp_path: Path, kind: str, mutation
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(Path(_entry(fixture, kind)["artifact_path"]))["payload"]
    )
    mutation(payload)
    _replace_payload(fixture, kind, payload)

    with pytest.raises(ReadEvidenceIndexError, match=f"{kind.replace('_', ' ')}|fields|cases"):
        _verify(fixture)


@pytest.mark.parametrize("kind", ["live_odoo", "accounting_oracle", "pi_e2e"])
def test_read_artifact_revalidates_read_receipt_v2(
    tmp_path: Path, kind: str
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(Path(_entry(fixture, kind)["artifact_path"]))["payload"]
    )
    payload["cases"][0]["receipt"]["signature"] = "0" * 64
    _replace_payload(fixture, kind, payload)

    with pytest.raises(ReadEvidenceIndexError, match="receipt.*signature|receipt"):
        _verify(fixture)


def test_receipt_record_count_is_derived_from_result_not_from_receipt(
    tmp_path: Path,
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(Path(_entry(fixture, "live_odoo")["artifact_path"]))[
            "payload"
        ]
    )
    case = payload["cases"][0]
    case["receipt"] = _create_receipt(
        capability_id=sorted(CAPABILITY_CONTRACTS)[0],
        kind="live_odoo",
        parameters=case["parameters"],
        result_body=case["result_body"],
        auth_token_id=case["auth_token_id"],
        record_count=999,
    )
    _replace_payload(fixture, "live_odoo", payload)

    with pytest.raises(ReadEvidenceIndexError, match="record count|record_count"):
        _verify(fixture)


@pytest.mark.parametrize(
    "observed_at",
    [
        COLLECTED_AT - timedelta(minutes=6),
        COLLECTED_AT + timedelta(seconds=1),
    ],
)
def test_receipt_observation_time_is_bound_to_source_collection_window(
    tmp_path: Path, observed_at: datetime
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(Path(_entry(fixture, "live_odoo")["artifact_path"]))[
            "payload"
        ]
    )
    case = payload["cases"][0]
    case["receipt"] = _create_receipt(
        capability_id=sorted(CAPABILITY_CONTRACTS)[0],
        kind="live_odoo",
        parameters=case["parameters"],
        result_body=case["result_body"],
        auth_token_id=case["auth_token_id"],
        observed_at=observed_at,
    )
    _replace_payload(fixture, "live_odoo", payload)

    with pytest.raises(ReadEvidenceIndexError, match="receipt.*time|expired|future"):
        _verify(fixture)


def test_accounting_oracle_requires_exact_odoo_oracle_result_equality(
    tmp_path: Path,
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(
            Path(_entry(fixture, "accounting_oracle")["artifact_path"])
        )["payload"]
    )
    payload["cases"][0]["oracle_result"]["lines"][0]["balance"] = "999.00"
    payload["cases"][0]["postgresql_witness"][
        "oracle_result_sha256"
    ] = _json_sha256(payload["cases"][0]["oracle_result"])
    _replace_payload(fixture, "accounting_oracle", payload)

    with pytest.raises(ReadEvidenceIndexError, match="oracle result"):
        _verify(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda witness: witness.update({"post_state_sha256": "f" * 64}),
        lambda witness: witness.update({"transaction_read_only": False}),
        lambda witness: witness.update({"rolled_back": False}),
        lambda witness: witness.update({"write_statement_count": 1}),
    ],
)
def test_accounting_oracle_requires_unchanged_read_only_witness(
    tmp_path: Path, mutation
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(
            Path(_entry(fixture, "accounting_oracle")["artifact_path"])
        )["payload"]
    )
    mutation(payload["cases"][0]["postgresql_witness"])
    _replace_payload(fixture, "accounting_oracle", payload)

    with pytest.raises(ReadEvidenceIndexError, match="witness.*read-only|witness"):
        _verify(fixture)


def test_security_negative_requires_the_exact_five_cases(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(
            Path(_entry(fixture, "security_negative")["artifact_path"])
        )["payload"]
    )
    payload["cases"] = [
        case for case in payload["cases"] if case["case_id"] != "replay"
    ]
    _replace_payload(fixture, "security_negative", payload)

    with pytest.raises(ReadEvidenceIndexError, match="security negative cases"):
        _verify(fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("odoo_write_count", 1),
        ("postgresql_write_count", 1),
        ("receipt_count", 1),
        ("odoo_effect", "created_record"),
    ],
)
def test_security_negative_rejects_any_write_or_receipt(
    tmp_path: Path, field: str, value: object
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(
            Path(_entry(fixture, "security_negative")["artifact_path"])
        )["payload"]
    )
    payload["cases"][0][field] = value
    _replace_payload(fixture, "security_negative", payload)

    with pytest.raises(ReadEvidenceIndexError, match="side-effect-free rejection"):
        _verify(fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("canonical_package_sha256", "a" * 64),
        ("capability_contract_sha256", "b" * 64),
        ("commit", "f" * 40),
        ("registry_digest", "c" * 64),
        ("release", "0.1.0.dev262-ffffffffffff"),
        ("release_manifest_identity_sha256", "d" * 64),
        ("release_root", str(Path("/wrong/release/root").resolve())),
        ("version", "0.1.0.dev999"),
    ],
)
def test_release_identity_artifact_compares_every_field(
    tmp_path: Path, field: str, value: object
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(
            Path(_entry(fixture, "release_identity")["artifact_path"])
        )["payload"]
    )
    payload[field] = value
    _replace_payload(fixture, "release_identity", payload)

    with pytest.raises(ReadEvidenceIndexError, match="release identity evidence"):
        _verify(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda case: case.update({"selected_capability_id": "acct.unknown.read.v1"}),
        lambda case: case["collected_parameters"].update({"limit": 99}),
        lambda case: case["event_order"].reverse(),
        lambda case: case.update({"assistant_result_sha256": "f" * 64}),
        lambda case: case.update({"audit_receipt_sha256": "e" * 64}),
    ],
)
def test_pi_e2e_rejects_selection_parameter_event_and_result_drift(
    tmp_path: Path, mutation
):
    fixture = _build_bundle(tmp_path)
    payload = deepcopy(
        _read_json(Path(_entry(fixture, "pi_e2e")["artifact_path"]))[
            "payload"
        ]
    )
    mutation(payload["cases"][0])
    _replace_payload(fixture, "pi_e2e", payload)

    with pytest.raises(ReadEvidenceIndexError, match="Pi E2E"):
        _verify(fixture)


def test_read_evidence_index_rejects_noncanonical_json(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    value = _read_json(fixture.index_path)
    fixture.index_path.write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )

    with pytest.raises(ReadEvidenceIndexError, match="canonical JSON"):
        _verify(fixture)


def test_read_evidence_index_rejects_duplicate_json_keys(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.index_path.write_bytes(
        b'{"schema_version":"x","schema_version":"y"}\n'
    )

    with pytest.raises(ReadEvidenceIndexError, match="duplicate JSON key"):
        _verify(fixture)


def test_read_evidence_index_rejects_path_escape(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    fixture.index["capabilities"][0]["evidence"][0]["artifact_path"] = str(
        (tmp_path / "outside.json").resolve()
    )
    _rewrite_index(fixture)

    with pytest.raises(ReadEvidenceIndexError, match="canonical evidence path"):
        _verify(fixture)


def test_read_evidence_index_rejects_unapproved_evidence_parent(tmp_path: Path):
    fixture = _build_bundle(tmp_path)

    with pytest.raises(ReadEvidenceIndexError, match="canonical evidence parent"):
        verify_read_evidence_index(
            fixture.index_path,
            expected_release_identity=IDENTITY,
            expected_capability_contracts=CAPABILITY_CONTRACTS,
            require_root_owner=False,
            evidence_parent=(tmp_path / "different-evidence-parent").resolve(),
            attestation_keys_parent=fixture.attestation_keys_parent,
            evidence_source_parent=fixture.evidence_source_parent,
            trusted_artifact_parent=fixture.trusted_artifact_parent,
        )


def test_read_evidence_index_derives_the_exact_release_anchor_path(tmp_path: Path):
    fixture = _build_bundle(tmp_path)
    moved = fixture.anchor_path.with_name("caller-selected-anchor.json")
    fixture.anchor_path.replace(moved)

    with pytest.raises(ReadEvidenceIndexError, match="trust anchor"):
        _verify(fixture)


@pytest.mark.parametrize(
    "mode,expected",
    [
        (0o400, True),
        (0o600, True),
        (0o440, False),
        (0o444, False),
        (0o640, False),
        (0o644, False),
        (0o660, False),
        (0o666, False),
    ],
)
def test_attestation_key_private_mode_policy(mode: int, expected: bool):
    assert evidence_index_module._private_mode_is_safe(
        stat.S_IFREG | mode
    ) is expected


@pytest.mark.parametrize(
    "mode,directory,expected",
    [
        (0o400, False, True),
        (0o500, True, True),
        (0o600, False, False),
        (0o440, False, False),
        (0o700, True, False),
        (0o550, True, False),
    ],
)
def test_source_bundle_immutable_mode_policy(
    mode: int, directory: bool, expected: bool
):
    assert evidence_index_module._source_mode_is_immutable(
        (stat.S_IFDIR if directory else stat.S_IFREG) | mode,
        directory=directory,
    ) is expected


def test_create_attestation_rejects_weak_secret():
    with pytest.raises(ReadEvidenceIndexError, match="secret"):
        create_read_evidence_attestation({}, key_id="key", secret=b"short")
