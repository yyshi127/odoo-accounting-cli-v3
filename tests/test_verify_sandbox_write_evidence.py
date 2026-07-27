from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_sandbox_write_evidence",
    ROOT / "tools" / "verify_sandbox_write_evidence.py",
)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


KINDS = (
    "accounting_oracle",
    "live_odoo",
    "pi_e2e",
    "recovery",
    "release_identity",
    "sandbox_write_lifecycle",
    "security_negative",
)


def _receipt(kind: str, *, capability_id: str = "acct.invoice.customer_create.v1"):
    return {
        "artifact_sha256": "a" * 64,
        "capability_id": capability_id,
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "id": f"receipt-{kind}",
        "kind": kind,
        "registry_sha256": "b" * 64,
        "release_sha256": "c" * 64,
        "signature": "d" * 64,
        "verified_at": "2026-07-27T00:00:00Z",
    }


def _document():
    return {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-evidence.v1",
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "production_promotion_allowed": False,
        "release_identity": {
            "commit": "abc123",
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev160-abc123",
        },
        "lifecycle": {
            "approval_digest": "1" * 64,
            "execution_receipt_id": "execution-receipt",
            "failure_case_digest": "2" * 64,
            "final_audit_receipt_id": "audit-receipt",
            "idempotency_replay_digest": "3" * 64,
            "odoo_record_receipt_id": "odoo-record-receipt",
            "parameter_roundtrip_sha256": "4" * 64,
            "pi_e2e_digest": "5" * 64,
            "prepare_receipt_id": "prepare-receipt",
            "preview_digest": "6" * 64,
            "recovery_case_digest": "7" * 64,
            "security_negative_digest": "8" * 64,
            "verification_receipt_id": "verification-receipt",
        },
        "registry_receipts": [_receipt(kind) for kind in KINDS],
    }


def test_complete_sandbox_write_evidence_is_accepted():
    result = verifier.verify_document(_document())

    assert result == {
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "production_promotion_allowed": False,
        "registry_digest": "b" * 64,
        "registry_receipt_count": 7,
        "release_sha256": "c" * 64,
        "verified": True,
    }


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda document: document.__setitem__(
                "production_promotion_allowed", True
            ),
            "must not authorize production",
        ),
        (
            lambda document: document["registry_receipts"].pop(),
            "registry evidence kinds are incomplete",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "capability_id", "acct.bill.vendor_create.v1"
            ),
            "capability_id mismatch",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "registry_sha256", "f" * 64
            ),
            "registry_sha256 mismatch",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "release_sha256", "f" * 64
            ),
            "release_sha256 mismatch",
        ),
        (
            lambda document: document["lifecycle"].pop("recovery_case_digest"),
            "lifecycle fields are invalid",
        ),
    ),
)
def test_sandbox_write_evidence_rejects_non_promotable_bundles(mutate, match):
    document = copy.deepcopy(_document())
    mutate(document)

    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.verify_document(document)


def test_cli_returns_nonzero_for_invalid_evidence(tmp_path, capsys):
    path = tmp_path / "evidence.json"
    path.write_text('{"schema_version":1}', encoding="utf-8")

    assert verifier.main([str(path)]) == 1
    assert "evidence fields are invalid" in capsys.readouterr().err
