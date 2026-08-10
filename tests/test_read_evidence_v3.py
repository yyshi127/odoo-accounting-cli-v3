from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import odoo_accounting_cli_v3.read_evidence_v3 as v3


IDENTITY = {
    "commit": "1" * 40,
    "manifest_sha256": "2" * 64,
    "package_sha256": "3" * 64,
    "registry_digest": "4" * 64,
    "release": "odoo-accounting-cli-v3-0.1.0.dev263-111111111111",
    "verified": True,
    "version": "0.1.0.dev263",
}
CONTRACTS = {
    "acct.ar.open_items.v1": "5" * 64,
    "acct.gl.trial_balance.v1": "6" * 64,
}
RUN_ID = "run-20260803-000001"
NOW = datetime(2026, 8, 3, 8, 0, 0, tzinfo=timezone.utc)
PI_EVENT_ORDER = [
    "user_input",
    "capability_selected",
    "clarification_completed",
    "material_parameters_finalized",
    "cli_input",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
]
SECURITY_CASES = {
    "acl_deny": "odoo_acl_denied",
    "cross_company": "company_binding_rejected",
    "expired": "authentication_expired",
    "replay": "authentication_replayed",
    "tamper_parameters": "authentication_tampered",
}


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_ref(root: Path, relative: str) -> dict[str, object]:
    raw = (root / relative).read_bytes()
    return {"path": relative, "sha256": _digest(raw), "size": len(raw)}


def _signed_ref(root: Path, relative: str, role: str) -> dict[str, object]:
    signature = relative + ".sshsig"
    return {
        **_file_ref(root, relative),
        "role": role,
        "signature_path": signature,
        "signature_sha256": _digest((root / signature).read_bytes()),
        "signature_size": (root / signature).stat().st_size,
    }


def _tree_digest(entries: list[dict[str, object]]) -> str:
    normalized = sorted(entries, key=lambda item: str(item["path"]))
    return _digest(_canonical(normalized))


def _raw_case(kind: str, capability_id: str, contract: str) -> dict[str, object]:
    seed = _digest(f"{kind}:{capability_id}".encode())
    if kind == "accounting_oracle":
        return {
            "actual_sha256": seed,
            "difference_count": 0,
            "expected_sha256": seed,
            "input_sha256": _digest(f"input:{capability_id}".encode()),
            "row_count": 1,
        }
    if kind == "live_odoo":
        return {
            "company_id": 1,
            "database_uuid": "11111111-2222-4333-8444-555555555555",
            "odoo_model": "account.move.line",
            "odoo_write_count": 0,
            "read_only": True,
            "receipt_sha256": _digest(f"receipt:{capability_id}".encode()),
            "record_count": 1,
            "request_sha256": _digest(f"request:{capability_id}".encode()),
            "response_sha256": seed,
        }
    if kind == "pi_e2e":
        return {
            "audit_receipt_sha256": _digest(f"audit:{capability_id}".encode()),
            "cli_parameters_sha256": _digest(f"parameters:{capability_id}".encode()),
            "event_order": PI_EVENT_ORDER,
            "natural_language_sha256": _digest(f"nl:{capability_id}".encode()),
            "odoo_result_sha256": seed,
            "selected_capability_id": capability_id,
        }
    if kind == "release_identity":
        return {
            "capability_contract_sha256": contract,
            "observed_release_identity": deepcopy(IDENTITY),
        }
    if kind == "security_negative":
        return {
            "cases": [
                {
                    "case_id": case_id,
                    "expected_error_code": expected,
                    "observed_error_code": expected,
                    "odoo_write_count": 0,
                    "postgresql_write_count": 0,
                    "receipt_count": 0,
                }
                for case_id, expected in SECURITY_CASES.items()
            ]
        }
    raise AssertionError(kind)


def _raw_document(
    kind: str,
    *,
    scope_sha256: str,
) -> dict[str, object]:
    return {
        "capabilities": [
            {
                "capability_contract_sha256": contract,
                "capability_id": capability_id,
                "case": _raw_case(kind, capability_id, contract),
            }
            for capability_id, contract in sorted(CONTRACTS.items())
        ],
        "evidence_kind": kind,
        "release_identity": deepcopy(IDENTITY),
        "run_id": RUN_ID,
        "schema_version": v3.RAW_EVIDENCE_SCHEMA,
        "scope_sha256": scope_sha256,
    }


def _semantic_summary(raw: dict[str, object]) -> dict[str, object]:
    capabilities = raw["capabilities"]
    assert isinstance(capabilities, list)
    return {
        "capabilities": [
            {
                "capability_contract_sha256": item["capability_contract_sha256"],
                "capability_id": item["capability_id"],
                "case_sha256": _digest(_canonical(item["case"])),
            }
            for item in capabilities
        ],
        "evidence_kind": raw["evidence_kind"],
    }


class EvidenceFixture:
    def __init__(self, tmp_path: Path) -> None:
        self.release = IDENTITY["release"]
        self.release_root = tmp_path / "releases" / self.release
        self.trust_root = tmp_path / "trust" / self.release
        self.runs_root = tmp_path / "evidence" / self.release / "runs"
        self.run_root = self.runs_root / RUN_ID
        self.active_record_path = tmp_path / "evidence" / self.release / "active.json"
        self.admission_store_path = (
            tmp_path / "evidence" / self.release / "admissions.sqlite3"
        )
        self.anchor_path = (
            tmp_path / "trusted-artifacts" / f"{self.release}.read-evidence-v3.json"
        )
        self.ssh_keygen = tmp_path / "bin" / "ssh-keygen"
        self.context = v3._ExecutionContext(
            active_record_path=self.active_record_path,
            admission_store_path=self.admission_store_path,
            evidence_runs_root=self.runs_root,
            identity=deepcopy(IDENTITY),
            read_capability_contracts=deepcopy(CONTRACTS),
            release_root=self.release_root,
            trust_anchor_path=self.anchor_path,
            trust_root=self.trust_root,
            ssh_keygen_path=self.ssh_keygen,
        )
        self.fingerprints = {
            role: hashlib.sha256(f"public-key:{role}".encode()).hexdigest()
            for role in v3.ROLE_BINDINGS
        }
        self._create()

    @property
    def index_path(self) -> Path:
        return self.run_root / v3.INDEX_FILENAME

    @property
    def admission_path(self) -> Path:
        return self.run_root / v3.ADMISSION_FILENAME

    def write_json(self, relative: str, value: object) -> None:
        path = self.run_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical(value))

    def sign(self, relative: str, role: str) -> None:
        path = self.run_root / f"{relative}.sshsig"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"detached-sshsig:{role}:{relative}\n".encode())

    def _create(self) -> None:
        self.release_root.mkdir(parents=True)
        self.trust_root.joinpath("roles").mkdir(parents=True)
        self.runs_root.mkdir(parents=True)
        self.anchor_path.parent.mkdir(parents=True)
        self.ssh_keygen.parent.mkdir(parents=True)
        self.ssh_keygen.write_bytes(b"test ssh-keygen executable\n")
        revocations = self.trust_root / v3.REVOCATIONS_FILENAME
        revocations.write_bytes(b"# no revoked keys\n")
        roles: dict[str, object] = {}
        for role in v3.ROLE_BINDINGS:
            allowed = self.trust_root / "roles" / v3._role_filename(role)
            allowed.write_bytes(f"allowed:{role}\n".encode())
            roles[role] = {
                "allowed_signers_sha256": _digest(allowed.read_bytes()),
                "public_key_sha256": self.fingerprints[role],
            }
        anchor = {
            "release_identity": deepcopy(IDENTITY),
            "revocations_sha256": _digest(revocations.read_bytes()),
            "roles": roles,
            "schema_version": v3.TRUST_ANCHOR_SCHEMA,
            "ssh_keygen_sha256": _digest(self.ssh_keygen.read_bytes()),
        }
        self.anchor_path.write_bytes(_canonical(anchor))

        scope = {
            "capability_contracts": deepcopy(CONTRACTS),
            "company_ids": [1],
            "database_name": "odoo_sandbox",
            "database_uuid": "11111111-2222-4333-8444-555555555555",
            "environment": "sandbox",
            "release_identity": deepcopy(IDENTITY),
            "run_id": RUN_ID,
            "schema_version": v3.SCOPE_SCHEMA,
        }
        self.write_json(v3.SCOPE_FILENAME, scope)
        self.sign(v3.SCOPE_FILENAME, "scope")
        scope_sha256 = _digest((self.run_root / v3.SCOPE_FILENAME).read_bytes())

        authorization = {
            "authorization_id": "auth-20260803-000001",
            "collector_role": "collector",
            "expires_at": "2026-08-03T09:00:00Z",
            "nonce_sha256": "7" * 64,
            "not_before": "2026-08-03T07:00:00Z",
            "release_identity": deepcopy(IDENTITY),
            "run_id": RUN_ID,
            "schema_version": v3.AUTHORIZATION_SCHEMA,
            "scope_sha256": scope_sha256,
            "verifier_roles": {
                kind: f"verifier.{kind}" for kind in v3.EVIDENCE_KINDS
            },
        }
        self.write_json(v3.AUTHORIZATION_FILENAME, authorization)
        self.sign(v3.AUTHORIZATION_FILENAME, "authorization")
        authorization_sha256 = _digest(
            (self.run_root / v3.AUTHORIZATION_FILENAME).read_bytes()
        )

        raw_paths = [f"raw/{kind}.json" for kind in v3.EVIDENCE_KINDS]
        plan = {
            "authorization_sha256": authorization_sha256,
            "expected_raw_paths": raw_paths,
            "release_identity": deepcopy(IDENTITY),
            "run_id": RUN_ID,
            "schema_version": v3.COLLECTION_PLAN_SCHEMA,
            "scope_sha256": scope_sha256,
        }
        self.write_json(v3.COLLECTION_PLAN_FILENAME, plan)
        self.sign(v3.COLLECTION_PLAN_FILENAME, "collector")
        plan_sha256 = _digest(
            (self.run_root / v3.COLLECTION_PLAN_FILENAME).read_bytes()
        )

        raw_refs: list[dict[str, object]] = []
        for kind, raw_path in zip(v3.EVIDENCE_KINDS, raw_paths, strict=True):
            self.write_json(raw_path, _raw_document(kind, scope_sha256=scope_sha256))
            raw_refs.append(_file_ref(self.run_root, raw_path))
        raw_manifest = {
            "authorization_sha256": authorization_sha256,
            "collection_plan_sha256": plan_sha256,
            "files": raw_refs,
            "release_identity": deepcopy(IDENTITY),
            "run_id": RUN_ID,
            "schema_version": v3.RAW_MANIFEST_SCHEMA,
            "scope_sha256": scope_sha256,
        }
        self.write_json(v3.RAW_MANIFEST_FILENAME, raw_manifest)
        self.sign(v3.RAW_MANIFEST_FILENAME, "collector")
        raw_manifest_sha256 = _digest(
            (self.run_root / v3.RAW_MANIFEST_FILENAME).read_bytes()
        )

        verifier_refs: list[dict[str, object]] = []
        for kind, raw_ref in zip(v3.EVIDENCE_KINDS, raw_refs, strict=True):
            report_path = f"verifiers/{kind}.json"
            raw_document = json.loads(
                (self.run_root / str(raw_ref["path"])).read_text("utf-8")
            )
            report = {
                "authorization_sha256": authorization_sha256,
                "collection_plan_sha256": plan_sha256,
                "evidence_kind": kind,
                "raw_manifest_sha256": raw_manifest_sha256,
                "raw_path": raw_ref["path"],
                "raw_sha256": raw_ref["sha256"],
                "raw_size": raw_ref["size"],
                "release_identity": deepcopy(IDENTITY),
                "run_id": RUN_ID,
                "schema_version": v3.VERIFIER_REPORT_SCHEMA,
                "scope_sha256": scope_sha256,
                "verification_summary": _semantic_summary(raw_document),
            }
            self.write_json(report_path, report)
            role = f"verifier.{kind}"
            self.sign(report_path, role)
            verifier_refs.append(
                {"evidence_kind": kind, **_signed_ref(self.run_root, report_path, role)}
            )

        pre_admission_paths = sorted(
            {
                v3.SCOPE_FILENAME,
                f"{v3.SCOPE_FILENAME}.sshsig",
                v3.AUTHORIZATION_FILENAME,
                f"{v3.AUTHORIZATION_FILENAME}.sshsig",
                v3.COLLECTION_PLAN_FILENAME,
                f"{v3.COLLECTION_PLAN_FILENAME}.sshsig",
                v3.RAW_MANIFEST_FILENAME,
                f"{v3.RAW_MANIFEST_FILENAME}.sshsig",
                v3.INDEX_FILENAME,
                f"{v3.INDEX_FILENAME}.sshsig",
                *raw_paths,
                *(
                    path
                    for kind in v3.EVIDENCE_KINDS
                    for path in (
                        f"verifiers/{kind}.json",
                        f"verifiers/{kind}.json.sshsig",
                    )
                ),
            }
        )
        index = {
            "admission_path": v3.ADMISSION_FILENAME,
            "authorization": _signed_ref(
                self.run_root, v3.AUTHORIZATION_FILENAME, "authorization"
            ),
            "collection_plan": _signed_ref(
                self.run_root, v3.COLLECTION_PLAN_FILENAME, "collector"
            ),
            "closure_paths": pre_admission_paths,
            "raw_manifest": _signed_ref(
                self.run_root, v3.RAW_MANIFEST_FILENAME, "collector"
            ),
            "release_identity": deepcopy(IDENTITY),
            "run_id": RUN_ID,
            "schema_version": v3.EVIDENCE_INDEX_SCHEMA,
            "scope": _signed_ref(self.run_root, v3.SCOPE_FILENAME, "scope"),
            "verifier_reports": verifier_refs,
        }
        self.write_json(v3.INDEX_FILENAME, index)
        self.sign(v3.INDEX_FILENAME, "collector")

        pre_admission = []
        for path in sorted(self.run_root.rglob("*")):
            if path.is_file():
                pre_admission.append(_file_ref(self.run_root, path.relative_to(self.run_root).as_posix()))
        admission = {
            "admitted_at": "2026-08-03T08:00:00Z",
            "authorization_id": authorization["authorization_id"],
            "authorization_sha256": authorization_sha256,
            "closure_file_count": len(pre_admission),
            "closure_total_bytes": sum(int(item["size"]) for item in pre_admission),
            "closure_tree_sha256": _tree_digest(pre_admission),
            "index_path": v3.INDEX_FILENAME,
            "index_sha256": _digest(self.index_path.read_bytes()),
            "index_signature_path": f"{v3.INDEX_FILENAME}.sshsig",
            "index_signature_sha256": _digest(
                (self.run_root / f"{v3.INDEX_FILENAME}.sshsig").read_bytes()
            ),
            "index_signature_size": (
                self.run_root / f"{v3.INDEX_FILENAME}.sshsig"
            ).stat().st_size,
            "index_size": self.index_path.stat().st_size,
            "nonce_sha256": authorization["nonce_sha256"],
            "release_identity": {
                field: IDENTITY[field]
                for field in v3.ADMISSION_RELEASE_IDENTITY_FIELDS
            },
            "run_id": RUN_ID,
            "schema_version": v3.ACTIVE_ADMISSION_SCHEMA,
            "scope_sha256": scope_sha256,
            "sequence": 1,
        }
        self.write_json(v3.ADMISSION_FILENAME, admission)
        self.sign(v3.ADMISSION_FILENAME, "admission")
        active_record = {
            "admission_sha256": _digest(self.admission_path.read_bytes()),
            "index_sha256": _digest(self.index_path.read_bytes()),
            "payload_sha256": _digest(self.admission_path.read_bytes()),
            "release_identity": {
                field: IDENTITY[field]
                for field in v3.ADMISSION_RELEASE_IDENTITY_FIELDS
            },
            "run_id": RUN_ID,
            "schema_version": v3.ACTIVE_RECORD_SCHEMA,
            "sequence": 1,
        }
        self.active_record_path.parent.mkdir(parents=True, exist_ok=True)
        self.active_record_path.write_bytes(_canonical(active_record))

    def fake_sshsig(self, message: bytes, **kwargs: object) -> dict[str, object]:
        principal = str(kwargs["principal"])
        namespace = str(kwargs["namespace"])
        role = next(
            role
            for role, binding in v3.ROLE_BINDINGS.items()
            if binding.principal == principal and binding.namespace == namespace
        )
        return {
            "algorithm": "ssh-ed25519-sshsig",
            "allowed_signers_sha256": kwargs["allowed_signers_sha256"],
            "message_sha256": _digest(message),
            "namespace": namespace,
            "principal": principal,
            "public_key_sha256": self.fingerprints[role],
            "revocations_sha256": kwargs["revocations_sha256"],
            "signature_sha256": kwargs["signature_sha256"],
            "ssh_keygen_sha256": kwargs["ssh_keygen_sha256"],
            "verification_boundary": "posix-root-managed-pinned-fd",
            "verified": True,
        }

    def refresh_after_raw_change(
        self,
        kind: str,
        *,
        refresh_verifier_summary: bool,
    ) -> None:
        raw_manifest = json.loads(
            (self.run_root / v3.RAW_MANIFEST_FILENAME).read_text("utf-8")
        )
        raw_manifest["files"] = [
            _file_ref(self.run_root, f"raw/{evidence_kind}.json")
            for evidence_kind in v3.EVIDENCE_KINDS
        ]
        self.write_json(v3.RAW_MANIFEST_FILENAME, raw_manifest)
        self.sign(v3.RAW_MANIFEST_FILENAME, "collector")
        raw_manifest_sha256 = _digest(
            (self.run_root / v3.RAW_MANIFEST_FILENAME).read_bytes()
        )

        for evidence_kind in v3.EVIDENCE_KINDS:
            report_path = f"verifiers/{evidence_kind}.json"
            raw_path = f"raw/{evidence_kind}.json"
            report = json.loads((self.run_root / report_path).read_text("utf-8"))
            raw_ref = _file_ref(self.run_root, raw_path)
            report["raw_manifest_sha256"] = raw_manifest_sha256
            report["raw_sha256"] = raw_ref["sha256"]
            report["raw_size"] = raw_ref["size"]
            if evidence_kind == kind and refresh_verifier_summary:
                report["verification_summary"] = _semantic_summary(
                    json.loads((self.run_root / raw_path).read_text("utf-8"))
                )
            self.write_json(report_path, report)
            self.sign(report_path, f"verifier.{evidence_kind}")

        self.refresh_index_admission_and_active()

    def refresh_index_admission_and_active(self) -> None:
        """Refresh fixture bindings after a signed pre-admission member changes."""

        index = json.loads(self.index_path.read_text("utf-8"))
        index["raw_manifest"] = _signed_ref(
            self.run_root, v3.RAW_MANIFEST_FILENAME, "collector"
        )
        index["verifier_reports"] = [
            {
                "evidence_kind": evidence_kind,
                **_signed_ref(
                    self.run_root,
                    f"verifiers/{evidence_kind}.json",
                    f"verifier.{evidence_kind}",
                ),
            }
            for evidence_kind in v3.EVIDENCE_KINDS
        ]
        self.write_json(v3.INDEX_FILENAME, index)
        self.sign(v3.INDEX_FILENAME, "collector")

        pre_admission = [
            _file_ref(self.run_root, path.relative_to(self.run_root).as_posix())
            for path in sorted(self.run_root.rglob("*"))
            if path.is_file()
            and path.name not in {
                v3.ADMISSION_FILENAME,
                f"{v3.ADMISSION_FILENAME}.sshsig",
            }
        ]
        admission = json.loads(self.admission_path.read_text("utf-8"))
        admission.update(
            {
                "closure_file_count": len(pre_admission),
                "closure_total_bytes": sum(int(item["size"]) for item in pre_admission),
                "closure_tree_sha256": _tree_digest(pre_admission),
                "index_sha256": _digest(self.index_path.read_bytes()),
                "index_signature_sha256": _digest(
                    (self.run_root / f"{v3.INDEX_FILENAME}.sshsig").read_bytes()
                ),
                "index_signature_size": (
                    self.run_root / f"{v3.INDEX_FILENAME}.sshsig"
                ).stat().st_size,
                "index_size": self.index_path.stat().st_size,
            }
        )
        self.write_json(v3.ADMISSION_FILENAME, admission)
        self.sign(v3.ADMISSION_FILENAME, "admission")
        active = json.loads(self.active_record_path.read_text("utf-8"))
        active.update(
            {
                "admission_sha256": _digest(self.admission_path.read_bytes()),
                "index_sha256": _digest(self.index_path.read_bytes()),
                "payload_sha256": _digest(self.admission_path.read_bytes()),
            }
        )
        self.active_record_path.write_bytes(_canonical(active))


@pytest.fixture
def evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EvidenceFixture:
    fixture = EvidenceFixture(tmp_path)
    monkeypatch.setattr(v3, "_require_linux_boundary", lambda: None)
    monkeypatch.setattr(v3, "_load_execution_context", lambda: fixture.context)
    monkeypatch.setattr(v3, "_validate_posix_path", lambda _path, *, directory: None)
    monkeypatch.setattr(v3, "verify_sshsig", fixture.fake_sshsig)
    monkeypatch.setattr(v3, "_utc_now", lambda: NOW)
    monkeypatch.setattr(
        v3,
        "_lookup_published_admission",
        lambda _context, *, authorization_id, payload_sha256, sequence,
        admission_signature_sha256: {
            "authorization_id": authorization_id,
            "payload_sha256": payload_sha256,
            "publication_state": "PUBLISHED",
            "published_at": "2026-08-03T08:00:00Z",
            "sequence": sequence,
            "admission_signature_path": f"{v3.ADMISSION_FILENAME}.sshsig",
            "admission_signature_sha256": admission_signature_sha256,
            "admission_signature_size": (
                fixture.run_root / f"{v3.ADMISSION_FILENAME}.sshsig"
            ).stat().st_size,
        },
    )
    return fixture


def _verify(fixture: EvidenceFixture, **changes: object) -> dict[str, Any]:
    arguments: dict[str, object] = {
        "expected_release_identity": IDENTITY,
    }
    arguments.update(changes)
    return v3.verify_read_evidence_v3(fixture.index_path, **arguments)


def _copied_index(fixture: EvidenceFixture, tmp_path: Path) -> Path:
    retained = (
        tmp_path
        / "final-bundle"
        / "read-evidence-v3"
        / fixture.release
        / RUN_ID
    )
    shutil.copytree(fixture.run_root, retained)
    return retained / v3.INDEX_FILENAME


def test_role_bindings_are_fixed_unique_and_cover_nine_keys() -> None:
    expected = {
        "admission",
        "authorization",
        "collector",
        "scope",
        *(f"verifier.{kind}" for kind in v3.EVIDENCE_KINDS),
    }
    assert set(v3.ROLE_BINDINGS) == expected
    assert len(v3.ROLE_BINDINGS) == 9
    assert len({binding.principal for binding in v3.ROLE_BINDINGS.values()}) == 9
    assert len({binding.namespace for binding in v3.ROLE_BINDINGS.values()}) == 9
    assert all(binding.principal.startswith("odoo-read-evidence-v3-") for binding in v3.ROLE_BINDINGS.values())
    assert all(binding.namespace.startswith("odoo-accounting-cli-v3/read-evidence-v3/") for binding in v3.ROLE_BINDINGS.values())


def test_public_verifier_exposes_no_trust_key_clock_or_owner_bypass() -> None:
    parameters = inspect.signature(v3.verify_read_evidence_v3).parameters
    assert set(parameters) == {
        "index_path",
        "expected_release_identity",
    }
    forbidden = (
        "trust", "key", "private", "secret", "clock", "now", "owner", "root",
        "mode", "sealed",
    )
    assert not any(token in name for name in parameters for token in forbidden)

    with pytest.raises(TypeError):
        v3.verify_read_evidence_v3(  # type: ignore[call-arg]
            Path("/tmp/index.json"),
            expected_release_identity=IDENTITY,
            trust_root=Path("/tmp/attacker"),
        )

    with pytest.raises(TypeError):
        v3.verify_read_evidence_v3(  # type: ignore[call-arg]
            Path("/tmp/index.json"),
            expected_release_identity=IDENTITY,
            expected_capability_contracts={
                "acct.ar.open_items.v1": CONTRACTS["acct.ar.open_items.v1"]
            },
        )

    for forbidden_mode in ("active", "sealed", "debug"):
        with pytest.raises(TypeError):
            v3.verify_read_evidence_v3(  # type: ignore[call-arg]
                Path("/tmp/index.json"),
                expected_release_identity=IDENTITY,
                mode=forbidden_mode,
            )


def test_non_linux_fails_before_context_or_file_use(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v3, "_is_supported_linux", lambda: False)
    monkeypatch.setattr(
        v3,
        "_load_execution_context",
        lambda: pytest.fail("context must not be loaded"),
    )
    with pytest.raises(v3.ReadEvidenceV3Error, match="Linux"):
        v3.verify_read_evidence_v3(
            Path("/tmp/index.json"),
            expected_release_identity=IDENTITY,
        )


def test_minimal_complete_fixture_verifies_and_reports_copyable_closure(
    evidence: EvidenceFixture,
) -> None:
    report = _verify(evidence)

    assert report["cryptographic_closure_verified"] is True
    assert report["semantic_evidence_level"] == "normalized_contract_only"
    assert report["external_read_evidence_verified"] is False
    assert report["goal_evidence_admissible"] is False
    assert report["blockers"] == [v3.RAW_SOURCE_ADAPTER_BLOCKER]
    assert report["evidence_protocol"] == "sshsig-v3"
    assert report["index_kind"] == v3.EVIDENCE_INDEX_SCHEMA
    assert report["mode"] == "active"
    assert report["release_identity"] == IDENTITY
    assert report["index_path"] == str(evidence.index_path)
    assert report["admission_path"] == str(evidence.admission_path)
    assert report["index_sha256"] == _digest(evidence.index_path.read_bytes())
    assert report["admission_sha256"] == _digest(evidence.admission_path.read_bytes())
    assert report["file_count"] == len(report["closure_files"])
    assert report["total_bytes"] == sum(item["size"] for item in report["closure_files"])
    assert [item["path"] for item in report["closure_files"]] == sorted(
        item["path"] for item in report["closure_files"]
    )
    assert report["closure_tree_sha256"] == _tree_digest(report["closure_files"])
    assert report["verified_evidence_kinds"] == []
    assert report["cryptographically_verified_evidence_kinds"] == list(
        v3.EVIDENCE_KINDS
    )
    assert [item["capability_id"] for item in report["capabilities"]] == sorted(
        CONTRACTS
    )
    assert all(
        item["verified"] is False
        and item["verified_evidence_kinds"] == []
        and item["signed_evidence_kinds"] == list(v3.EVIDENCE_KINDS)
        for item in report["capabilities"]
    )
    assert report["production_promotion_allowed"] is False
    assert report["real_odoo_write_performed"] is False


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"a":1,"a":2}\n', "duplicate JSON key"),
        (b'{"a":NaN}\n', "non-finite"),
        (b'{ "a":1}\n', "canonical JSON"),
        (b'[]\n', "JSON object"),
    ],
)
def test_strict_json_rejects_duplicate_nan_noncanonical_and_non_object(
    raw: bytes, message: str
) -> None:
    with pytest.raises(v3.ReadEvidenceV3Error, match=message):
        v3._strict_json_object(raw, "fixture")


def test_json_depth_node_string_and_file_size_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    deep: object = 0
    for _ in range(v3.MAX_JSON_DEPTH + 1):
        deep = [deep]
    with pytest.raises(v3.ReadEvidenceV3Error, match="depth"):
        v3._check_json_complexity(deep)

    monkeypatch.setattr(v3, "MAX_JSON_NODES", 3)
    with pytest.raises(v3.ReadEvidenceV3Error, match="node"):
        v3._check_json_complexity({"a": [1, 2]})

    monkeypatch.setattr(v3, "MAX_JSON_STRING_BYTES", 3)
    with pytest.raises(v3.ReadEvidenceV3Error, match="string"):
        v3._check_json_complexity({"a": "four"})

    with pytest.raises(v3.ReadEvidenceV3Error, match="size limit"):
        v3._read_bounded_fd(-1, maximum=0, label="fixture")


def test_expected_identity_and_contracts_are_exact_assertions_before_evidence(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        v3,
        "_open_snapshot",
        lambda *_args, **_kwargs: pytest.fail("evidence must not be opened"),
    )
    mismatched = deepcopy(IDENTITY)
    mismatched["commit"] = "f" * 40
    with pytest.raises(v3.ReadEvidenceV3Error, match="executing release"):
        _verify(evidence, expected_release_identity=mismatched)


def test_anchor_requires_nine_unique_key_fingerprints(evidence: EvidenceFixture) -> None:
    anchor = json.loads(evidence.anchor_path.read_text("utf-8"))
    anchor["roles"]["scope"]["public_key_sha256"] = anchor["roles"]["collector"]["public_key_sha256"]
    evidence.anchor_path.write_bytes(_canonical(anchor))
    with pytest.raises(v3.ReadEvidenceV3Error, match="fingerprints must be unique"):
        _verify(evidence)


def test_anchor_cannot_redirect_role_or_runtime_trust_paths(
    evidence: EvidenceFixture,
) -> None:
    anchor = json.loads(evidence.anchor_path.read_text("utf-8"))
    anchor["roles"]["scope"]["allowed_signers_path"] = "/tmp/attacker"
    evidence.anchor_path.write_bytes(_canonical(anchor))
    with pytest.raises(v3.ReadEvidenceV3Error, match="fields"):
        _verify(evidence)


def test_reference_path_traversal_is_rejected(evidence: EvidenceFixture) -> None:
    index = json.loads(evidence.index_path.read_text("utf-8"))
    index["scope"]["path"] = "../scope.json"
    evidence.index_path.write_bytes(_canonical(index))
    with pytest.raises(v3.ReadEvidenceV3Error, match="relative path"):
        _verify(evidence)


@pytest.mark.parametrize("field", ["sha256", "size", "signature_sha256", "signature_size"])
def test_reference_hash_and_size_closure_is_exact(
    evidence: EvidenceFixture, field: str
) -> None:
    index = json.loads(evidence.index_path.read_text("utf-8"))
    index["scope"][field] = "f" * 64 if "sha256" in field else 1
    evidence.index_path.write_bytes(_canonical(index))
    with pytest.raises(v3.ReadEvidenceV3Error, match="mismatch"):
        _verify(evidence)


def test_tree_rejects_unreferenced_extra_file(evidence: EvidenceFixture) -> None:
    (evidence.run_root / "unreferenced.txt").write_bytes(b"extra")
    with pytest.raises(v3.ReadEvidenceV3Error, match="file set is not exact"):
        _verify(evidence)


def test_single_link_snapshot_rejects_hardlinks(
    evidence: EvidenceFixture, tmp_path: Path
) -> None:
    alias = tmp_path / "scope-hardlink"
    try:
        os.link(evidence.run_root / v3.SCOPE_FILENAME, alias)
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(v3.ReadEvidenceV3Error, match="single-link"):
        _verify(evidence)


def test_snapshot_rejects_symlink_member(evidence: EvidenceFixture, tmp_path: Path) -> None:
    raw_path = evidence.run_root / f"raw/{v3.EVIDENCE_KINDS[0]}.json"
    parked = tmp_path / "parked-raw.json"
    raw_path.replace(parked)
    try:
        raw_path.symlink_to(parked)
    except OSError:
        parked.replace(raw_path)
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(v3.ReadEvidenceV3Error, match="non-link"):
        _verify(evidence)


def test_capability_contract_set_and_digest_are_exact(evidence: EvidenceFixture) -> None:
    changed_digest = deepcopy(CONTRACTS)
    changed_digest["acct.gl.trial_balance.v1"] = "f" * 64
    for changed in (
        {"acct.ar.open_items.v1": CONTRACTS["acct.ar.open_items.v1"]},
        changed_digest,
    ):
        evidence.context.read_capability_contracts.clear()
        evidence.context.read_capability_contracts.update(changed)
        with pytest.raises(v3.ReadEvidenceV3Error, match="capability contracts"):
            _verify(evidence)


def test_scope_malformed_types_return_structured_rejections(
    evidence: EvidenceFixture,
) -> None:
    scope = json.loads((evidence.run_root / v3.SCOPE_FILENAME).read_text("utf-8"))
    cases = (
        ("company_ids", [1, []], "company_ids"),
        ("database_uuid", None, "database_uuid"),
        ("environment", [], "environment"),
    )

    for field, malformed, message in cases:
        candidate = deepcopy(scope)
        candidate[field] = malformed
        with pytest.raises(v3.ReadEvidenceV3Error, match=message):
            v3._validate_scope(
                candidate,
                identity=IDENTITY,
                contracts=CONTRACTS,
                run_id=RUN_ID,
            )


def test_verifier_roles_and_kind_order_are_fixed(evidence: EvidenceFixture) -> None:
    index = json.loads(evidence.index_path.read_text("utf-8"))
    index["verifier_reports"] = list(reversed(index["verifier_reports"]))
    evidence.index_path.write_bytes(_canonical(index))
    with pytest.raises(v3.ReadEvidenceV3Error, match="verifier evidence kinds/order"):
        _verify(evidence)


def test_detached_signature_rejection_is_fail_closed(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise v3.SSHSigError("bad signature")

    monkeypatch.setattr(v3, "verify_sshsig", reject)
    with pytest.raises(v3.ReadEvidenceV3Error, match="SSHSIG"):
        _verify(evidence)


@pytest.mark.parametrize(
    "admitted_at",
    ["2026-08-03T09:00:00Z", "2026-08-03T10:00:00Z"],
)
def test_admitted_at_must_be_inside_half_open_authorization_window(
    evidence: EvidenceFixture, admitted_at: str,
) -> None:
    admission = json.loads(evidence.admission_path.read_text("utf-8"))
    admission["admitted_at"] = admitted_at
    evidence.admission_path.write_bytes(_canonical(admission))
    with pytest.raises(v3.ReadEvidenceV3Error, match="authorization window"):
        _verify(evidence)


def test_active_requires_canonical_location_and_has_no_sealed_path(
    evidence: EvidenceFixture, tmp_path: Path
) -> None:
    retained_index = _copied_index(evidence, tmp_path)

    with pytest.raises(v3.ReadEvidenceV3Error, match="canonical active"):
        v3.verify_read_evidence_v3(
            retained_index,
            expected_release_identity=IDENTITY,
        )

@pytest.mark.parametrize(
    "now",
    [
        datetime(2026, 8, 3, 9, 0, 0, tzinfo=timezone.utc),
        datetime(2030, 1, 1, tzinfo=timezone.utc),
    ],
)
def test_active_rejects_at_or_after_authorization_expiry(
    evidence: EvidenceFixture,
    monkeypatch: pytest.MonkeyPatch,
    now: datetime,
) -> None:
    monkeypatch.setattr(v3, "_utc_now", lambda: now)
    with pytest.raises(v3.ReadEvidenceV3Error, match="expired"):
        _verify(evidence)


def test_schema_detector_is_bounded_canonical_and_exact() -> None:
    assert (
        v3.detect_read_evidence_schema(
            _canonical({"schema_version": v3.EVIDENCE_INDEX_SCHEMA})
        )
        == "v3"
    )
    assert (
        v3.detect_read_evidence_schema(
            _canonical(
                {"schema_version": "odoo-accounting-cli-v3.read-evidence-index.v2"}
            )
        )
        == "v2"
    )
    for raw in (
        b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v3","schema_version":"x"}\n',
        b'{ "schema_version":"odoo-accounting-cli-v3.read-evidence-index.v3"}\n',
        b'{"schema_version":NaN}\n',
        b"x" * (v3.MAX_INDEX_BYTES + 1),
    ):
        assert v3.detect_read_evidence_schema(raw) == "invalid"


@pytest.mark.parametrize("mutation", ["empty", "missing", "duplicate", "contract"])
def test_raw_capabilities_must_cover_exact_contract_set(
    evidence: EvidenceFixture, mutation: str
) -> None:
    kind = "live_odoo"
    path = evidence.run_root / f"raw/{kind}.json"
    raw = json.loads(path.read_text("utf-8"))
    capabilities = raw["capabilities"]
    if mutation == "empty":
        raw["capabilities"] = []
    elif mutation == "missing":
        raw["capabilities"] = capabilities[:-1]
    elif mutation == "duplicate":
        raw["capabilities"] = [capabilities[0], deepcopy(capabilities[0])]
    else:
        capabilities[0]["capability_contract_sha256"] = "f" * 64
    path.write_bytes(_canonical(raw))
    evidence.refresh_after_raw_change(kind, refresh_verifier_summary=True)

    with pytest.raises(v3.ReadEvidenceV3Error, match="capability contracts"):
        _verify(evidence)


def test_raw_semantics_are_recomputed_even_after_resign(
    evidence: EvidenceFixture,
) -> None:
    kind = "live_odoo"
    path = evidence.run_root / f"raw/{kind}.json"
    raw = json.loads(path.read_text("utf-8"))
    raw["capabilities"][0]["case"]["odoo_write_count"] = 1
    path.write_bytes(_canonical(raw))
    evidence.refresh_after_raw_change(kind, refresh_verifier_summary=True)

    with pytest.raises(v3.ReadEvidenceV3Error, match="read-only"):
        _verify(evidence)


@pytest.mark.parametrize("company_id", [True, 1.0, 0, -1])
def test_live_odoo_company_id_requires_an_exact_positive_integer(
    evidence: EvidenceFixture, company_id: object
) -> None:
    kind = "live_odoo"
    path = evidence.run_root / f"raw/{kind}.json"
    raw = json.loads(path.read_text("utf-8"))
    raw["capabilities"][0]["case"]["company_id"] = company_id
    path.write_bytes(_canonical(raw))
    evidence.refresh_after_raw_change(kind, refresh_verifier_summary=True)

    with pytest.raises(v3.ReadEvidenceV3Error, match="company_id.*positive integer"):
        _verify(evidence)


def test_verifier_summary_must_equal_recomputed_raw_summary(
    evidence: EvidenceFixture,
) -> None:
    kind = "accounting_oracle"
    path = evidence.run_root / f"raw/{kind}.json"
    raw = json.loads(path.read_text("utf-8"))
    raw["capabilities"][0]["case"]["row_count"] = 2
    path.write_bytes(_canonical(raw))
    evidence.refresh_after_raw_change(kind, refresh_verifier_summary=False)

    with pytest.raises(v3.ReadEvidenceV3Error, match="recomputed summary"):
        _verify(evidence)


def test_verifier_raw_size_requires_an_exact_integer(
    evidence: EvidenceFixture,
) -> None:
    kind = "accounting_oracle"
    report_path = f"verifiers/{kind}.json"
    report = json.loads((evidence.run_root / report_path).read_text("utf-8"))
    report["raw_size"] = float(report["raw_size"])
    evidence.write_json(report_path, report)
    evidence.sign(report_path, f"verifier.{kind}")
    evidence.refresh_index_admission_and_active()

    with pytest.raises(v3.ReadEvidenceV3Error, match="raw_size.*positive integer"):
        _verify(evidence)


def test_index_declares_the_complete_pre_admission_tree(
    evidence: EvidenceFixture,
) -> None:
    index = json.loads(evidence.index_path.read_text("utf-8"))
    index["closure_paths"] = index["closure_paths"][:-1]
    evidence.index_path.write_bytes(_canonical(index))
    with pytest.raises(v3.ReadEvidenceV3Error, match="pre-admission closure paths"):
        _verify(evidence)


@pytest.mark.parametrize(
    "field",
    [
        "closure_file_count",
        "closure_total_bytes",
        "index_signature_size",
        "index_size",
    ],
)
def test_active_admission_counts_and_sizes_require_exact_integers(
    evidence: EvidenceFixture, field: str
) -> None:
    admission = json.loads(evidence.admission_path.read_text("utf-8"))
    admission[field] = float(admission[field])
    evidence.admission_path.write_bytes(_canonical(admission))
    active = json.loads(evidence.active_record_path.read_text("utf-8"))
    active["admission_sha256"] = _digest(evidence.admission_path.read_bytes())
    active["payload_sha256"] = active["admission_sha256"]
    evidence.active_record_path.write_bytes(_canonical(active))

    with pytest.raises(v3.ReadEvidenceV3Error, match=f"{field}.*positive integer"):
        _verify(evidence)


@pytest.mark.parametrize("sequence", [True, 1.0])
def test_active_admission_sequence_requires_an_exact_integer(
    evidence: EvidenceFixture, sequence: object
) -> None:
    admission = json.loads(evidence.admission_path.read_text("utf-8"))
    admission["sequence"] = sequence
    evidence.admission_path.write_bytes(_canonical(admission))
    active = json.loads(evidence.active_record_path.read_text("utf-8"))
    active["admission_sha256"] = _digest(evidence.admission_path.read_bytes())
    active["payload_sha256"] = active["admission_sha256"]
    active["sequence"] = sequence
    evidence.active_record_path.write_bytes(_canonical(active))

    with pytest.raises(v3.ReadEvidenceV3Error, match="admission sequence.*positive integer"):
        _verify(evidence)


def test_active_record_is_required(evidence: EvidenceFixture) -> None:
    evidence.active_record_path.unlink()
    with pytest.raises(v3.ReadEvidenceV3Error, match="active record"):
        _verify(evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "another-run"),
        ("index_sha256", "f" * 64),
        ("admission_sha256", "e" * 64),
        ("sequence", 2),
    ],
)
def test_active_record_exactly_binds_current_closure(
    evidence: EvidenceFixture, field: str, value: object
) -> None:
    active = json.loads(evidence.active_record_path.read_text("utf-8"))
    active[field] = value
    evidence.active_record_path.write_bytes(_canonical(active))
    with pytest.raises(v3.ReadEvidenceV3Error, match="active record.*mismatch"):
        _verify(evidence)


@pytest.mark.parametrize("sequence", [True, 1.0])
def test_active_record_sequence_requires_an_exact_integer(
    evidence: EvidenceFixture, sequence: object
) -> None:
    active = json.loads(evidence.active_record_path.read_text("utf-8"))
    active["sequence"] = sequence
    evidence.active_record_path.write_bytes(_canonical(active))
    with pytest.raises(v3.ReadEvidenceV3Error, match="positive integer"):
        _verify(evidence)


def test_active_record_extra_field_is_rejected(evidence: EvidenceFixture) -> None:
    active = json.loads(evidence.active_record_path.read_text("utf-8"))
    active["attacker"] = True
    evidence.active_record_path.write_bytes(_canonical(active))
    with pytest.raises(v3.ReadEvidenceV3Error, match="active record fields"):
        _verify(evidence)


def test_active_requires_published_ledger_row(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        v3,
        "_lookup_published_admission",
        lambda *_args, **_kwargs: {"publication_state": "CONSUMED"},
    )
    with pytest.raises(v3.ReadEvidenceV3Error, match="PUBLISHED"):
        _verify(evidence)


def test_active_ledger_publication_signature_binding_is_exact(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        v3,
        "_lookup_published_admission",
        lambda _context, **_kwargs: {
            "authorization_id": "auth-20260803-000001",
            "payload_sha256": _digest(evidence.admission_path.read_bytes()),
            "publication_state": "PUBLISHED",
            "published_at": "2026-08-03T08:00:00Z",
            "sequence": 1,
            "admission_signature_path": f"{v3.ADMISSION_FILENAME}.sshsig",
            "admission_signature_sha256": "f" * 64,
            "admission_signature_size": 1,
        },
    )
    with pytest.raises(v3.ReadEvidenceV3Error, match="publication binding"):
        _verify(evidence)


@pytest.mark.parametrize("field", ["admission_signature_size", "sequence"])
def test_active_ledger_numeric_bindings_require_exact_integers(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    signature = evidence.run_root / f"{v3.ADMISSION_FILENAME}.sshsig"

    def publication(
        _context: object,
        *,
        authorization_id: str,
        payload_sha256: str,
        sequence: int,
        admission_signature_sha256: str,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "admission_signature_path": f"{v3.ADMISSION_FILENAME}.sshsig",
            "admission_signature_sha256": admission_signature_sha256,
            "admission_signature_size": signature.stat().st_size,
            "authorization_id": authorization_id,
            "payload_sha256": payload_sha256,
            "publication_state": "PUBLISHED",
            "published_at": "2026-08-03T08:00:00Z",
            "sequence": sequence,
        }
        result[field] = float(result[field])
        return result

    monkeypatch.setattr(v3, "_lookup_published_admission", publication)
    with pytest.raises(v3.ReadEvidenceV3Error, match="publication.*positive integer"):
        _verify(evidence)


def test_active_rejects_future_publication_timestamp(
    evidence: EvidenceFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    signature = evidence.run_root / f"{v3.ADMISSION_FILENAME}.sshsig"
    monkeypatch.setattr(
        v3,
        "_lookup_published_admission",
        lambda _context, *, authorization_id, payload_sha256, sequence,
        admission_signature_sha256: {
            "admission_signature_path": f"{v3.ADMISSION_FILENAME}.sshsig",
            "admission_signature_sha256": admission_signature_sha256,
            "admission_signature_size": signature.stat().st_size,
            "authorization_id": authorization_id,
            "payload_sha256": payload_sha256,
            "publication_state": "PUBLISHED",
            "published_at": "2026-08-03T08:00:01Z",
            "sequence": sequence,
        },
    )
    with pytest.raises(v3.ReadEvidenceV3Error, match="publication timestamp"):
        _verify(evidence)
