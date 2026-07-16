from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from odoo_accounting_cli_v3 import write_app
from odoo_accounting_cli_v3.auth import context_payload, sign_write_action_context
from odoo_accounting_cli_v3.operations import (
    canonical_json,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.registry import registry_digest, validate_registry
from odoo_accounting_cli_v3.write_api import parse_write_api_request
from odoo_accounting_cli_v3.write_app import WriteApplicationError
from odoo_accounting_cli_v3.write_protocol import (
    approval_from_mapping,
    approval_to_mapping,
    operation_from_mapping,
    trusted_result_to_mapping,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan_v2,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 15, 5, 30, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE_DIGEST = "d" * 64
WRITE_AUTH_SECRET = b"write-app-auth-secret-material-00001"
APPROVAL_SECRET = b"write-app-approval-secret-material-01"
EXECUTION_SECRET = b"write-app-execution-secret-material-1"
VERIFICATION_SECRET = b"write-app-verification-secret-material"
RECOVERY_SECRET = b"write-app-recovery-secret-material-001"
RECEIPT_SECRET = b"write-app-receipt-secret-material-0001"
SECOND_RECEIPT_SECRET = b"write-app-second-receipt-secret-material"
CAPABILITY_ID = "acct.bill.vendor_create.v1"


def _capabilities():
    document = json.loads(
        (ROOT / "registry" / "capabilities.json").read_text(encoding="utf-8")
    )
    for item in document["capabilities"]:
        if item["access"] == "write":
            item["staged_environments"] = ["sandbox"]
            item["evidence"]["level"] = "contract_tested"
    return validate_registry(document)


def _parameters(idempotency_key: str = "vendor-bill-full-parameters-1") -> dict[str, Any]:
    return {
        "company_id": 7,
        "partner_id": 901,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-16",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "post",
        "vendor_reference": "SUPPLIER-SG-2026-0715",
        "lines": [
            {
                "line_reference": "supplier-line-1",
                "name": "Cross-border supplier service",
                "product_id": None,
                "account_id": 401,
                "quantity": "2.5000",
                "price_unit": "88.90",
                "tax_ids": [31, 32],
            },
            {
                "line_reference": "supplier-line-2",
                "name": "Bank handling fee",
                "product_id": 88,
                "account_id": 402,
                "quantity": "1",
                "price_unit": "12.34",
                "tax_ids": [],
            },
        ],
        "idempotency_key": idempotency_key,
    }


def _mapping(context) -> dict[str, Any]:
    return {**context_payload(context), "auth_signature": context.auth_signature}


class FakeOdoo:
    def __init__(self, harness: "Harness") -> None:
        self.harness = harness
        self.executor_authorized = True
        self.approver_authorized = True
        self.raise_approved = False
        self.executor_requests: list[dict[str, Any]] = []
        self.approver_requests: list[dict[str, Any]] = []
        self.precheck_requests: list[dict[str, Any]] = []
        self.approved_requests: list[dict[str, Any]] = []

    def _runtime_binding(self) -> dict[str, Any]:
        base = self.harness.config.base_runtime
        return {
            "odoo_instance_id": base.instance_id,
            "database_name": base.database_name,
            "database_uuid": base.database_uuid,
            "environment": base.environment,
            "capability_channel": base.capability_channel,
        }

    def _release_digest(self) -> str:
        return self.harness.identity["manifest_sha256"]

    def authorize_executor(
        self,
        _config,
        _secrets,
        request,
        *,
        release_digest,
        timeout_seconds,
    ):
        assert release_digest == self._release_digest()
        assert timeout_seconds == write_app.ODOO_WRITE_TIMEOUT_SECONDS
        self.executor_requests.append(copy.deepcopy(request))
        return {
            "authorized": self.executor_authorized,
            "user_id": 42,
            "company_id": 7,
            "capability_id": request["capability_id"],
            "missing_groups": [] if self.executor_authorized else ["account.group_account_invoice"],
            "runtime_binding": self._runtime_binding(),
            "registry_digest": self.harness.registry_digest,
            "release_digest": self._release_digest(),
        }

    def authorize_approver(
        self,
        _config,
        _secrets,
        request,
        *,
        release_digest,
        timeout_seconds,
    ):
        assert release_digest == self._release_digest()
        assert timeout_seconds == write_app.ODOO_WRITE_TIMEOUT_SECONDS
        self.approver_requests.append(copy.deepcopy(request))
        parameters = request["parameters"]
        return {
            "authorized": self.approver_authorized,
            "approver_user_id": parameters["approver_user_id"],
            "company_id": parameters["company_id"],
            "capability_id": request["capability_id"],
            "runtime_binding": self._runtime_binding(),
            "registry_digest": self.harness.registry_digest,
            "release_digest": self._release_digest(),
        }

    def precheck(
        self,
        _config,
        _secrets,
        request,
        *,
        release_digest,
        timeout_seconds,
    ):
        assert release_digest == self._release_digest()
        assert timeout_seconds == write_app.ODOO_WRITE_TIMEOUT_SECONDS
        self.precheck_requests.append(copy.deepcopy(request))
        return {
            "capability_id": request["capability_id"],
            "company_id": request["parameters"]["company_id"],
            "parameters_digest": hashlib.sha256(
                canonical_json(request["parameters"])
            ).hexdigest(),
            "checks": ["acl", "company", "currency", "dates", "nested_lines"],
            "handler_details": {},
            "passed": True,
            "registry_digest": self.harness.registry_digest,
            "release_digest": self._release_digest(),
            "runtime_binding": {
                "user_id": 42,
                **self._runtime_binding(),
            },
        }

    @staticmethod
    def _execution_evidence(operation) -> dict[str, Any]:
        is_recovery = operation.capability_id == "acct.recovery.execute.v1"
        record_id = 601 if is_recovery else 501
        before = create_record_snapshot(
            model="account.move",
            record_id=record_id,
            exists=False,
            record_state="absent",
            values={},
        )
        values = (
            {
                "company_id": operation.company_id,
                "origin_operation_id": operation.parameters["origin_operation_id"],
                "state": "posted",
            }
            if is_recovery
            else {
                "company_id": operation.company_id,
                "partner_id": operation.parameters["partner_id"],
                "currency_id": operation.parameters["currency_id"],
                "invoice_date": operation.parameters["invoice_date"],
                "state": "posted",
            }
        )
        after = create_record_snapshot(
            model="account.move",
            record_id=record_id,
            exists=True,
            record_state="posted",
            values=values,
        )
        target = {
            "model": "account.move",
            "record_id": record_id,
            "company_id": operation.company_id,
            "record_state": "posted",
            "record_fingerprint": hashlib.sha256(
                canonical_json(after)
            ).hexdigest(),
        }
        guard_before = create_record_snapshot(
            model="account.move.line",
            record_id=record_id + 1,
            exists=False,
            record_state="absent",
            values={},
        )
        guard_after = create_record_snapshot(
            model="account.move.line",
            record_id=record_id + 1,
            exists=True,
            record_state="unknown",
            values={"company_id": operation.company_id, "move_id": record_id},
        )
        guard_reference = {
            "model": "account.move.line",
            "record_id": record_id + 1,
            "company_id": operation.company_id,
            "record_state": "unknown",
            "record_fingerprint": hashlib.sha256(
                canonical_json(guard_after)
            ).hexdigest(),
        }
        recovery_parameters = (
            {"origin_operation_id": operation.parameters["origin_operation_id"]}
            if is_recovery
            else {
                "move_id": 501,
                "action_targets": [{"model": "account.move", "record_id": 501}],
                "guard_records": [
                    {"model": "account.move.line", "record_id": 502}
                ],
                "oracle_id": "cancel_draft_move_exact_v1",
            }
        )
        return {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "succeeded": True,
            "odoo_records": [target, guard_reference],
            "difference": create_difference(
                before=[before, guard_before],
                after=[after, guard_after],
                changed_fields=[
                    *(
                        ["company_id", "origin_operation_id", "state"]
                        if is_recovery
                        else [
                            "company_id",
                            "currency_id",
                            "invoice_date",
                            "partner_id",
                            "state", "move_id",
                        ]
                    ),
                ],
            ),
            "recovery_plan": create_recovery_plan_v2(
                origin_operation_id=operation.operation_id,
                recovery_capability_id="acct.recovery.execute.v1",
                status="not_applicable" if is_recovery else "available",
                method="recovery_completed" if is_recovery else "cancel_draft_move",
                requires_approval=not is_recovery,
                action_targets=[] if is_recovery else [target],
                guard_records=(
                    [
                        {
                            **guard_reference,
                            "expected_outcome": "survive_exact",
                        }
                    ]
                    if not is_recovery
                    else []
                ),
                oracle_id=(
                    "not_applicable"
                    if is_recovery
                    else "cancel_draft_move_exact_v1"
                ),
                parameters=recovery_parameters,
            ),
            "recovery_parameters": recovery_parameters,
            "failure_checks": [],
        }

    def approved_write(
        self,
        _config,
        _secrets,
        request,
        *,
        release_digest,
        timeout_seconds,
    ):
        assert release_digest == self._release_digest()
        assert timeout_seconds == write_app.ODOO_WRITE_TIMEOUT_SECONDS
        self.approved_requests.append(copy.deepcopy(request))
        if self.raise_approved:
            raise RuntimeError("simulated lost Odoo response")

        operation = operation_from_mapping(request["operation"])
        approval = approval_from_mapping(request["approval"])
        assert approval.operation_id == operation.operation_id
        if operation.capability_id == "acct.recovery.execute.v1":
            assert request["trusted_recovery_plan"]["plan_digest"] == operation.parameters[
                "expected_recovery_plan_digest"
            ]
        else:
            assert request["trusted_recovery_plan"] is None
        execution_evidence = self._execution_evidence(operation)
        execution = sign_execution_result(
            operation=operation,
            issuer=self.harness.config.execution.issuer,
            key_id=self.harness.config.execution.key_id,
            succeeded=True,
            evidence_digest=hashlib.sha256(
                canonical_json(execution_evidence)
            ).hexdigest(),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        verifying = record_execution_result(
            operation,
            execution,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id=self.harness.config.execution.key_id,
            allowed_issuers=frozenset({self.harness.config.execution.issuer}),
            expected_revision=operation.revision,
        )
        verification_evidence = {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "passed": True,
            "method": (
                "read_back_trusted_plan_target_fingerprints_and_action_specific_compensation_state_v1"
                if operation.capability_id == "acct.recovery.execute.v1"
                else "read_back_exact_move_lines_tax_preview_single_due_residual_and_content_business_bindings_v1"
            ),
            "checks": [
                "company_matches",
                "supplier_matches",
                "currency_matches",
                "dates_match",
                "nested_lines_match",
            ],
            "verified_at": NOW.isoformat(),
            "readback": {
                "company_id": operation.company_id,
                "records": copy.deepcopy(execution_evidence["odoo_records"]),
                "fresh_snapshots": copy.deepcopy(
                    execution_evidence["difference"]["after"]
                ),
                "fresh_snapshots_digest": hashlib.sha256(
                    canonical_json(execution_evidence["difference"]["after"])
                ).hexdigest(),
                "request_parameters_digest": hashlib.sha256(
                    canonical_json(operation.parameters)
                ).hexdigest(),
                "control_anchor": {
                    "operation_id": operation.operation_id,
                    "capability_id": operation.capability_id,
                    "company_id": operation.company_id,
                    "state": "verified",
                    "execution_evidence_digest": verifying.execution_result_digest,
                },
            },
        }
        verification = sign_verification_result(
            operation=verifying,
            issuer=self.harness.config.verification.issuer,
            key_id=self.harness.config.verification.key_id,
            succeeded=True,
            evidence_digest=hashlib.sha256(
                canonical_json(verification_evidence)
            ).hexdigest(),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        return {
            "reconciliation_only": request["reconciliation_only"],
            "execution": {
                "result": trusted_result_to_mapping(execution),
                "evidence": execution_evidence,
            },
            "verification": {
                "result": trusted_result_to_mapping(verification),
                "evidence": verification_evidence,
            },
        }


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.capabilities = _capabilities()
        self.registry_digest = registry_digest(self.capabilities)
        base_runtime = SimpleNamespace(
            instance_id="odoo19@sandbox",
            database_name="odoo_v3_sandbox",
            database_uuid=DATABASE_UUID,
            environment="sandbox",
            capability_channel="staged",
            release_root=ROOT,
        )
        role = lambda key_id, issuer=None: SimpleNamespace(  # noqa: E731
            key_id=key_id, issuer=issuer
        )
        self.config = SimpleNamespace(
            write_execution_mode="sandbox_staged",
            write_state_path=(tmp_path / "write-operations.sqlite3").resolve(),
            base_runtime=base_runtime,
            write_auth=role("write-auth-v2"),
            approval=role("approval-v3"),
            execution=role("execution-v1", "odoo-write-executor"),
            verification=role("verification-v1", "odoo-write-verifier"),
            recovery=role("recovery-v1", "odoo-write-recovery"),
            write_receipt=role("write-receipt-v1"),
        )
        self.secrets = SimpleNamespace(
            write_auth=WRITE_AUTH_SECRET,
            approval=APPROVAL_SECRET,
            execution=EXECUTION_SECRET,
            verification=VERIFICATION_SECRET,
            recovery=RECOVERY_SECRET,
            write_receipt=RECEIPT_SECRET,
        )
        self.identity = {
            "manifest_sha256": RELEASE_DIGEST,
            "registry_digest": self.registry_digest,
        }
        self.odoo = FakeOdoo(self)
        self._token = 0

        monkeypatch.setattr(write_app, "_utcnow", lambda: NOW)
        monkeypatch.setattr(
            write_app, "load_write_runtime_config", lambda _path: self.config
        )
        monkeypatch.setattr(
            write_app, "load_write_runtime_secrets", lambda _config: self.secrets
        )
        monkeypatch.setattr(
            write_app, "_load_verified_release_identity", lambda _config: self.identity
        )
        monkeypatch.setattr(
            write_app, "load_registry", lambda _path: self.capabilities
        )
        monkeypatch.setattr(
            write_app, "run_odoo_authorize_executor", self.odoo.authorize_executor
        )
        monkeypatch.setattr(
            write_app, "run_odoo_authorize_approver", self.odoo.authorize_approver
        )
        monkeypatch.setattr(write_app, "run_odoo_write_precheck", self.odoo.precheck)
        monkeypatch.setattr(
            write_app, "run_odoo_approved_write", self.odoo.approved_write
        )

    def parsed(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        signed_action: str | None = None,
        signed_payload: dict[str, Any] | None = None,
    ):
        self._token += 1
        context = sign_write_action_context(
            auth_token_id=f"write-app-token-{self._token}",
            principal="pi:sandbox-user-42",
            odoo_instance_id=self.config.base_runtime.instance_id,
            database_name=self.config.base_runtime.database_name,
            database_uuid=self.config.base_runtime.database_uuid,
            user_id=42,
            company_id=7,
            allowed_company_ids=frozenset({7}),
            environment="sandbox",
            action=signed_action or action,
            request=copy.deepcopy(signed_payload if signed_payload is not None else payload),
            issued_at=NOW - timedelta(seconds=30),
            expires_at=NOW + timedelta(minutes=4),
            key_id=self.config.write_auth.key_id,
            secret=WRITE_AUTH_SECRET,
        )
        return parse_write_api_request(
            action, {"context": _mapping(context), **copy.deepcopy(payload)}
        )

    def call(self, action: str, payload: dict[str, Any], **kwargs):
        return write_app.execute_write_action(
            action, self.parsed(action, payload, **kwargs)
        )

    def store(self) -> SQLitePersistence:
        return SQLitePersistence(self.config.write_state_path)

    def prepare_preview(self, suffix: str = "main"):
        parameters = _parameters(f"vendor-bill-{suffix}")
        prepared = self.call(
            "operation.prepare",
            {
                "operation_id": f"op-vendor-{suffix}",
                "request_id": f"req-vendor-{suffix}",
                "capability_id": CAPABILITY_ID,
                "parameters": parameters,
            },
        )
        preview = self.call(
            "operation.preview", {"operation_id": prepared["operation_id"]}
        )
        return parameters, prepared, preview

    def approval(self, operation_id: str, nonce: str = "approval-main"):
        status = self.call("operation.status", {"operation_id": operation_id})
        operation = operation_from_mapping(status["operation"])
        return sign_approval(
            operation=operation,
            approver_user_id=99,
            nonce=nonce,
            issued_at=NOW - timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=5),
            approval_ttl_seconds=900,
            key_id=self.config.approval.key_id,
            secret=APPROVAL_SECRET,
        )

    def complete(self, suffix: str = "main"):
        parameters, prepared, preview = self.prepare_preview(suffix)
        approval = self.approval(prepared["operation_id"], f"approval-{suffix}")
        approval_payload = {
            "operation_id": prepared["operation_id"],
            "approval": approval_to_mapping(approval),
            "reconciliation_only": False,
        }
        executed = self.call("operation.approve_execute", approval_payload)
        result = self.call(
            "operation.result", {"operation_id": prepared["operation_id"]}
        )
        return parameters, prepared, preview, approval, approval_payload, executed, result


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def _install_trusted_runtime_handoff(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    *,
    release_digest: str,
    registry_digest_value: str,
    expected_config_digest: str | None = None,
    descriptor_path: Path | None = None,
) -> int:
    descriptor = os.open(descriptor_path or path, os.O_RDONLY)
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG", str(path.resolve())
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_SHA256",
        expected_config_digest or hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_FD", str(descriptor)
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST", release_digest
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST", registry_digest_value
    )
    return descriptor


def test_ordinary_cli_environment_cannot_override_runtime_config(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    attacker_config = (tmp_path / "caller-selected.json").resolve()
    attacker_config.write_bytes(b'{"caller":"selected"}')
    loaded: list[Path] = []

    def load(path):
        loaded.append(Path(path))
        return harness.config

    monkeypatch.setattr(write_app, "load_write_runtime_config", load)
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG",
        str(attacker_config),
    )

    with pytest.raises(WriteApplicationError) as rejected:
        harness.call(
            "operation.prepare",
            {
                "operation_id": "op-env-override",
                "request_id": "req-env-override",
                "capability_id": CAPABILITY_ID,
                "parameters": _parameters("env-override"),
            },
        )

    assert rejected.value.code == "trusted_runtime_handoff_rejected"
    assert rejected.value.odoo_effect == "none"
    assert loaded == []
    assert harness.odoo.executor_requests == []


def test_complete_environment_without_inherited_config_fd_is_rejected(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = (tmp_path / "untrusted-complete.json").resolve()
    config_path.write_bytes(b'{"complete":"but-not-inherited"}')
    digest = hashlib.sha256(config_path.read_bytes()).hexdigest()
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG", str(config_path)
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_SHA256", digest
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_FD", "999999"
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST", RELEASE_DIGEST
    )
    monkeypatch.setenv(
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST",
        harness.registry_digest,
    )

    with pytest.raises(WriteApplicationError) as rejected:
        harness.call(
            "operation.prepare",
            {
                "operation_id": "op-no-inherited-fd",
                "request_id": "req-no-inherited-fd",
                "capability_id": CAPABILITY_ID,
                "parameters": _parameters("no-inherited-fd"),
            },
        )

    assert rejected.value.code == "trusted_runtime_handoff_rejected"
    assert rejected.value.odoo_effect == "none"
    assert harness.odoo.executor_requests == []


def test_trusted_historical_handoff_loads_exact_runtime_and_release(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    historical_config = (tmp_path / "retained" / "write-runtime.json").resolve()
    historical_config.parent.mkdir()
    historical_config.write_bytes(b'{"release":"retained"}')
    descriptor = _install_trusted_runtime_handoff(
        monkeypatch,
        historical_config,
        release_digest=RELEASE_DIGEST,
        registry_digest_value=harness.registry_digest,
    )
    loaded: list[Path] = []

    def load(path):
        loaded.append(Path(path))
        return harness.config

    monkeypatch.setattr(write_app, "load_write_runtime_config", load)
    try:
        prepared = harness.call(
            "operation.prepare",
            {
                "operation_id": "op-retained-handoff",
                "request_id": "req-retained-handoff",
                "capability_id": CAPABILITY_ID,
                "parameters": _parameters("retained-handoff"),
            },
        )
    finally:
        os.close(descriptor)

    assert loaded == [historical_config]
    assert prepared["operation_state"] == "prepared"
    assert operation_from_mapping(prepared["operation"]).release_digest == (
        RELEASE_DIGEST
    )


@pytest.mark.parametrize(
    ("release_digest", "expected_registry"),
    [("e" * 64, None), (RELEASE_DIGEST, "f" * 64)],
)
def test_trusted_handoff_requires_exact_release_and_registry_identity(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    release_digest: str,
    expected_registry: str | None,
) -> None:
    historical_config = (tmp_path / "identity-mismatch.json").resolve()
    historical_config.write_bytes(b'{"release":"mismatch"}')
    descriptor = _install_trusted_runtime_handoff(
        monkeypatch,
        historical_config,
        release_digest=release_digest,
        registry_digest_value=expected_registry or harness.registry_digest,
    )
    try:
        with pytest.raises(WriteApplicationError) as rejected:
            harness.call(
                "operation.prepare",
                {
                    "operation_id": "op-retained-mismatch",
                    "request_id": "req-retained-mismatch",
                    "capability_id": CAPABILITY_ID,
                    "parameters": _parameters("retained-mismatch"),
                },
            )
    finally:
        os.close(descriptor)

    assert rejected.value.code == "trusted_runtime_handoff_rejected"
    assert rejected.value.odoo_effect == "none"
    assert harness.odoo.executor_requests == []


def test_trusted_handoff_rejects_hash_drift_and_descriptor_path_substitution(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    selected = (tmp_path / "selected.json").resolve()
    substituted = (tmp_path / "substituted.json").resolve()
    selected.write_bytes(b'{"release":"selected"}')
    substituted.write_bytes(b'{"release":"substituted"}')
    selected_digest = hashlib.sha256(selected.read_bytes()).hexdigest()
    descriptor = _install_trusted_runtime_handoff(
        monkeypatch,
        selected,
        release_digest=RELEASE_DIGEST,
        registry_digest_value=harness.registry_digest,
        expected_config_digest=selected_digest,
        descriptor_path=substituted,
    )
    try:
        with pytest.raises(WriteApplicationError) as substituted_error:
            harness.call(
                "operation.prepare",
                {
                    "operation_id": "op-substituted-config",
                    "request_id": "req-substituted-config",
                    "capability_id": CAPABILITY_ID,
                    "parameters": _parameters("substituted-config"),
                },
            )
    finally:
        os.close(descriptor)
    assert substituted_error.value.code == "trusted_runtime_handoff_rejected"

    drifted = (tmp_path / "drifted.json").resolve()
    drifted.write_bytes(b'{"release":"before"}')
    original_digest = hashlib.sha256(drifted.read_bytes()).hexdigest()
    descriptor = _install_trusted_runtime_handoff(
        monkeypatch,
        drifted,
        release_digest=RELEASE_DIGEST,
        registry_digest_value=harness.registry_digest,
        expected_config_digest=original_digest,
    )

    def load_then_drift(_path):
        drifted.write_bytes(b'{"release":"after"}')
        return harness.config

    monkeypatch.setattr(write_app, "load_write_runtime_config", load_then_drift)
    try:
        with pytest.raises(WriteApplicationError) as drift_error:
            harness.call(
                "operation.prepare",
                {
                    "operation_id": "op-drifted-config",
                    "request_id": "req-drifted-config",
                    "capability_id": CAPABILITY_ID,
                    "parameters": _parameters("drifted-config"),
                },
            )
    finally:
        os.close(descriptor)
    assert drift_error.value.code == "trusted_runtime_handoff_rejected"
    assert harness.odoo.executor_requests == []


def test_full_lifecycle_preserves_parameters_and_returns_signed_evidence(harness: Harness):
    parameters, prepared, preview, _approval, _payload, executed, result = harness.complete()

    status_before = harness.call(
        "operation.status", {"operation_id": prepared["operation_id"]}
    )
    assert prepared["operation_state"] == "prepared"
    assert preview["operation_state"] == "awaiting_approval"
    assert executed == result
    assert status_before["operation_state"] == "completed"
    assert result["operation_state"] == "completed"
    assert result["verification"]["passed"] is True
    assert result["recovery_plan"]["status"] == "available"
    assert result["audit_receipt"]["signature_purpose"] == "write_audit_receipt_v1"
    assert result["audit_receipt"]["signing_key_id"] == "write-receipt-v1"
    assert len(result["audit_receipt"]["signature"]) == 64

    assert harness.odoo.executor_requests[0]["parameters"] == parameters
    assert harness.odoo.precheck_requests[0]["parameters"] == parameters
    assert operation_from_mapping(
        harness.odoo.approved_requests[0]["operation"]
    ).parameters == parameters
    assert parameters["partner_id"] == 901
    assert parameters["currency_id"] == 12
    assert parameters["invoice_date"] == "2026-07-15"
    assert parameters["accounting_date"] == "2026-07-16"
    assert parameters["due_date"] == "2026-08-15"
    assert len(parameters["lines"]) == 2

    trusted = harness.store().get_trusted_result_records(prepared["operation_id"])
    assert [record.kind for record in trusted] == ["execution", "verification"]
    assert [record.key_id for record in trusted] == ["execution-v1", "verification-v1"]
    assert all(len(record.signature) == 64 for record in trusted)
    assert len(
        harness.store().get_final_write_receipts(prepared["operation_id"])
    ) == 1


def test_retained_releases_share_write_state_with_distinct_receipt_keys(
    harness: Harness,
) -> None:
    (
        _old_parameters,
        old_prepared,
        _old_preview,
        _old_approval,
        _old_payload,
        _old_executed,
        old_result,
    ) = harness.complete("retained-old")

    second_release = "e" * 64
    harness.identity = {
        "manifest_sha256": second_release,
        "registry_digest": harness.registry_digest,
    }
    harness.config.write_receipt = SimpleNamespace(key_id="write-receipt-v2")
    harness.secrets.write_receipt = SECOND_RECEIPT_SECRET
    (
        _new_parameters,
        new_prepared,
        _new_preview,
        _new_approval,
        _new_payload,
        _new_executed,
        new_result,
    ) = harness.complete("retained-new")

    assert old_result["audit_receipt"]["signing_key_id"] == "write-receipt-v1"
    assert new_result["audit_receipt"]["signing_key_id"] == "write-receipt-v2"
    assert operation_from_mapping(old_prepared["operation"]).release_digest == RELEASE_DIGEST
    assert operation_from_mapping(new_prepared["operation"]).release_digest == second_release

    harness.identity = {
        "manifest_sha256": RELEASE_DIGEST,
        "registry_digest": harness.registry_digest,
    }
    harness.config.write_receipt = SimpleNamespace(key_id="write-receipt-v1")
    harness.secrets.write_receipt = RECEIPT_SECRET
    replayed_old = harness.call(
        "operation.result", {"operation_id": old_prepared["operation_id"]}
    )
    assert replayed_old["audit_receipt"] == old_result["audit_receipt"]
    assert len(harness.store().get_final_write_receipts(old_prepared["operation_id"])) == 1
    assert len(harness.store().get_final_write_receipts(new_prepared["operation_id"])) == 1


def test_recover_creates_durable_binding_then_previews_receipt_plan(harness: Harness):
    _parameters_value, prepared, _preview, _approval, _payload, _executed, result = (
        harness.complete("recover-origin")
    )
    origin_status = harness.call(
        "operation.status", {"operation_id": prepared["operation_id"]}
    )
    recovery_payload = {
        "origin_operation_id": prepared["operation_id"],
        "expected_origin_revision": origin_status["operation_revision"],
        "recovery_operation_id": "op-vendor-recovery",
        "request_id": "req-vendor-recovery",
        "recovery_date": "2026-07-16",
        "reason": "Reverse the approved duplicate supplier bill",
        "idempotency_key": "recover-vendor-bill-origin",
    }

    recovered = harness.call("operation.recover", recovery_payload)
    binding = harness.store().get_recovery_operation_binding(
        recovered["operation_id"]
    )
    recovery_preview = harness.call(
        "operation.preview", {"operation_id": recovered["operation_id"]}
    )

    assert recovered["operation_state"] == "prepared"
    assert recovered["origin_operation_id"] == prepared["operation_id"]
    assert recovered["recovery_plan_digest"] == result["recovery_plan"]["plan_digest"]
    assert binding.origin_operation_id == prepared["operation_id"]
    assert binding.recovery_operation_id == recovered["operation_id"]
    assert binding.plan_digest == result["recovery_plan"]["plan_digest"]
    assert recovery_preview["operation_state"] == "awaiting_approval"
    assert recovery_preview["parameters"] == {
        "company_id": 7,
        "origin_operation_id": prepared["operation_id"],
        "expected_recovery_plan_digest": result["recovery_plan"]["plan_digest"],
        "recovery_date": "2026-07-16",
        "reason": "Reverse the approved duplicate supplier bill",
        "idempotency_key": "recover-vendor-bill-origin",
    }
    recovery_request = harness.odoo.precheck_requests[-1]
    assert recovery_request["trusted_recovery_plan"] == result["recovery_plan"]


def test_recovery_operation_executes_with_trusted_plan_and_returns_verified_receipt(
    harness: Harness,
):
    _parameters_value, prepared, _preview, _approval, _payload, _executed, result = (
        harness.complete("recover-execute-origin")
    )
    origin_status = harness.call(
        "operation.status", {"operation_id": prepared["operation_id"]}
    )
    recovery = harness.call(
        "operation.recover",
        {
            "origin_operation_id": prepared["operation_id"],
            "expected_origin_revision": origin_status["operation_revision"],
            "recovery_operation_id": "op-vendor-recovery-execute",
            "request_id": "req-vendor-recovery-execute",
            "recovery_date": "2026-07-16",
            "reason": "Approved compensating reversal",
            "idempotency_key": "recover-vendor-bill-execute",
        },
    )
    harness.call("operation.preview", {"operation_id": recovery["operation_id"]})
    approval = harness.approval(
        recovery["operation_id"], "approval-recovery-execute"
    )
    payload = {
        "operation_id": recovery["operation_id"],
        "approval": approval_to_mapping(approval),
        "reconciliation_only": False,
    }

    executed = harness.call("operation.approve_execute", payload)
    replayed = harness.call(
        "operation.approve_execute", {**payload, "reconciliation_only": True}
    )
    recovered_result = harness.call(
        "operation.result", {"operation_id": recovery["operation_id"]}
    )

    assert executed == replayed == recovered_result
    assert executed["operation_state"] == "completed"
    assert executed["verification"]["passed"] is True
    assert executed["recovery_plan"]["status"] == "not_applicable"
    assert executed["audit_receipt"]["capability_id"] == "acct.recovery.execute.v1"
    assert harness.odoo.approved_requests[-1]["trusted_recovery_plan"] == result[
        "recovery_plan"
    ]
    assert harness.call(
        "operation.status", {"operation_id": prepared["operation_id"]}
    )["operation_state"] == "completed"


def test_v2_parameter_tamper_and_cross_action_replay_are_rejected(harness: Harness):
    original_parameters = _parameters("vendor-bill-auth-original")
    original_payload = {
        "operation_id": "op-vendor-auth-tamper",
        "request_id": "req-vendor-auth-tamper",
        "capability_id": CAPABILITY_ID,
        "parameters": original_parameters,
    }
    tampered_payload = copy.deepcopy(original_payload)
    tampered_payload["parameters"]["currency_id"] = 99

    with pytest.raises(WriteApplicationError) as parameter_error:
        harness.call(
            "operation.prepare",
            tampered_payload,
            signed_payload=original_payload,
        )
    assert parameter_error.value.code == "write_action_authentication_failed"
    assert parameter_error.value.odoo_effect == "none"
    assert harness.odoo.executor_requests == []

    _parameters_value, prepared, _preview = harness.prepare_preview("cross-action")
    shared_payload = {"operation_id": prepared["operation_id"]}
    with pytest.raises(WriteApplicationError) as replay_error:
        harness.call(
            "operation.preview",
            shared_payload,
            signed_action="operation.status",
        )
    assert replay_error.value.code == "write_action_authentication_failed"
    assert replay_error.value.odoo_effect == "none"


def test_disabled_allows_status_and_result_but_rejects_four_mutations(harness: Harness):
    _parameters_value, prepared, _preview, approval, _payload, _executed, expected = (
        harness.complete("disabled")
    )
    harness.config.write_execution_mode = "disabled"

    status = harness.call(
        "operation.status", {"operation_id": prepared["operation_id"]}
    )
    result = harness.call(
        "operation.result", {"operation_id": prepared["operation_id"]}
    )
    assert status["operation_state"] == "completed"
    assert result == expected

    mutation_payloads = {
        "operation.prepare": {
            "operation_id": "op-disabled-new",
            "request_id": "req-disabled-new",
            "capability_id": CAPABILITY_ID,
            "parameters": _parameters("disabled-new"),
        },
        "operation.preview": {"operation_id": prepared["operation_id"]},
        "operation.approve_execute": {
            "operation_id": prepared["operation_id"],
            "approval": approval_to_mapping(approval),
            "reconciliation_only": True,
        },
        "operation.recover": {
            "origin_operation_id": prepared["operation_id"],
            "expected_origin_revision": status["operation_revision"],
            "recovery_operation_id": "op-disabled-recovery",
            "request_id": "req-disabled-recovery",
            "recovery_date": "2026-07-16",
            "reason": "Policy-disabled recovery request",
            "idempotency_key": "disabled-recovery",
        },
    }
    approved_calls = len(harness.odoo.approved_requests)
    for action, payload in mutation_payloads.items():
        with pytest.raises(WriteApplicationError) as rejected:
            harness.call(action, payload)
        assert rejected.value.code == "accounting_writes_disabled"
        assert rejected.value.odoo_effect == "none"
    assert len(harness.odoo.approved_requests) == approved_calls


def test_executor_acl_denial_never_reaches_approved_runner(harness: Harness):
    harness.odoo.executor_authorized = False

    with pytest.raises(WriteApplicationError) as rejected:
        harness.call(
            "operation.prepare",
            {
                "operation_id": "op-executor-denied",
                "request_id": "req-executor-denied",
                "capability_id": CAPABILITY_ID,
                "parameters": _parameters("executor-denied"),
            },
        )

    assert rejected.value.code == "write_lifecycle_rejected"
    assert rejected.value.odoo_effect == "none"
    assert len(harness.odoo.executor_requests) == 1
    assert harness.odoo.approved_requests == []


def test_approver_acl_denial_never_reaches_approved_runner(harness: Harness):
    _parameters_value, prepared, _preview = harness.prepare_preview("approver-denied")
    approval = harness.approval(prepared["operation_id"], "approval-denied")
    harness.odoo.approver_authorized = False

    with pytest.raises(WriteApplicationError) as rejected:
        harness.call(
            "operation.approve_execute",
            {
                "operation_id": prepared["operation_id"],
                "approval": approval_to_mapping(approval),
                "reconciliation_only": False,
            },
        )

    assert rejected.value.code == "write_lifecycle_rejected"
    assert rejected.value.odoo_effect == "none"
    assert len(harness.odoo.approver_requests) == 1
    assert harness.odoo.approved_requests == []
    assert harness.store().get_operation(prepared["operation_id"]).state.value == "awaiting_approval"


def test_approved_runner_exception_is_unknown_and_same_approval_can_resume(harness: Harness):
    _parameters_value, prepared, _preview = harness.prepare_preview("response-loss")
    approval = harness.approval(prepared["operation_id"], "approval-response-loss")
    payload = {
        "operation_id": prepared["operation_id"],
        "approval": approval_to_mapping(approval),
        "reconciliation_only": False,
    }
    harness.odoo.raise_approved = True

    with pytest.raises(WriteApplicationError) as uncertain:
        harness.call("operation.approve_execute", payload)

    assert uncertain.value.code == "odoo_write_outcome_unknown"
    assert uncertain.value.odoo_effect == "unknown"
    assert uncertain.value.retryable is True
    assert uncertain.value.operation_id == prepared["operation_id"]
    assert harness.store().get_operation(prepared["operation_id"]).state.value == "executing"

    harness.odoo.raise_approved = False
    resumed = harness.call("operation.approve_execute", payload)
    result = harness.call(
        "operation.result", {"operation_id": prepared["operation_id"]}
    )
    assert resumed == result
    assert result["operation_state"] == "completed"
    assert result["recovery_plan"]["status"] == "available"
    assert len(harness.odoo.approved_requests) == 2


def test_malformed_post_odoo_envelope_is_retryable_unknown_with_durable_state(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
):
    _parameters_value, prepared, _preview = harness.prepare_preview("malformed-result")
    approval = harness.approval(prepared["operation_id"], "approval-malformed-result")
    payload = {
        "operation_id": prepared["operation_id"],
        "approval": approval_to_mapping(approval),
        "reconciliation_only": False,
    }

    def malformed(_config, _secrets, request, **_kwargs):
        harness.odoo.approved_requests.append(copy.deepcopy(request))
        return {
            "reconciliation_only": request["reconciliation_only"],
            "execution": {"unexpected": True},
            "verification": None,
        }

    monkeypatch.setattr(write_app, "run_odoo_approved_write", malformed)
    with pytest.raises(WriteApplicationError) as uncertain:
        harness.call("operation.approve_execute", payload)

    assert uncertain.value.code == "invalid_backend_evidence"
    assert uncertain.value.odoo_effect == "unknown"
    assert uncertain.value.retryable is True
    assert uncertain.value.operation_id == prepared["operation_id"]
    assert uncertain.value.state == "executing"

    monkeypatch.setattr(
        write_app, "run_odoo_approved_write", harness.odoo.approved_write
    )
    resumed = harness.call("operation.approve_execute", payload)
    assert resumed["operation_state"] == "completed"


def test_odoo_reconciliation_mode_echo_mismatch_is_retryable_unknown(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
):
    _parameters_value, prepared, _preview = harness.prepare_preview("mode-echo")
    approval = harness.approval(prepared["operation_id"], "approval-mode-echo")
    payload = {
        "operation_id": prepared["operation_id"],
        "approval": approval_to_mapping(approval),
        "reconciliation_only": False,
    }
    approved_write = harness.odoo.approved_write

    def flipped(_config, _secrets, request, **kwargs):
        result = approved_write(_config, _secrets, request, **kwargs)
        return {**result, "reconciliation_only": True}

    monkeypatch.setattr(write_app, "run_odoo_approved_write", flipped)

    with pytest.raises(WriteApplicationError) as uncertain:
        harness.call("operation.approve_execute", payload)

    assert uncertain.value.code == "odoo_write_reconciliation_mode_mismatch"
    assert uncertain.value.odoo_effect == "unknown"
    assert uncertain.value.retryable is True
    assert uncertain.value.state == "executing"
    assert harness.odoo.approved_requests[-1]["reconciliation_only"] is False
