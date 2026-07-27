from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import time
from typing import Any

import pytest

from odoo_accounting_cli_v3.auth import sign_request_context
from odoo_accounting_cli_v3.broker_audit import SQLiteBrokerAuditSink
from odoo_accounting_cli_v3.historical_router import HistoricalRouterError
from odoo_accounting_cli_v3.odoo.bootstrap import request_context_from_mapping
from odoo_accounting_cli_v3.persistence import StoredPrecheckRecord
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    approve_operation,
    begin_execution,
    canonical_json,
    complete_operation,
    record_execution_result,
    record_precheck,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.trusted_authority import (
    ApprovalDecision,
    AuthorityCommitOutcomeUnknownError,
    AuthorityError,
    AuthorityKnownCommittedError,
    AuthorityKeys,
    AuthorityReconciliationRequiredError,
    InMemoryApprovalChallengeStore,
    TrustedAuthority,
    TrustedSession,
)
from odoo_accounting_cli_v3.trusted_broker import (
    AuthorizedReadAction,
    ReleaseAuthority,
    ReleaseResponseVerifier,
    TrustedBroker,
    TrustedBrokerError,
)
from odoo_accounting_cli_v3.trusted_broker_uds import (
    BrokerDispatchRequest,
    BrokerDispatchResult,
)
from odoo_accounting_cli_v3.trusted_session_sqlite import (
    TrustedSessionCommitOutcomeUnknownError,
    TrustedSessionKnownCommittedError,
    TrustedSessionReconciliationRequiredError,
    TrustedSessionStoreError,
)
from odoo_accounting_cli_v3.write_protocol import approval_from_mapping


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
CURRENT_RELEASE = "1" * 64
CURRENT_REGISTRY = "2" * 64
OLD_RELEASE = "3" * 64
OLD_REGISTRY = "4" * 64
EXECUTION_SECRET = b"broker-execution-result-secret-32-bytes"
VERIFICATION_SECRET = b"broker-verification-result-secret-32-bytes"
READ_SECRET = b"broker-read-context-secret-material-32"


class MutableClock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class SequenceFactory:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return f"{self.prefix}-{self.value}"


def _session(
    session_id: str,
    principal: str,
    user_id: int,
    *,
    company_id: int = 7,
) -> TrustedSession:
    return TrustedSession(
        session_id=session_id,
        principal=principal,
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
        release_digest=CURRENT_RELEASE,
        registry_digest=CURRENT_REGISTRY,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=2),
    )


class FakeHistoricalExecutor:
    def __init__(self, operations: dict[str, Operation]) -> None:
        self.operations = operations
        self.calls: list[tuple[str, dict]] = []
        self.deadlines: list[float | None] = []
        self.expected_context_keys = {
            CURRENT_RELEASE: "current-context-key",
            OLD_RELEASE: "old-context-key",
        }
        self.expected_approval_keys = {
            CURRENT_RELEASE: "current-approval-key",
            OLD_RELEASE: "old-approval-key",
        }
        self.approval_secrets = {
            CURRENT_RELEASE: b"current-approval-secret-material-32",
            OLD_RELEASE: b"old-release-approval-secret-material",
        }
        self.execution_effects = 0
        self.prepare_effects = 0
        self.tamper_identity = False
        self.idempotency: dict[tuple[str, int, str, str], str] = {}
        self.recovery_idempotency: dict[tuple[str, int, str, str], str] = {}
        self.precheck_records: dict[str, dict[str, Any]] = {}
        self.precheck_evidence_mutator = lambda evidence: evidence
        self.recovery_effects = 0
        self.raise_after_effect_actions: set[str] = set()

    def _raise_after_effect(self, action: str) -> None:
        if action in self.raise_after_effect_actions:
            self.raise_after_effect_actions.remove(action)
            raise RuntimeError("executor response was lost after durable effect")

    def _route(self, action: str, request: dict) -> tuple[str, str, str]:
        if action == "operation.prepare":
            existing = self.operations.get(request["operation_id"])
            if existing is not None:
                return (
                    existing.release_digest,
                    existing.registry_digest,
                    existing.operation_id,
                )
            return CURRENT_RELEASE, CURRENT_REGISTRY, request["operation_id"]
        operation_id = (
            request["origin_operation_id"]
            if action == "operation.recover"
            else request["operation_id"]
        )
        operation = self.operations[operation_id]
        return operation.release_digest, operation.registry_digest, operation_id

    @staticmethod
    def _identity(operation: Operation) -> dict:
        return {
            "operation_id": operation.operation_id,
            "release_digest": operation.release_digest,
            "registry_digest": operation.registry_digest,
            "state": operation.state.value,
        }

    def _terminal(self, action: str, operation: Operation) -> dict:
        identity = {
            "operation_id": operation.operation_id,
            "release_digest": operation.release_digest,
            "registry_digest": operation.registry_digest,
            "signature": "a" * 64,
        }
        if self.tamper_identity:
            identity["release_digest"] = "f" * 64
        return {
            "business_succeeded": operation.state is State.COMPLETED,
            "command": action,
            "data": {
                "operation_id": operation.operation_id,
                "operation_state": operation.state.value,
                "audit_receipt": identity,
            },
            "ok": True,
        }

    def dispatch(
        self,
        action: str,
        request: dict,
        *,
        deadline_monotonic: float | None = None,
    ) -> dict:
        detached = request.copy()
        detached["context"] = request["context"].copy()
        self.calls.append((action, detached))
        self.deadlines.append(deadline_monotonic)
        release, registry, operation_id = self._route(action, request)
        context = request_context_from_mapping(request["context"])
        assert context.auth_key_id == self.expected_context_keys[release]

        if action == "operation.prepare":
            parameters = request["parameters"]
            candidate = Operation.prepare(
                operation_id=operation_id,
                request_id=request["request_id"],
                capability_id=request["capability_id"],
                parameters=parameters,
                principal=context.principal,
                user_id=context.user_id,
                company_id=context.company_id,
                idempotency_key=parameters["idempotency_key"],
                odoo_instance_id=context.odoo_instance_id,
                database_name=context.database_name,
                database_uuid=context.database_uuid,
                environment=context.environment,
                registry_digest=registry,
                release_digest=release,
            )
            key = (
                context.principal,
                context.company_id,
                request["capability_id"],
                parameters["idempotency_key"],
            )
            existing_id = self.idempotency.get(key)
            if existing_id is None:
                operation = candidate
                self.operations[operation.operation_id] = operation
                self.idempotency[key] = operation.operation_id
                self.prepare_effects += 1
            else:
                operation = self.operations[existing_id]
                if operation.digest != candidate.digest:
                    raise HistoricalRouterError(
                        "idempotency content mismatch",
                        code="idempotency_conflict",
                        odoo_effect="none",
                    )
            self._raise_after_effect(action)
            return {
                "command": action,
                "data": {
                    "operation_id": operation.operation_id,
                    "operation": self._identity(operation),
                },
                "ok": True,
            }

        operation = self.operations[operation_id]
        if action == "operation.preview":
            if operation.state is State.PREPARED:
                evidence = {
                    "capability_id": operation.capability_id,
                    "company_id": operation.company_id,
                    "parameters_digest": hashlib.sha256(
                        canonical_json(operation.parameters)
                    ).hexdigest(),
                    "passed": True,
                    "checks": ["accounting_dependencies", "tax_preview"],
                    "handler_details": {
                        "dependencies": [
                            {
                                "model": "res.partner",
                                "record_id": operation.parameters["partner_id"],
                                "display_name": "Customer 101",
                            }
                        ],
                        "financial_preview": {
                            "amount_untaxed": "100.00",
                            "amount_tax": "10.00",
                            "amount_total": "110.00",
                        },
                    },
                    "runtime_binding": {
                        "user_id": operation.user_id,
                        "odoo_instance_id": operation.odoo_instance_id,
                        "database_name": operation.database_name,
                        "database_uuid": operation.database_uuid,
                        "environment": operation.environment,
                        "capability_channel": "staged",
                    },
                    "registry_digest": operation.registry_digest,
                    "release_digest": operation.release_digest,
                }
                evidence = self.precheck_evidence_mutator(evidence)
                evidence_json = canonical_json(evidence).decode("utf-8")
                precheck_digest = hashlib.sha256(
                    evidence_json.encode("utf-8")
                ).hexdigest()
                self.precheck_records[operation_id] = {
                    "operation_id": operation.operation_id,
                    "request_id": operation.request_id,
                    "operation_digest": operation.digest,
                    "operation_revision": operation.revision,
                    "principal": operation.principal,
                    "user_id": operation.user_id,
                    "company_id": operation.company_id,
                    "evidence_digest": precheck_digest,
                    "evidence_json": evidence_json,
                    "occurred_at": NOW,
                }
                operation = record_precheck(
                    operation,
                    precheck_digest=precheck_digest,
                    expected_revision=operation.revision,
                )
                operation = operation.transition(
                    State.AWAITING_APPROVAL,
                    expected_revision=operation.revision,
                )
                self.operations[operation_id] = operation
            precheck = {
                "operation_id": operation_id,
                "operation_digest": operation.digest,
                "precheck_digest": operation.precheck_digest,
                "release_digest": release,
                "registry_digest": registry,
            }
            if self.tamper_identity:
                precheck["registry_digest"] = "f" * 64
            return {
                "command": action,
                "data": {
                    "operation_id": operation_id,
                    "precheck": precheck,
                    "precheck_identity": {
                        "operation_id": operation_id,
                        "precheck_digest": operation.precheck_digest,
                        "release_digest": release,
                        "registry_digest": (
                            "f" * 64 if self.tamper_identity else registry
                        ),
                    },
                },
                "ok": True,
            }
        if action == "operation.approve_execute":
            approval = approval_from_mapping(request["approval"])
            assert approval.key_id == self.expected_approval_keys[release]
            if operation.state is State.COMPLETED:
                return self._terminal(action, operation)
            approved = approve_operation(
                operation,
                approval,
                now=NOW,
                secret=self.approval_secrets[release],
                expected_key_id=self.expected_approval_keys[release],
                is_approver_authorized=lambda *_args: True,
                consume_nonce=lambda *_args: True,
                approval_ttl_seconds=120,
                expected_revision=operation.revision,
            )
            executing = begin_execution(
                approved,
                approval,
                now=NOW,
                secret=self.approval_secrets[release],
                expected_key_id=self.expected_approval_keys[release],
                is_approver_authorized=lambda *_args: True,
                approval_ttl_seconds=120,
                expected_revision=approved.revision,
            )
            execution = sign_execution_result(
                operation=executing,
                issuer="fake-odoo",
                key_id="execution-key",
                succeeded=True,
                evidence_digest="6" * 64,
                issued_at=NOW,
                secret=EXECUTION_SECRET,
            )
            verifying = record_execution_result(
                executing,
                execution,
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id="execution-key",
                allowed_issuers=frozenset({"fake-odoo"}),
                expected_revision=executing.revision,
            )
            verification = sign_verification_result(
                operation=verifying,
                issuer="fake-verifier",
                key_id="verification-key",
                succeeded=True,
                evidence_digest="7" * 64,
                issued_at=NOW,
                secret=VERIFICATION_SECRET,
            )
            completed = complete_operation(
                verifying,
                verification,
                now=NOW,
                secret=VERIFICATION_SECRET,
                expected_key_id="verification-key",
                allowed_issuers=frozenset({"fake-verifier"}),
                expected_revision=verifying.revision,
            )
            self.operations[operation_id] = completed
            self.execution_effects += 1
            self._raise_after_effect(action)
            return self._terminal(action, completed)
        if action == "operation.result":
            return self._terminal(action, operation)
        if action == "operation.status":
            return {
                "command": action,
                "data": {
                    "operation_id": operation_id,
                    "operation": self._identity(operation),
                },
                "ok": True,
            }
        if action == "operation.recover":
            recovery_parameters = {
                "company_id": operation.company_id,
                "origin_operation_id": operation.operation_id,
                "expected_recovery_plan_digest": "8" * 64,
                "recovery_date": request["recovery_date"],
                "reason": request["reason"],
                "idempotency_key": request["idempotency_key"],
            }
            candidate = Operation.prepare(
                operation_id=request["recovery_operation_id"],
                request_id=request["request_id"],
                capability_id="acct.recovery.execute.v1",
                parameters=recovery_parameters,
                principal=context.principal,
                user_id=context.user_id,
                company_id=context.company_id,
                idempotency_key=request["idempotency_key"],
                odoo_instance_id=context.odoo_instance_id,
                database_name=context.database_name,
                database_uuid=context.database_uuid,
                environment=context.environment,
                registry_digest=registry,
                release_digest=release,
            )
            key = (
                context.principal,
                context.company_id,
                operation.operation_id,
                request["idempotency_key"],
            )
            existing_id = self.recovery_idempotency.get(key)
            if existing_id is None:
                recovery = candidate
                self.operations[recovery.operation_id] = recovery
                self.recovery_idempotency[key] = recovery.operation_id
                self.recovery_effects += 1
            else:
                recovery = self.operations[existing_id]
                if recovery.digest != candidate.digest:
                    raise HistoricalRouterError(
                        "recovery idempotency content mismatch",
                        code="idempotency_conflict",
                        odoo_effect="none",
                    )
            self._raise_after_effect(action)
            return {
                "command": action,
                "data": {
                    "operation_id": recovery.operation_id,
                    "origin_operation_id": operation_id,
                    "operation": self._identity(recovery),
                },
                "ok": True,
            }
        raise AssertionError(action)


class Harness:
    def __init__(self, *, audit_sink=None) -> None:
        self.clock = MutableClock()
        self.sessions = {
            "requester-session-0123456789abcdef": _session(
                "session-requester", "pi:user-42", 42
            ),
            "approver-session-0123456789abcdef": _session(
                "session-approver", "pi:user-84", 84
            ),
            "other-session-0123456789abcdef0123": _session(
                "session-other", "pi:user-99", 99
            ),
            "company-8-session-0123456789abcdef": _session(
                "session-company-8", "pi:user-88", 88, company_id=8
            ),
            "email-session-0123456789abcdef0123": _session(
                "session-email", "user+accounting@example.com", 55
            ),
        }
        self.operations: dict[str, Operation] = {}
        self.executor = FakeHistoricalExecutor(self.operations)
        self.authorities: dict[tuple[str, str], ReleaseAuthority] = {}
        self.stores: dict[tuple[str, str], InMemoryApprovalChallengeStore] = {}
        self.authority_resolutions: list[tuple[str, str]] = []
        self.read_authorizations = 0
        self.read_executions = 0
        self.read_tamper = False
        self.response_verification_accepts = True
        self.response_verifier_unavailable_routes: set[tuple[str, str]] = set()
        self.response_verifications: list[tuple[str, str, str]] = []
        self.prepare_idempotency_resolution_error = False
        self.prepare_idempotency_override: str | None = None
        self.prepare_idempotency_override_enabled = False
        self.prepare_idempotency_resolutions: list[
            tuple[str, str, dict[str, object]]
        ] = []
        self._audit_directory = tempfile.TemporaryDirectory(
            prefix="odoo-accounting-cli-v3-broker-audit-"
        )
        self.audit = (
            SQLiteBrokerAuditSink(
                (Path(self._audit_directory.name) / "broker-audit.sqlite3").resolve()
            )
            if audit_sink is None
            else audit_sink
        )
        self._audit_record = self.audit.record
        self._add_authority(
            CURRENT_RELEASE,
            CURRENT_REGISTRY,
            context_key="current-context-key",
            context_secret=b"current-context-secret-material-32-bytes",
            approval_key="current-approval-key",
            approval_secret=self.executor.approval_secrets[CURRENT_RELEASE],
            challenge_prefix="current-challenge",
        )
        self._add_authority(
            OLD_RELEASE,
            OLD_REGISTRY,
            context_key="old-context-key",
            context_secret=b"old-context-secret-material-32-bytes",
            approval_key="old-approval-key",
            approval_secret=self.executor.approval_secrets[OLD_RELEASE],
            challenge_prefix="old-challenge",
        )
        self.broker = TrustedBroker(
            current_release_digest=CURRENT_RELEASE,
            current_registry_digest=CURRENT_REGISTRY,
            session_resolver=lambda handle: self.sessions.get(handle),
            authority_resolver=self.resolve_authority,
            challenge_authority_resolver=self.resolve_challenge_authority,
            response_verifier_resolver=self.resolve_response_verifier,
            audit_sink=self.audit,
            prepare_idempotency_resolver=self.resolve_prepare_idempotency,
            recovery_idempotency_resolver=self.resolve_recovery_idempotency,
            operation_resolver=lambda operation_id: self.operations.get(operation_id),
            historical_executor=self.executor,
            read_authorizer=self.authorize_read,
            read_executor=self.execute_read,
            operation_id_factory=SequenceFactory("operation"),
            request_id_factory=SequenceFactory("request"),
            recovery_operation_id_factory=SequenceFactory("recovery"),
            utc_clock=self.clock,
            precheck_resolver=lambda operation_id: self.executor.precheck_records.get(
                operation_id
            ),
        )

    def set_audit_failure(self, fail: bool) -> None:
        if fail:
            def unavailable(**_fields):
                raise RuntimeError("audit unavailable")

            self.audit.record = unavailable
        else:
            self.audit.record = self._audit_record

    def _add_authority(
        self,
        release: str,
        registry: str,
        *,
        context_key: str,
        context_secret: bytes,
        approval_key: str,
        approval_secret: bytes,
        challenge_prefix: str,
    ) -> None:
        store = InMemoryApprovalChallengeStore()
        authority = TrustedAuthority(
            session_resolver=lambda handle: self.sessions.get(handle),
            operation_resolver=lambda operation_id: self.operations.get(operation_id),
            approver_authorizer=lambda session, operation: (
                session.user_id == 84 and session.company_id == operation.company_id
            ),
            approval_ttl_resolver=lambda _operation: 120,
            keys=AuthorityKeys(
                context_key_id=context_key,
                context_secret=context_secret,
                approval_key_id=approval_key,
                approval_secret=approval_secret,
            ),
            store=store,
            clock=self.clock,
            context_ttl_seconds=300,
            challenge_id_factory=SequenceFactory(challenge_prefix),
            event_id_factory=SequenceFactory(f"{challenge_prefix}-event"),
            nonce_factory=SequenceFactory(f"{challenge_prefix}-nonce"),
            auth_token_id_factory=SequenceFactory(f"{challenge_prefix}-auth"),
        )
        route = (release, registry)
        self.stores[route] = store
        self.authorities[route] = ReleaseAuthority(
            release_digest=release,
            registry_digest=registry,
            authority=authority,
        )

    def resolve_authority(self, release: str, registry: str):
        self.authority_resolutions.append((release, registry))
        return self.authorities.get((release, registry))

    def resolve_challenge_authority(self, challenge_id: str):
        for route, store in self.stores.items():
            if any(item.challenge_id == challenge_id for item in store.challenges()):
                return self.authorities[route]
        return None

    def resolve_response_verifier(self, release: str, registry: str):
        if (
            (release, registry) not in self.authorities
            or (release, registry) in self.response_verifier_unavailable_routes
        ):
            return None

        def verify(action: str, _response: dict, _request: dict) -> bool:
            self.response_verifications.append((release, registry, action))
            return self.response_verification_accepts

        return ReleaseResponseVerifier(
            release_digest=release,
            registry_digest=registry,
            verify=verify,
        )

    def resolve_prepare_idempotency(
        self,
        session: TrustedSession,
        capability_id: str,
        parameters: dict[str, object],
    ) -> str | None:
        self.prepare_idempotency_resolutions.append(
            (session.session_id, capability_id, parameters.copy())
        )
        if self.prepare_idempotency_resolution_error:
            raise RuntimeError("global idempotency index unavailable")
        if self.prepare_idempotency_override_enabled:
            return self.prepare_idempotency_override
        key = (
            session.principal,
            session.company_id,
            capability_id,
            parameters["idempotency_key"],
        )
        return self.executor.idempotency.get(key)

    def resolve_recovery_idempotency(
        self,
        session: TrustedSession,
        origin: Operation,
        request: dict[str, object],
    ) -> str | None:
        key = (
            session.principal,
            session.company_id,
            origin.operation_id,
            request["idempotency_key"],
        )
        return self.executor.recovery_idempotency.get(key)

    def authorize_read(self, session_handle: str, request: dict) -> AuthorizedReadAction:
        self.read_authorizations += 1
        session = self.sessions.get(session_handle)
        if session is None:
            raise TrustedBrokerError("broker_session_rejected")
        context = sign_request_context(
            auth_token_id=f"read-token-{self.read_authorizations}",
            principal=session.principal,
            odoo_instance_id=session.odoo_instance_id,
            database_name=session.database_name,
            database_uuid=session.database_uuid,
            user_id=session.user_id,
            company_id=session.company_id,
            allowed_company_ids=session.allowed_company_ids,
            environment=session.environment,
            capability_id=request["capability_id"],
            parameters=request["parameters"],
            issued_at=self.clock.value,
            expires_at=self.clock.value + timedelta(minutes=5),
            key_id="read-key",
            secret=READ_SECRET,
        )
        return AuthorizedReadAction(context=context, request=request)

    def execute_read(self, request: dict) -> dict:
        self.read_executions += 1
        receipt_release = "f" * 64 if self.read_tamper else CURRENT_RELEASE
        return {
            "command": "read",
            "data": {
                "capability_id": request["capability_id"],
                "release_identity": {
                    "manifest_sha256": CURRENT_RELEASE,
                    "registry_digest": CURRENT_REGISTRY,
                    "verified": True,
                },
                "result": {
                    "receipt": {
                        "release_digest": receipt_release,
                        "registry_digest": CURRENT_REGISTRY,
                    }
                },
                "runtime": {},
            },
            "ok": True,
        }

    def dispatch(
        self,
        action: str,
        payload: dict,
        session: str = "requester-session-0123456789abcdef",
        *,
        deadline_monotonic: float | None = None,
    ):
        return self.broker.dispatch(
            action=action,
            payload=payload,
            session_handle=session,
            expected_release_digest=CURRENT_RELEASE,
            expected_registry_digest=CURRENT_REGISTRY,
            deadline_monotonic=deadline_monotonic,
        )

    def prepare(self) -> str:
        result = self.dispatch(
            "operation.prepare",
            {
                "capability_id": "acct.invoice.customer_create.v1",
                "parameters": {
                    "company_id": 7,
                    "partner_id": 101,
                    "currency_id": 12,
                    "invoice_date": "2026-07-15",
                    "idempotency_key": "invoice-101-20260715",
                },
            },
        )
        assert result.status_code == 200
        return result.body["data"]["operation_id"]

    def preview(self, operation_id: str) -> dict:
        result = self.dispatch("operation.preview", {"operation_id": operation_id})
        assert result.status_code == 200
        return result.body["data"]["approval_challenge"]


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.mark.parametrize(
    "action",
    [
        "read",
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
        "operation.status",
        "operation.result",
        "operation.recover",
    ],
)
@pytest.mark.parametrize(
    "route_override",
    [
        {"release_digest": OLD_RELEASE},
        {"registry_digest": OLD_REGISTRY},
    ],
)
def test_every_pi_entry_rejects_session_from_a_noncurrent_addon_route(
    harness: Harness, action: str, route_override: dict[str, str]
) -> None:
    handle = "requester-session-0123456789abcdef"
    harness.sessions[handle] = replace(harness.sessions[handle], **route_override)

    result = harness.dispatch(action, {}, session=handle)

    assert result.status_code == 401
    assert result.authority_verified is False
    assert result.body["error"]["code"] == "broker_session_rejected"
    assert harness.read_authorizations == 0
    assert harness.read_executions == 0
    assert harness.executor.calls == []
    assert harness.audit.events() == ()


@pytest.mark.parametrize("approval_entry", ["request", "inspect", "decide"])
@pytest.mark.parametrize(
    "route_override",
    [
        {"release_digest": OLD_RELEASE},
        {"registry_digest": OLD_REGISTRY},
    ],
)
def test_every_approval_entry_rejects_session_from_a_noncurrent_addon_route(
    harness: Harness,
    approval_entry: str,
    route_override: dict[str, str],
) -> None:
    handle = (
        "requester-session-0123456789abcdef"
        if approval_entry == "request"
        else "approver-session-0123456789abcdef"
    )
    harness.sessions[handle] = replace(harness.sessions[handle], **route_override)

    with pytest.raises(TrustedBrokerError) as rejected:
        if approval_entry == "request":
            harness.broker.request_approval(
                session_handle=handle,
                operation_id="unreachable-operation",
            )
        elif approval_entry == "inspect":
            harness.broker.inspect_approval(
                session_handle=handle,
                challenge_id="unreachable-challenge",
            )
        else:
            harness.broker.decide_approval(
                session_handle=handle,
                challenge_id="unreachable-challenge",
                decision=ApprovalDecision.APPROVE,
            )

    assert rejected.value.code == "broker_session_rejected"
    assert rejected.value.status_code == 401
    assert harness.executor.calls == []
    assert harness.audit.events() == ()


def test_write_forwards_the_exact_outer_deadline_to_historical_execution(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    deadline = time.monotonic() + 30

    result = harness.dispatch(
        "operation.status",
        {"operation_id": operation_id},
        deadline_monotonic=deadline,
    )

    assert result.body["ok"] is True
    assert harness.executor.deadlines[-1] == deadline


@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
def test_session_reconciliation_error_is_safe_non_authoritative_and_stops_before_executor(
    harness: Harness,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
) -> None:
    backend_secret = "private-session-backend-state"
    session_handle = "requester-session-0123456789abcdef"

    def wrapped_failure(_handle: str) -> TrustedSession:
        try:
            raise reconciliation_error(backend_secret)
        except TrustedSessionStoreError as exc:
            raise TrustedSessionStoreError("private-wrapper") from exc

    harness.broker._session_resolver = wrapped_failure
    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": "session-reconciliation-required",
            },
        },
        session=session_handle,
    )

    assert result.status_code == 503
    assert result.authority_verified is False
    assert result.executed_release_digest is None
    assert result.executed_registry_digest is None
    assert result.body["error"] == {
        "code": "broker_session_reconciliation_required",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "reconciliation_required": True,
        "retryable": False,
    }
    serialized = json.dumps(result.body, sort_keys=True)
    assert session_handle not in serialized
    assert backend_secret not in serialized
    assert "private-wrapper" not in serialized
    assert harness.executor.calls == []
    assert harness.read_authorizations == 0
    assert harness.audit.events() == ()


@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
def test_authenticated_read_reconciliation_keeps_authority_envelope_and_stops_executor(
    harness: Harness,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
) -> None:
    backend_secret = "private-read-authority-state"

    def fail_authorization(*_args, **_kwargs) -> AuthorizedReadAction:
        try:
            raise reconciliation_error(backend_secret)
        except TrustedSessionReconciliationRequiredError as exc:
            raise TrustedSessionStoreError("private-wrapper") from exc

    harness.broker._read_authorizer = fail_authorization
    result = harness.dispatch(
        "read",
        {
            "capability_id": "acct.gl.trial_balance.v1",
            "parameters": {"company_id": 7},
        },
    )

    assert result.status_code == 200
    assert result.authority_verified is True
    assert result.executed_release_digest is None
    assert result.executed_registry_digest is None
    assert result.body["error"] == {
        "code": "broker_session_reconciliation_required",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "reconciliation_required": True,
        "retryable": False,
    }
    serialized = json.dumps(result.body, sort_keys=True)
    assert backend_secret not in serialized
    assert "private-wrapper" not in serialized
    assert harness.read_executions == 0
    assert harness.executor.calls == []


@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
@pytest.mark.parametrize(
    ("approval_action", "authority_method"),
    [
        ("request", "request_approval"),
        ("inspect", "inspect_approval"),
        ("decide", "decide_approval"),
    ],
)
def test_independent_approval_reconciliation_has_one_safe_non_retryable_mapping(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
    approval_action: str,
    authority_method: str,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    executor_calls = len(harness.executor.calls)
    backend_secret = f"private-{approval_action}-authority-state"

    def fail_authority(*_args, **_kwargs):
        try:
            raise reconciliation_error(backend_secret)
        except TrustedSessionReconciliationRequiredError as exc:
            raise TrustedSessionStoreError("private-wrapper") from exc

    monkeypatch.setattr(TrustedAuthority, authority_method, fail_authority)
    with pytest.raises(TrustedBrokerError) as rejected:
        if approval_action == "request":
            harness.broker.request_approval(
                session_handle="requester-session-0123456789abcdef",
                operation_id=operation_id,
            )
        elif approval_action == "inspect":
            harness.broker.inspect_approval(
                session_handle="approver-session-0123456789abcdef",
                challenge_id=challenge["challenge_id"],
            )
        else:
            harness.broker.decide_approval(
                session_handle="approver-session-0123456789abcdef",
                challenge_id=challenge["challenge_id"],
                decision=ApprovalDecision.APPROVE,
            )

    error = rejected.value
    assert error.code == "broker_session_reconciliation_required"
    assert error.status_code == 503
    assert error.odoo_effect == "none"
    assert error.retryable is False
    assert error.reconciliation_required is True
    assert backend_secret not in str(error)
    assert "private-wrapper" not in str(error)
    assert len(harness.executor.calls) == executor_calls
    event = harness.audit.events()[-1]
    assert event.action == f"approval.{approval_action}"
    assert event.outcome_code == "broker_session_reconciliation_required"


@pytest.mark.parametrize(
    "reconciliation_error",
    [AuthorityKnownCommittedError, AuthorityCommitOutcomeUnknownError],
)
@pytest.mark.parametrize(
    ("approval_action", "authority_method"),
    [
        ("request", "request_approval"),
        ("inspect", "inspect_approval"),
        ("decide", "decide_approval"),
    ],
)
def test_authority_reconciliation_is_non_retryable_and_stops_before_executor(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_error: type[AuthorityReconciliationRequiredError],
    approval_action: str,
    authority_method: str,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    executor_calls = len(harness.executor.calls)
    backend_secret = f"private-{approval_action}-authority-store-state"

    def fail_authority(*_args, **_kwargs):
        try:
            raise reconciliation_error(backend_secret)
        except AuthorityReconciliationRequiredError as exc:
            raise AuthorityError("private-authority-wrapper") from exc

    monkeypatch.setattr(TrustedAuthority, authority_method, fail_authority)
    with pytest.raises(TrustedBrokerError) as rejected:
        if approval_action == "request":
            harness.broker.request_approval(
                session_handle="requester-session-0123456789abcdef",
                operation_id=operation_id,
            )
        elif approval_action == "inspect":
            harness.broker.inspect_approval(
                session_handle="approver-session-0123456789abcdef",
                challenge_id=challenge["challenge_id"],
            )
        else:
            harness.broker.decide_approval(
                session_handle="approver-session-0123456789abcdef",
                challenge_id=challenge["challenge_id"],
                decision=ApprovalDecision.APPROVE,
            )

    error = rejected.value
    assert error.code == "broker_authority_reconciliation_required"
    assert error.status_code == 503
    assert error.odoo_effect == "none"
    assert error.retryable is False
    assert error.reconciliation_required is True
    assert backend_secret not in str(error)
    assert "private-authority-wrapper" not in str(error)
    assert len(harness.executor.calls) == executor_calls
    event = harness.audit.events()[-1]
    assert event.action == f"approval.{approval_action}"
    assert event.outcome_code == "broker_authority_reconciliation_required"


def test_authority_reconciliation_dominates_secondary_approval_audit_failure(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)

    def fail_decision(*_args, **_kwargs):
        raise AuthorityKnownCommittedError("private committed decision")

    monkeypatch.setattr(TrustedAuthority, "decide_approval", fail_decision)
    harness.set_audit_failure(True)
    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.decide_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            decision=ApprovalDecision.APPROVE,
        )

    assert rejected.value.code == "broker_authority_reconciliation_required"
    assert rejected.value.retryable is False
    assert rejected.value.reconciliation_required is True


def test_write_authority_reconciliation_dominates_broker_audit_failure(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    executor_calls = len(harness.executor.calls)

    def fail_issue(*_args, **_kwargs):
        raise AuthorityCommitOutcomeUnknownError("private commit state")

    monkeypatch.setattr(
        TrustedAuthority,
        "issue_approved_execute_for_operation",
        fail_issue,
    )
    harness.set_audit_failure(True)
    result = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )

    assert result.status_code == 200
    assert result.authority_verified is True
    assert result.body["error"] == {
        "code": "broker_authority_reconciliation_required",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "reconciliation_required": True,
        "retryable": False,
    }
    assert len(harness.executor.calls) == executor_calls


@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
def test_approve_execute_session_reconciliation_never_claims_unknown_odoo_effect(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    executor_calls = len(harness.executor.calls)
    execution_effects = harness.executor.execution_effects
    backend_secret = "private-approved-execute-authority-state"

    def fail_authority(*_args, **_kwargs):
        try:
            raise reconciliation_error(backend_secret)
        except TrustedSessionReconciliationRequiredError as exc:
            raise TrustedSessionStoreError("private-wrapper") from exc

    monkeypatch.setattr(
        TrustedAuthority,
        "issue_approved_execute_for_operation",
        fail_authority,
    )
    result = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )

    assert result.status_code == 200
    assert result.authority_verified is True
    assert result.executed_release_digest is None
    assert result.executed_registry_digest is None
    assert result.body["error"] == {
        "code": "broker_session_reconciliation_required",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "reconciliation_required": True,
        "retryable": False,
    }
    assert result.body["error"]["odoo_effect"] != "unknown"
    serialized = json.dumps(result.body, sort_keys=True)
    assert backend_secret not in serialized
    assert "private-wrapper" not in serialized
    assert len(harness.executor.calls) == executor_calls
    assert harness.executor.execution_effects == execution_effects
    event = harness.audit.events()[-1]
    assert event.action == "operation.approve_execute"
    assert event.operation_id == operation_id
    assert event.outcome_code == "broker_session_reconciliation_required"


def test_full_business_lifecycle_requires_independent_approval_and_is_replay_safe(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)

    assert harness.operations[operation_id].state is State.AWAITING_APPROVAL
    assert challenge == {
        "capability_id": "acct.invoice.customer_create.v1",
        "challenge_id": "current-challenge-1",
        "company_id": 7,
        "expires_at": "2026-07-15T08:02:00+00:00",
        "issued_at": "2026-07-15T08:00:00+00:00",
        "operation_digest": harness.operations[operation_id].digest,
        "operation_id": operation_id,
        "precheck_digest": harness.operations[operation_id].precheck_digest,
        "requester_user_id": 42,
        "state": "pending",
    }

    before = len(harness.executor.calls)
    rejected = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert rejected.status_code == 200
    assert rejected.body["ok"] is False
    assert rejected.authority_verified is True
    assert len(harness.executor.calls) == before

    decided = harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    assert decided["state"] == "approved"
    assert "approval" not in decided
    assert "signature" not in str(decided)

    executed = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert executed.status_code == 200
    assert executed.body["business_succeeded"] is True
    assert executed.executed_release_digest == CURRENT_RELEASE
    assert harness.operations[operation_id].state is State.COMPLETED
    assert harness.executor.execution_effects == 1

    result = harness.dispatch("operation.result", {"operation_id": operation_id})
    replay = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert result.body["data"]["audit_receipt"] == replay.body["data"]["audit_receipt"]
    assert harness.executor.execution_effects == 1


def test_preview_reuses_one_challenge_and_never_exposes_approval_material(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    first = harness.preview(operation_id)
    second = harness.preview(operation_id)
    assert second == first
    assert len(harness.stores[(CURRENT_RELEASE, CURRENT_REGISTRY)].challenges()) == 1
    assert "nonce" not in str(second)
    assert "approval" not in second


def test_independent_approval_audit_records_transport_observed_peer_facts(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)

    requested = harness.broker.request_approval(
        session_handle="requester-session-0123456789abcdef",
        operation_id=operation_id,
        peer_uid=1101,
        peer_gid=1102,
        peer_pid=4321,
    )
    assert requested["challenge_id"] == challenge["challenge_id"]
    request_event = harness.audit.events()[-1]
    assert request_event.action == "approval.request"
    assert request_event.peer_uid == 1101
    assert request_event.peer_gid == 1102
    assert request_event.peer_pid == 4321

    decided = harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
        peer_uid=1101,
        peer_gid=1103,
        peer_pid=4322,
    )
    assert decided["state"] == "approved"
    decision_event = harness.audit.events()[-1]
    assert decision_event.action == "approval.decide"
    assert decision_event.peer_uid == 1101
    assert decision_event.peer_gid == 1103
    assert decision_event.peer_pid == 4322


def test_approval_inspect_returns_bound_precheck_evidence_and_audits_peer(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    operation = harness.operations[operation_id]

    inspected = harness.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        peer_uid=1101,
        peer_gid=1103,
        peer_pid=4322,
    )

    assert json.loads(canonical_json(inspected)) == inspected
    assert inspected["challenge"]["challenge_id"] == challenge["challenge_id"]
    assert inspected["operation"]["parameters"] == {
        "company_id": 7,
        "currency_id": 12,
        "idempotency_key": "invoice-101-20260715",
        "invoice_date": "2026-07-15",
        "partner_id": 101,
    }
    precheck = inspected["precheck"]
    assert precheck["operation_id"] == operation.operation_id
    assert precheck["request_id"] == operation.request_id
    assert precheck["operation_digest"] == operation.digest
    assert precheck["operation_revision"] == operation.revision
    assert precheck["source_operation_revision"] == operation.revision - 2
    assert precheck["principal"] == operation.principal
    assert precheck["user_id"] == operation.user_id
    assert precheck["company_id"] == operation.company_id
    assert precheck["evidence_digest"] == operation.precheck_digest
    assert precheck["evidence"]["handler_details"]["financial_preview"] == {
        "amount_untaxed": "100.00",
        "amount_tax": "10.00",
        "amount_total": "110.00",
    }
    assert precheck["evidence"]["handler_details"]["dependencies"] == [
        {
            "display_name": "Customer 101",
            "model": "res.partner",
            "record_id": 101,
        }
    ]
    unsigned = {
        key: value for key, value in inspected.items() if key != "inspection_digest"
    }
    assert inspected["inspection_digest"] == hashlib.sha256(
        canonical_json(unsigned)
    ).hexdigest()
    assert "session_handle" not in str(inspected)
    assert "signature" not in str(inspected)
    assert "approval" not in inspected

    event = harness.audit.events()[-1]
    assert event.action == "approval.inspect"
    assert event.operation_id == operation.operation_id
    assert event.request_id == operation.request_id
    assert event.challenge_id == challenge["challenge_id"]
    assert event.selected_release_digest == operation.release_digest
    assert event.selected_registry_digest == operation.registry_digest
    assert event.peer_uid == 1101
    assert event.peer_gid == 1103
    assert event.peer_pid == 4322
    assert event.outcome_code == "ok"

    inspected["operation"]["parameters"]["partner_id"] = 999
    inspected["precheck"]["evidence"]["handler_details"]["dependencies"][0][
        "display_name"
    ] = "tampered"
    repeated = harness.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
    )
    assert repeated["operation"]["parameters"]["partner_id"] == 101
    assert repeated["precheck"]["evidence"]["handler_details"]["dependencies"][0][
        "display_name"
    ] == "Customer 101"


def test_approval_inspect_accepts_sqlite_persistence_precheck_record_contract(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    raw = harness.executor.precheck_records[operation_id]
    stored = StoredPrecheckRecord(
        **raw,
        audit_event_id="operation.prechecked:test",
        record_hash="a" * 64,
    )
    harness.broker._precheck_resolver = lambda selected_id: (
        stored if selected_id == operation_id else None
    )

    inspected = harness.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
    )

    assert inspected["precheck"]["evidence_digest"] == stored.evidence_digest
    assert inspected["precheck"]["evidence"] == stored.evidence


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record.__setitem__("operation_revision", 1),
        lambda record: record.__setitem__("company_id", 8),
        lambda record: record.__setitem__("evidence_digest", "f" * 64),
        lambda record: record.__setitem__("occurred_at", NOW + timedelta(seconds=1)),
        lambda record: record.__setitem__(
            "evidence_json",
            record["evidence_json"].replace(
                '"amount_total":"110.00"', '"amount_total":"999.00"'
            ),
        ),
    ],
)
def test_approval_inspect_fails_closed_on_precheck_record_drift(
    harness: Harness, mutate
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    mutate(harness.executor.precheck_records[operation_id])

    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.inspect_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            peer_uid=1101,
            peer_gid=1103,
            peer_pid=4322,
        )

    assert rejected.value.code == "broker_approval_precheck_rejected"
    assert str(rejected.value) == "broker_approval_precheck_rejected"
    event = harness.audit.events()[-1]
    assert event.action == "approval.inspect"
    assert event.outcome_code == "broker_approval_precheck_rejected"
    assert event.peer_uid == 1101
    assert event.peer_gid == 1103
    assert event.peer_pid == 4322


@pytest.mark.parametrize(
    "mutate_evidence",
    [
        lambda evidence: {**evidence, "capability_id": "acct.bill.vendor_create.v1"},
        lambda evidence: {
            key: value
            for key, value in evidence.items()
            if key not in {"capability_id", "company_id", "parameters_digest"}
        },
        lambda evidence: {
            key: value for key, value in evidence.items() if key != "company_id"
        },
        lambda evidence: {**evidence, "parameters_digest": "f" * 64},
        lambda evidence: {
            **evidence,
            "runtime_binding": {
                **evidence["runtime_binding"],
                "user_id": 999,
            },
        },
        lambda evidence: {
            key: value for key, value in evidence.items() if key != "runtime_binding"
        },
        lambda evidence: {
            **evidence,
            "runtime_binding": {
                key: value
                for key, value in evidence["runtime_binding"].items()
                if key != "database_uuid"
            },
        },
        lambda evidence: {**evidence, "release_digest": "f" * 64},
        lambda evidence: {
            key: value
            for key, value in evidence.items()
            if key not in {"release_digest", "registry_digest"}
        },
        lambda evidence: {
            key: value for key, value in evidence.items() if key != "registry_digest"
        },
    ],
)
def test_approval_inspect_rejects_semantically_unbound_precheck_evidence(
    harness: Harness, mutate_evidence
) -> None:
    operation_id = harness.prepare()
    harness.executor.precheck_evidence_mutator = mutate_evidence
    challenge = harness.preview(operation_id)
    operation = harness.operations[operation_id]
    record = harness.executor.precheck_records[operation_id]
    assert record["evidence_digest"] == operation.precheck_digest

    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.inspect_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
        )

    assert rejected.value.code == "broker_approval_precheck_rejected"
    assert harness.audit.events()[-1].outcome_code == (
        "broker_approval_precheck_rejected"
    )


def test_approval_inspect_reports_recomputed_expired_and_stale_states(
    harness: Harness,
) -> None:
    expired_operation_id = harness.prepare()
    expired_challenge = harness.preview(expired_operation_id)
    harness.clock.value = NOW + timedelta(seconds=120)

    expired = harness.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=expired_challenge["challenge_id"],
    )

    assert expired["challenge"]["state"] == "expired"
    expired_store = harness.stores[(CURRENT_RELEASE, CURRENT_REGISTRY)]
    assert expired_store.get_challenge(
        expired_challenge["challenge_id"]
    ).approval is None

    second = Harness()
    stale_operation_id = second.prepare()
    stale_challenge = second.preview(stale_operation_id)
    second.operations[stale_operation_id] = replace(
        second.operations[stale_operation_id], precheck_digest="f" * 64
    )

    stale = second.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=stale_challenge["challenge_id"],
    )

    assert stale["challenge"]["state"] == "stale"
    stale_store = second.stores[(CURRENT_RELEASE, CURRENT_REGISTRY)]
    assert stale_store.get_challenge(stale_challenge["challenge_id"]).approval is None


def test_approval_inspect_never_exposes_authority_after_decision(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )

    inspected = harness.broker.inspect_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
    )

    assert inspected["challenge"]["state"] == "approved"

    def keys(value):
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert keys(inspected).isdisjoint(
        {
            "approval",
            "approval_signature",
            "auth_signature",
            "nonce",
            "session_handle",
        }
    )


def test_approval_inspect_backend_error_is_safe_and_audited(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)

    def fail_precheck(_operation_id: str):
        raise RuntimeError("private durable precheck backend detail")

    harness.broker._precheck_resolver = fail_precheck
    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.inspect_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            peer_uid=1101,
            peer_gid=1103,
            peer_pid=4322,
        )

    assert rejected.value.code == "broker_approval_precheck_rejected"
    assert str(rejected.value) == "broker_approval_precheck_rejected"
    assert "private durable precheck backend detail" not in str(rejected.value)
    event = harness.audit.events()[-1]
    assert event.action == "approval.inspect"
    assert event.operation_id == operation_id
    assert event.challenge_id == challenge["challenge_id"]
    assert event.outcome_code == "broker_approval_precheck_rejected"


@pytest.mark.parametrize(
    ("session_handle", "expected_code"),
    [
        ("requester-session-0123456789abcdef", "broker_approval_rejected"),
        ("other-session-0123456789abcdef0123", "broker_approval_rejected"),
        ("company-8-session-0123456789abcdef", "broker_approval_rejected"),
    ],
)
def test_approval_inspect_enforces_approver_identity_acl_and_company(
    harness: Harness, session_handle: str, expected_code: str
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)

    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.inspect_approval(
            session_handle=session_handle,
            challenge_id=challenge["challenge_id"],
        )

    assert rejected.value.code == expected_code
    assert harness.audit.events()[-1].action == "approval.inspect"
    assert harness.audit.events()[-1].outcome_code == expected_code


@pytest.mark.parametrize(
    "peer_metadata",
    [
        {"peer_uid": 1101},
        {"peer_uid": True, "peer_gid": 1102, "peer_pid": 4321},
        {"peer_uid": 1101, "peer_gid": -1, "peer_pid": 4321},
        {"peer_uid": 1101, "peer_gid": 1102, "peer_pid": 0},
        {"peer_uid": 2**32, "peer_gid": 1102, "peer_pid": 4321},
        {"peer_uid": 1101, "peer_gid": 1102, "peer_pid": 2**31},
    ],
)
def test_independent_approval_rejects_malformed_transport_peer_tuple_before_audit(
    harness: Harness, peer_metadata: dict[str, Any]
) -> None:
    operation_id = harness.prepare()
    audit_count = len(harness.audit.events())

    with pytest.raises(
        TrustedBrokerError,
        match="broker_approval_peer_rejected",
    ):
        harness.broker.request_approval(
            session_handle="requester-session-0123456789abcdef",
            operation_id=operation_id,
            **peer_metadata,
        )

    assert len(harness.audit.events()) == audit_count


def test_denied_or_expired_challenge_cannot_execute(harness: Harness) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    denied = harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.DENY,
        reason="Supporting evidence is incomplete",
    )
    assert denied["state"] == "denied"
    denied_execute = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert denied_execute.status_code == 200
    assert denied_execute.body["ok"] is False

    second = Harness()
    second_id = second.prepare()
    second.preview(second_id)
    second.clock.value = NOW + timedelta(seconds=121)
    expired = second.dispatch(
        "operation.approve_execute", {"operation_id": second_id}
    )
    assert expired.status_code == 200
    assert expired.body["ok"] is False
    assert second.executor.execution_effects == 0


def test_requester_cannot_approve_and_other_requester_cannot_execute(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    with pytest.raises(TrustedBrokerError, match="approval_rejected"):
        harness.broker.decide_approval(
            session_handle="requester-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            decision=ApprovalDecision.APPROVE,
        )
    assert harness.audit.events()[-1].action == "approval.decide"
    assert harness.audit.events()[-1].outcome_code == "broker_approval_rejected"
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    assert harness.audit.events()[-1].action == "approval.decide"
    assert harness.audit.events()[-1].outcome_code == "ok"
    assert harness.audit.events()[-1].challenge_id == challenge["challenge_id"]
    rejected = harness.dispatch(
        "operation.approve_execute",
        {"operation_id": operation_id},
        session="other-session-0123456789abcdef0123",
    )
    assert rejected.status_code == 200
    assert rejected.body["ok"] is False
    assert rejected.authority_verified is True
    assert harness.executor.execution_effects == 0


def test_business_schema_rejects_authority_route_and_generated_id_injection(
    harness: Harness,
) -> None:
    injected_values = [
        {"operation_id": "x", "approval": {"signature": "attacker"}},
        {"operation_id": "x", "context": {"user_id": 1}},
        {"operation_id": "x", "release_digest": OLD_RELEASE},
        {"operation_id": "x", "challenge_id": "attacker"},
    ]
    for payload in injected_values:
        result = harness.dispatch("operation.approve_execute", payload)
        assert result.status_code == 200
        assert result.body["error"]["code"] == "broker_business_request_rejected"
    prepare = harness.dispatch(
        "operation.prepare",
        {
            "operation_id": "caller-id",
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {"company_id": 7},
        },
    )
    assert prepare.status_code == 200
    assert harness.executor.calls == []


def test_cross_company_and_current_header_tamper_fail_before_executor(
    harness: Harness,
) -> None:
    cross = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {"company_id": 8, "idempotency_key": "cross"},
        },
    )
    assert cross.status_code == 200
    assert cross.body["ok"] is False
    assert harness.executor.calls == []

    wrong_header = harness.broker.dispatch(
        action="operation.prepare",
        payload={
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {"company_id": 7, "idempotency_key": "header"},
        },
        session_handle="requester-session-0123456789abcdef",
        expected_release_digest=OLD_RELEASE,
        expected_registry_digest=OLD_REGISTRY,
    )
    assert wrong_header.status_code == 409
    assert wrong_header.authority_verified is False
    assert harness.executor.calls == []


def test_read_uses_separate_authorizer_and_requires_current_verified_identity(
    harness: Harness,
) -> None:
    result = harness.dispatch(
        "read",
        {
            "capability_id": "acct.gl.trial_balance.v1",
            "parameters": {
                "company_id": 7,
                "date_from": "2026-01-01",
                "date_to": "2026-07-15",
            },
        },
    )
    assert result.status_code == 200
    assert result.executed_release_digest == CURRENT_RELEASE
    assert result.executed_registry_digest == CURRENT_REGISTRY
    assert harness.read_authorizations == 1
    assert harness.read_executions == 1
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []

    harness.read_tamper = True
    rejected = harness.dispatch(
        "read",
        {
            "capability_id": "acct.gl.trial_balance.v1",
            "parameters": {"company_id": 7},
        },
    )
    assert rejected.status_code == 200
    assert rejected.body["ok"] is False
    assert rejected.executed_release_digest is None


def _seed_old_operation(harness: Harness, operation_id: str = "old-operation") -> None:
    requester = harness.sessions["requester-session-0123456789abcdef"]
    harness.operations[operation_id] = Operation.prepare(
        operation_id=operation_id,
        request_id="old-request",
        capability_id="acct.invoice.customer_create.v1",
        parameters={
            "company_id": 7,
            "partner_id": 101,
            "idempotency_key": "old-invoice",
        },
        principal=requester.principal,
        user_id=requester.user_id,
        company_id=requester.company_id,
        idempotency_key="old-invoice",
        odoo_instance_id=requester.odoo_instance_id,
        database_name=requester.database_name,
        database_uuid=requester.database_uuid,
        environment=requester.environment,
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )


def _seed_historical_prepare_retry(
    harness: Harness,
    *,
    operation_id: str = "old-prepare-operation",
    release_digest: str = OLD_RELEASE,
    registry_digest: str = OLD_REGISTRY,
) -> tuple[Operation, dict[str, object]]:
    requester = harness.sessions["requester-session-0123456789abcdef"]
    parameters: dict[str, object] = {
        "company_id": 7,
        "partner_id": 707,
        "currency_id": 12,
        "invoice_date": "2026-07-15",
        "idempotency_key": "cross-release-lost-response-1",
    }
    operation = Operation.prepare(
        operation_id=operation_id,
        request_id="old-prepare-request",
        capability_id="acct.invoice.customer_create.v1",
        parameters=parameters,
        principal=requester.principal,
        user_id=requester.user_id,
        company_id=requester.company_id,
        idempotency_key=parameters["idempotency_key"],
        odoo_instance_id=requester.odoo_instance_id,
        database_name=requester.database_name,
        database_uuid=requester.database_uuid,
        environment=requester.environment,
        registry_digest=registry_digest,
        release_digest=release_digest,
    )
    harness.operations[operation.operation_id] = operation
    harness.executor.idempotency[
        (
            requester.principal,
            requester.company_id,
            operation.capability_id,
            operation.idempotency_key,
        )
    ] = operation.operation_id
    harness.executor.prepare_effects = 1
    return operation, parameters


def test_prepare_retry_after_release_switch_reuses_original_release_and_ids(
    harness: Harness,
) -> None:
    operation, parameters = _seed_historical_prepare_retry(harness)

    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": operation.capability_id,
            "parameters": parameters,
        },
    )

    assert result.status_code == 200
    assert result.body["ok"] is True
    assert result.body["data"]["operation_id"] == operation.operation_id
    assert result.executed_release_digest == OLD_RELEASE
    assert result.executed_registry_digest == OLD_REGISTRY
    assert harness.executor.prepare_effects == 1
    action, trusted_request = harness.executor.calls[-1]
    assert action == "operation.prepare"
    assert trusted_request["operation_id"] == operation.operation_id
    assert trusted_request["request_id"] == operation.request_id
    assert (
        request_context_from_mapping(trusted_request["context"]).auth_key_id
        == "old-context-key"
    )
    assert harness.authority_resolutions == [(OLD_RELEASE, OLD_REGISTRY)]
    assert harness.response_verifications[-1] == (
        OLD_RELEASE,
        OLD_REGISTRY,
        "operation.prepare",
    )


def test_prepare_retry_after_release_switch_rejects_content_drift(
    harness: Harness,
) -> None:
    operation, parameters = _seed_historical_prepare_retry(harness)

    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": operation.capability_id,
            "parameters": {**parameters, "partner_id": 999},
        },
    )

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "idempotency_conflict"
    assert harness.executor.calls == []
    assert harness.executor.prepare_effects == 1


@pytest.mark.parametrize("mismatch", ["company", "user", "database"])
def test_prepare_global_resolution_cannot_cross_tenant_or_requester(
    harness: Harness, mismatch: str
) -> None:
    operation, parameters = _seed_historical_prepare_retry(harness)
    harness.prepare_idempotency_override_enabled = True
    harness.prepare_idempotency_override = operation.operation_id
    session_handle = "requester-session-0123456789abcdef"
    if mismatch == "company":
        session_handle = "company-8-session-0123456789abcdef"
    elif mismatch == "user":
        session_handle = "other-session-0123456789abcdef0123"
    else:
        original = harness.sessions[session_handle]
        session_handle = "different-database-session-0123456789"
        harness.sessions[session_handle] = replace(
            original,
            session_id="session-different-database",
            database_name="odoo_v3_other_sandbox",
            database_uuid="22222222-2222-4222-8222-222222222222",
        )

    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": operation.capability_id,
            "parameters": parameters,
        },
        session=session_handle,
    )

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "idempotency_conflict"
    assert harness.executor.calls == []


@pytest.mark.parametrize("route_state", ["deleted", "unknown"])
def test_prepare_retry_never_falls_back_when_retained_release_is_unavailable(
    harness: Harness, route_state: str
) -> None:
    if route_state == "deleted":
        operation, parameters = _seed_historical_prepare_retry(harness)
        del harness.authorities[(OLD_RELEASE, OLD_REGISTRY)]
    else:
        operation, parameters = _seed_historical_prepare_retry(
            harness,
            release_digest="e" * 64,
            registry_digest="f" * 64,
        )

    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": operation.capability_id,
            "parameters": parameters,
        },
    )

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_release_authority_unavailable"
    assert harness.executor.calls == []


def test_prepare_global_idempotency_resolver_exception_fails_closed(
    harness: Harness,
) -> None:
    harness.prepare_idempotency_resolution_error = True

    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": "resolver-unavailable-1",
            },
        },
    )

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"] == {
        "code": "broker_prepare_idempotency_resolver_failed",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "retryable": True,
    }
    assert harness.executor.calls == []


def test_historical_operation_uses_matching_old_authority_and_executor_route(
    harness: Harness,
) -> None:
    _seed_old_operation(harness)
    challenge = harness.preview("old-operation")
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    result = harness.dispatch(
        "operation.approve_execute", {"operation_id": "old-operation"}
    )
    assert result.status_code == 200
    assert result.executed_release_digest == OLD_RELEASE
    assert result.executed_registry_digest == OLD_REGISTRY
    preview_context = request_context_from_mapping(harness.executor.calls[0][1]["context"])
    execute_context = request_context_from_mapping(harness.executor.calls[1][1]["context"])
    assert preview_context.auth_key_id == "old-context-key"
    assert execute_context.auth_key_id == "old-context-key"
    assert (
        approval_from_mapping(harness.executor.calls[1][1]["approval"]).key_id
        == "old-approval-key"
    )


def test_missing_historical_authority_never_falls_back_to_current_key(
    harness: Harness,
) -> None:
    _seed_old_operation(harness)
    del harness.authorities[(OLD_RELEASE, OLD_REGISTRY)]
    result = harness.dispatch("operation.preview", {"operation_id": "old-operation"})
    assert result.status_code == 200
    assert result.body["error"]["code"] == "broker_release_authority_unavailable"
    assert harness.executor.calls == []
    assert harness.authority_resolutions == [(OLD_RELEASE, OLD_REGISTRY)]


def test_executor_route_identity_tamper_is_not_reported_as_success(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    harness.executor.tamper_identity = True
    result = harness.dispatch("operation.preview", {"operation_id": operation_id})
    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_executor_response_rejected"
    assert result.executed_release_digest is None


def test_recovery_enriches_only_trusted_ids_and_preserves_business_fields(
    harness: Harness,
) -> None:
    _seed_old_operation(harness, "origin-operation")
    origin = harness.operations["origin-operation"]
    result = harness.dispatch(
        "operation.recover",
        {
            "origin_operation_id": origin.operation_id,
            "recovery_date": "2026-07-16",
            "reason": "Reverse the verified source operation",
            "idempotency_key": "recover-old-1",
        },
    )
    assert result.status_code == 200
    action, request = harness.executor.calls[-1]
    assert action == "operation.recover"
    assert request["expected_origin_revision"] == origin.revision
    assert request["recovery_operation_id"] == "recovery-1"
    assert request["request_id"] == "request-1"
    assert request["recovery_date"] == "2026-07-16"
    assert request["reason"] == "Reverse the verified source operation"
    assert result.executed_release_digest == OLD_RELEASE


def test_recovery_lost_response_reuses_exact_durable_recovery_operation(
    harness: Harness,
) -> None:
    _seed_old_operation(harness, "origin-retry")
    request = {
        "origin_operation_id": "origin-retry",
        "recovery_date": "2026-07-16",
        "reason": "Reverse the verified source operation",
        "idempotency_key": "recover-lost-response-1",
    }
    first = harness.dispatch("operation.recover", request)
    second = harness.dispatch("operation.recover", request)

    recovery_id = first.body["data"]["operation_id"]
    assert second.status_code == 200
    assert second.body["ok"] is True
    assert second.body["data"]["operation_id"] == recovery_id
    assert harness.executor.recovery_effects == 1
    assert "recovery-2" not in harness.operations

    changed = harness.dispatch(
        "operation.recover",
        {**request, "reason": "Different recovery content"},
    )
    assert changed.status_code == 200
    assert changed.body["ok"] is False
    assert changed.body["error"]["code"] == "idempotency_conflict"
    assert harness.executor.recovery_effects == 1


def test_errors_are_safe_and_never_echo_session_handle(harness: Harness) -> None:
    secret_handle = "missing-session-handle-that-must-not-be-echoed"
    result = harness.broker.dispatch(
        action="read",
        payload={
            "capability_id": "acct.gl.trial_balance.v1",
            "parameters": {"company_id": 7},
        },
        session_handle=secret_handle,
        expected_release_digest=CURRENT_RELEASE,
        expected_registry_digest=CURRENT_REGISTRY,
    )
    assert result.status_code == 401
    assert secret_handle not in str(result.body)
    assert result.body["ok"] is False
    assert result.body["error"]["odoo_effect"] == "none"


def test_prepare_lost_response_reuses_exact_durable_operation_and_rejects_drift(
    harness: Harness,
) -> None:
    request = {
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {
            "company_id": 7,
            "partner_id": 101,
            "currency_id": 12,
            "invoice_date": "2026-07-15",
            "idempotency_key": "lost-response-invoice-1",
        },
    }
    first = harness.dispatch("operation.prepare", request)
    second = harness.dispatch("operation.prepare", request)

    first_id = first.body["data"]["operation_id"]
    assert second.status_code == 200
    assert second.body["ok"] is True
    assert second.body["data"]["operation_id"] == first_id
    assert harness.executor.prepare_effects == 1
    assert "operation-2" not in harness.operations

    changed = harness.dispatch(
        "operation.prepare",
        {
            **request,
            "parameters": {**request["parameters"], "partner_id": 999},
        },
    )
    assert changed.status_code == 200
    assert changed.body["ok"] is False
    assert changed.body["error"]["code"] == "idempotency_conflict"
    assert harness.executor.prepare_effects == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_name", "attacker"),
        ("database_uuid", DATABASE_UUID),
        ("environment", "production"),
        ("odoo_instance_id", "attacker"),
        ("binary_path", "/tmp/attacker"),
        ("cli_path", "/tmp/attacker"),
        ("config_path", "/tmp/attacker"),
        ("runtime_config", {"path": "/tmp/attacker"}),
        ("reconciliation_only", True),
        ("signature", "f" * 64),
        ("key_id", "attacker-key"),
    ],
)
def test_nested_runtime_and_authority_injection_is_rejected(
    harness: Harness, field: str, value: object
) -> None:
    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": "nested-authority",
                "metadata": {field: value},
            },
        },
    )
    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.executor.calls == []


def test_preview_tamper_stales_challenge_before_independent_approval(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.operations[operation_id] = replace(
        harness.operations[operation_id], precheck_digest="f" * 64
    )

    with pytest.raises(TrustedBrokerError, match="approval_rejected"):
        harness.broker.decide_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            decision=ApprovalDecision.APPROVE,
        )
    stored = harness.stores[(CURRENT_RELEASE, CURRENT_REGISTRY)].get_challenge(
        challenge["challenge_id"]
    )
    assert stored.state.value == "stale"
    assert stored.approval is None


def test_release_pinned_response_verifier_is_mandatory_and_fail_closed(
    harness: Harness,
) -> None:
    harness.response_verifier_unavailable_routes.add(
        (CURRENT_RELEASE, CURRENT_REGISTRY)
    )
    unavailable = harness.dispatch(
        "read",
        {
            "capability_id": "acct.gl.trial_balance.v1",
            "parameters": {"company_id": 7},
        },
    )
    assert unavailable.status_code == 200
    assert unavailable.body["ok"] is False
    assert unavailable.body["error"]["code"] == "broker_response_verifier_unavailable"
    assert harness.read_executions == 0

    second = Harness()
    operation_id = second.prepare()
    challenge = second.preview(operation_id)
    second.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    second.response_verification_accepts = False
    rejected = second.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert rejected.status_code == 200
    assert rejected.body["ok"] is False
    assert rejected.body["error"]["code"] == "broker_response_verification_failed"
    assert rejected.body["error"]["odoo_effect"] == "unknown"
    assert rejected.body["error"]["retryable"] is True
    assert rejected.executed_release_digest is None
    assert second.executor.execution_effects == 1

    second.clock.value = NOW + timedelta(seconds=121)
    second.response_verification_accepts = True
    replay = second.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert replay.body["ok"] is True
    assert replay.body["business_succeeded"] is True
    assert second.executor.execution_effects == 1
    assert second.executor.calls[-1][1]["reconciliation_only"] is True


def test_lost_approved_response_is_retryable_and_reconciles_after_expiry(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    harness.executor.raise_after_effect_actions.add("operation.approve_execute")

    hidden = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )

    assert hidden.body["error"]["code"] == "broker_executor_failed"
    assert hidden.body["error"]["odoo_effect"] == "unknown"
    assert hidden.body["error"]["retryable"] is True
    assert harness.executor.execution_effects == 1

    harness.clock.value = NOW + timedelta(seconds=121)
    replay = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert replay.body["ok"] is True
    assert replay.body["business_succeeded"] is True
    assert harness.executor.execution_effects == 1
    assert harness.executor.calls[-1][1]["reconciliation_only"] is True


def test_malformed_approved_envelope_is_retryable_and_reconciles_after_expiry(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    dispatch = harness.executor.dispatch

    def malformed(action, request, *, deadline_monotonic=None):
        response = dispatch(
            action, request, deadline_monotonic=deadline_monotonic
        )
        if action == "operation.approve_execute":
            response.pop("data")
        return response

    monkeypatch.setattr(harness.executor, "dispatch", malformed)
    hidden = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )

    assert hidden.body["error"]["code"] == "broker_executor_response_rejected"
    assert hidden.body["error"]["odoo_effect"] == "unknown"
    assert hidden.body["error"]["retryable"] is True
    assert harness.executor.execution_effects == 1

    monkeypatch.setattr(harness.executor, "dispatch", dispatch)
    harness.clock.value = NOW + timedelta(seconds=121)
    replay = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert replay.body["ok"] is True
    assert replay.body["business_succeeded"] is True
    assert harness.executor.execution_effects == 1
    assert harness.executor.calls[-1][1]["reconciliation_only"] is True


def test_post_submit_deadline_is_retryable_and_reconciles_after_expiry(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    ticks = iter((1.0, 3.0))
    harness.broker._monotonic_clock = lambda: next(ticks)

    hidden = harness.dispatch(
        "operation.approve_execute",
        {"operation_id": operation_id},
        deadline_monotonic=2.0,
    )

    assert hidden.body["error"] == {
        "code": "broker_deadline_exceeded",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "unknown",
        "retryable": True,
    }
    assert harness.executor.execution_effects == 1

    harness.clock.value = NOW + timedelta(seconds=121)
    replay = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert replay.body["ok"] is True
    assert harness.executor.execution_effects == 1
    assert harness.executor.calls[-1][1]["reconciliation_only"] is True


def test_pre_submit_deadline_reports_no_odoo_effect_and_is_retryable(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )
    harness.broker._monotonic_clock = lambda: 3.0

    rejected = harness.dispatch(
        "operation.approve_execute",
        {"operation_id": operation_id},
        deadline_monotonic=2.0,
    )

    assert rejected.body["error"]["code"] == "broker_deadline_exceeded"
    assert rejected.body["error"]["odoo_effect"] == "none"
    assert rejected.body["error"]["retryable"] is True
    assert harness.executor.execution_effects == 0


def test_uds_adapter_preserves_trusted_application_errors_and_pre_auth_errors(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    authenticated = harness.broker(
        BrokerDispatchRequest(
            action="operation.approve_execute",
            payload={"operation_id": operation_id},
            session_handle="requester-session-0123456789abcdef",
            release_digest=CURRENT_RELEASE,
            registry_digest=CURRENT_REGISTRY,
            peer_uid=1001,
            observed_peer_pid=4321,
            deadline_monotonic=time.monotonic() + 30,
            observed_peer_gid=1002,
        )
    )
    assert isinstance(authenticated, BrokerDispatchResult)
    assert authenticated.status_code == 200
    assert authenticated.authority_verified is True
    assert authenticated.body["ok"] is False
    assert authenticated.body["error"]["code"] == "broker_approval_not_executable"
    assert authenticated.executed_release_digest is None
    assert harness.audit.events()[-1].peer_uid == 1001
    assert harness.audit.events()[-1].peer_gid == 1002
    assert harness.audit.events()[-1].peer_pid == 4321

    audit_count = len(harness.audit.events())
    unauthenticated = harness.broker(
        BrokerDispatchRequest(
            action="operation.status",
            payload={"operation_id": operation_id},
            session_handle="unknown-session-0123456789abcdef0",
            release_digest=CURRENT_RELEASE,
            registry_digest=CURRENT_REGISTRY,
            peer_uid=1001,
            observed_peer_pid=4321,
            deadline_monotonic=time.monotonic() + 30,
        )
    )
    assert unauthenticated.status_code == 401
    assert unauthenticated.authority_verified is False
    assert unauthenticated.body["ok"] is False
    assert len(harness.audit.events()) == audit_count


def test_authenticated_write_denials_are_audited_without_sensitive_payloads(
    harness: Harness,
) -> None:
    injected = harness.dispatch(
        "operation.approve_execute",
        {"operation_id": "claimed-operation", "approval": {"signature": "attacker"}},
    )
    event = harness.audit.events()[-1]
    assert event.outcome_code == injected.body["error"]["code"]
    assert event.principal == "pi:user-42"
    assert event.company_id == 7
    assert event.operation_id == "claimed-operation"
    assert len(event.request_digest) == 64
    assert not hasattr(event, "session_handle")
    assert not hasattr(event, "parameters")
    assert not hasattr(event, "approval")

    cross_company = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {"company_id": 8, "idempotency_key": "audit-cross"},
        },
    )
    assert harness.audit.events()[-1].outcome_code == cross_company.body["error"][
        "code"
    ]
    assert harness.audit.events()[-1].odoo_effect == "none"

    operation_id = harness.prepare()
    harness.preview(operation_id)
    harness.clock.value = NOW + timedelta(seconds=121)
    expired = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert expired.body["ok"] is False
    assert harness.audit.events()[-1].outcome_code == expired.body["error"]["code"]
    assert harness.audit.events()[-1].operation_id == operation_id
    assert harness.executor.execution_effects == 0


def test_real_sqlite_broker_audit_records_broker_result_without_business_payload(
    tmp_path,
) -> None:
    audit_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sink = SQLiteBrokerAuditSink(audit_path)
    harness = Harness(audit_sink=sink)
    sensitive_marker = "private-invoice-memo-must-not-be-persisted"
    session_handle = "requester-session-0123456789abcdef"
    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": "sqlite-audit-integration",
                "memo": sensitive_marker,
            },
        },
        session=session_handle,
    )
    assert result.body["ok"] is True

    events = sink.events()
    assert len(events) == 1
    assert events[0].action == "operation.prepare"
    assert events[0].outcome_code == "ok"
    assert events[0].operation_id == result.body["data"]["operation_id"]
    assert events[0].request_id is not None
    for candidate in (audit_path, audit_path.with_name(audit_path.name + "-wal")):
        if candidate.exists():
            payload = candidate.read_bytes()
            assert sensitive_marker.encode() not in payload
            assert session_handle.encode() not in payload


def test_audit_failure_suppresses_success_and_retry_does_not_duplicate_effect(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.broker.decide_approval(
        session_handle="approver-session-0123456789abcdef",
        challenge_id=challenge["challenge_id"],
        decision=ApprovalDecision.APPROVE,
    )

    harness.set_audit_failure(True)
    hidden = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert hidden.body["ok"] is False
    assert hidden.body["error"]["code"] == "broker_audit_failed"
    assert hidden.body["error"]["odoo_effect"] == "unknown"
    assert hidden.body["error"]["retryable"] is True
    assert harness.executor.execution_effects == 1

    harness.set_audit_failure(False)
    harness.clock.value = NOW + timedelta(seconds=121)
    replay = harness.dispatch(
        "operation.approve_execute", {"operation_id": operation_id}
    )
    assert replay.body["ok"] is True
    assert replay.body["business_succeeded"] is True
    assert harness.executor.execution_effects == 1
    assert harness.executor.calls[-1][1]["reconciliation_only"] is True
    assert harness.audit.events()[-1].outcome_code == "business_succeeded"
    assert harness.audit.events()[-1].odoo_effect == "verified"


def test_prepare_audit_failure_retry_recovers_the_original_operation(
    harness: Harness,
) -> None:
    request = {
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {
            "company_id": 7,
            "partner_id": 101,
            "currency_id": 12,
            "invoice_date": "2026-07-15",
            "idempotency_key": "audit-lost-response-prepare",
        },
    }
    harness.set_audit_failure(True)
    hidden = harness.dispatch("operation.prepare", request)
    assert hidden.body["error"]["code"] == "broker_audit_failed"
    assert harness.executor.prepare_effects == 1
    original_id = next(iter(harness.operations))

    harness.set_audit_failure(False)
    recovered = harness.dispatch("operation.prepare", request)
    assert recovered.body["ok"] is True
    assert recovered.body["data"]["operation_id"] == original_id
    assert harness.executor.prepare_effects == 1


def test_approval_audit_failure_is_fail_closed_and_challenge_is_recoverable(
    harness: Harness,
) -> None:
    operation_id = harness.prepare()
    challenge = harness.preview(operation_id)
    harness.set_audit_failure(True)
    with pytest.raises(TrustedBrokerError, match="broker_audit_failed"):
        harness.broker.decide_approval(
            session_handle="approver-session-0123456789abcdef",
            challenge_id=challenge["challenge_id"],
            decision=ApprovalDecision.APPROVE,
        )

    stored = harness.stores[(CURRENT_RELEASE, CURRENT_REGISTRY)].get_challenge(
        challenge["challenge_id"]
    )
    assert stored.state.value == "approved"
    harness.set_audit_failure(False)
    recovered = harness.broker.request_approval(
        session_handle="requester-session-0123456789abcdef",
        operation_id=operation_id,
    )
    assert recovered["state"] == "approved"
    assert harness.audit.events()[-1].action == "approval.request"
    assert harness.audit.events()[-1].outcome_code == "ok"


def test_broker_audits_valid_email_principal_end_to_end(harness: Harness) -> None:
    result = harness.dispatch(
        "operation.prepare",
        {
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": "email-principal-audit",
            },
        },
        session="email-session-0123456789abcdef0123",
    )

    assert result.body["ok"] is True
    event = harness.audit.events()[-1]
    assert event.principal == "user+accounting@example.com"
    assert event.operation_id == result.body["data"]["operation_id"]
    assert event.outcome_code == "ok"


def test_prepare_lost_response_audit_keeps_generated_ids_and_route(
    harness: Harness,
) -> None:
    request = {
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {
            "company_id": 7,
            "partner_id": 101,
            "idempotency_key": "prepare-lost-response-audit-metadata",
        },
    }
    harness.executor.raise_after_effect_actions.add("operation.prepare")

    hidden = harness.dispatch("operation.prepare", request)

    assert hidden.body["ok"] is False
    assert hidden.body["error"] == {
        "code": "broker_executor_failed",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "retryable": True,
    }
    event = harness.audit.events()[-1]
    assert event.operation_id == "operation-1"
    assert event.request_id == "request-1"
    assert event.selected_release_digest == CURRENT_RELEASE
    assert event.selected_registry_digest == CURRENT_REGISTRY
    assert event.outcome_code == "broker_executor_failed"
    assert harness.executor.prepare_effects == 1

    recovered = harness.dispatch("operation.prepare", request)
    assert recovered.body["ok"] is True
    assert recovered.body["data"]["operation_id"] == "operation-1"
    assert harness.executor.prepare_effects == 1


def test_prepare_race_lost_response_audit_reloads_winning_durable_identity(
    harness: Harness, monkeypatch
) -> None:
    request = {
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {
            "company_id": 7,
            "partner_id": 101,
            "idempotency_key": "prepare-race-lost-response-audit",
        },
    }

    def competing_dispatch(
        action: str,
        trusted_request: dict,
        *,
        deadline_monotonic: float | None = None,
    ) -> dict:
        assert deadline_monotonic is None
        assert action == "operation.prepare"
        context = request_context_from_mapping(trusted_request["context"])
        winner = Operation.prepare(
            operation_id="concurrent-winner-operation",
            request_id="concurrent-winner-request",
            capability_id=trusted_request["capability_id"],
            parameters=trusted_request["parameters"],
            principal=context.principal,
            user_id=context.user_id,
            company_id=context.company_id,
            idempotency_key=trusted_request["parameters"]["idempotency_key"],
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            environment=context.environment,
            registry_digest=CURRENT_REGISTRY,
            release_digest=CURRENT_RELEASE,
        )
        harness.operations[winner.operation_id] = winner
        harness.executor.idempotency[
            (
                context.principal,
                context.company_id,
                winner.capability_id,
                winner.idempotency_key,
            )
        ] = winner.operation_id
        harness.executor.prepare_effects += 1
        raise RuntimeError("the losing child did not receive the winning response")

    monkeypatch.setattr(harness.executor, "dispatch", competing_dispatch)
    hidden = harness.dispatch("operation.prepare", request)

    assert hidden.body["error"]["code"] == "broker_executor_failed"
    event = harness.audit.events()[-1]
    assert event.operation_id == "concurrent-winner-operation"
    assert event.request_id == "concurrent-winner-request"
    assert event.selected_release_digest == CURRENT_RELEASE
    assert event.selected_registry_digest == CURRENT_REGISTRY
    assert event.operation_id != "operation-1"


def test_prepare_refresh_cannot_replace_the_already_selected_route(
    harness: Harness, monkeypatch
) -> None:
    request = {
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {
            "company_id": 7,
            "partner_id": 101,
            "idempotency_key": "prepare-wrong-route-refresh",
        },
    }
    requester = harness.sessions["requester-session-0123456789abcdef"]
    wrong_route = Operation.prepare(
        operation_id="wrong-route-prepare",
        request_id="wrong-route-request",
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        principal=requester.principal,
        user_id=requester.user_id,
        company_id=requester.company_id,
        idempotency_key=request["parameters"]["idempotency_key"],
        odoo_instance_id=requester.odoo_instance_id,
        database_name=requester.database_name,
        database_uuid=requester.database_uuid,
        environment=requester.environment,
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    harness.operations[wrong_route.operation_id] = wrong_route
    resolutions = iter((None, wrong_route.operation_id))
    monkeypatch.setattr(
        harness.broker,
        "_prepare_idempotency_resolver",
        lambda *_args: next(resolutions),
    )

    def lose_response(*_args, **_kwargs):
        raise RuntimeError("ambiguous child response")

    monkeypatch.setattr(harness.executor, "dispatch", lose_response)
    hidden = harness.dispatch("operation.prepare", request)

    assert hidden.body["error"]["code"] == "broker_executor_failed"
    event = harness.audit.events()[-1]
    assert event.operation_id == "operation-1"
    assert event.request_id == "request-1"
    assert event.selected_release_digest == CURRENT_RELEASE
    assert event.selected_registry_digest == CURRENT_REGISTRY


def test_recovery_lost_response_audit_keeps_generated_ids_and_route(
    harness: Harness,
) -> None:
    _seed_old_operation(harness, "audit-recovery-origin")
    request = {
        "origin_operation_id": "audit-recovery-origin",
        "recovery_date": "2026-07-16",
        "reason": "Recover the verified source operation",
        "idempotency_key": "recovery-lost-response-audit-metadata",
    }
    harness.executor.raise_after_effect_actions.add("operation.recover")

    hidden = harness.dispatch("operation.recover", request)

    assert hidden.body["ok"] is False
    assert hidden.body["error"]["code"] == "broker_executor_failed"
    assert hidden.body["error"]["retryable"] is True
    event = harness.audit.events()[-1]
    assert event.operation_id == "recovery-1"
    assert event.request_id == "request-1"
    assert event.selected_release_digest == OLD_RELEASE
    assert event.selected_registry_digest == OLD_REGISTRY
    assert event.outcome_code == "broker_executor_failed"
    assert harness.executor.recovery_effects == 1

    recovered = harness.dispatch("operation.recover", request)
    assert recovered.body["ok"] is True
    assert recovered.body["data"]["operation_id"] == "recovery-1"
    assert harness.executor.recovery_effects == 1


def test_recovery_retry_lost_response_audit_reloads_existing_recovery_identity(
    harness: Harness,
) -> None:
    _seed_old_operation(harness, "audit-existing-recovery-origin")
    request = {
        "origin_operation_id": "audit-existing-recovery-origin",
        "recovery_date": "2026-07-16",
        "reason": "Recover the verified source operation",
        "idempotency_key": "existing-recovery-lost-response-audit",
    }
    first = harness.dispatch("operation.recover", request)
    assert first.body["data"]["operation_id"] == "recovery-1"
    harness.executor.raise_after_effect_actions.add("operation.recover")

    hidden = harness.dispatch("operation.recover", request)

    assert hidden.body["error"]["code"] == "broker_executor_failed"
    event = harness.audit.events()[-1]
    assert event.operation_id == "recovery-1"
    assert event.request_id == "request-1"
    assert event.selected_release_digest == OLD_RELEASE
    assert event.selected_registry_digest == OLD_REGISTRY
    assert event.operation_id != "recovery-2"
    assert harness.executor.recovery_effects == 1


def test_recovery_refresh_rejects_wrong_resolver_content(
    harness: Harness, monkeypatch
) -> None:
    _seed_old_operation(harness, "audit-wrong-resolver-origin")
    origin = harness.operations["audit-wrong-resolver-origin"]
    request = {
        "origin_operation_id": origin.operation_id,
        "recovery_date": "2026-07-16",
        "reason": "Recover the verified source operation",
        "idempotency_key": "requested-recovery-key",
    }
    wrong = Operation.prepare(
        operation_id="wrong-resolver-recovery",
        request_id="wrong-resolver-request",
        capability_id="acct.recovery.execute.v1",
        parameters={
            "company_id": 7,
            "origin_operation_id": origin.operation_id,
            "expected_recovery_plan_digest": "8" * 64,
            "recovery_date": request["recovery_date"],
            "reason": request["reason"],
            "idempotency_key": request["idempotency_key"],
            "unexpected": "must-not-be-accepted",
        },
        principal=origin.principal,
        user_id=origin.user_id,
        company_id=origin.company_id,
        idempotency_key="different-top-level-key",
        odoo_instance_id=origin.odoo_instance_id,
        database_name=origin.database_name,
        database_uuid=origin.database_uuid,
        environment=origin.environment,
        registry_digest=origin.registry_digest,
        release_digest=origin.release_digest,
    )
    harness.operations[wrong.operation_id] = wrong
    monkeypatch.setattr(
        harness.broker,
        "_recovery_idempotency_resolver",
        lambda *_args: wrong.operation_id,
    )

    def lose_response(*_args, **_kwargs):
        raise RuntimeError("ambiguous child response")

    monkeypatch.setattr(harness.executor, "dispatch", lose_response)
    hidden = harness.dispatch("operation.recover", request)

    assert hidden.body["error"]["code"] == "broker_executor_failed"
    event = harness.audit.events()[-1]
    assert event.operation_id == "recovery-1"
    assert event.request_id == "request-1"
    assert event.operation_id != wrong.operation_id
    assert event.selected_release_digest == OLD_RELEASE


def test_preview_challenge_wrapped_authority_reconciliation_is_non_replayable(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_id = harness.prepare()
    executor_calls = len(harness.executor.calls)
    execution_effects = harness.executor.execution_effects
    backend_secret = "private-preview-authority-commit-state"

    def fail_approval_request(*_args, **_kwargs):
        try:
            raise AuthorityCommitOutcomeUnknownError(backend_secret)
        except AuthorityReconciliationRequiredError as exc:
            raise RuntimeError("private-preview-authority-wrapper") from exc

    monkeypatch.setattr(harness.broker, "_request_approval", fail_approval_request)
    result = harness.dispatch("operation.preview", {"operation_id": operation_id})

    assert result.status_code == 200
    assert result.authority_verified is True
    assert result.body["error"] == {
        "code": "broker_authority_reconciliation_required",
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": "none",
        "reconciliation_required": True,
        "retryable": False,
    }
    serialized = json.dumps(result.body, sort_keys=True)
    assert backend_secret not in serialized
    assert "private-preview-authority-wrapper" not in serialized
    assert len(harness.executor.calls) == executor_calls + 1
    assert harness.executor.calls[-1][0] == "operation.preview"
    assert harness.executor.execution_effects == execution_effects
    assert all(
        action != "operation.approve_execute" for action, _ in harness.executor.calls
    )
    event = harness.audit.events()[-1]
    assert event.action == "operation.preview"
    assert event.operation_id == operation_id
    assert event.outcome_code == "broker_authority_reconciliation_required"


def test_unexpected_preview_exception_is_safe_and_audited(
    harness: Harness, monkeypatch
) -> None:
    operation_id = harness.prepare()

    def fail_approval_request(*_args, **_kwargs):
        raise RuntimeError("private approval backend failure")

    monkeypatch.setattr(harness.broker, "_request_approval", fail_approval_request)
    result = harness.dispatch("operation.preview", {"operation_id": operation_id})

    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_write_dispatch_failed"
    assert "private approval backend failure" not in str(result.body)
    event = harness.audit.events()[-1]
    assert event.action == "operation.preview"
    assert event.operation_id == operation_id
    assert event.request_id == harness.operations[operation_id].request_id
    assert event.selected_release_digest == CURRENT_RELEASE
    assert event.outcome_code == "broker_write_dispatch_failed"


def test_unexpected_approval_request_exception_is_safe_and_audited(
    harness: Harness, monkeypatch
) -> None:
    operation_id = harness.prepare()

    def fail_approval_request(*_args, **_kwargs):
        raise RuntimeError("private approval backend failure")

    monkeypatch.setattr(harness.broker, "_request_approval", fail_approval_request)
    with pytest.raises(TrustedBrokerError) as rejected:
        harness.broker.request_approval(
            session_handle="requester-session-0123456789abcdef",
            operation_id=operation_id,
        )

    assert rejected.value.code == "broker_approval_rejected"
    assert str(rejected.value) == "broker_approval_rejected"
    event = harness.audit.events()[-1]
    assert event.action == "approval.request"
    assert event.operation_id == operation_id
    assert event.request_id == harness.operations[operation_id].request_id
    assert event.selected_release_digest == CURRENT_RELEASE
    assert event.outcome_code == "broker_approval_rejected"


def test_broker_rejects_noop_audit_sink() -> None:
    class NoOpAuditSink:
        def record(self, **fields):
            return fields

    with pytest.raises(TrustedBrokerError, match="broker_audit_sink_rejected"):
        Harness(audit_sink=NoOpAuditSink())
