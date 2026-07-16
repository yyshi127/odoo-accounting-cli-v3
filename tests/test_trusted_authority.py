from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.auth import verify_write_action_context
from odoo_accounting_cli_v3.operations import (
    ApprovalRejected,
    Operation,
    State,
    approve_operation,
    begin_execution,
    canonical_json,
    record_precheck,
)
from odoo_accounting_cli_v3.trusted_authority import (
    ApprovalChallengeState,
    ApprovalDecision,
    AuthorityError,
    AuthorityKeys,
    ChallengeExpired,
    ChallengeTerminal,
    InMemoryApprovalChallengeStore,
    TrustedAuthority,
    TrustedSession,
)
from odoo_accounting_cli_v3.write_protocol import approval_to_mapping


NOW = datetime(2026, 7, 15, 4, 0, tzinfo=timezone.utc)
AUTH_SECRET = b"authority-auth-secret-material-32-bytes"
APPROVAL_SECRET = b"authority-approval-secret-32-bytes"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
PRECHECK_DIGEST = "a" * 64


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class SequenceFactory:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.sequence = 0

    def __call__(self) -> str:
        self.sequence += 1
        return f"{self.prefix}-{self.sequence}"


def session(
    *,
    session_id: str,
    principal: str,
    user_id: int,
    company_id: int = 7,
    allowed_company_ids: frozenset[int] = frozenset({7}),
    expires_at: datetime = NOW + timedelta(hours=1),
) -> TrustedSession:
    return TrustedSession(
        session_id=session_id,
        principal=principal,
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        environment="sandbox",
        release_digest="c" * 64,
        registry_digest="b" * 64,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
    )


def awaiting_operation(*, operation_id: str = "op-1") -> Operation:
    prepared = Operation.prepare(
        operation_id=operation_id,
        request_id="request-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "partner_id": 101},
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="invoice-2026-1",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest="b" * 64,
        release_digest="c" * 64,
    )
    prechecked = record_precheck(
        prepared,
        precheck_digest=PRECHECK_DIGEST,
        expected_revision=0,
    )
    return prechecked.transition(State.AWAITING_APPROVAL, expected_revision=1)


@pytest.fixture
def harness():
    clock = MutableClock()
    requester = session(
        session_id="trusted-requester-session",
        principal="pi:user-42",
        user_id=42,
    )
    approver = session(
        session_id="trusted-approver-session",
        principal="pi:user-84",
        user_id=84,
    )
    sessions = {"requester-handle": requester, "approver-handle": approver}
    operations = {"op-1": awaiting_operation()}
    store = InMemoryApprovalChallengeStore()
    authority = TrustedAuthority(
        session_resolver=lambda handle: sessions.get(handle),
        operation_resolver=lambda operation_id: operations.get(operation_id),
        approver_authorizer=lambda trusted_session, operation: (
            trusted_session.user_id == 84 and operation.company_id == 7
        ),
        approval_ttl_resolver=lambda operation: 120,
        keys=AuthorityKeys(
            context_key_id="auth-key-1",
            context_secret=AUTH_SECRET,
            approval_key_id="approval-key-1",
            approval_secret=APPROVAL_SECRET,
        ),
        store=store,
        clock=clock,
        challenge_id_factory=SequenceFactory("challenge"),
        event_id_factory=SequenceFactory("event"),
        nonce_factory=SequenceFactory("nonce"),
        auth_token_id_factory=SequenceFactory("auth-token"),
    )
    return authority, store, clock, sessions, operations


def test_write_context_identity_comes_only_from_trusted_session(harness) -> None:
    authority, store, _, _, _ = harness
    request = {
        "operation_id": "new-op",
        "request_id": "new-request",
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {"company_id": 7, "partner_id": 101},
    }

    authorized = authority.issue_write_action(
        session_handle="requester-handle",
        action="operation.prepare",
        request=request,
    )

    assert authorized.request == request
    assert authorized.context.user_id == 42
    assert authorized.context.company_id == 7
    assert authorized.context.principal == "pi:user-42"
    assert authorized.context.auth_token_id == "auth-token-1"
    assert authorized.context.auth_token_id != "trusted-requester-session"
    assert verify_write_action_context(
        authorized.context,
        action="operation.prepare",
        request=request,
        now=NOW,
        secret=AUTH_SECRET,
        expected_key_id="auth-key-1",
    )
    assert [event.event_type for event in store.audit_events()] == [
        "write_action.context_issued"
    ]


@pytest.mark.parametrize(
    "changed",
    [
        {"context": {}},
        {"user_id": 999},
        {"principal": "attacker"},
        {"operation_digest": "d" * 64},
        {"precheck_digest": "e" * 64},
        {"approval": {}},
    ],
)
def test_write_context_rejects_caller_supplied_authority_fields(
    harness, changed
) -> None:
    authority, store, _, _, _ = harness
    request = {
        "operation_id": "new-op",
        "request_id": "new-request",
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {"company_id": 7},
        **changed,
    }

    with pytest.raises(AuthorityError, match="authority-controlled"):
        authority.issue_write_action(
            session_handle="requester-handle",
            action="operation.prepare",
            request=request,
        )

    assert store.audit_events() == ()


def test_write_context_rejects_cross_company_and_untrusted_sessions(harness) -> None:
    authority, store, clock, sessions, _ = harness
    request = {
        "operation_id": "new-op",
        "request_id": "new-request",
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {"company_id": 8},
    }
    with pytest.raises(AuthorityError, match="bound company"):
        authority.issue_write_action("requester-handle", "operation.prepare", request)
    with pytest.raises(AuthorityError, match="trusted session"):
        authority.issue_write_action("attacker-handle", "operation.prepare", request)

    sessions["expired"] = session(
        session_id="expired-session",
        principal="pi:user-42",
        user_id=42,
        expires_at=NOW,
    )
    with pytest.raises(AuthorityError, match="not currently valid"):
        authority.issue_write_action("expired", "operation.prepare", request)
    clock.value = NOW.replace(tzinfo=None)
    with pytest.raises(AuthorityError, match="timezone-aware"):
        authority.issue_write_action("requester-handle", "operation.prepare", request)
    assert store.audit_events() == ()


def test_public_issuer_methods_do_not_accept_identity_or_digest_arguments() -> None:
    prohibited = {
        "user_id",
        "company_id",
        "principal",
        "operation_digest",
        "precheck_digest",
        "approver_user_id",
        "approval",
    }
    for method_name in (
        "issue_write_action",
        "request_approval",
        "inspect_approval",
        "decide_approval",
        "issue_approved_execute",
    ):
        parameters = set(
            inspect.signature(getattr(TrustedAuthority, method_name)).parameters
        )
        assert parameters.isdisjoint(prohibited)


def test_challenge_uses_authoritative_operation_and_reuses_exact_binding(harness) -> None:
    authority, store, _, _, _ = harness

    first = authority.request_approval("requester-handle", "op-1")
    second = authority.request_approval("requester-handle", "op-1")

    assert second == first
    assert first.operation.digest == awaiting_operation().digest
    assert first.operation.precheck_digest == PRECHECK_DIGEST
    assert first.operation.revision == 2
    assert first.state is ApprovalChallengeState.PENDING
    assert [event.event_type for event in store.audit_events()] == [
        "approval.challenge_created",
        "approval.challenge_reused",
    ]


def test_approver_inspection_is_authoritative_serializable_and_detached(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")

    preview = authority.inspect_approval(
        "approver-handle", challenge.challenge_id
    )

    assert json.loads(canonical_json(preview)) == preview
    assert set(preview) == {
        "schema_version",
        "challenge",
        "operation",
        "summary",
        "preview_digest",
    }
    assert preview["schema_version"] == 1
    assert preview["challenge"] == {
        "challenge_id": challenge.challenge_id,
        "binding_digest": challenge.binding_digest,
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(seconds=120)).isoformat(),
        "ttl_seconds": 120,
        "state": "pending",
        "version": 0,
    }
    assert preview["operation"]["parameters"] == {
        "company_id": 7,
        "partner_id": 101,
    }
    assert preview["operation"]["operation_id"] == "op-1"
    assert preview["operation"]["request_id"] == "request-1"
    assert preview["operation"]["operation_digest"] == challenge.operation.digest
    assert preview["operation"]["precheck_digest"] == PRECHECK_DIGEST
    assert preview["operation"]["revision"] == challenge.operation.revision
    parameters_digest = hashlib.sha256(
        canonical_json(challenge.operation.parameters)
    ).hexdigest()
    assert preview["operation"]["parameters_digest"] == parameters_digest
    assert preview["summary"] == {
        "binding_digest": challenge.binding_digest,
        "capability_id": challenge.operation.capability_id,
        "challenge_id": challenge.challenge_id,
        "company_id": challenge.operation.company_id,
        "operation_digest": challenge.operation.digest,
        "operation_id": challenge.operation.operation_id,
        "parameters_digest": parameters_digest,
        "precheck_digest": challenge.operation.precheck_digest,
        "requester_principal": challenge.operation.principal,
        "requester_user_id": challenge.operation.user_id,
    }
    unsigned = {
        key: value for key, value in preview.items() if key != "preview_digest"
    }
    assert preview["preview_digest"] == hashlib.sha256(
        canonical_json(unsigned)
    ).hexdigest()

    def keys(value):
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert keys(preview).isdisjoint(
        {
            "approval",
            "approval_signature",
            "auth_signature",
            "nonce",
            "session_handle",
        }
    )

    preview["operation"]["parameters"]["partner_id"] = 999
    repeated = authority.inspect_approval(
        "approver-handle", challenge.challenge_id
    )
    assert repeated["operation"]["parameters"]["partner_id"] == 101
    assert [event.event_type for event in store.audit_events()] == [
        "approval.challenge_created",
        "approval.challenge_inspected",
        "approval.challenge_inspected",
    ]
    assert store.audit_events()[-1].payload == {
        "operation_revision": challenge.operation.revision,
        "preview_digest": repeated["preview_digest"],
        "state": "pending",
    }


def test_inspection_enforces_approver_acl_separation_and_company(harness) -> None:
    authority, store, _, sessions, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")

    with pytest.raises(AuthorityError, match="cannot approve"):
        authority.inspect_approval("requester-handle", challenge.challenge_id)
    sessions["unauthorized"] = session(
        session_id="unauthorized-session", principal="pi:user-85", user_id=85
    )
    with pytest.raises(AuthorityError, match="not authorized"):
        authority.inspect_approval("unauthorized", challenge.challenge_id)
    sessions["cross-company"] = session(
        session_id="cross-company-session",
        principal="pi:user-84",
        user_id=84,
        company_id=8,
        allowed_company_ids=frozenset({8}),
    )
    with pytest.raises(AuthorityError, match="company binding"):
        authority.inspect_approval("cross-company", challenge.challenge_id)

    assert store.get_challenge(challenge.challenge_id).state is ApprovalChallengeState.PENDING
    assert [event.event_type for event in store.audit_events()] == [
        "approval.challenge_created"
    ]


def test_inspection_recomputes_expired_without_approval(harness) -> None:
    authority, store, clock, _, _ = harness
    expired = authority.request_approval("requester-handle", "op-1")
    clock.value = NOW + timedelta(seconds=120)

    expired_preview = authority.inspect_approval(
        "approver-handle", expired.challenge_id
    )

    expired_stored = store.get_challenge(expired.challenge_id)
    assert expired_preview["challenge"]["state"] == "expired"
    assert expired_stored.state is ApprovalChallengeState.EXPIRED
    assert expired_stored.approval is None


def test_inspection_recomputes_stale_without_approval(harness) -> None:
    authority, store, _, _, operations = harness
    stale = authority.request_approval("requester-handle", "op-1")
    operations["op-1"] = replace(operations["op-1"], precheck_digest="f" * 64)

    stale_preview = authority.inspect_approval(
        "approver-handle", stale.challenge_id
    )

    stale_stored = store.get_challenge(stale.challenge_id)
    assert stale_preview["challenge"]["state"] == "stale"
    assert stale_stored.state is ApprovalChallengeState.STALE
    assert stale_stored.approval is None


def test_requester_must_exactly_match_authoritative_operation(harness) -> None:
    authority, store, _, sessions, _ = harness
    sessions["wrong-principal"] = session(
        session_id="wrong-principal-session",
        principal="pi:user-else",
        user_id=42,
    )
    with pytest.raises(AuthorityError, match="requester binding"):
        authority.request_approval("wrong-principal", "op-1")
    with pytest.raises(AuthorityError, match="requester binding"):
        authority.request_approval("approver-handle", "op-1")
    assert store.audit_events() == ()


def test_approval_enforces_separation_authorization_and_company(harness) -> None:
    authority, store, _, sessions, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")

    with pytest.raises(AuthorityError, match="cannot approve"):
        authority.decide_approval(
            "requester-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    sessions["unauthorized"] = session(
        session_id="unauthorized-session", principal="pi:user-85", user_id=85
    )
    with pytest.raises(AuthorityError, match="not authorized"):
        authority.decide_approval(
            "unauthorized", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    sessions["cross-company"] = session(
        session_id="cross-company-session",
        principal="pi:user-84",
        user_id=84,
        company_id=8,
        allowed_company_ids=frozenset({8}),
    )
    with pytest.raises(AuthorityError, match="company binding"):
        authority.decide_approval(
            "cross-company", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    assert store.get_challenge(challenge.challenge_id).state is ApprovalChallengeState.PENDING


def test_approved_challenge_returns_one_reusable_exact_signed_approval(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")

    approved = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    retried = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )

    assert approved == retried
    assert approved.approval is not None
    assert approved.approval.operation_digest == approved.operation.digest
    assert approved.approval.precheck_digest == approved.operation.precheck_digest
    assert approved.approval.operation_revision == approved.operation.revision
    accepted = approve_operation(
        approved.operation,
        approved.approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-key-1",
        is_approver_authorized=lambda user_id, company_id, capability_id: True,
        consume_nonce=lambda nonce, operation_id, approver_user_id: True,
        approval_ttl_seconds=120,
        expected_revision=approved.operation.revision,
    )
    assert accepted.state is State.APPROVED
    assert [event.event_type for event in store.audit_events()] == [
        "approval.challenge_created",
        "approval.challenge_approved",
        "approval.challenge_reused",
    ]
    assert all(
        "nonce" not in event.payload_json and "signature" not in event.payload_json
        for event in store.audit_events()
    )


def test_denial_is_terminal_and_same_decision_retry_reuses_it(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    denied = authority.decide_approval(
        "approver-handle",
        challenge.challenge_id,
        ApprovalDecision.DENY,
        reason="Invoice evidence is incomplete",
    )
    retried = authority.decide_approval(
        "approver-handle",
        challenge.challenge_id,
        ApprovalDecision.DENY,
        reason="Invoice evidence is incomplete",
    )

    assert retried == denied
    assert denied.state is ApprovalChallengeState.DENIED
    assert authority.request_approval("requester-handle", "op-1") == denied
    with pytest.raises(ChallengeTerminal, match="denied"):
        authority.decide_approval(
            "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    assert len(store.challenges()) == 1


def test_expiry_is_terminal_and_cannot_be_bypassed_by_new_request(harness) -> None:
    authority, store, clock, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    clock.value = NOW + timedelta(seconds=120)

    with pytest.raises(ChallengeExpired, match="expired"):
        authority.decide_approval(
            "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    expired = authority.request_approval("requester-handle", "op-1")
    assert expired.state is ApprovalChallengeState.EXPIRED
    assert len(store.challenges()) == 1
    with pytest.raises(ChallengeExpired, match="expired"):
        authority.decide_approval(
            "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )


def test_invalid_ttl_policy_fails_closed_without_a_challenge(harness) -> None:
    authority, store, clock, sessions, operations = harness
    invalid = TrustedAuthority(
        session_resolver=lambda handle: sessions.get(handle),
        operation_resolver=lambda operation_id: operations.get(operation_id),
        approver_authorizer=lambda trusted_session, operation: True,
        approval_ttl_resolver=lambda operation: 901,
        keys=AuthorityKeys(
            context_key_id="auth-key-1",
            context_secret=AUTH_SECRET,
            approval_key_id="approval-key-1",
            approval_secret=APPROVAL_SECRET,
        ),
        store=store,
        clock=clock,
    )
    with pytest.raises(AuthorityError, match="TTL policy"):
        invalid.request_approval("requester-handle", "op-1")
    assert store.challenges() == ()


def test_operation_change_makes_challenge_stale_and_never_signs(harness) -> None:
    authority, store, _, _, operations = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    operations["op-1"] = replace(
        operations["op-1"], precheck_digest="f" * 64
    )

    with pytest.raises(ChallengeTerminal, match="changed"):
        authority.decide_approval(
            "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    stale = store.get_challenge(challenge.challenge_id)
    assert stale.state is ApprovalChallengeState.STALE
    assert stale.approval is None
    with pytest.raises(ChallengeTerminal, match="stale"):
        authority.request_approval("requester-handle", "op-1")


def test_approved_execute_builds_approval_and_context_internally(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    approved = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )

    action = authority.issue_approved_execute(
        "requester-handle", challenge.challenge_id
    )

    assert action.action == "operation.approve_execute"
    assert action.request == {
        "operation_id": "op-1",
        "approval": approval_to_mapping(approved.approval),
        "reconciliation_only": False,
    }
    assert action.context.user_id == 42
    assert verify_write_action_context(
        action.context,
        action=action.action,
        request=action.request,
        now=NOW,
        secret=AUTH_SECRET,
        expected_key_id="auth-key-1",
    )
    assert store.audit_events()[-1].event_type == "write_action.approved_context_issued"


def test_approved_execute_rejects_nonrequester_and_expired_approval(harness) -> None:
    authority, _, clock, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    with pytest.raises(AuthorityError, match="requester binding"):
        authority.issue_approved_execute("approver-handle", challenge.challenge_id)
    clock.value = challenge.expires_at
    with pytest.raises(ChallengeExpired, match="expired"):
        authority.issue_approved_execute("requester-handle", challenge.challenge_id)


@pytest.mark.parametrize("state", [State.EXECUTING, State.VERIFYING])
def test_expired_inflight_approval_issues_reconciliation_only_authority(
    harness, state
) -> None:
    authority, store, clock, _, operations = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    approved = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    accepted = approve_operation(
        approved.operation,
        approved.approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-key-1",
        is_approver_authorized=lambda *_args: True,
        consume_nonce=lambda *_args: True,
        approval_ttl_seconds=120,
        expected_revision=approved.operation.revision,
    )
    executing = begin_execution(
        accepted,
        approved.approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-key-1",
        is_approver_authorized=lambda *_args: True,
        approval_ttl_seconds=120,
        expected_revision=accepted.revision,
    )
    operations["op-1"] = (
        executing
        if state is State.EXECUTING
        else replace(
            executing,
            state=State.VERIFYING,
            revision=executing.revision + 1,
            execution_result_digest="d" * 64,
        )
    )
    operations["op-1"].assert_integrity()
    clock.value = challenge.expires_at

    action = authority.issue_approved_execute_for_operation(
        "requester-handle", "op-1"
    )

    assert action.request["reconciliation_only"] is True
    assert action.request["approval"] == approval_to_mapping(approved.approval)
    assert verify_write_action_context(
        action.context,
        action=action.action,
        request=action.request,
        now=clock.value,
        secret=AUTH_SECRET,
        expected_key_id="auth-key-1",
    )
    assert store.audit_events()[-1].payload["reconciliation_only"] is True


@pytest.mark.parametrize(
    ("state", "expected_reconciliation_only"),
    [(State.EXECUTING, False), (State.VERIFYING, True)],
)
def test_unexpired_inflight_retry_uses_safe_reconciliation_mode(
    harness, state, expected_reconciliation_only
) -> None:
    authority, _, _, _, operations = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    approved = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    accepted = approve_operation(
        approved.operation,
        approved.approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-key-1",
        is_approver_authorized=lambda *_args: True,
        consume_nonce=lambda *_args: True,
        approval_ttl_seconds=120,
        expected_revision=approved.operation.revision,
    )
    executing = begin_execution(
        accepted,
        approved.approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-key-1",
        is_approver_authorized=lambda *_args: True,
        approval_ttl_seconds=120,
        expected_revision=accepted.revision,
    )
    operations["op-1"] = (
        executing
        if state is State.EXECUTING
        else replace(
            executing,
            state=State.VERIFYING,
            revision=executing.revision + 1,
            execution_result_digest="d" * 64,
        )
    )
    operations["op-1"].assert_integrity()

    action = authority.issue_approved_execute_for_operation(
        "requester-handle", "op-1"
    )

    assert action.request["reconciliation_only"] is expected_reconciliation_only


def test_store_exposes_frozen_hash_chained_append_only_audit(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.DENY,
        reason="Not approved",
    )
    events = store.audit_events()

    assert isinstance(events, tuple)
    assert events[0].previous_hash is None
    assert events[1].previous_hash == events[0].event_hash
    store.verify_audit_chain()
    with pytest.raises(FrozenInstanceError):
        events[0].event_type = "tampered"
    detached = events[0].payload
    detached["state"] = "tampered"
    assert events[0].payload["state"] == "pending"


def test_store_rejects_backdated_audit_events(harness) -> None:
    authority, store, clock, _, _ = harness
    request = {
        "operation_id": "new-op",
        "request_id": "new-request",
        "capability_id": "acct.invoice.customer_create.v1",
        "parameters": {"company_id": 7},
    }
    authority.issue_write_action("requester-handle", "operation.prepare", request)
    clock.value = NOW - timedelta(seconds=1)

    with pytest.raises(AuthorityError, match="time moved backwards"):
        authority.issue_write_action("requester-handle", "operation.prepare", request)
    assert len(store.audit_events()) == 1


def test_store_rejects_duplicate_approval_nonce_without_partial_decision(
    harness,
) -> None:
    authority, store, _, _, operations = harness
    operations["op-2"] = awaiting_operation(operation_id="op-2")
    object.__setattr__(authority, "_nonce_factory", lambda: "fixed-nonce")
    first = authority.request_approval("requester-handle", "op-1")
    authority.decide_approval(
        "approver-handle", first.challenge_id, ApprovalDecision.APPROVE
    )
    second = authority.request_approval("requester-handle", "op-2")

    with pytest.raises(AuthorityError, match="nonce was already issued"):
        authority.decide_approval(
            "approver-handle", second.challenge_id, ApprovalDecision.APPROVE
        )
    stored = store.get_challenge(second.challenge_id)
    assert stored.state is ApprovalChallengeState.PENDING
    assert stored.approval is None


def test_key_and_session_configuration_fail_closed() -> None:
    with pytest.raises(AuthorityError, match="at least 32 bytes"):
        AuthorityKeys(
            context_key_id="auth",
            context_secret=b"short",
            approval_key_id="approval",
            approval_secret=APPROVAL_SECRET,
        )
    with pytest.raises(AuthorityError, match="allowed companies"):
        session(
            session_id="bad",
            principal="pi:user-42",
            user_id=42,
            company_id=7,
            allowed_company_ids=frozenset({8}),
        )
    with pytest.raises(AuthorityError, match="trusted principal"):
        session(
            session_id="bad-del-principal",
            principal="pi:user\x7f42",
            user_id=42,
        )


def test_store_rejects_external_mutation_and_duplicate_ids(harness) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    with pytest.raises(FrozenInstanceError):
        challenge.state = ApprovalChallengeState.APPROVED
    assert store.get_challenge(challenge.challenge_id).state is ApprovalChallengeState.PENDING


def test_signing_errors_are_normalized_and_no_partial_approval_is_stored(
    harness, monkeypatch
) -> None:
    authority, store, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    def fail_signing(**kwargs):
        raise ApprovalRejected("injected signer failure")

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.trusted_authority.sign_approval", fail_signing
    )

    with pytest.raises(AuthorityError, match="approval signing failed"):
        authority.decide_approval(
            "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
        )
    assert store.get_challenge(challenge.challenge_id).state is ApprovalChallengeState.PENDING
    assert store.get_challenge(challenge.challenge_id).approval is None


def test_underlying_approval_rejects_wrong_policy_ttl(harness) -> None:
    authority, _, _, _, _ = harness
    challenge = authority.request_approval("requester-handle", "op-1")
    approved = authority.decide_approval(
        "approver-handle", challenge.challenge_id, ApprovalDecision.APPROVE
    )
    with pytest.raises(ApprovalRejected, match="policy TTL"):
        approve_operation(
            approved.operation,
            approved.approval,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id="approval-key-1",
            is_approver_authorized=lambda user_id, company_id, capability_id: True,
            consume_nonce=lambda nonce, operation_id, approver_user_id: True,
            approval_ttl_seconds=30,
            expected_revision=approved.operation.revision,
        )
