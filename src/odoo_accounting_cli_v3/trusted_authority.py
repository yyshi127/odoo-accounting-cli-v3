"""Fail-closed trusted identity and approval issuer core.

This module is intentionally transport- and SSO-agnostic.  Callers provide
only opaque session handles and business requests; trusted adapters resolve
identity, authoritative operations, approval policy, and signing keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Callable, Protocol

from .auth import MAX_CONTEXT_TTL, sign_write_action_context
from .gateway import RequestContext
from .operations import (
    MAX_APPROVAL_TTL,
    Approval,
    ApprovalRejected,
    Operation,
    State,
    canonical_json,
    sign_approval,
)
from .write_protocol import approval_to_mapping


class AuthorityError(ValueError):
    """A trusted-authority request was rejected without issuing authority."""


class ChallengeExpired(AuthorityError):
    pass


class ChallengeTerminal(AuthorityError):
    pass


class AuthorityConcurrentUpdate(AuthorityError):
    pass


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class ApprovalChallengeState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    STALE = "stale"


def _aware(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _identifier(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AuthorityError(f"{field_name} is invalid")
    return value


def _strong_secret(value: object) -> bool:
    return isinstance(value, bytes) and len(value) >= 32


def _release_digest(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AuthorityError(f"{field_name} is invalid")
    return value


@dataclass(frozen=True)
class TrustedSession:
    """Identity returned by a trusted session resolver, never by the caller."""

    session_id: str
    principal: str
    odoo_instance_id: str
    database_name: str
    database_uuid: str
    user_id: int
    company_id: int
    allowed_company_ids: frozenset[int]
    environment: str
    release_digest: str
    registry_digest: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.session_id, "trusted session ID")
        _identifier(self.principal, "trusted principal")
        _identifier(self.odoo_instance_id, "trusted Odoo instance")
        _identifier(self.database_name, "trusted database name")
        try:
            normalized_uuid = str(uuid.UUID(self.database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise AuthorityError("trusted database UUID is invalid") from exc
        object.__setattr__(self, "database_uuid", normalized_uuid)
        if (
            type(self.user_id) is not int
            or self.user_id <= 0
            or type(self.company_id) is not int
            or self.company_id <= 0
        ):
            raise AuthorityError("trusted user and company bindings are invalid")
        if (
            not isinstance(self.allowed_company_ids, frozenset)
            or not self.allowed_company_ids
            or any(
                type(company_id) is not int or company_id <= 0
                for company_id in self.allowed_company_ids
            )
            or self.company_id not in self.allowed_company_ids
        ):
            raise AuthorityError("trusted allowed companies are invalid")
        if self.environment not in {"test", "sandbox", "production"}:
            raise AuthorityError("trusted environment is invalid")
        _release_digest(self.release_digest, "trusted release digest")
        _release_digest(self.registry_digest, "trusted registry digest")
        if (
            not _aware(self.issued_at)
            or not _aware(self.expires_at)
            or self.expires_at <= self.issued_at
        ):
            raise AuthorityError("trusted session timestamps are invalid")


@dataclass(frozen=True)
class AuthorityKeys:
    context_key_id: str
    context_secret: bytes = field(repr=False)
    approval_key_id: str
    approval_secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _identifier(self.context_key_id, "context key ID")
        _identifier(self.approval_key_id, "approval key ID")
        if not _strong_secret(self.context_secret) or not _strong_secret(
            self.approval_secret
        ):
            raise AuthorityError("authority HMAC secrets must be bytes of at least 32 bytes")


@dataclass(frozen=True)
class AuthorizedWriteAction:
    action: str
    request: dict[str, Any]
    context: RequestContext


@dataclass(frozen=True)
class ApprovalChallenge:
    challenge_id: str
    binding_digest: str
    operation: Operation
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int
    state: ApprovalChallengeState = ApprovalChallengeState.PENDING
    version: int = 0
    decided_at: datetime | None = None
    decider_user_id: int | None = None
    denial_reason: str | None = None
    approval: Approval | None = None

    def __post_init__(self) -> None:
        _identifier(self.challenge_id, "approval challenge ID")
        self.operation.assert_integrity()
        if (
            not isinstance(self.binding_digest, str)
            or len(self.binding_digest) != 64
            or self.binding_digest != self.binding_digest.lower()
            or any(character not in "0123456789abcdef" for character in self.binding_digest)
            or not _aware(self.issued_at)
            or not _aware(self.expires_at)
            or self.expires_at <= self.issued_at
            or type(self.ttl_seconds) is not int
            or not 1 <= self.ttl_seconds <= int(MAX_APPROVAL_TTL.total_seconds())
            or self.expires_at - self.issued_at > timedelta(seconds=self.ttl_seconds)
            or type(self.version) is not int
            or self.version < 0
        ):
            raise AuthorityError("approval challenge metadata is invalid")
        terminal = self.state is not ApprovalChallengeState.PENDING
        if terminal != (self.decided_at is not None):
            raise AuthorityError("approval challenge decision metadata is incomplete")
        if self.decided_at is not None and not _aware(self.decided_at):
            raise AuthorityError("approval challenge decision time is invalid")
        if self.state is ApprovalChallengeState.APPROVED:
            if (
                self.approval is None
                or type(self.decider_user_id) is not int
                or self.decider_user_id <= 0
                or self.denial_reason is not None
            ):
                raise AuthorityError("approved challenge metadata is invalid")
        elif self.state is ApprovalChallengeState.DENIED:
            if (
                self.approval is not None
                or type(self.decider_user_id) is not int
                or self.decider_user_id <= 0
                or not isinstance(self.denial_reason, str)
                or not self.denial_reason
            ):
                raise AuthorityError("denied challenge metadata is invalid")
        elif self.state in {
            ApprovalChallengeState.EXPIRED,
            ApprovalChallengeState.STALE,
        }:
            if (
                self.approval is not None
                or self.decider_user_id is not None
                or self.denial_reason is not None
            ):
                raise AuthorityError("closed challenge metadata is invalid")
        elif (
            self.approval is not None
            or self.decider_user_id is not None
            or self.denial_reason is not None
        ):
            raise AuthorityError("pending challenge metadata is invalid")


@dataclass(frozen=True)
class AuthorityAuditDraft:
    event_id: str
    event_type: str
    occurred_at: datetime
    challenge_id: str | None
    operation_id: str | None
    binding_digest: str | None
    actor_user_id: int
    payload_json: str


@dataclass(frozen=True)
class AuthorityAuditEvent:
    sequence: int
    event_id: str
    event_type: str
    occurred_at: datetime
    challenge_id: str | None
    operation_id: str | None
    binding_digest: str | None
    actor_user_id: int
    payload_json: str
    previous_hash: str | None
    event_hash: str

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.payload_json)


def _audit_hash(event: AuthorityAuditEvent) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "actor_user_id": event.actor_user_id,
                "binding_digest": event.binding_digest,
                "challenge_id": event.challenge_id,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "occurred_at": event.occurred_at.astimezone(timezone.utc).isoformat(),
                "operation_id": event.operation_id,
                "payload": event.payload,
                "previous_hash": event.previous_hash,
                "sequence": event.sequence,
            }
        )
    ).hexdigest()


class ApprovalChallengeStore(Protocol):
    """Atomic challenge plus append-only audit persistence contract."""

    def get_challenge(self, challenge_id: str) -> ApprovalChallenge: ...

    def find_challenge(self, challenge_id: str) -> ApprovalChallenge | None: ...

    def find_by_binding(self, binding_digest: str) -> ApprovalChallenge | None: ...

    def find_by_operation_revision(
        self, operation_id: str, revision: int
    ) -> ApprovalChallenge | None: ...

    def create_challenge(
        self, challenge: ApprovalChallenge, event: AuthorityAuditDraft
    ) -> tuple[ApprovalChallenge, bool]: ...

    def transition_challenge(
        self,
        challenge: ApprovalChallenge,
        *,
        expected_version: int,
        event: AuthorityAuditDraft,
    ) -> ApprovalChallenge: ...

    def append_audit_event(self, event: AuthorityAuditDraft) -> AuthorityAuditEvent: ...

    def audit_events(self) -> tuple[AuthorityAuditEvent, ...]: ...


class InMemoryApprovalChallengeStore:
    """Thread-safe reference store for tests; production needs durable storage."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._challenges: dict[str, ApprovalChallenge] = {}
        self._bindings: dict[str, str] = {}
        self._operation_revisions: dict[tuple[str, int], str] = {}
        self._events: tuple[AuthorityAuditEvent, ...] = ()
        self._event_ids: set[str] = set()
        self._approval_nonce_digests: set[str] = set()

    def get_challenge(self, challenge_id: str) -> ApprovalChallenge:
        with self._lock:
            try:
                return self._challenges[challenge_id]
            except KeyError as exc:
                raise AuthorityError("approval challenge is unknown") from exc

    def find_challenge(self, challenge_id: str) -> ApprovalChallenge | None:
        _identifier(challenge_id, "approval challenge ID")
        with self._lock:
            return self._challenges.get(challenge_id)

    def find_by_binding(self, binding_digest: str) -> ApprovalChallenge | None:
        with self._lock:
            challenge_id = self._bindings.get(binding_digest)
            return None if challenge_id is None else self._challenges[challenge_id]

    def find_by_operation_revision(
        self, operation_id: str, revision: int
    ) -> ApprovalChallenge | None:
        with self._lock:
            challenge_id = self._operation_revisions.get((operation_id, revision))
            return None if challenge_id is None else self._challenges[challenge_id]

    def challenges(self) -> tuple[ApprovalChallenge, ...]:
        with self._lock:
            return tuple(self._challenges.values())

    def _append_locked(self, draft: AuthorityAuditDraft) -> AuthorityAuditEvent:
        _identifier(draft.event_id, "authority audit event ID")
        _identifier(draft.event_type, "authority audit event type")
        if draft.event_id in self._event_ids:
            raise AuthorityError("authority audit event ID already exists")
        if (
            not _aware(draft.occurred_at)
            or type(draft.actor_user_id) is not int
            or draft.actor_user_id <= 0
        ):
            raise AuthorityError("authority audit event metadata is invalid")
        if self._events and draft.occurred_at < self._events[-1].occurred_at:
            raise AuthorityError("authority audit time moved backwards")
        try:
            payload = json.loads(draft.payload_json)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuthorityError("authority audit payload is invalid") from exc
        if (
            not isinstance(payload, dict)
            or canonical_json(payload).decode("utf-8") != draft.payload_json
        ):
            raise AuthorityError("authority audit payload is not canonical")
        previous_hash = self._events[-1].event_hash if self._events else None
        unsigned = AuthorityAuditEvent(
            sequence=len(self._events) + 1,
            event_id=draft.event_id,
            event_type=draft.event_type,
            occurred_at=draft.occurred_at,
            challenge_id=draft.challenge_id,
            operation_id=draft.operation_id,
            binding_digest=draft.binding_digest,
            actor_user_id=draft.actor_user_id,
            payload_json=draft.payload_json,
            previous_hash=previous_hash,
            event_hash="",
        )
        event = replace(unsigned, event_hash=_audit_hash(unsigned))
        self._events = (*self._events, event)
        self._event_ids.add(event.event_id)
        return event

    def create_challenge(
        self, challenge: ApprovalChallenge, event: AuthorityAuditDraft
    ) -> tuple[ApprovalChallenge, bool]:
        with self._lock:
            if (
                challenge.state is not ApprovalChallengeState.PENDING
                or challenge.version != 0
                or challenge.binding_digest
                != _operation_binding_digest(challenge.operation)
            ):
                raise AuthorityError("new approval challenge is invalid")
            existing_id = self._bindings.get(challenge.binding_digest)
            if existing_id is not None:
                return self._challenges[existing_id], False
            operation_key = (challenge.operation.operation_id, challenge.operation.revision)
            conflicting_id = self._operation_revisions.get(operation_key)
            if conflicting_id is not None:
                raise AuthorityConcurrentUpdate(
                    "operation revision already has an approval challenge"
                )
            if challenge.challenge_id in self._challenges:
                raise AuthorityError("approval challenge ID already exists")
            if (
                event.challenge_id != challenge.challenge_id
                or event.operation_id != challenge.operation.operation_id
                or event.binding_digest != challenge.binding_digest
            ):
                raise AuthorityError("challenge audit binding is invalid")
            self._append_locked(event)
            self._challenges[challenge.challenge_id] = challenge
            self._bindings[challenge.binding_digest] = challenge.challenge_id
            self._operation_revisions[operation_key] = challenge.challenge_id
            return challenge, True

    @staticmethod
    def _immutable_challenge_fields(challenge: ApprovalChallenge) -> tuple[Any, ...]:
        return (
            challenge.challenge_id,
            challenge.binding_digest,
            challenge.operation,
            challenge.issued_at,
            challenge.expires_at,
            challenge.ttl_seconds,
        )

    def transition_challenge(
        self,
        challenge: ApprovalChallenge,
        *,
        expected_version: int,
        event: AuthorityAuditDraft,
    ) -> ApprovalChallenge:
        with self._lock:
            current = self.get_challenge(challenge.challenge_id)
            if current.version != expected_version:
                raise AuthorityConcurrentUpdate("approval challenge version changed")
            if (
                self._immutable_challenge_fields(current)
                != self._immutable_challenge_fields(challenge)
                or challenge.version != current.version + 1
                or current.state is not ApprovalChallengeState.PENDING
                or challenge.state is ApprovalChallengeState.PENDING
                or event.challenge_id != challenge.challenge_id
                or event.operation_id != challenge.operation.operation_id
                or event.binding_digest != challenge.binding_digest
            ):
                raise AuthorityError("approval challenge transition is invalid")
            nonce_digest = None
            if challenge.state is ApprovalChallengeState.APPROVED:
                if challenge.approval is None:  # pragma: no cover - dataclass invariant
                    raise AuthorityError("approved challenge has no approval")
                nonce_digest = hashlib.sha256(
                    challenge.approval.nonce.encode("utf-8")
                ).hexdigest()
                if nonce_digest in self._approval_nonce_digests:
                    raise AuthorityError("approval nonce was already issued")
            self._append_locked(event)
            self._challenges[challenge.challenge_id] = challenge
            if nonce_digest is not None:
                self._approval_nonce_digests.add(nonce_digest)
            return challenge

    def append_audit_event(self, event: AuthorityAuditDraft) -> AuthorityAuditEvent:
        with self._lock:
            return self._append_locked(event)

    def audit_events(self) -> tuple[AuthorityAuditEvent, ...]:
        with self._lock:
            return self._events

    def verify_audit_chain(self) -> bool:
        with self._lock:
            previous_hash = None
            previous_time = None
            for sequence, event in enumerate(self._events, start=1):
                if (
                    event.sequence != sequence
                    or event.previous_hash != previous_hash
                    or (
                        previous_time is not None
                        and event.occurred_at < previous_time
                    )
                    or event.event_hash != _audit_hash(replace(event, event_hash=""))
                ):
                    raise AuthorityError("authority audit chain verification failed")
                previous_hash = event.event_hash
                previous_time = event.occurred_at
        return True


_FORBIDDEN_CALLER_KEYS = frozenset(
    {
        "allowed_company_ids",
        "approval",
        "approval_nonce_digest",
        "approval_signature",
        "approver_user_id",
        "auth_expires_at",
        "auth_issued_at",
        "auth_key_id",
        "auth_request_digest",
        "auth_signature",
        "auth_signature_purpose",
        "auth_signature_version",
        "auth_token_id",
        "context",
        "operation_digest",
        "precheck_digest",
        "principal",
        "user_id",
    }
)


def _caller_controls_authority(value: Any) -> bool:
    if isinstance(value, dict):
        if set(value).intersection(_FORBIDDEN_CALLER_KEYS):
            return True
        return any(_caller_controls_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_caller_controls_authority(item) for item in value)
    return False


def _operation_binding_digest(operation: Operation) -> str:
    operation.assert_integrity()
    if (
        operation.state is not State.AWAITING_APPROVAL
        or operation.precheck_digest is None
    ):
        raise AuthorityError("operation is not awaiting approval with a precheck")
    return hashlib.sha256(
        canonical_json(
            {
                "company_id": operation.company_id,
                "database_name": operation.database_name,
                "database_uuid": operation.database_uuid,
                "environment": operation.environment,
                "odoo_instance_id": operation.odoo_instance_id,
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "precheck_digest": operation.precheck_digest,
                "principal": operation.principal,
                "request_id": operation.request_id,
                "user_id": operation.user_id,
            }
        )
    ).hexdigest()


def _approval_inspection_preview(
    challenge: ApprovalChallenge,
) -> dict[str, Any]:
    """Rebuild one unsigned, JSON-only preview from the frozen challenge."""

    operation = challenge.operation
    binding_digest = _operation_binding_digest(operation)
    if not hmac.compare_digest(binding_digest, challenge.binding_digest):
        raise AuthorityError("approval challenge binding integrity failed")
    parameters = operation.parameters
    parameters_digest = hashlib.sha256(canonical_json(parameters)).hexdigest()
    unsigned = {
        "schema_version": 1,
        "challenge": {
            "challenge_id": challenge.challenge_id,
            "binding_digest": challenge.binding_digest,
            "issued_at": challenge.issued_at.astimezone(timezone.utc).isoformat(),
            "expires_at": challenge.expires_at.astimezone(timezone.utc).isoformat(),
            "ttl_seconds": challenge.ttl_seconds,
            "state": challenge.state.value,
            "version": challenge.version,
        },
        "operation": {
            "operation_id": operation.operation_id,
            "request_id": operation.request_id,
            "capability_id": operation.capability_id,
            "parameters": parameters,
            "parameters_digest": parameters_digest,
            "principal": operation.principal,
            "user_id": operation.user_id,
            "company_id": operation.company_id,
            "idempotency_key": operation.idempotency_key,
            "odoo_instance_id": operation.odoo_instance_id,
            "database_name": operation.database_name,
            "database_uuid": operation.database_uuid,
            "environment": operation.environment,
            "registry_digest": operation.registry_digest,
            "release_digest": operation.release_digest,
            "operation_digest": operation.digest,
            "precheck_digest": operation.precheck_digest,
            "state": operation.state.value,
            "revision": operation.revision,
            "protocol_version": operation.protocol_version,
        },
        "summary": {
            "binding_digest": challenge.binding_digest,
            "capability_id": operation.capability_id,
            "challenge_id": challenge.challenge_id,
            "company_id": operation.company_id,
            "operation_digest": operation.digest,
            "operation_id": operation.operation_id,
            "parameters_digest": parameters_digest,
            "precheck_digest": operation.precheck_digest,
            "requester_principal": operation.principal,
            "requester_user_id": operation.user_id,
        },
    }
    preview = {
        **unsigned,
        "preview_digest": hashlib.sha256(canonical_json(unsigned)).hexdigest(),
    }
    try:
        detached = json.loads(canonical_json(preview))
    except (TypeError, ValueError, UnicodeError) as exc:  # pragma: no cover - guarded data
        raise AuthorityError("approval inspection preview is invalid") from exc
    if not isinstance(detached, dict):  # pragma: no cover - canonical invariant
        raise AuthorityError("approval inspection preview is invalid")
    return detached


class TrustedAuthority:
    """Issue trusted write contexts and exact, single-use approval authority."""

    def __init__(
        self,
        *,
        session_resolver: Callable[[str], TrustedSession | None],
        operation_resolver: Callable[[str], Operation | None],
        approver_authorizer: Callable[[TrustedSession, Operation], bool],
        approval_ttl_resolver: Callable[[Operation], int],
        keys: AuthorityKeys,
        store: ApprovalChallengeStore,
        clock: Callable[[], datetime],
        context_ttl_seconds: int = 300,
        challenge_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        event_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        auth_token_id_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ) -> None:
        if not isinstance(keys, AuthorityKeys):
            raise AuthorityError("authority signing keys are invalid")
        if (
            type(context_ttl_seconds) is not int
            or not 1 <= context_ttl_seconds <= int(MAX_CONTEXT_TTL.total_seconds())
        ):
            raise AuthorityError("write context TTL is invalid")
        for dependency in (
            session_resolver,
            operation_resolver,
            approver_authorizer,
            approval_ttl_resolver,
            clock,
            challenge_id_factory,
            event_id_factory,
            nonce_factory,
            auth_token_id_factory,
        ):
            if not callable(dependency):
                raise AuthorityError("authority dependency is not callable")
        self._session_resolver = session_resolver
        self._operation_resolver = operation_resolver
        self._approver_authorizer = approver_authorizer
        self._approval_ttl_resolver = approval_ttl_resolver
        self._keys = keys
        self._store = store
        self._clock = clock
        self._context_ttl_seconds = context_ttl_seconds
        self._challenge_id_factory = challenge_id_factory
        self._event_id_factory = event_id_factory
        self._nonce_factory = nonce_factory
        self._auth_token_id_factory = auth_token_id_factory

    def _now(self) -> datetime:
        try:
            now = self._clock()
        except Exception as exc:
            raise AuthorityError("trusted clock failed") from exc
        if not _aware(now):
            raise AuthorityError("trusted clock must return timezone-aware time")
        return now

    def _session(self, session_handle: str, now: datetime) -> TrustedSession:
        _identifier(session_handle, "session handle")
        try:
            trusted = self._session_resolver(session_handle)
        except Exception as exc:
            raise AuthorityError("trusted session resolution failed") from exc
        if not isinstance(trusted, TrustedSession):
            raise AuthorityError("trusted session was not resolved")
        if now < trusted.issued_at or now >= trusted.expires_at:
            raise AuthorityError("trusted session is not currently valid")
        return trusted

    def _operation(self, operation_id: str) -> Operation:
        _identifier(operation_id, "operation ID")
        try:
            operation = self._operation_resolver(operation_id)
        except Exception as exc:
            raise AuthorityError("trusted operation resolution failed") from exc
        if not isinstance(operation, Operation):
            raise AuthorityError("trusted operation was not resolved")
        try:
            operation.assert_integrity()
        except Exception as exc:
            raise AuthorityError("trusted operation integrity failed") from exc
        return operation

    @staticmethod
    def _requester_matches(session: TrustedSession, operation: Operation) -> bool:
        return (
            session.principal == operation.principal
            and session.user_id == operation.user_id
            and session.company_id == operation.company_id
            and session.odoo_instance_id == operation.odoo_instance_id
            and session.database_name == operation.database_name
            and session.database_uuid == operation.database_uuid
            and session.environment == operation.environment
        )

    @classmethod
    def _require_requester(
        cls, session: TrustedSession, operation: Operation
    ) -> None:
        if not cls._requester_matches(session, operation):
            raise AuthorityError("trusted requester binding does not match operation")

    @staticmethod
    def _require_approver_company(
        session: TrustedSession, operation: Operation
    ) -> None:
        if (
            session.company_id != operation.company_id
            or operation.company_id not in session.allowed_company_ids
            or session.odoo_instance_id != operation.odoo_instance_id
            or session.database_name != operation.database_name
            or session.database_uuid != operation.database_uuid
            or session.environment != operation.environment
        ):
            raise AuthorityError("trusted approver company binding does not match operation")

    def _authorized_approver(
        self, session: TrustedSession, operation: Operation
    ) -> None:
        if session.user_id == operation.user_id:
            raise AuthorityError("requester cannot approve their own operation")
        self._require_approver_company(session, operation)
        try:
            authorized = self._approver_authorizer(session, operation)
        except Exception as exc:
            raise AuthorityError("trusted approver authorization failed") from exc
        if authorized is not True:
            raise AuthorityError("trusted approver is not authorized")

    def _draft(
        self,
        *,
        event_type: str,
        now: datetime,
        actor_user_id: int,
        payload: dict[str, Any],
        challenge: ApprovalChallenge | None = None,
        operation: Operation | None = None,
    ) -> AuthorityAuditDraft:
        event_id = self._event_id_factory()
        _identifier(event_id, "authority audit event ID")
        selected_operation = operation if operation is not None else (
            None if challenge is None else challenge.operation
        )
        return AuthorityAuditDraft(
            event_id=event_id,
            event_type=event_type,
            occurred_at=now,
            challenge_id=None if challenge is None else challenge.challenge_id,
            operation_id=(
                None if selected_operation is None else selected_operation.operation_id
            ),
            binding_digest=(
                None if challenge is None else challenge.binding_digest
            ),
            actor_user_id=actor_user_id,
            payload_json=canonical_json(payload).decode("utf-8"),
        )

    @staticmethod
    def _validate_business_company(
        session: TrustedSession, request: dict[str, Any]
    ) -> None:
        parameters = request.get("parameters")
        if not isinstance(parameters, dict):
            return
        if "company_id" in parameters and parameters["company_id"] != session.company_id:
            raise AuthorityError("request does not match trusted bound company")
        requested_companies = parameters.get("company_ids")
        if requested_companies is not None and (
            not isinstance(requested_companies, list)
            or not requested_companies
            or any(type(company_id) is not int for company_id in requested_companies)
            or not set(requested_companies).issubset(session.allowed_company_ids)
        ):
            raise AuthorityError("request company set exceeds trusted allowed companies")

    def _context(
        self,
        *,
        session: TrustedSession,
        action: str,
        request: dict[str, Any],
        now: datetime,
        not_after: datetime | None = None,
    ) -> RequestContext:
        expires_at = min(
            session.expires_at,
            now + timedelta(seconds=self._context_ttl_seconds),
            not_after if not_after is not None else session.expires_at,
        )
        if expires_at <= now:
            raise AuthorityError("write context has no remaining validity")
        try:
            auth_token_id = self._auth_token_id_factory()
            _identifier(auth_token_id, "write authentication token ID")
            return sign_write_action_context(
                # A trusted session may authorize many actions, while each
                # signed action token is deliberately single-use in durable
                # replay storage.  Never reuse the session identifier here.
                auth_token_id=auth_token_id,
                principal=session.principal,
                odoo_instance_id=session.odoo_instance_id,
                database_name=session.database_name,
                database_uuid=session.database_uuid,
                user_id=session.user_id,
                company_id=session.company_id,
                allowed_company_ids=session.allowed_company_ids,
                environment=session.environment,
                action=action,
                request=request,
                issued_at=now,
                expires_at=expires_at,
                key_id=self._keys.context_key_id,
                secret=self._keys.context_secret,
            )
        except Exception as exc:
            raise AuthorityError("write context signing failed") from exc

    def issue_write_action(
        self,
        session_handle: str,
        action: str,
        request: dict[str, Any],
    ) -> AuthorizedWriteAction:
        """Sign a business write action; approval execution has a separate API."""

        now = self._now()
        trusted = self._session(session_handle, now)
        if action == "operation.approve_execute":
            raise AuthorityError("approval execution must use internally issued approval")
        if not isinstance(request, dict) or _caller_controls_authority(request):
            raise AuthorityError("request contains authority-controlled fields")
        try:
            detached = json.loads(canonical_json(request))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityError("write action request is invalid") from exc
        if not isinstance(detached, dict):
            raise AuthorityError("write action request must be an object")
        self._validate_business_company(trusted, detached)
        operation_id = detached.get("operation_id")
        if action in {
            "operation.preview",
            "operation.status",
            "operation.result",
        }:
            operation = self._operation(operation_id)
            self._require_requester(trusted, operation)
        elif action == "operation.recover":
            operation = self._operation(detached.get("origin_operation_id"))
            self._require_requester(trusted, operation)
        context = self._context(
            session=trusted, action=action, request=detached, now=now
        )
        self._store.append_audit_event(
            self._draft(
                event_type="write_action.context_issued",
                now=now,
                actor_user_id=trusted.user_id,
                operation=(
                    None
                    if action == "operation.prepare"
                    else operation
                    if "operation" in locals()
                    else None
                ),
                payload={
                    "action": action,
                    "request_digest": context.auth_request_digest,
                },
            )
        )
        return AuthorizedWriteAction(action=action, request=detached, context=context)

    def _ttl(self, operation: Operation) -> int:
        try:
            ttl = self._approval_ttl_resolver(operation)
        except Exception as exc:
            raise AuthorityError("trusted approval TTL policy failed") from exc
        if (
            type(ttl) is not int
            or not 1 <= ttl <= int(MAX_APPROVAL_TTL.total_seconds())
        ):
            raise AuthorityError("trusted approval TTL policy is invalid")
        return ttl

    def _transition_closed(
        self,
        challenge: ApprovalChallenge,
        *,
        state: ApprovalChallengeState,
        now: datetime,
        event_type: str,
        actor_user_id: int,
        payload: dict[str, Any],
    ) -> ApprovalChallenge:
        changed = replace(
            challenge,
            state=state,
            version=challenge.version + 1,
            decided_at=now,
        )
        try:
            return self._store.transition_challenge(
                changed,
                expected_version=challenge.version,
                event=self._draft(
                    event_type=event_type,
                    now=now,
                    actor_user_id=actor_user_id,
                    challenge=challenge,
                    payload=payload,
                ),
            )
        except AuthorityConcurrentUpdate:
            return self._store.get_challenge(challenge.challenge_id)

    def _expire_pending(
        self, challenge: ApprovalChallenge, now: datetime, actor_user_id: int
    ) -> ApprovalChallenge:
        if challenge.state is ApprovalChallengeState.PENDING and now >= challenge.expires_at:
            return self._transition_closed(
                challenge,
                state=ApprovalChallengeState.EXPIRED,
                now=now,
                event_type="approval.challenge_expired",
                actor_user_id=actor_user_id,
                payload={"state": "expired"},
            )
        return challenge

    def _mark_stale(
        self, challenge: ApprovalChallenge, now: datetime, actor_user_id: int
    ) -> ApprovalChallenge:
        if challenge.state is ApprovalChallengeState.PENDING:
            return self._transition_closed(
                challenge,
                state=ApprovalChallengeState.STALE,
                now=now,
                event_type="approval.challenge_stale",
                actor_user_id=actor_user_id,
                payload={"state": "stale"},
            )
        return challenge

    def _audit_reuse(
        self,
        challenge: ApprovalChallenge,
        now: datetime,
        actor_user_id: int,
    ) -> None:
        self._store.append_audit_event(
            self._draft(
                event_type="approval.challenge_reused",
                now=now,
                actor_user_id=actor_user_id,
                challenge=challenge,
                payload={"state": challenge.state.value},
            )
        )

    def request_approval(
        self, session_handle: str, operation_id: str
    ) -> ApprovalChallenge:
        now = self._now()
        trusted = self._session(session_handle, now)
        operation = self._operation(operation_id)
        self._require_requester(trusted, operation)
        binding_digest = _operation_binding_digest(operation)

        revision_challenge = self._store.find_by_operation_revision(
            operation.operation_id, operation.revision
        )
        if revision_challenge is not None and (
            revision_challenge.binding_digest != binding_digest
        ):
            stale = self._mark_stale(revision_challenge, now, trusted.user_id)
            raise ChallengeTerminal(
                f"approval challenge {stale.state.value}; trusted operation changed"
            )
        existing = self._store.find_by_binding(binding_digest)
        if existing is not None:
            existing = self._expire_pending(existing, now, trusted.user_id)
            if existing.state is ApprovalChallengeState.STALE:
                raise ChallengeTerminal("approval challenge is stale")
            self._audit_reuse(existing, now, trusted.user_id)
            return existing

        ttl = self._ttl(operation)
        challenge_id = self._challenge_id_factory()
        _identifier(challenge_id, "approval challenge ID")
        candidate = ApprovalChallenge(
            challenge_id=challenge_id,
            binding_digest=binding_digest,
            operation=operation,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
            ttl_seconds=ttl,
        )
        try:
            stored, created = self._store.create_challenge(
                candidate,
                self._draft(
                    event_type="approval.challenge_created",
                    now=now,
                    actor_user_id=trusted.user_id,
                    challenge=candidate,
                    payload={"state": "pending", "ttl_seconds": ttl},
                ),
            )
        except AuthorityConcurrentUpdate as exc:
            conflict = self._store.find_by_operation_revision(
                operation.operation_id, operation.revision
            )
            if conflict is None or conflict.binding_digest != binding_digest:
                raise ChallengeTerminal("trusted operation changed during challenge creation") from exc
            stored, created = conflict, False
        if not created:
            self._audit_reuse(stored, now, trusted.user_id)
        return stored

    def inspect_approval(
        self, session_handle: str, challenge_id: str
    ) -> dict[str, Any]:
        """Return the exact unsigned approval subject to an authorized approver."""

        now = self._now()
        trusted = self._session(session_handle, now)
        _identifier(challenge_id, "approval challenge ID")
        challenge = self._store.get_challenge(challenge_id)
        self._authorized_approver(trusted, challenge.operation)
        challenge = self._expire_pending(challenge, now, trusted.user_id)
        if challenge.state is ApprovalChallengeState.PENDING:
            current = self._operation(challenge.operation.operation_id)
            try:
                current_binding = _operation_binding_digest(current)
            except AuthorityError:
                current_binding = None
            if current_binding != challenge.binding_digest:
                challenge = self._mark_stale(challenge, now, trusted.user_id)

        preview = _approval_inspection_preview(challenge)
        self._store.append_audit_event(
            self._draft(
                event_type="approval.challenge_inspected",
                now=now,
                actor_user_id=trusted.user_id,
                challenge=challenge,
                payload={
                    "operation_revision": challenge.operation.revision,
                    "preview_digest": preview["preview_digest"],
                    "state": challenge.state.value,
                },
            )
        )
        # The audit store never receives or owns this object, and callers get a
        # fresh canonical copy on every inspection.
        return json.loads(canonical_json(preview))

    @staticmethod
    def _denial_reason(reason: str | None) -> str:
        if (
            not isinstance(reason, str)
            or reason != reason.strip()
            or not reason
            or len(reason) > 512
        ):
            raise AuthorityError("approval denial reason is invalid")
        return reason

    def _terminal_decision(
        self,
        challenge: ApprovalChallenge,
        decision: ApprovalDecision,
        reason: str | None,
        *,
        now: datetime,
        actor_user_id: int,
    ) -> ApprovalChallenge:
        if challenge.state is ApprovalChallengeState.EXPIRED or (
            challenge.state is ApprovalChallengeState.APPROVED
            and now >= challenge.expires_at
        ):
            raise ChallengeExpired("approval challenge or approval has expired")
        if challenge.state is ApprovalChallengeState.STALE:
            raise ChallengeTerminal("approval challenge is stale")
        if (
            challenge.state is ApprovalChallengeState.APPROVED
            and decision is ApprovalDecision.APPROVE
            and reason is None
        ):
            self._audit_reuse(challenge, now, actor_user_id)
            return challenge
        if (
            challenge.state is ApprovalChallengeState.DENIED
            and decision is ApprovalDecision.DENY
            and reason == challenge.denial_reason
        ):
            self._audit_reuse(challenge, now, actor_user_id)
            return challenge
        raise ChallengeTerminal(
            f"approval challenge is already {challenge.state.value}"
        )

    def decide_approval(
        self,
        session_handle: str,
        challenge_id: str,
        decision: ApprovalDecision,
        *,
        reason: str | None = None,
    ) -> ApprovalChallenge:
        if type(decision) is not ApprovalDecision:
            raise AuthorityError("approval decision is invalid")
        if decision is ApprovalDecision.APPROVE and reason is not None:
            raise AuthorityError("approval reason is only valid for denial")
        if decision is ApprovalDecision.DENY:
            reason = self._denial_reason(reason)
        now = self._now()
        trusted = self._session(session_handle, now)
        challenge = self._store.get_challenge(challenge_id)
        self._authorized_approver(trusted, challenge.operation)
        challenge = self._expire_pending(challenge, now, trusted.user_id)
        if challenge.state is not ApprovalChallengeState.PENDING:
            return self._terminal_decision(
                challenge,
                decision,
                reason,
                now=now,
                actor_user_id=trusted.user_id,
            )

        current = self._operation(challenge.operation.operation_id)
        try:
            current_binding = _operation_binding_digest(current)
        except AuthorityError:
            current_binding = None
        if current_binding != challenge.binding_digest:
            self._mark_stale(challenge, now, trusted.user_id)
            raise ChallengeTerminal("trusted operation changed after challenge issuance")

        if decision is ApprovalDecision.DENY:
            changed = replace(
                challenge,
                state=ApprovalChallengeState.DENIED,
                version=challenge.version + 1,
                decided_at=now,
                decider_user_id=trusted.user_id,
                denial_reason=reason,
            )
            event_type = "approval.challenge_denied"
            payload = {"state": "denied", "reason": reason}
        else:
            try:
                nonce = self._nonce_factory()
                approval = sign_approval(
                    operation=challenge.operation,
                    approver_user_id=trusted.user_id,
                    nonce=nonce,
                    issued_at=now,
                    expires_at=challenge.expires_at,
                    approval_ttl_seconds=challenge.ttl_seconds,
                    key_id=self._keys.approval_key_id,
                    secret=self._keys.approval_secret,
                )
            except Exception as exc:
                raise AuthorityError("approval signing failed") from exc
            changed = replace(
                challenge,
                state=ApprovalChallengeState.APPROVED,
                version=challenge.version + 1,
                decided_at=now,
                decider_user_id=trusted.user_id,
                approval=approval,
            )
            event_type = "approval.challenge_approved"
            payload = {"approver_user_id": trusted.user_id, "state": "approved"}
        try:
            return self._store.transition_challenge(
                changed,
                expected_version=challenge.version,
                event=self._draft(
                    event_type=event_type,
                    now=now,
                    actor_user_id=trusted.user_id,
                    challenge=challenge,
                    payload=payload,
                ),
            )
        except AuthorityConcurrentUpdate:
            current_challenge = self._store.get_challenge(challenge.challenge_id)
            return self._terminal_decision(
                current_challenge,
                decision,
                reason,
                now=now,
                actor_user_id=trusted.user_id,
            )

    @staticmethod
    def _same_approved_operation(
        challenge: ApprovalChallenge, current: Operation
    ) -> bool:
        """Match immutable content after the operation advances past approval."""

        approved = challenge.operation
        return (
            approved.operation_id == current.operation_id
            and approved.request_id == current.request_id
            and approved.capability_id == current.capability_id
            and approved.parameters_json == current.parameters_json
            and approved.principal == current.principal
            and approved.user_id == current.user_id
            and approved.company_id == current.company_id
            and approved.idempotency_key == current.idempotency_key
            and approved.odoo_instance_id == current.odoo_instance_id
            and approved.database_name == current.database_name
            and approved.database_uuid == current.database_uuid
            and approved.environment == current.environment
            and approved.registry_digest == current.registry_digest
            and approved.release_digest == current.release_digest
            and approved.digest == current.digest
            and approved.precheck_digest == current.precheck_digest
        )

    @staticmethod
    def _stored_approval_matches(
        challenge: ApprovalChallenge, current: Operation
    ) -> bool:
        approval = challenge.approval
        if approval is None:
            return False
        return (
            current.approval_signature == approval.signature
            and current.approval_nonce_digest
            == hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest()
            and current.approval_issued_at == approval.issued_at
            and current.approval_expires_at == approval.expires_at
            and current.approval_revision == approval.operation_revision
            and current.approver_user_id == approval.approver_user_id
        )

    def _issue_approved_execute(
        self,
        *,
        trusted: TrustedSession,
        challenge: ApprovalChallenge,
        current: Operation,
        now: datetime,
    ) -> AuthorizedWriteAction:
        self._require_requester(trusted, current)
        if (
            challenge.state is not ApprovalChallengeState.APPROVED
            or challenge.approval is None
        ):
            raise ChallengeTerminal("approval challenge is not approved")
        if not self._same_approved_operation(challenge, current):
            raise ChallengeTerminal("trusted operation changed after approval")
        if current.state is State.AWAITING_APPROVAL:
            try:
                binding = _operation_binding_digest(current)
            except AuthorityError as exc:  # pragma: no cover - state guard
                raise ChallengeTerminal(
                    "trusted operation changed after approval"
                ) from exc
            if binding != challenge.binding_digest:
                raise ChallengeTerminal("trusted operation changed after approval")
            terminal_replay = False
        elif current.state in {
            State.APPROVED,
            State.EXECUTING,
            State.VERIFYING,
            State.COMPLETED,
            State.FAILED,
        }:
            if not self._stored_approval_matches(challenge, current):
                raise ChallengeTerminal("stored approval differs from challenge")
            terminal_replay = current.state in {State.COMPLETED, State.FAILED}
        else:
            raise ChallengeTerminal("operation cannot use the approved challenge")
        expired = now >= challenge.expires_at
        reconciliation_only = (
            terminal_replay
            or current.state is State.VERIFYING
            or (expired and current.state is State.EXECUTING)
        )
        if expired and not reconciliation_only:
            raise ChallengeExpired("approved challenge has expired")
        request = {
            "operation_id": challenge.operation.operation_id,
            "approval": approval_to_mapping(challenge.approval),
            "reconciliation_only": reconciliation_only,
        }
        context = self._context(
            session=trusted,
            action="operation.approve_execute",
            request=request,
            now=now,
            not_after=None if reconciliation_only else challenge.expires_at,
        )
        self._store.append_audit_event(
            self._draft(
                event_type="write_action.approved_context_issued",
                now=now,
                actor_user_id=trusted.user_id,
                challenge=challenge,
                payload={
                    "action": "operation.approve_execute",
                    "request_digest": context.auth_request_digest,
                    "reconciliation_only": reconciliation_only,
                },
            )
        )
        return AuthorizedWriteAction(
            action="operation.approve_execute", request=request, context=context
        )

    def issue_approved_execute(
        self, session_handle: str, challenge_id: str
    ) -> AuthorizedWriteAction:
        now = self._now()
        trusted = self._session(session_handle, now)
        challenge = self._store.get_challenge(challenge_id)
        current = self._operation(challenge.operation.operation_id)
        return self._issue_approved_execute(
            trusted=trusted,
            challenge=challenge,
            current=current,
            now=now,
        )

    def issue_approved_execute_for_operation(
        self, session_handle: str, operation_id: str
    ) -> AuthorizedWriteAction:
        """Issue execution only from a pre-existing approved challenge.

        No challenge is created here.  Once execution has advanced, the
        immutable ``approval_revision`` locates the same durable challenge so
        response-loss retries can retrieve the terminal result without a
        second accounting effect.
        """

        now = self._now()
        trusted = self._session(session_handle, now)
        current = self._operation(operation_id)
        self._require_requester(trusted, current)
        challenge_revision = (
            current.revision
            if current.state is State.AWAITING_APPROVAL
            else current.approval_revision
        )
        if type(challenge_revision) is not int or challenge_revision < 0:
            raise ChallengeTerminal(
                "operation has no pre-existing approved challenge"
            )
        challenge = self._store.find_by_operation_revision(
            current.operation_id, challenge_revision
        )
        if challenge is None:
            raise ChallengeTerminal(
                "operation has no pre-existing approved challenge"
            )
        return self._issue_approved_execute(
            trusted=trusted,
            challenge=challenge,
            current=current,
            now=now,
        )


__all__ = [
    "ApprovalChallenge",
    "ApprovalChallengeState",
    "ApprovalChallengeStore",
    "ApprovalDecision",
    "AuthorityAuditEvent",
    "AuthorityConcurrentUpdate",
    "AuthorityError",
    "AuthorityKeys",
    "AuthorizedWriteAction",
    "ChallengeExpired",
    "ChallengeTerminal",
    "InMemoryApprovalChallengeStore",
    "TrustedAuthority",
    "TrustedSession",
]
