"""Fail-closed verification of raw Pi-to-broker accounting exchanges.

Normalized scenario events are useful derived data, but they are not authority.
This module accepts only the complete raw exchanges and reuses the production
release-pinned receipt verifier for their cryptographic checks.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .contracts import ContractError, validate_value
from .operations import (
    ALLOWED_TRANSITIONS,
    Operation,
    State,
    approve_operation,
    begin_execution,
    canonical_json,
)
from .registry import Capability
from .trusted_response_verifier import (
    ReleaseReceiptVerificationConfig,
    build_release_response_verifier,
)
from .verified_release import VerifiedReleaseRoute
from .write_protocol import (
    approval_from_mapping,
    operation_from_mapping,
    operation_to_mapping,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
_RELEASE_IDENTITY_FIELDS = frozenset(
    {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
        "verified",
        "version",
    }
)
_EXCHANGE_FIELDS = frozenset(
    {
        "action",
        "tool_name",
        "tool_call_id",
        "pi_arguments",
        "occurred_at",
        "broker_request",
        "broker_dispatched_at",
        "broker_response",
        "broker_responded_at",
        "pi_result",
        "tool_completed_at",
        "operation_before",
        "operation_after",
    }
)
_TOOL_NAMES = {
    "read": "odoo_v3_read",
    "operation.prepare": "odoo_v3_operation_prepare",
    "operation.preview": "odoo_v3_operation_preview",
    "operation.approve_execute": "odoo_v3_operation_approve_execute",
    "operation.diagnostics": "odoo_v3_operation_diagnostics",
    "operation.recover": "odoo_v3_operation_recover",
}
_REGISTRY_CAPABILITY_ID = "acct.registry.list.v1"
_DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1"
_RECOVERY_CAPABILITY_ID = "acct.recovery.execute.v1"
_REGISTRY_TOOL_NAME = "odoo_v3_capability_list"
_WRITE_ACTIONS = (
    "operation.prepare",
    "operation.preview",
    "operation.approve_execute",
)
_RECOVERY_WRITE_ACTIONS = (
    "operation.recover",
    "operation.preview",
    "operation.approve_execute",
)
_WRITE_ACTION_SET = frozenset(_WRITE_ACTIONS + _RECOVERY_WRITE_ACTIONS)
_WRITE_START_ACTIONS = frozenset(
    {"operation.prepare", "operation.recover"}
)
_PREVIEW_DATA_FIELDS = frozenset(
    {
        "approval",
        "business_description",
        "capability_id",
        "operation_digest",
        "operation_id",
        "operation_state",
        "parameters",
        "precheck",
        "precheck_digest",
        "precheck_identity",
        "recovery",
        "risk_level",
    }
)
_APPROVAL_CHALLENGE_FIELDS = frozenset(
    {
        "capability_id",
        "challenge_id",
        "company_id",
        "expires_at",
        "issued_at",
        "operation_digest",
        "operation_id",
        "precheck_digest",
        "requester_user_id",
        "state",
    }
)
_READ_EVIDENCE_FIELDS = frozenset({"read_exchange"})
_WRITE_EVIDENCE_FIELDS = frozenset(
    {
        "prepare_exchange",
        "preview_exchange",
        "approve_execute_exchange",
    }
)
_MAX_APPROVAL_TTL_SECONDS = 900


class PiEvidenceError(ValueError):
    """Raw Pi evidence was incomplete, untrusted, stale, or replayed."""


def _reject(reason: str) -> None:
    raise PiEvidenceError(reason)


def _exact_mapping(
    value: object,
    fields: frozenset[str] | set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        _reject(f"{label} fields are invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(f"{label} is invalid")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        _reject(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PiEvidenceError(
            f"{label} must be a canonical UTC timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _iso_utc_timestamp(value: object, label: str) -> datetime:
    if type(value) is not str:
        _reject(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PiEvidenceError(
            f"{label} must be a canonical UTC timestamp"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.astimezone(timezone.utc).isoformat() != value
    ):
        _reject(f"{label} must be a canonical UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _wire_utc_timestamp(value: object, label: str) -> datetime:
    """Accept either canonical RFC 3339 ``Z`` or ISO ``+00:00`` wire forms."""

    if type(value) is not str:
        _reject(f"{label} must be a canonical UTC timestamp")
    if value.endswith("Z"):
        return _timestamp(value, label)
    return _iso_utc_timestamp(value, label)


def _clock(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _reject("UTC clock returned an invalid timestamp")
    return value.astimezone(timezone.utc)


def _detached(value: object, label: str) -> object:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PiEvidenceError(f"{label} is not canonical JSON") from exc


def _json_equal(left: object, right: object) -> bool:
    """Compare JSON values without Python's bool/int coercion."""

    try:
        return canonical_json(left) == canonical_json(right)
    except (TypeError, ValueError, UnicodeError):
        return False


def _release_identity(value: object) -> tuple[dict[str, Any], str]:
    detached = _detached(value, "release identity")
    identity = _exact_mapping(
        detached,
        _RELEASE_IDENTITY_FIELDS,
        "release identity",
    )
    if identity["verified"] is not True:
        _reject("release identity is not verified")
    for field_name in (
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
    ):
        if (
            type(identity[field_name]) is not str
            or _SHA256.fullmatch(identity[field_name]) is None
        ):
            _reject("release identity digest is invalid")
    for field_name in ("commit", "release", "version"):
        text = identity[field_name]
        if (
            type(text) is not str
            or not text.strip()
            or text != text.strip()
            or len(text) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in text)
        ):
            _reject("release identity text is invalid")
    return identity, canonical_json(identity).decode("utf-8")


def _capability_descriptor(
    capability: Capability,
    *,
    capability_channel: str,
) -> dict[str, Any]:
    data = capability.data
    return {
        "id": data["id"],
        "domain": data["domain"],
        "business_description": data["business_description"],
        "access": data["access"],
        "risk_level": data["risk_level"],
        "company_scope": data["company_scope"],
        "odoo_permissions": data["odoo_permissions"],
        "approval_required": data["approval"]["required"],
        "idempotency_required": data["idempotency"]["required"],
        "input_schema_json": canonical_json(data["input_schema"]).decode(
            "utf-8"
        ),
        "output_schema_json": canonical_json(data["output_schema"]).decode(
            "utf-8"
        ),
        "contract_digest": hashlib.sha256(canonical_json(data)).hexdigest(),
        "evidence_level": data["evidence"]["level"],
        "verification_method": data["verification"]["method"],
        "recovery_method": data["recovery"]["method"],
        "capability_channel": capability_channel,
    }


@dataclass(frozen=True, slots=True, repr=False)
class PiEvidenceTrust:
    """Release-pinned receipt, approval, and output-schema trust.

    ``from_release_config`` may be used for read-only evidence by omitting all
    approval arguments. Such a trust object rejects every write exchange.
    """

    receipt_config: ReleaseReceiptVerificationConfig
    release_identity_json: str
    capabilities: tuple[Capability, ...]
    approval_key_id: str | None = None
    approval_secret: bytes | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    approval_ttl_resolver: Callable[[Operation], int] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.receipt_config) is not ReleaseReceiptVerificationConfig:
            _reject("receipt verification configuration is invalid")
        try:
            raw_identity = json.loads(self.release_identity_json)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise PiEvidenceError("release identity is invalid") from exc
        identity, identity_json = _release_identity(raw_identity)
        if (
            identity["manifest_sha256"] != self.receipt_config.release_digest
            or identity["registry_digest"]
            != self.receipt_config.registry_digest
        ):
            _reject("release identity does not match receipt trust")
        if (
            not isinstance(self.capabilities, tuple)
            or not self.capabilities
            or any(type(item) is not Capability for item in self.capabilities)
            or len({item.id for item in self.capabilities})
            != len(self.capabilities)
        ):
            _reject("capability output-schema trust is invalid")
        for capability in self.capabilities:
            data = capability.data
            if (
                data.get("access") not in {"read", "write"}
                or not isinstance(data.get("output_schema"), dict)
            ):
                _reject("capability output-schema trust is incomplete")
        approval_values = (
            self.approval_key_id,
            self.approval_secret,
            self.approval_ttl_resolver,
        )
        if any(value is not None for value in approval_values):
            if (
                type(self.approval_key_id) is not str
                or _IDENTIFIER.fullmatch(self.approval_key_id) is None
                or type(self.approval_secret) is not bytes
                or len(self.approval_secret) < 32
                or not callable(self.approval_ttl_resolver)
            ):
                _reject("write approval trust is invalid")
        object.__setattr__(self, "release_identity_json", identity_json)

    @classmethod
    def from_verified_release(
        cls,
        route: VerifiedReleaseRoute,
    ) -> "PiEvidenceTrust":
        """Construct full read/write trust from one verified release route."""

        if type(route) is not VerifiedReleaseRoute:
            _reject("verified release route is invalid")
        receipt_config = ReleaseReceiptVerificationConfig(
            release_digest=route.release_digest,
            registry_digest=route.registry_digest,
            capability_channel=route.base_runtime.capability_channel,
            read_receipt_key_id=route.base_runtime.receipt_key_id,
            read_receipt_secret=route.read_receipt_secret,
            write_receipt_key_id=route.write_runtime.write_receipt.key_id,
            write_receipt_secret=route.write_secrets.write_receipt,
        )
        return cls.from_release_config(
            receipt_config,
            release_identity=route.release_identity,
            capabilities=route.capabilities,
            approval_key_id=route.write_runtime.approval.key_id,
            approval_secret=route.write_secrets.approval,
            approval_ttl_resolver=route.approval_ttl_seconds,
        )

    @classmethod
    def from_release_config(
        cls,
        receipt_config: ReleaseReceiptVerificationConfig,
        *,
        release_identity: Mapping[str, Any],
        capabilities: tuple[Capability, ...],
        approval_key_id: str | None = None,
        approval_secret: bytes | None = None,
        approval_ttl_resolver: Callable[[Operation], int] | None = None,
    ) -> "PiEvidenceTrust":
        """Construct trust from already root-loaded purpose-specific material."""

        _identity, identity_json = _release_identity(release_identity)
        return cls(
            receipt_config=receipt_config,
            release_identity_json=identity_json,
            capabilities=tuple(capabilities),
            approval_key_id=approval_key_id,
            approval_secret=approval_secret,
            approval_ttl_resolver=approval_ttl_resolver,
        )

    @property
    def release_identity(self) -> dict[str, Any]:
        return json.loads(self.release_identity_json)

    @property
    def write_enabled(self) -> bool:
        return (
            self.approval_key_id is not None
            and self.approval_secret is not None
            and self.approval_ttl_resolver is not None
        )

    def capability(self, capability_id: str, *, access: str) -> Capability:
        matches = [
            item
            for item in self.capabilities
            if item.id == capability_id
            and item.data.get("access") == access
        ]
        if len(matches) != 1:
            _reject("capability is not present in the trusted release registry")
        return matches[0]

    def approval_ttl_seconds(self, operation: Operation) -> int:
        if not self.write_enabled:
            _reject("write approval trust is unavailable")
        try:
            ttl = self.approval_ttl_resolver(operation)  # type: ignore[misc]
        except Exception as exc:
            raise PiEvidenceError("approval TTL resolution failed") from exc
        if (
            type(ttl) is not int
            or not 1 <= ttl <= _MAX_APPROVAL_TTL_SECONDS
        ):
            _reject("approval TTL is invalid")
        return ttl

    def __repr__(self) -> str:
        return (
            "<PiEvidenceTrust "
            f"release={self.receipt_config.release_digest} "
            f"registry={self.receipt_config.registry_digest} "
            f"write_enabled={self.write_enabled}>"
        )

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("PiEvidenceTrust contains non-serializable secrets")


@dataclass(frozen=True, slots=True)
class PiEvidenceActionReport:
    action: str
    tool_call_id: str
    capability_id: str
    operation_id: str | None
    read_receipt_id: str | None
    write_receipt_id: str | None
    result_digest: str | None
    response_verified: bool
    output_schema_verified: bool
    authority_signature_verified: bool
    approval_ttl_verified: bool
    begin_execution_verified: bool
    operation_continuity_verified: bool
    acl_independently_rechecked: bool
    release_digest: str
    registry_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "tool_call_id": self.tool_call_id,
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "read_receipt_id": self.read_receipt_id,
            "write_receipt_id": self.write_receipt_id,
            "result_digest": self.result_digest,
            "response_verified": self.response_verified,
            "output_schema_verified": self.output_schema_verified,
            "authority_signature_verified": (
                self.authority_signature_verified
            ),
            "approval_ttl_verified": self.approval_ttl_verified,
            "begin_execution_verified": self.begin_execution_verified,
            "operation_continuity_verified": (
                self.operation_continuity_verified
            ),
            "acl_independently_rechecked": self.acl_independently_rechecked,
            "release_digest": self.release_digest,
            "registry_digest": self.registry_digest,
        }


@dataclass(frozen=True, slots=True)
class PiEvidenceSummary:
    kind: str
    verified_actions: tuple[str, ...]
    capability_id: str
    operation_id: str | None
    read_receipt_id: str | None
    write_receipt_id: str | None
    result_digest: str
    authority_signature_verified: bool
    acl_independently_rechecked: bool
    release_digest: str
    registry_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "verified_actions": list(self.verified_actions),
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "read_receipt_id": self.read_receipt_id,
            "write_receipt_id": self.write_receipt_id,
            "result_digest": self.result_digest,
            "authority_signature_verified": (
                self.authority_signature_verified
            ),
            "acl_independently_rechecked": self.acl_independently_rechecked,
            "release_digest": self.release_digest,
            "registry_digest": self.registry_digest,
        }


@dataclass(frozen=True, slots=True)
class _PendingConsumption:
    trace_id: str
    action: str
    tool_call_id: str
    operation_id: str | None
    read_receipt_id: str | None
    write_receipt_id: str | None
    approval_nonce_digest: str | None
    operation_before_json: str | None
    operation_after_json: str | None
    occurred_at: datetime
    completed_at: datetime


class PiEvidenceUniquenessState:
    """Thread-safe one-time consumption state for one evidence corpus."""

    __slots__ = (
        "_action_keys",
        "_approval_nonces",
        "_last_completed",
        "_lock",
        "_operation_traces",
        "_read_receipts",
        "_snapshots",
        "_tool_call_ids",
        "_write_receipts",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._read_receipts: set[str] = set()
        self._write_receipts: set[str] = set()
        self._approval_nonces: set[str] = set()
        self._operation_traces: dict[str, str] = {}
        self._snapshots: dict[tuple[str, str], str] = {}
        self._last_completed: dict[tuple[str, str], datetime] = {}
        self._action_keys: set[tuple[str, str]] = set()
        self._tool_call_ids: set[str] = set()

    def _commit(self, pending: tuple[_PendingConsumption, ...]) -> None:
        if not pending:
            _reject("no evidence consumption was supplied")
        with self._lock:
            read_receipts = set(self._read_receipts)
            write_receipts = set(self._write_receipts)
            approval_nonces = set(self._approval_nonces)
            operation_traces = dict(self._operation_traces)
            snapshots = dict(self._snapshots)
            last_completed = dict(self._last_completed)
            action_keys = set(self._action_keys)
            tool_call_ids = set(self._tool_call_ids)

            for item in pending:
                action_key = (item.trace_id, item.action)
                if action_key in action_keys:
                    _reject("evidence action was already consumed")
                if item.tool_call_id in tool_call_ids:
                    _reject("tool call was already consumed")
                action_keys.add(action_key)
                tool_call_ids.add(item.tool_call_id)

                if item.read_receipt_id is not None:
                    if item.read_receipt_id in read_receipts:
                        _reject("read receipt was already consumed")
                    read_receipts.add(item.read_receipt_id)
                if item.write_receipt_id is not None:
                    if item.write_receipt_id in write_receipts:
                        _reject("write receipt was already consumed")
                    write_receipts.add(item.write_receipt_id)
                if item.approval_nonce_digest is not None:
                    if item.approval_nonce_digest in approval_nonces:
                        _reject("approval nonce was already consumed")
                    approval_nonces.add(item.approval_nonce_digest)

                if item.operation_id is None:
                    continue
                bound_trace = operation_traces.get(item.operation_id)
                if bound_trace is not None and bound_trace != item.trace_id:
                    _reject("operation ID is already bound to another trace")
                operation_traces[item.operation_id] = item.trace_id
                snapshot_key = (item.trace_id, item.operation_id)
                current_snapshot = snapshots.get(snapshot_key)
                current_completed = last_completed.get(snapshot_key)
                if (
                    current_completed is not None
                    and item.occurred_at < current_completed
                ):
                    _reject("operation exchange chronology is invalid")
                if item.action in _WRITE_START_ACTIONS:
                    if (
                        item.operation_before_json is not None
                        or current_snapshot is not None
                    ):
                        _reject("prepared operation was replayed")
                elif (
                    current_snapshot is not None
                    and item.operation_before_json != current_snapshot
                ):
                    _reject("operation snapshot chain is discontinuous")
                if item.operation_after_json is None:
                    _reject("operation snapshot is missing")
                snapshots[snapshot_key] = item.operation_after_json
                last_completed[snapshot_key] = item.completed_at

            self._read_receipts = read_receipts
            self._write_receipts = write_receipts
            self._approval_nonces = approval_nonces
            self._operation_traces = operation_traces
            self._snapshots = snapshots
            self._last_completed = last_completed
            self._action_keys = action_keys
            self._tool_call_ids = tool_call_ids

    def __repr__(self) -> str:
        return "<PiEvidenceUniquenessState>"

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("PiEvidenceUniquenessState is not serializable")


@dataclass(frozen=True, slots=True)
class _ValidatedExchange:
    report: PiEvidenceActionReport
    pending: _PendingConsumption


class PiEvidenceVerifier:
    """Verify exact raw Pi exchanges against one immutable release trust."""

    __slots__ = (
        "_clock",
        "_operation_resolver",
        "_state",
        "_trust",
    )

    def __init__(
        self,
        trust: PiEvidenceTrust,
        *,
        operation_resolver: Callable[[str], Operation | None] | None = None,
        utc_clock: Callable[[], datetime],
        uniqueness_state: PiEvidenceUniquenessState | None = None,
    ) -> None:
        if (
            type(trust) is not PiEvidenceTrust
            or (
                operation_resolver is not None
                and not callable(operation_resolver)
            )
            or not callable(utc_clock)
            or (
                uniqueness_state is not None
                and type(uniqueness_state)
                is not PiEvidenceUniquenessState
            )
        ):
            _reject("Pi evidence verifier dependencies are invalid")
        self._trust = trust
        self._operation_resolver = operation_resolver or (
            lambda _operation_id: None
        )
        self._clock = utc_clock
        self._state = uniqueness_state or PiEvidenceUniquenessState()

    def verify_exchange(
        self,
        exchange: Mapping[str, Any],
        *,
        trace_id: str,
    ) -> PiEvidenceActionReport:
        """Verify and consume one exact raw exchange."""

        try:
            now = _clock(self._clock())
            validated = self._validate_exchange(
                exchange,
                trace_id=_identifier(trace_id, "trace ID"),
                now=now,
            )
            self._state._commit((validated.pending,))
            return validated.report
        except PiEvidenceError:
            raise
        except Exception as exc:
            raise PiEvidenceError("trusted Pi evidence rejected") from exc

    def verify_trusted_evidence(
        self,
        evidence: Mapping[str, Any],
        *,
        trace_id: str,
    ) -> PiEvidenceSummary:
        """Verify one read exchange or the full prepare/preview/execute chain."""

        try:
            if not isinstance(evidence, dict):
                _reject("trusted evidence must be an exact object")
            trace = _identifier(trace_id, "trace ID")
            now = _clock(self._clock())
            if set(evidence) == set(_READ_EVIDENCE_FIELDS):
                validated = (
                    self._validate_exchange(
                        evidence["read_exchange"],
                        trace_id=trace,
                        now=now,
                    ),
                )
                if validated[0].report.action not in {
                    "read",
                    "operation.diagnostics",
                }:
                    _reject("read evidence action is invalid")
                kind = "read"
            elif set(evidence) == set(_WRITE_EVIDENCE_FIELDS):
                keys = (
                    "prepare_exchange",
                    "preview_exchange",
                    "approve_execute_exchange",
                )
                validated = tuple(
                    self._validate_exchange(
                        evidence[key],
                        trace_id=trace,
                        now=now,
                    )
                    for key in keys
                )
                actions = tuple(
                    item.report.action for item in validated
                )
                if actions not in {
                    _WRITE_ACTIONS,
                    _RECOVERY_WRITE_ACTIONS,
                }:
                    _reject("write evidence actions are invalid")
                if not (
                    validated[0].pending.operation_after_json
                    == validated[1].pending.operation_before_json
                    and validated[1].pending.operation_after_json
                    == validated[2].pending.operation_before_json
                    and validated[0].pending.completed_at
                    <= validated[1].pending.occurred_at
                    and validated[1].pending.completed_at
                    <= validated[2].pending.occurred_at
                ):
                    _reject("write evidence chain is discontinuous")
                approval = approval_from_mapping(
                    evidence["approve_execute_exchange"][
                        "broker_request"
                    ].get("approval")
                )
                challenge = evidence["preview_exchange"][
                    "broker_response"
                ]["data"]["approval_challenge"]
                challenge_issued_at = _iso_utc_timestamp(
                    challenge["issued_at"],
                    "approval challenge issued_at",
                )
                challenge_expires_at = _iso_utc_timestamp(
                    challenge["expires_at"],
                    "approval challenge expires_at",
                )
                if not (
                    validated[1].pending.completed_at
                    <= approval.issued_at
                    <= validated[2].pending.occurred_at
                    and challenge_issued_at
                    <= approval.issued_at
                    < challenge_expires_at
                    and approval.expires_at == challenge_expires_at
                ):
                    _reject(
                        "approval was not issued after the trusted preview"
                    )
                operation_ids = {
                    item.report.operation_id for item in validated
                }
                capability_ids = {
                    item.report.capability_id for item in validated
                }
                if len(operation_ids) != 1 or len(capability_ids) != 1:
                    _reject("write evidence identity is inconsistent")
                kind = "write"
            else:
                _reject(
                    "legacy hashes and normalized summaries are not trusted evidence"
                )

            self._state._commit(
                tuple(item.pending for item in validated)
            )
            reports = tuple(item.report for item in validated)
            final = reports[-1]
            if final.result_digest is None:
                _reject("trusted terminal evidence has no result digest")
            return PiEvidenceSummary(
                kind=kind,
                verified_actions=tuple(item.action for item in reports),
                capability_id=final.capability_id,
                operation_id=final.operation_id,
                read_receipt_id=next(
                    (
                        item.read_receipt_id
                        for item in reports
                        if item.read_receipt_id is not None
                    ),
                    None,
                ),
                write_receipt_id=next(
                    (
                        item.write_receipt_id
                        for item in reports
                        if item.write_receipt_id is not None
                    ),
                    None,
                ),
                result_digest=final.result_digest,
                authority_signature_verified=any(
                    item.authority_signature_verified for item in reports
                ),
                acl_independently_rechecked=False,
                release_digest=self._trust.receipt_config.release_digest,
                registry_digest=self._trust.receipt_config.registry_digest,
            )
        except PiEvidenceError:
            raise
        except Exception as exc:
            raise PiEvidenceError("trusted Pi evidence rejected") from exc

    def _validate_exchange(
        self,
        raw_exchange: object,
        *,
        trace_id: str,
        now: datetime,
    ) -> _ValidatedExchange:
        exchange = _exact_mapping(
            raw_exchange,
            _EXCHANGE_FIELDS,
            "raw exchange",
        )
        action = exchange["action"]
        if action not in _TOOL_NAMES:
            _reject("exchange action is unsupported")
        tool_call_id = _identifier(exchange["tool_call_id"], "tool call ID")
        pi_arguments = exchange["pi_arguments"]
        request = exchange["broker_request"]
        response = exchange["broker_response"]
        if (
            not isinstance(pi_arguments, dict)
            or not isinstance(request, dict)
            or not isinstance(response, dict)
        ):
            _reject("exchange request or response is invalid")
        self._verify_pi_result(exchange["pi_result"], response)

        occurred_at = _timestamp(exchange["occurred_at"], "occurred_at")
        dispatched_at = _timestamp(
            exchange["broker_dispatched_at"],
            "broker_dispatched_at",
        )
        responded_at = _timestamp(
            exchange["broker_responded_at"],
            "broker_responded_at",
        )
        completed_at = _timestamp(
            exchange["tool_completed_at"],
            "tool_completed_at",
        )
        if not (
            occurred_at
            <= dispatched_at
            <= responded_at
            <= completed_at
            <= now
        ):
            _reject("exchange chronology is invalid")

        before = self._operation_snapshot(
            exchange["operation_before"],
            required=action in {
                "operation.preview",
                "operation.approve_execute",
                "operation.diagnostics",
                "operation.recover",
            },
            label="operation_before",
        )
        after = self._operation_snapshot(
            exchange["operation_after"],
            required=action in _WRITE_ACTION_SET,
            label="operation_after",
        )
        if action in {"read", "operation.prepare"} and before is not None:
            _reject("unexpected operation_before snapshot")
        if action in {"read", "operation.diagnostics"} and after is not None:
            _reject("unexpected operation_after snapshot")

        capability_id = self._verify_pi_request_binding(
            action,
            pi_arguments,
            request,
            before=before,
            after=after,
        )
        self._verify_capability_route(
            action,
            capability_id,
            exchange["tool_name"],
        )
        access = (
            "read"
            if action in {"read", "operation.diagnostics"}
            else "write"
        )
        capability = self._trust.capability(
            capability_id,
            access=access,
        )
        self._verify_operation_transition(
            action,
            before=before,
            after=after,
        )

        def resolve(operation_id: str) -> Operation | None:
            if after is not None and operation_id == after.operation_id:
                return after
            if before is not None and operation_id == before.operation_id:
                return before
            resolved = self._operation_resolver(operation_id)
            if resolved is None:
                return None
            if type(resolved) is not Operation:
                _reject("operation resolver returned an invalid snapshot")
            resolved.assert_integrity()
            return resolved

        verified_response = response
        preview_data: dict[str, Any] | None = None
        if action == "operation.preview":
            preview_envelope = _exact_mapping(
                response,
                {"command", "data", "ok"},
                "preview response",
            )
            preview_data = _exact_mapping(
                preview_envelope["data"],
                set(_PREVIEW_DATA_FIELDS) | {"approval_challenge"},
                "preview response data",
            )
            verified_response = {
                "command": preview_envelope["command"],
                "data": {
                    field: preview_data[field]
                    for field in _PREVIEW_DATA_FIELDS
                },
                "ok": preview_envelope["ok"],
            }

        response_verifier = build_release_response_verifier(
            self._trust.receipt_config,
            operation_resolver=resolve,
            utc_clock=lambda: now,
        )
        if (
            response_verifier.verify(
                action,
                verified_response,
                request,
            )
            is not True
        ):
            _reject("production release response verification failed")
        if action == "operation.preview":
            if preview_data is None or after is None:
                _reject("trusted preview is incomplete")
            self._verify_trusted_preview(
                preview_data,
                capability=capability,
                operation=after,
                responded_at=responded_at,
            )

        read_receipt_id: str | None = None
        write_receipt_id: str | None = None
        result_digest: str | None = None
        nonce_digest: str | None = None
        authority_verified = False
        approval_ttl_verified = False
        execution_verified = False
        if action == "read":
            data = response.get("data")
            if (
                not isinstance(data, dict)
                or not _json_equal(
                    data.get("release_identity"),
                    self._trust.release_identity,
                )
                or not isinstance(data.get("result"), dict)
            ):
                _reject("read release identity is not exact")
            result = data["result"]
            self._validate_output(result, capability)
            receipt = result.get("receipt")
            if not isinstance(receipt, dict):
                _reject("read receipt is missing")
            if capability_id == _REGISTRY_CAPABILITY_ID:
                self._verify_registry_result(result)
            read_receipt_id = _identifier(receipt.get("id"), "read receipt ID")
            result_digest = receipt.get("result_digest")
            observed_at = _wire_utc_timestamp(
                receipt.get("observed_at"),
                "read receipt observed_at",
            )
            if not dispatched_at <= observed_at <= responded_at:
                _reject("read receipt is outside the broker response window")
        elif action == "operation.diagnostics":
            data = response.get("data")
            if not isinstance(data, dict):
                _reject("diagnostics output is missing")
            self._validate_output(data, capability)
            receipt = data.get("receipt")
            if not isinstance(receipt, dict):
                _reject("diagnostics receipt is missing")
            read_receipt_id = _identifier(
                receipt.get("id"),
                "read receipt ID",
            )
            result_digest = receipt.get("result_digest")
            observed_at = _wire_utc_timestamp(
                receipt.get("observed_at"),
                "diagnostics receipt observed_at",
            )
            if not dispatched_at <= observed_at <= responded_at:
                _reject(
                    "diagnostics receipt is outside the broker response window"
                )
        elif action == "operation.approve_execute":
            if before is None or after is None:
                _reject("approve-execute operation snapshots are missing")
            approval = approval_from_mapping(request.get("approval"))
            if not self._trust.write_enabled:
                _reject("write approval trust is unavailable")
            ttl = self._trust.approval_ttl_seconds(before)
            authorizer = (
                lambda approver_user_id, company_id, approved_capability_id: (
                    approver_user_id == approval.approver_user_id
                    and company_id == before.company_id
                    and approved_capability_id == before.capability_id
                )
            )
            approved = approve_operation(
                before,
                approval,
                now=dispatched_at,
                secret=self._trust.approval_secret,  # type: ignore[arg-type]
                expected_key_id=self._trust.approval_key_id,  # type: ignore[arg-type]
                is_approver_authorized=authorizer,
                consume_nonce=lambda _nonce, _operation_id, _revision: True,
                approval_ttl_seconds=ttl,
                expected_revision=before.revision,
            )
            executing = begin_execution(
                approved,
                approval,
                now=dispatched_at,
                secret=self._trust.approval_secret,  # type: ignore[arg-type]
                expected_key_id=self._trust.approval_key_id,  # type: ignore[arg-type]
                is_approver_authorized=authorizer,
                approval_ttl_seconds=ttl,
                expected_revision=approved.revision,
            )
            if not self._terminal_follows_execution(executing, after):
                _reject("terminal operation does not follow begin_execution")
            data = response.get("data")
            if not isinstance(data, dict):
                _reject("terminal output is missing")
            self._validate_output(data, capability)
            receipt = data.get("audit_receipt")
            if not isinstance(receipt, dict):
                _reject("write audit receipt is missing")
            write_receipt_id = _identifier(
                receipt.get("receipt_id"),
                "write receipt ID",
            )
            result_digest = receipt.get("result_digest")
            verification = data.get("verification")
            if not isinstance(verification, dict):
                _reject("write verification is missing")
            verified_at = _wire_utc_timestamp(
                verification.get("verified_at"),
                "write verification verified_at",
            )
            receipt_issued_at = _wire_utc_timestamp(
                receipt.get("issued_at"),
                "write receipt issued_at",
            )
            if not (
                dispatched_at
                <= verified_at
                <= receipt_issued_at
                <= responded_at
            ):
                _reject(
                    "write verification or receipt is outside the broker "
                    "response window"
                )
            nonce_digest = hashlib.sha256(
                approval.nonce.encode("utf-8")
            ).hexdigest()
            authority_verified = True
            approval_ttl_verified = True
            execution_verified = True

        if (
            action
            in {"read", "operation.diagnostics", "operation.approve_execute"}
            and (
                type(result_digest) is not str
                or _SHA256.fullmatch(result_digest) is None
            )
        ):
            _reject("trusted result digest is invalid")
        operation_id = (
            None
            if action in {"read", "operation.diagnostics"}
            else after.operation_id  # type: ignore[union-attr]
        )
        report = PiEvidenceActionReport(
            action=action,
            tool_call_id=tool_call_id,
            capability_id=capability_id,
            operation_id=operation_id,
            read_receipt_id=read_receipt_id,
            write_receipt_id=write_receipt_id,
            result_digest=result_digest,
            response_verified=True,
            output_schema_verified=action
            in {
                "read",
                "operation.diagnostics",
                "operation.approve_execute",
            },
            authority_signature_verified=authority_verified,
            approval_ttl_verified=approval_ttl_verified,
            begin_execution_verified=execution_verified,
            operation_continuity_verified=action
            not in {"read", "operation.diagnostics"},
            acl_independently_rechecked=False,
            release_digest=self._trust.receipt_config.release_digest,
            registry_digest=self._trust.receipt_config.registry_digest,
        )
        pending = _PendingConsumption(
            trace_id=trace_id,
            action=action,
            tool_call_id=tool_call_id,
            operation_id=operation_id,
            read_receipt_id=read_receipt_id,
            write_receipt_id=write_receipt_id,
            approval_nonce_digest=nonce_digest,
            operation_before_json=(
                None
                if action
                in {
                    "read",
                    "operation.diagnostics",
                    "operation.recover",
                }
                else self._snapshot_json(before)
            ),
            operation_after_json=self._snapshot_json(after),
            occurred_at=occurred_at,
            completed_at=completed_at,
        )
        return _ValidatedExchange(report=report, pending=pending)

    @staticmethod
    def _verify_pi_result(value: object, response: dict[str, Any]) -> None:
        result = _exact_mapping(value, {"content", "details"}, "Pi result")
        if not _json_equal(result["details"], response):
            _reject("Pi details do not equal the broker response")
        content = result["content"]
        if not isinstance(content, list) or len(content) != 1:
            _reject("Pi text result is invalid")
        item = _exact_mapping(
            content[0],
            {"type", "text"},
            "Pi text result",
        )
        if item["type"] != "text" or type(item["text"]) is not str:
            _reject("Pi text result is invalid")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            mapped: dict[str, Any] = {}
            for key, raw in items:
                if key in mapped:
                    raise ValueError("duplicate key")
                mapped[key] = raw
            return mapped

        try:
            parsed = json.loads(
                item["text"],
                object_pairs_hook=pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(value)
                ),
            )
        except (TypeError, ValueError, UnicodeError) as exc:
            raise PiEvidenceError("Pi text result is invalid JSON") from exc
        if not _json_equal(parsed, response):
            _reject("Pi text result does not equal the broker response")

    @staticmethod
    def _operation_snapshot(
        value: object,
        *,
        required: bool,
        label: str,
    ) -> Operation | None:
        if value is None:
            if required:
                _reject(f"{label} is required")
            return None
        try:
            operation = operation_from_mapping(value)
        except Exception as exc:
            raise PiEvidenceError(f"{label} is invalid") from exc
        if (
            not isinstance(value, dict)
            or not _json_equal(value, operation_to_mapping(operation))
        ):
            _reject(f"{label} is not the exact durable mapping")
        return operation

    @staticmethod
    def _snapshot_json(operation: Operation | None) -> str | None:
        if operation is None:
            return None
        return canonical_json(operation_to_mapping(operation)).decode("utf-8")

    @staticmethod
    def _verify_capability_route(
        action: str,
        capability_id: str,
        tool_name: object,
    ) -> None:
        if capability_id == _REGISTRY_CAPABILITY_ID:
            if action != "read":
                _reject("registry capability used the wrong broker action")
            expected_tool = _REGISTRY_TOOL_NAME
        elif capability_id == _DIAGNOSTICS_CAPABILITY_ID:
            if action != "operation.diagnostics":
                _reject("diagnostics capability used the wrong broker action")
            expected_tool = _TOOL_NAMES["operation.diagnostics"]
        elif capability_id == _RECOVERY_CAPABILITY_ID:
            if action not in _RECOVERY_WRITE_ACTIONS:
                _reject("recovery capability used the wrong broker action")
            expected_tool = _TOOL_NAMES[action]
        else:
            if action in {"operation.diagnostics", "operation.recover"}:
                _reject("dedicated broker action used the wrong capability")
            expected_tool = _TOOL_NAMES[action]
        if tool_name != expected_tool:
            _reject("Pi tool name does not match the broker action")

    def _verify_registry_result(self, result: dict[str, Any]) -> None:
        descriptors = result.get("capabilities")
        page = result.get("page")
        if (
            not isinstance(descriptors, list)
            or not descriptors
            or not isinstance(page, dict)
            or page
            != {
                "count": len(descriptors),
                "total_count": len(descriptors),
            }
        ):
            _reject("registry result is empty or internally inconsistent")
        trusted_by_id = {
            capability.id: capability
            for capability in self._trust.capabilities
        }
        descriptor_ids: list[str] = []
        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                _reject("registry descriptor is invalid")
            capability_id = descriptor.get("id")
            if (
                type(capability_id) is not str
                or capability_id not in trusted_by_id
                or not _json_equal(
                    descriptor,
                    _capability_descriptor(
                        trusted_by_id[capability_id],
                        capability_channel=(
                            self._trust.receipt_config.capability_channel
                        ),
                    ),
                )
            ):
                _reject("registry descriptor is not release-bound")
            descriptor_ids.append(capability_id)
        if (
            descriptor_ids != sorted(descriptor_ids)
            or len(descriptor_ids) != len(set(descriptor_ids))
        ):
            _reject("registry descriptors are not unique and ordered")

    def _verify_trusted_preview(
        self,
        data: dict[str, Any],
        *,
        capability: Capability,
        operation: Operation,
        responded_at: datetime,
    ) -> None:
        challenge = _exact_mapping(
            data["approval_challenge"],
            _APPROVAL_CHALLENGE_FIELDS,
            "approval challenge",
        )
        issued_at = _iso_utc_timestamp(
            challenge["issued_at"],
            "approval challenge issued_at",
        )
        expires_at = _iso_utc_timestamp(
            challenge["expires_at"],
            "approval challenge expires_at",
        )
        ttl_seconds = self._trust.approval_ttl_seconds(operation)
        if (
            data["business_description"]
            != capability.data.get("business_description")
            or data["risk_level"] != capability.data.get("risk_level")
            or not _json_equal(
                data["approval"],
                capability.data.get("approval"),
            )
            or not _json_equal(
                data["recovery"],
                capability.data.get("recovery"),
            )
            or challenge["capability_id"] != operation.capability_id
            or type(challenge["company_id"]) is not int
            or challenge["company_id"] != operation.company_id
            or challenge["operation_digest"] != operation.digest
            or challenge["operation_id"] != operation.operation_id
            or challenge["precheck_digest"] != operation.precheck_digest
            or type(challenge["requester_user_id"]) is not int
            or challenge["requester_user_id"] != operation.user_id
            or challenge["state"] != "pending"
            or not (
                issued_at <= responded_at < expires_at
                and expires_at - issued_at
                == timedelta(seconds=ttl_seconds)
            )
        ):
            _reject(
                "trusted preview does not match the registry or challenge"
            )
        _identifier(challenge["challenge_id"], "approval challenge ID")

    @staticmethod
    def _verify_pi_request_binding(
        action: str,
        pi_arguments: dict[str, Any],
        request: dict[str, Any],
        *,
        before: Operation | None,
        after: Operation | None,
    ) -> str:
        if (
            action == "read"
            and request.get("capability_id") == _REGISTRY_CAPABILITY_ID
        ):
            _exact_mapping(pi_arguments, set(), "Pi arguments")
            if request.get("parameters") != {}:
                _reject("registry parameters must be broker-bound")
            return _REGISTRY_CAPABILITY_ID

        if action in {"read", "operation.prepare"}:
            arguments = _exact_mapping(
                pi_arguments,
                {"capability_id", "parameters"},
                "Pi arguments",
            )
            if (
                not isinstance(arguments["parameters"], dict)
                or request.get("capability_id")
                != arguments["capability_id"]
                or not _json_equal(
                    request.get("parameters"),
                    arguments["parameters"],
                )
            ):
                _reject("Pi business parameters were not passed exactly")
            capability_id = _identifier(
                arguments["capability_id"],
                "capability ID",
            )
            if (
                action == "operation.prepare"
                and (
                    after is None
                    or after.capability_id != capability_id
                    or not _json_equal(
                        after.parameters,
                        arguments["parameters"],
                    )
                )
            ):
                _reject("prepared operation does not contain exact Pi parameters")
            return capability_id

        if action == "operation.diagnostics":
            arguments = _exact_mapping(
                pi_arguments,
                {"company_id", "operation_id"},
                "Pi arguments",
            )
            operation_id = _identifier(
                arguments["operation_id"],
                "operation ID",
            )
            company_id = arguments["company_id"]
            if (
                type(company_id) is not int
                or company_id <= 0
                or request.get("company_id") != company_id
                or request.get("operation_id") != operation_id
                or before is None
                or after is not None
                or before.operation_id != operation_id
                or before.company_id != company_id
            ):
                _reject("diagnostics parameters were not passed exactly")
            return _DIAGNOSTICS_CAPABILITY_ID

        if action == "operation.recover":
            arguments = _exact_mapping(
                pi_arguments,
                {
                    "idempotency_key",
                    "origin_operation_id",
                    "reason",
                    "recovery_date",
                },
                "Pi arguments",
            )
            origin_operation_id = _identifier(
                arguments["origin_operation_id"],
                "origin operation ID",
            )
            idempotency_key = _identifier(
                arguments["idempotency_key"],
                "idempotency key",
            )
            recovery_date = arguments["recovery_date"]
            reason = arguments["reason"]
            if (
                type(recovery_date) is not str
                or _DATE.fullmatch(recovery_date) is None
                or type(reason) is not str
                or not reason.strip()
                or reason != reason.strip()
                or len(reason) > 512
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in reason
                )
                or before is None
                or after is None
                or before.operation_id != origin_operation_id
                or before.state not in {State.COMPLETED, State.FAILED}
                or after.capability_id != _RECOVERY_CAPABILITY_ID
                or after.company_id != before.company_id
                or request.get("origin_operation_id")
                != origin_operation_id
                or request.get("expected_origin_revision")
                != before.revision
                or request.get("recovery_operation_id")
                != after.operation_id
                or request.get("request_id") != after.request_id
                or request.get("recovery_date") != recovery_date
                or request.get("reason") != reason
                or request.get("idempotency_key") != idempotency_key
            ):
                _reject("recovery parameters were not passed exactly")
            parameters = after.parameters
            if (
                set(parameters)
                != {
                    "company_id",
                    "expected_recovery_plan_digest",
                    "idempotency_key",
                    "origin_operation_id",
                    "reason",
                    "recovery_date",
                }
                or parameters["company_id"] != before.company_id
                or parameters["origin_operation_id"]
                != origin_operation_id
                or parameters["recovery_date"] != recovery_date
                or parameters["reason"] != reason
                or parameters["idempotency_key"] != idempotency_key
                or type(parameters["expected_recovery_plan_digest"])
                is not str
                or _SHA256.fullmatch(
                    parameters["expected_recovery_plan_digest"]
                )
                is None
            ):
                _reject("broker-derived recovery parameters are invalid")
            return _RECOVERY_CAPABILITY_ID

        arguments = _exact_mapping(
            pi_arguments,
            {"operation_id"},
            "Pi arguments",
        )
        operation_id = _identifier(arguments["operation_id"], "operation ID")
        if (
            request.get("operation_id") != operation_id
            or before is None
            or after is None
            or before.operation_id != operation_id
            or after.operation_id != operation_id
        ):
            _reject("Pi operation ID was not passed exactly")
        return after.capability_id

    @staticmethod
    def _same_lineage(left: Operation, right: Operation) -> bool:
        return (
            left.operation_id == right.operation_id
            and left.request_id == right.request_id
            and left.capability_id == right.capability_id
            and left.parameters_json == right.parameters_json
            and left.principal == right.principal
            and left.user_id == right.user_id
            and left.company_id == right.company_id
            and left.idempotency_key == right.idempotency_key
            and left.odoo_instance_id == right.odoo_instance_id
            and left.database_name == right.database_name
            and left.database_uuid == right.database_uuid
            and left.environment == right.environment
            and left.registry_digest == right.registry_digest
            and left.release_digest == right.release_digest
            and left.digest == right.digest
            and left.protocol_version == right.protocol_version
        )

    @staticmethod
    def _state_reachable(left: Operation, right: Operation) -> bool:
        steps = right.revision - left.revision
        if steps < 0:
            return False
        states = {left.state}
        for _unused in range(steps):
            states = {
                candidate
                for state in states
                for candidate in ALLOWED_TRANSITIONS[state]
            }
        return right.state in states

    def _verify_operation_transition(
        self,
        action: str,
        *,
        before: Operation | None,
        after: Operation | None,
    ) -> None:
        if action == "read":
            return
        if action == "operation.diagnostics":
            if (
                before is None
                or after is not None
                or before.release_digest
                != self._trust.receipt_config.release_digest
                or before.registry_digest
                != self._trust.receipt_config.registry_digest
            ):
                _reject("diagnostics operation route is invalid")
            return
        if after is None:
            _reject("operation_after is required")
        if (
            after.release_digest
            != self._trust.receipt_config.release_digest
            or after.registry_digest
            != self._trust.receipt_config.registry_digest
        ):
            _reject("operation route is invalid")
        if action == "operation.recover":
            if (
                before is None
                or before.operation_id == after.operation_id
                or before.state not in {State.COMPLETED, State.FAILED}
                or before.release_digest
                != self._trust.receipt_config.release_digest
                or before.registry_digest
                != self._trust.receipt_config.registry_digest
                or after.capability_id != _RECOVERY_CAPABILITY_ID
                or after.state != State.PREPARED
                or after.revision != 0
                or after.precheck_digest is not None
            ):
                _reject("recovery operation snapshot is invalid")
            return
        if action == "operation.prepare":
            if (
                before is not None
                or after.state != State.PREPARED
                or after.revision != 0
                or after.precheck_digest is not None
            ):
                _reject("prepared operation snapshot is invalid")
            return
        if before is None or not self._same_lineage(before, after):
            _reject("operation lineage is invalid")
        if action == "operation.preview":
            if (
                before.state != State.PREPARED
                or before.revision != 0
                or before.precheck_digest is not None
                or after.state != State.AWAITING_APPROVAL
                or after.revision != 2
                or after.precheck_digest is None
                or not self._state_reachable(before, after)
            ):
                _reject("preview operation transition is invalid")
            return
        if (
            before.state != State.AWAITING_APPROVAL
            or before.precheck_digest is None
            or after.state not in {State.COMPLETED, State.FAILED}
        ):
            _reject("approve-execute operation transition is invalid")

    def _terminal_follows_execution(
        self,
        executing: Operation,
        terminal: Operation,
    ) -> bool:
        return (
            self._same_lineage(executing, terminal)
            and executing.precheck_digest == terminal.precheck_digest
            and executing.approval_signature == terminal.approval_signature
            and executing.approval_nonce_digest
            == terminal.approval_nonce_digest
            and executing.approval_issued_at == terminal.approval_issued_at
            and executing.approval_expires_at == terminal.approval_expires_at
            and executing.approval_revision == terminal.approval_revision
            and executing.approver_user_id == terminal.approver_user_id
            and self._state_reachable(executing, terminal)
        )

    @staticmethod
    def _validate_output(
        value: object,
        capability: Capability,
    ) -> None:
        try:
            validate_value(
                value,
                capability.data["output_schema"],
                "$.broker_response.data",
            )
        except (ContractError, KeyError, TypeError, ValueError) as exc:
            raise PiEvidenceError(
                "broker output does not match the trusted output schema"
            ) from exc

    def __repr__(self) -> str:
        return "<PiEvidenceVerifier release-pinned>"


__all__ = [
    "PiEvidenceActionReport",
    "PiEvidenceError",
    "PiEvidenceSummary",
    "PiEvidenceTrust",
    "PiEvidenceUniquenessState",
    "PiEvidenceVerifier",
]
