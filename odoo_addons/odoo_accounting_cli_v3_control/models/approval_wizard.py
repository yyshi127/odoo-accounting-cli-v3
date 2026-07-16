"""Record-bound Odoo UI for independently reviewing V3 approvals."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError


_APPROVER_GROUP = "odoo_accounting_cli_v3_control.group_approver"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SNAPSHOT_BYTES = 1024 * 1024
_MAX_APPROVAL_TTL_SECONDS = 15 * 60
_STATES = {"pending", "approved", "denied", "expired", "stale"}
_AUTHORITY_KEYS = {
    "approval",
    "approval_nonce_digest",
    "approval_signature",
    "approver_user_id",
    "auth_key_id",
    "auth_signature",
    "auth_token_id",
    "deadline_monotonic",
    "nonce",
    "session_handle",
    "signature",
}
_INSPECTION_FIELDS = {
    "schema_version",
    "challenge",
    "operation",
    "summary",
    "preview_digest",
    "precheck",
    "inspection_digest",
}
_CHALLENGE_FIELDS = {
    "challenge_id",
    "binding_digest",
    "issued_at",
    "expires_at",
    "ttl_seconds",
    "state",
    "version",
}
_OPERATION_FIELDS = {
    "operation_id",
    "request_id",
    "capability_id",
    "parameters",
    "parameters_digest",
    "principal",
    "user_id",
    "company_id",
    "idempotency_key",
    "odoo_instance_id",
    "database_name",
    "database_uuid",
    "environment",
    "registry_digest",
    "release_digest",
    "operation_digest",
    "precheck_digest",
    "state",
    "revision",
    "protocol_version",
}
_SUMMARY_FIELDS = {
    "binding_digest",
    "capability_id",
    "challenge_id",
    "company_id",
    "operation_digest",
    "operation_id",
    "parameters_digest",
    "precheck_digest",
    "requester_principal",
    "requester_user_id",
}
_PRECHECK_FIELDS = {
    "operation_id",
    "request_id",
    "operation_digest",
    "operation_revision",
    "source_operation_revision",
    "principal",
    "user_id",
    "company_id",
    "evidence_digest",
    "occurred_at",
    "evidence",
}


class ApprovalWizardError(RuntimeError):
    """An unsigned preview failed local reconstruction."""


def _canonical_json(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        normalized = json.loads(encoded)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ApprovalWizardError("approval preview is not canonical JSON") from exc
    if normalized != value or len(encoded.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
        raise ApprovalWizardError("approval preview is not canonical JSON")
    return encoded


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ApprovalWizardError(f"approval {label} is invalid")
    return value


def _required_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ApprovalWizardError(f"approval {label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ApprovalWizardError(f"approval {label} is invalid") from exc
    if len(encoded) > 2048:
        raise ApprovalWizardError(f"approval {label} is invalid")
    return value


def _required_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ApprovalWizardError(f"approval {label} is invalid")
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value.isascii() or not 20 <= len(value) <= 40:
        raise ApprovalWizardError(f"approval {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ApprovalWizardError(f"approval {label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != value
    ):
        raise ApprovalWizardError(f"approval {label} is invalid")
    return value, parsed


def _exact_object(value: object, fields_set: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields_set:
        raise ApprovalWizardError(f"approval {label} fields are invalid")
    return value


def _reject_authority_material(value: object) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if any(
                isinstance(key, str)
                and key.lower().replace("-", "_") in _AUTHORITY_KEYS
                for key in item
            ):
                raise ApprovalWizardError("approval preview contains authority material")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _validated_inspection(value: object) -> dict[str, Any]:
    inspection = _exact_object(value, _INSPECTION_FIELDS, "inspection")
    if inspection["schema_version"] != 1:
        raise ApprovalWizardError("approval inspection version is invalid")
    _reject_authority_material(inspection)
    challenge = _exact_object(
        inspection["challenge"], _CHALLENGE_FIELDS, "challenge"
    )
    operation = _exact_object(
        inspection["operation"], _OPERATION_FIELDS, "operation"
    )
    summary = _exact_object(inspection["summary"], _SUMMARY_FIELDS, "summary")
    precheck = _exact_object(
        inspection["precheck"], _PRECHECK_FIELDS, "precheck"
    )

    challenge_id = _identifier(challenge["challenge_id"], "challenge ID")
    for field_name in ("binding_digest",):
        _required_digest(challenge[field_name], field_name)
    issued_at, issued = _timestamp(challenge["issued_at"], "issued time")
    expires_at, expires = _timestamp(challenge["expires_at"], "expiry time")
    if (
        expires <= issued
        or type(challenge["ttl_seconds"]) is not int
        or not 1 <= challenge["ttl_seconds"] <= _MAX_APPROVAL_TTL_SECONDS
        or expires - issued > timedelta(seconds=challenge["ttl_seconds"])
        or challenge["state"] not in _STATES
        or type(challenge["version"]) is not int
        or challenge["version"] < 0
    ):
        raise ApprovalWizardError("approval challenge content is invalid")

    for field_name in (
        "operation_id",
        "request_id",
        "capability_id",
        "idempotency_key",
    ):
        _identifier(operation[field_name], field_name)
    for field_name in (
        "principal",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "environment",
    ):
        _required_text(operation[field_name], field_name)
    for field_name in (
        "parameters_digest",
        "registry_digest",
        "release_digest",
        "operation_digest",
        "precheck_digest",
    ):
        _required_digest(operation[field_name], field_name)
    if (
        type(operation["parameters"]) is not dict
        or type(operation["user_id"]) is not int
        or operation["user_id"] <= 0
        or type(operation["company_id"]) is not int
        or operation["company_id"] <= 0
        or operation["state"] != "awaiting_approval"
        or type(operation["revision"]) is not int
        or operation["revision"] < 2
        or operation["protocol_version"] != 4
        or operation["environment"] not in {"test", "sandbox", "production"}
    ):
        raise ApprovalWizardError("approval operation content is invalid")
    try:
        if str(uuid.UUID(operation["database_uuid"])) != operation["database_uuid"]:
            raise ApprovalWizardError("approval database UUID is invalid")
    except (AttributeError, TypeError, ValueError) as exc:
        raise ApprovalWizardError("approval database UUID is invalid") from exc
    parameters_digest = _digest(operation["parameters"])
    operation_digest = _digest(
        {
            "capability_id": operation["capability_id"],
            "parameters": operation["parameters"],
            "principal": operation["principal"],
            "user_id": operation["user_id"],
            "company_id": operation["company_id"],
            "idempotency_key": operation["idempotency_key"],
            "odoo_instance_id": operation["odoo_instance_id"],
            "database_name": operation["database_name"],
            "database_uuid": operation["database_uuid"],
            "environment": operation["environment"],
            "registry_digest": operation["registry_digest"],
            "release_digest": operation["release_digest"],
        }
    )
    binding_digest = _digest(
        {
            "company_id": operation["company_id"],
            "database_name": operation["database_name"],
            "database_uuid": operation["database_uuid"],
            "environment": operation["environment"],
            "odoo_instance_id": operation["odoo_instance_id"],
            "operation_digest": operation["operation_digest"],
            "operation_id": operation["operation_id"],
            "operation_revision": operation["revision"],
            "precheck_digest": operation["precheck_digest"],
            "principal": operation["principal"],
            "request_id": operation["request_id"],
            "user_id": operation["user_id"],
        }
    )
    if not (
        _same(operation["parameters_digest"], parameters_digest)
        and _same(operation["operation_digest"], operation_digest)
        and _same(challenge["binding_digest"], binding_digest)
    ):
        raise ApprovalWizardError("approval operation binding is invalid")

    expected_summary = {
        "binding_digest": challenge["binding_digest"],
        "capability_id": operation["capability_id"],
        "challenge_id": challenge_id,
        "company_id": operation["company_id"],
        "operation_digest": operation["operation_digest"],
        "operation_id": operation["operation_id"],
        "parameters_digest": operation["parameters_digest"],
        "precheck_digest": operation["precheck_digest"],
        "requester_principal": operation["principal"],
        "requester_user_id": operation["user_id"],
    }
    if summary != expected_summary:
        raise ApprovalWizardError("approval summary binding is invalid")

    for field_name in ("operation_id", "request_id"):
        _identifier(precheck[field_name], f"precheck {field_name}")
    _required_text(precheck["principal"], "precheck principal")
    _required_digest(precheck["operation_digest"], "precheck operation digest")
    _required_digest(precheck["evidence_digest"], "precheck evidence digest")
    occurred_at, occurred = _timestamp(precheck["occurred_at"], "precheck time")
    evidence = precheck["evidence"]
    if (
        type(evidence) is not dict
        or precheck["operation_id"] != operation["operation_id"]
        or precheck["request_id"] != operation["request_id"]
        or precheck["operation_digest"] != operation["operation_digest"]
        or precheck["principal"] != operation["principal"]
        or precheck["user_id"] != operation["user_id"]
        or precheck["company_id"] != operation["company_id"]
        or type(precheck["operation_revision"]) is not int
        or precheck["operation_revision"] != operation["revision"]
        or type(precheck["source_operation_revision"]) is not int
        or precheck["source_operation_revision"] != operation["revision"] - 2
        or occurred > issued
        or not _same(precheck["evidence_digest"], _digest(evidence))
        or not _same(precheck["evidence_digest"], operation["precheck_digest"])
    ):
        raise ApprovalWizardError("approval precheck binding is invalid")
    core_fields = {"capability_id", "company_id", "parameters_digest"}
    present_core = set(evidence).intersection(core_fields)
    if present_core and (
        present_core != core_fields
        or evidence["capability_id"] != operation["capability_id"]
        or evidence["company_id"] != operation["company_id"]
        or evidence["parameters_digest"] != operation["parameters_digest"]
    ):
        raise ApprovalWizardError("approval precheck semantics are invalid")
    release_fields = {"registry_digest", "release_digest"}
    present_release = set(evidence).intersection(release_fields)
    if present_release and (
        present_release != release_fields
        or evidence["registry_digest"] != operation["registry_digest"]
        or evidence["release_digest"] != operation["release_digest"]
    ):
        raise ApprovalWizardError("approval precheck semantics are invalid")
    if "runtime_binding" in evidence:
        runtime = evidence["runtime_binding"]
        if (
            type(runtime) is not dict
            or runtime.get("user_id") != operation["user_id"]
            or runtime.get("odoo_instance_id") != operation["odoo_instance_id"]
            or runtime.get("database_name") != operation["database_name"]
            or runtime.get("database_uuid") != operation["database_uuid"]
            or runtime.get("environment") != operation["environment"]
        ):
            raise ApprovalWizardError("approval precheck semantics are invalid")

    preview_unsigned = {
        "schema_version": inspection["schema_version"],
        "challenge": challenge,
        "operation": operation,
        "summary": summary,
    }
    _required_digest(inspection["preview_digest"], "preview digest")
    _required_digest(inspection["inspection_digest"], "inspection digest")
    inspection_unsigned = {
        **preview_unsigned,
        "preview_digest": inspection["preview_digest"],
        "precheck": precheck,
    }
    if not (
        _same(inspection["preview_digest"], _digest(preview_unsigned))
        and _same(inspection["inspection_digest"], _digest(inspection_unsigned))
    ):
        raise ApprovalWizardError("approval preview digest is invalid")

    normalized = json.loads(_canonical_json(inspection))
    normalized["challenge"]["issued_at"] = issued_at
    normalized["challenge"]["expires_at"] = expires_at
    normalized["precheck"]["occurred_at"] = occurred_at
    return normalized


def _denial_reason(value: object, *, required: bool) -> str | bool:
    if value in (None, False, "") and not required:
        return False
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ApprovalWizardError("approval denial reason is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ApprovalWizardError("approval denial reason is invalid") from exc
    if len(encoded) > 2048:
        raise ApprovalWizardError("approval denial reason is invalid")
    return value


def _status_message(state: str) -> str:
    return {
        "pending": "Authoritative preview refreshed; verify all canonical JSON fields.",
        "approved": "Approval recorded and independently re-verified.",
        "denied": "Denial recorded and independently re-verified.",
        "expired": "The approval challenge has expired and cannot be decided.",
        "stale": "The approval challenge is stale and cannot be decided.",
    }[state]


class OdooAccountingCliV3ApprovalWizard(models.TransientModel):
    _name = "odoo.accounting.cli.v3.approval.wizard"
    _description = "Odoo Accounting CLI V3 Approval Review"
    _transient_max_hours = 1.0

    challenge_id = fields.Char(required=True, copy=False, index=True)
    operation_id = fields.Char(readonly=True, required=True)
    request_id = fields.Char(readonly=True, required=True)
    capability_id = fields.Char(readonly=True, required=True)
    company_id = fields.Many2one(
        "res.company", readonly=True, required=True, ondelete="cascade", index=True
    )
    requester_user_id = fields.Many2one(
        "res.users", readonly=True, required=True, ondelete="cascade"
    )
    approver_user_id = fields.Many2one(
        "res.users", readonly=True, required=True, ondelete="cascade"
    )
    state = fields.Selection(
        [(value, value) for value in sorted(_STATES)], readonly=True, required=True
    )
    issued_at = fields.Char(readonly=True, required=True)
    expires_at = fields.Char(readonly=True, required=True)
    operation_revision = fields.Integer(readonly=True, required=True)
    operation_digest = fields.Char(readonly=True, required=True)
    parameters_digest = fields.Char(readonly=True, required=True)
    precheck_digest = fields.Char(readonly=True, required=True)
    preview_digest = fields.Char(readonly=True, required=True)
    inspection_digest = fields.Char(readonly=True, required=True)
    parameters_json = fields.Text(readonly=True, required=True)
    precheck_json = fields.Text(readonly=True, required=True)
    snapshot_json = fields.Text(readonly=True, required=True)
    denial_reason = fields.Text(copy=False)
    status_message = fields.Text(readonly=True, required=True)
    last_checked_at = fields.Datetime(readonly=True, required=True)

    def _assert_approver(self) -> None:
        if self.env.su or not self.env.user.has_group(_APPROVER_GROUP):
            raise AccessError("V3 approval review requires a bound approver")

    def _assert_preview_binding(self, inspection: dict[str, Any]) -> None:
        operation = inspection["operation"]
        if (
            operation["company_id"] != self.env.company.id
            or operation["company_id"] not in self.env.companies.ids
        ):
            raise AccessError("approval company is not the active Odoo company")
        if operation["user_id"] == self.env.uid:
            raise AccessError("requesters cannot approve their own operation")

    def _assert_record_bound(self) -> None:
        self.ensure_one()
        self._assert_approver()
        if (
            self.create_uid.id != self.env.uid
            or self.approver_user_id.id != self.env.uid
            or self.company_id.id != self.env.company.id
            or self.company_id.id not in self.env.companies.ids
        ):
            raise AccessError("approval review is bound to a different user or company")
        if self.requester_user_id.id == self.env.uid:
            raise AccessError("requesters cannot approve their own operation")

    def _inspect(self) -> dict[str, Any]:
        client = self.env["odoo.accounting.cli.v3.approval.client"]
        try:
            value = client._odoo_v3_inspect_approval(
                {"challenge_id": self.challenge_id}
            )
            inspection = _validated_inspection(value)
        except (AccessError, UserError):
            raise
        except Exception:
            raise UserError(
                "The V3 approval preview could not be verified safely."
            ) from None
        self._assert_preview_binding(inspection)
        return inspection

    def _snapshot_values(self, inspection: dict[str, Any]) -> dict[str, Any]:
        challenge = inspection["challenge"]
        operation = inspection["operation"]
        return {
            "challenge_id": challenge["challenge_id"],
            "operation_id": operation["operation_id"],
            "request_id": operation["request_id"],
            "capability_id": operation["capability_id"],
            "company_id": operation["company_id"],
            "requester_user_id": operation["user_id"],
            "approver_user_id": self.env.uid,
            "state": challenge["state"],
            "issued_at": challenge["issued_at"],
            "expires_at": challenge["expires_at"],
            "operation_revision": operation["revision"],
            "operation_digest": operation["operation_digest"],
            "parameters_digest": operation["parameters_digest"],
            "precheck_digest": operation["precheck_digest"],
            "preview_digest": inspection["preview_digest"],
            "inspection_digest": inspection["inspection_digest"],
            "parameters_json": _canonical_json(operation["parameters"]),
            "precheck_json": _canonical_json(inspection["precheck"]),
            "snapshot_json": _canonical_json(inspection),
            "status_message": _status_message(challenge["state"]),
            "last_checked_at": fields.Datetime.now(),
        }

    @api.model_create_multi
    def create(self, vals_list):
        self._assert_approver()
        if (
            not isinstance(vals_list, list)
            or len(vals_list) != 1
            or type(vals_list[0]) is not dict
            or set(vals_list[0]) != {"challenge_id"}
        ):
            raise AccessError("approval review accepts only one challenge ID")
        client = self.env["odoo.accounting.cli.v3.approval.client"]
        try:
            challenge_id = _identifier(
                vals_list[0]["challenge_id"], "challenge ID"
            )
            inspection = _validated_inspection(
                client._odoo_v3_inspect_approval({"challenge_id": challenge_id})
            )
        except (AccessError, UserError):
            raise
        except Exception:
            raise UserError(
                "The V3 approval preview could not be verified safely."
            ) from None
        self._assert_preview_binding(inspection)
        if inspection["challenge"]["challenge_id"] != challenge_id:
            raise UserError("The V3 approval preview binding is invalid.")
        return super().create([self._snapshot_values(inspection)])

    def write(self, values):
        if not self:
            raise AccessError("approval review record is required")
        for wizard in self:
            wizard._assert_record_bound()
            if wizard.state != "pending" or wizard._is_expired():
                raise UserError("Only a pending approval review can be edited.")
        if type(values) is not dict or set(values) != {"denial_reason"}:
            raise AccessError("only the denial reason may be edited")
        try:
            denial_reason = _denial_reason(values["denial_reason"], required=False)
        except ApprovalWizardError:
            raise UserError("The V3 denial reason is invalid.") from None
        return super().write({"denial_reason": denial_reason})

    def _is_expired(self) -> bool:
        try:
            _value, expires = _timestamp(self.expires_at, "expiry time")
        except ApprovalWizardError:
            raise UserError(
                "The V3 approval validity could not be verified."
            ) from None
        return expires <= datetime.now(timezone.utc)

    def _assert_pending_snapshot(self, inspection: dict[str, Any]) -> None:
        challenge = inspection["challenge"]
        if challenge["state"] != "pending" or self._is_expired():
            raise UserError("The V3 approval challenge is no longer pending.")
        expected = self._snapshot_values(inspection)
        actual = {
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "capability_id": self.capability_id,
            "company_id": self.company_id.id,
            "requester_user_id": self.requester_user_id.id,
            "approver_user_id": self.approver_user_id.id,
            "state": self.state,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "operation_revision": self.operation_revision,
            "operation_digest": self.operation_digest,
            "parameters_digest": self.parameters_digest,
            "precheck_digest": self.precheck_digest,
            "preview_digest": self.preview_digest,
            "inspection_digest": self.inspection_digest,
            "parameters_json": self.parameters_json,
            "precheck_json": self.precheck_json,
            "snapshot_json": self.snapshot_json,
            "status_message": self.status_message,
        }
        expected.pop("last_checked_at")
        if actual != expected or not _same(
            self.snapshot_json, _canonical_json(inspection)
        ):
            raise UserError(
                "The V3 approval preview changed; refresh before deciding."
            )

    def _validate_decision_view(
        self, value: object, *, expected_state: str
    ) -> None:
        if type(value) is not dict or set(value) != {
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
        }:
            raise UserError("The V3 approval decision response is invalid.")
        if (
            value["challenge_id"] != self.challenge_id
            or value["operation_id"] != self.operation_id
            or value["capability_id"] != self.capability_id
            or value["company_id"] != self.company_id.id
            or value["requester_user_id"] != self.requester_user_id.id
            or value["requester_user_id"] == self.env.uid
            or value["operation_digest"] != self.operation_digest
            or value["precheck_digest"] != self.precheck_digest
            or value["state"] != expected_state
        ):
            raise UserError("The V3 approval decision response is invalid.")
        try:
            issued_at, issued = _timestamp(
                value["issued_at"], "decision issued time"
            )
            expires_at, expires = _timestamp(
                value["expires_at"], "decision expiry time"
            )
        except ApprovalWizardError:
            raise UserError("The V3 approval decision response is invalid.") from None
        if (
            issued_at != self.issued_at
            or expires_at != self.expires_at
            or expires <= issued
        ):
            raise UserError("The V3 approval decision response is invalid.")

    def _assert_final_transition(
        self,
        before: dict[str, Any],
        after: dict[str, Any],
        *,
        expected_state: str,
    ) -> None:
        before_challenge = before["challenge"]
        after_challenge = after["challenge"]
        stable_challenge_fields = _CHALLENGE_FIELDS - {"state", "version"}
        if (
            after_challenge["state"] != expected_state
            or after_challenge["version"] != before_challenge["version"] + 1
            or any(
                after_challenge[field_name] != before_challenge[field_name]
                for field_name in stable_challenge_fields
            )
            or after["operation"] != before["operation"]
            or after["summary"] != before["summary"]
            or after["precheck"] != before["precheck"]
        ):
            raise UserError("The V3 approval final state is not authoritative.")

    def _store_inspection(
        self, inspection: dict[str, Any], *, clear_denial: bool = False
    ) -> None:
        values = self._snapshot_values(inspection)
        if clear_denial:
            values["denial_reason"] = False
        super().write(values)

    def _review_action(self) -> dict[str, Any]:
        return {
            "type": "ir.actions.act_window",
            "name": "V3 Approval Review",
            "res_model": self._name,
            "res_id": self.id,
            "view_mode": "form",
            "target": "new",
        }

    def _decide(self, *, decision: str, reason: str | None) -> dict[str, Any]:
        before = self._inspect()
        self._assert_pending_snapshot(before)
        client = self.env["odoo.accounting.cli.v3.approval.client"]
        decided = client._odoo_v3_decide_approval(
            {
                "challenge_id": self.challenge_id,
                "decision": decision,
                "reason": reason,
            }
        )
        expected_state = "approved" if decision == "approve" else "denied"
        self._validate_decision_view(decided, expected_state=expected_state)
        after = self._inspect()
        self._assert_final_transition(before, after, expected_state=expected_state)
        self._store_inspection(after, clear_denial=decision == "approve")
        return self._review_action()

    def action_approve(self):
        self.ensure_one()
        self._assert_record_bound()
        return self._decide(decision="approve", reason=None)

    def action_deny(self):
        self.ensure_one()
        self._assert_record_bound()
        try:
            reason = _denial_reason(self.denial_reason, required=True)
        except ApprovalWizardError:
            raise UserError("A valid denial reason is required.") from None
        return self._decide(decision="deny", reason=reason)

    def action_refresh(self):
        self.ensure_one()
        self._assert_record_bound()
        inspection = self._inspect()
        self._store_inspection(inspection)
        return self._review_action()
