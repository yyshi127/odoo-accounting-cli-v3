from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta

from odoo import api, fields, models
from odoo.exceptions import AccessError, ValidationError


_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENVIRONMENTS = {"test", "sandbox", "production"}
_CHANNELS = {"staged", "enabled"}


class OdooAccountingCliOperation(models.Model):
    _name = "odoo.accounting.cli.operation"
    _description = "Odoo Accounting CLI V3 Operation Anchor"
    _order = "id desc"
    _check_company_auto = True

    operation_id = fields.Char(required=True, readonly=True, index=True)
    request_id = fields.Char(required=True, readonly=True, index=True)
    capability_id = fields.Char(required=True, readonly=True, index=True)
    idempotency_scope = fields.Char(required=True, readonly=True, index=True)
    operation_digest = fields.Char(required=True, readonly=True, index=True)
    protocol_version = fields.Integer(required=True, readonly=True)
    precheck_digest = fields.Char(required=True, readonly=True, index=True)
    principal = fields.Char(required=True, readonly=True)
    requester_id = fields.Many2one(
        "res.users", required=True, readonly=True, ondelete="restrict", index=True
    )
    approver_id = fields.Many2one(
        "res.users", required=True, readonly=True, ondelete="restrict", index=True
    )
    company_id = fields.Many2one(
        "res.company", required=True, readonly=True, ondelete="restrict", index=True
    )
    environment = fields.Selection(
        [(value, value) for value in sorted(_ENVIRONMENTS)],
        required=True,
        readonly=True,
    )
    capability_channel = fields.Selection(
        [(value, value) for value in sorted(_CHANNELS)],
        required=True,
        readonly=True,
    )
    registry_digest = fields.Char(required=True, readonly=True)
    release_digest = fields.Char(required=True, readonly=True)
    state = fields.Selection(
        [
            ("claimed", "Claimed"),
            ("committed", "Committed"),
            ("verified", "Verified"),
            ("failed", "Failed"),
            ("recovering", "Recovering"),
            ("recovered", "Recovered"),
        ],
        required=True,
        default="claimed",
        readonly=True,
        index=True,
    )
    execution_evidence_json = fields.Text(readonly=True)
    execution_evidence_digest = fields.Char(readonly=True)
    verification_evidence_json = fields.Text(readonly=True)
    verification_evidence_digest = fields.Char(readonly=True)
    failure_evidence_json = fields.Text(readonly=True)
    failure_evidence_digest = fields.Char(readonly=True)
    recovery_plan_json = fields.Text(readonly=True)
    recovery_plan_digest = fields.Char(readonly=True)
    recovery_evidence_json = fields.Text(readonly=True)
    recovery_evidence_digest = fields.Char(readonly=True)
    execution_result_json = fields.Text(readonly=True, copy=False)
    execution_result_digest = fields.Char(readonly=True, copy=False)
    verification_result_json = fields.Text(readonly=True, copy=False)
    verification_result_digest = fields.Char(readonly=True, copy=False)
    recovery_result_json = fields.Text(readonly=True, copy=False)
    recovery_result_digest = fields.Char(readonly=True, copy=False)

    _operation_id_unique = models.Constraint(
        "UNIQUE(operation_id)",
        "The V3 operation ID must be unique.",
    )
    _company_capability_scope_unique = models.Constraint(
        "UNIQUE(company_id, capability_id, idempotency_scope)",
        "The V3 company/capability/idempotency scope is already claimed.",
    )

    _IMMUTABLE_FIELDS = frozenset(
        {
            "operation_id",
            "request_id",
            "capability_id",
            "idempotency_scope",
            "operation_digest",
            "protocol_version",
            "precheck_digest",
            "principal",
            "requester_id",
            "approver_id",
            "company_id",
            "environment",
            "capability_channel",
            "registry_digest",
            "release_digest",
        }
    )
    _MUTABLE_FIELDS = frozenset(
        {
            "state",
            "execution_evidence_json",
            "execution_evidence_digest",
            "verification_evidence_json",
            "verification_evidence_digest",
            "failure_evidence_json",
            "failure_evidence_digest",
            "recovery_plan_json",
            "recovery_plan_digest",
            "recovery_evidence_json",
            "recovery_evidence_digest",
            "execution_result_json",
            "execution_result_digest",
            "verification_result_json",
            "verification_result_digest",
            "recovery_result_json",
            "recovery_result_digest",
        }
    )
    _CREATE_FIELDS = _IMMUTABLE_FIELDS | {"state"}
    _RESULT_STORAGE_FIELDS = frozenset(
        {
            "execution_evidence_json",
            "execution_evidence_digest",
            "execution_result_json",
            "execution_result_digest",
            "verification_evidence_json",
            "verification_evidence_digest",
            "verification_result_json",
            "verification_result_digest",
            "recovery_evidence_json",
            "recovery_evidence_digest",
            "recovery_result_json",
            "recovery_result_digest",
        }
    )
    _ROOT_VERIFICATION_FIELDS = frozenset(
        {
            "state",
            "verification_evidence_json",
            "verification_evidence_digest",
            "verification_result_json",
            "verification_result_digest",
            "failure_evidence_json",
            "failure_evidence_digest",
        }
    )
    _RESULT_ENVELOPE_FIELDS = frozenset(
        {
            "capability_id",
            "company_id",
            "evidence_digest",
            "issued_at",
            "issuer",
            "key_id",
            "kind",
            "operation_digest",
            "operation_id",
            "operation_revision",
            "operation_state_digest",
            "prior_evidence_digest",
            "purpose",
            "registry_digest",
            "release_digest",
            "request_id",
            "signature",
            "succeeded",
            "version",
        }
    )
    _RESULT_PURPOSES = {
        "execution": "execution_result_v2",
        "verification": "verification_result_v2",
        "recovery": "recovery_result_v2",
    }

    @staticmethod
    def _required_text(value, field_name, maximum=512):
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > maximum
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in value
            )
        ):
            raise ValidationError(f"{field_name} is invalid")
        return value

    @staticmethod
    def _required_digest(value, field_name):
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ValidationError(f"{field_name} must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def _canonical_evidence(cls, evidence, evidence_digest):
        if not isinstance(evidence, dict):
            raise ValidationError("operation evidence must be an object")
        try:
            encoded = json.dumps(
                evidence,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError("operation evidence is not canonical JSON") from exc
        cls._required_digest(evidence_digest, "evidence_digest")
        if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != evidence_digest:
            raise ValidationError("canonical evidence digest mismatch")
        return encoded

    @staticmethod
    def _required_utc_timestamp(value):
        if not isinstance(value, str):
            raise ValidationError("result issued_at must be canonical UTC ISO-8601")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError(
                "result issued_at must be canonical UTC ISO-8601"
            ) from exc
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() != timedelta(0)
            or parsed.isoformat() != value
        ):
            raise ValidationError("result issued_at must be canonical UTC ISO-8601")

    def _canonical_result_envelope(
        self,
        *,
        result,
        result_digest,
        kind,
        evidence_digest,
        succeeded,
        prior_evidence_digest,
    ):
        if not isinstance(result, dict) or set(result) != self._RESULT_ENVELOPE_FIELDS:
            raise ValidationError("result envelope fields are invalid")
        try:
            encoded = json.dumps(
                result,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError("result envelope is not canonical JSON") from exc
        self._required_digest(result_digest, "result_digest")
        if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != result_digest:
            raise ValidationError("result envelope digest mismatch")
        if (
            result["kind"] != kind
            or result["operation_id"] != self.operation_id
            or result["request_id"] != self.request_id
            or result["operation_digest"] != self.operation_digest
            or type(result["company_id"]) is not int
            or result["company_id"] != self.company_id.id
            or result["capability_id"] != self.capability_id
            or result["registry_digest"] != self.registry_digest
            or result["release_digest"] != self.release_digest
            or result["evidence_digest"] != evidence_digest
            or result["succeeded"] is not succeeded
            or result["prior_evidence_digest"] != prior_evidence_digest
        ):
            raise ValidationError("result envelope binding mismatch")
        if (
            type(result["operation_revision"]) is not int
            or result["operation_revision"] < 0
            or type(result["version"]) is not int
            or result["version"] != 2
            or result["purpose"] != self._RESULT_PURPOSES[kind]
            or type(result["succeeded"]) is not bool
        ):
            raise ValidationError("result envelope content is invalid")
        for field_name in (
            "operation_state_digest",
            "evidence_digest",
            "registry_digest",
            "release_digest",
            "signature",
        ):
            self._required_digest(result[field_name], f"result.{field_name}")
        if prior_evidence_digest is not None:
            self._required_digest(
                result["prior_evidence_digest"], "result.prior_evidence_digest"
            )
        self._required_text(result["issuer"], "result.issuer")
        self._required_text(result["key_id"], "result.key_id")
        self._required_utc_timestamp(result["issued_at"])
        return encoded

    def _is_same_result_replay(
        self,
        *,
        kind,
        encoded_evidence,
        evidence_digest,
        encoded_result,
        result_digest,
    ):
        stored = (
            self[f"{kind}_evidence_json"],
            self[f"{kind}_evidence_digest"],
            self[f"{kind}_result_json"],
            self[f"{kind}_result_digest"],
        )
        expected = (
            encoded_evidence,
            evidence_digest,
            encoded_result,
            result_digest,
        )
        if not any(stored):
            return False
        if not all(isinstance(value, str) and value for value in stored):
            raise ValidationError("stored result envelope is incomplete")
        if stored != expected:
            raise ValidationError(f"{kind} result envelope is immutable")
        return True

    def _assert_executor(self):
        if self.env.su or not self.env.user.has_group(
            "odoo_accounting_cli_v3_control.group_executor"
        ):
            raise AccessError("the bound user is not a V3 accounting CLI executor")

    def _assert_bound_executor(self):
        self.ensure_one()
        self._assert_executor()
        if self.requester_id.id != self.env.uid:
            raise AccessError("operation is bound to a different executor")
        if self.company_id.id not in self.env.companies.ids:
            raise AccessError("operation company is outside the active companies")

    @api.model
    def _assert_claim_binding(self, requester_id, company_id):
        self._assert_executor()
        if requester_id != self.env.uid:
            raise AccessError("operation requester does not match the bound Odoo user")
        if (
            company_id not in self.env.user.company_ids.ids
            or company_id not in self.env.companies.ids
        ):
            raise AccessError("operation company is outside the bound user companies")

    @api.model_create_multi
    def create(self, vals_list):
        raise AccessError("direct control operation creation is forbidden")

    @api.model_create_multi
    def _create_controlled(self, vals_list):
        self._assert_executor()
        for values in vals_list:
            if set(values) != self._CREATE_FIELDS:
                raise AccessError("operation anchor fields must match the create allowlist")
            requester_id = values.get("requester_id")
            approver_id = values.get("approver_id")
            company_id = values.get("company_id")
            environment = values.get("environment")
            capability_channel = values.get("capability_channel")
            self._assert_claim_binding(requester_id, company_id)
            if approver_id == requester_id:
                raise ValidationError("requester and approver must be different users")
            approver = self.env["res.users"].browse(approver_id).exists()
            if (
                not approver
                or len(approver) != 1
                or not approver.active
                or company_id not in approver.company_ids.ids
                or not approver.has_group(
                    "odoo_accounting_cli_v3_control.group_approver"
                )
            ):
                raise AccessError("operation approver is not an active company approver")
            if environment not in _ENVIRONMENTS or capability_channel not in _CHANNELS:
                raise ValidationError("operation runtime binding is invalid")
            if environment == "production" and capability_channel == "staged":
                raise ValidationError("a staged capability cannot write production")
            for field_name in (
                "operation_id",
                "request_id",
                "capability_id",
                "principal",
            ):
                self._required_text(values.get(field_name), field_name)
            for field_name in (
                "idempotency_scope",
                "operation_digest",
                "precheck_digest",
                "registry_digest",
                "release_digest",
            ):
                self._required_digest(values.get(field_name), field_name)
            if values.get("protocol_version") != 4:
                raise ValidationError("operation protocol version is invalid")
            if values.get("state", "claimed") != "claimed":
                raise ValidationError("new operation anchors must start claimed")
        for idempotency_scope in sorted(
            {values["idempotency_scope"] for values in vals_list}
        ):
            self._acquire_scope_lock(idempotency_scope)
        return super().create(vals_list)

    def write(self, values):
        raise AccessError("direct control operation writes are forbidden")

    def unlink(self):
        raise AccessError("control operations cannot be deleted")

    def _write_controlled(self, values, *, root_verification=False):
        if root_verification:
            self.ensure_one()
            if not self.env.su or not isinstance(values, dict) or not set(
                values
            ).issubset(self._ROOT_VERIFICATION_FIELDS):
                raise AccessError(
                    "root verification mutation is outside the narrow allowlist"
                )
        else:
            self._assert_bound_executor()
        if not isinstance(values, dict) or not set(values).issubset(self._MUTABLE_FIELDS):
            raise AccessError("control operation mutation is outside the allowlist")
        for field_name in set(values) & self._RESULT_STORAGE_FIELDS:
            if self[field_name] and self[field_name] != values[field_name]:
                raise AccessError("stored result envelope is immutable")
        if self.recovery_result_digest:
            for field_name in {"recovery_plan_json", "recovery_plan_digest"} & set(
                values
            ):
                if self[field_name] != values[field_name]:
                    raise AccessError("stored recovery plan is immutable")
        return super().write(values)

    @api.model
    def _acquire_scope_lock(self, idempotency_scope):
        self._required_digest(idempotency_scope, "idempotency_scope")
        lock_key = int(idempotency_scope[:16], 16)
        if lock_key >= 2**63:
            lock_key -= 2**64
        self.env.cr.execute("SELECT pg_advisory_xact_lock(%s)", [lock_key])

    def _acquire_resource_locks(self, resource_digests):
        self.ensure_one()
        self._assert_bound_executor()
        if self.state != "claimed":
            raise AccessError("resource locks require a claimed operation")
        if (
            not isinstance(resource_digests, list)
            or len(resource_digests) > 2000
            or resource_digests != sorted(set(resource_digests))
        ):
            raise AccessError("resource lock digests must be ordered and unique")
        for resource_digest in resource_digests:
            self._required_digest(resource_digest, "resource_digest")
            self._acquire_scope_lock(resource_digest)
        return True

    @api.model
    def _lookup_exact(
        self,
        *,
        operation_id,
        request_id,
        capability_id,
        idempotency_scope,
        operation_digest,
        protocol_version,
        precheck_digest,
        principal,
        requester_id,
        approver_id,
        company_id,
        environment,
        capability_channel,
        registry_digest,
        release_digest,
    ):
        """Read one immutable anchor through the root control plane only."""

        if not self.env.su:
            raise AccessError(
                "exact operation lookup is restricted to the root control plane"
            )
        for field_name, value in (
            ("operation_id", operation_id),
            ("request_id", request_id),
            ("capability_id", capability_id),
            ("principal", principal),
        ):
            self._required_text(value, field_name)
        for field_name, value in (
            ("idempotency_scope", idempotency_scope),
            ("operation_digest", operation_digest),
            ("precheck_digest", precheck_digest),
            ("registry_digest", registry_digest),
            ("release_digest", release_digest),
        ):
            self._required_digest(value, field_name)
        if (
            protocol_version != 4
            or type(requester_id) is not int
            or requester_id <= 0
            or type(approver_id) is not int
            or approver_id <= 0
            or type(company_id) is not int
            or company_id <= 0
            or environment not in _ENVIRONMENTS
            or capability_channel not in _CHANNELS
        ):
            raise ValidationError("operation lookup binding is invalid")
        anchor = self.search([("operation_id", "=", operation_id)], limit=2)
        if not anchor:
            return self.browse()
        if len(anchor) != 1:
            raise ValidationError("operation lookup is not unique")
        anchor.ensure_one()
        expected = {
            "operation_id": operation_id,
            "request_id": request_id,
            "capability_id": capability_id,
            "idempotency_scope": idempotency_scope,
            "operation_digest": operation_digest,
            "protocol_version": protocol_version,
            "precheck_digest": precheck_digest,
            "principal": principal,
            "requester_id": requester_id,
            "approver_id": approver_id,
            "company_id": company_id,
            "environment": environment,
            "capability_channel": capability_channel,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }
        actual = {
            **{field_name: anchor[field_name] for field_name in expected},
            "requester_id": anchor.requester_id.id,
            "approver_id": anchor.approver_id.id,
            "company_id": anchor.company_id.id,
        }
        if actual != expected:
            raise ValidationError("operation lookup immutable binding mismatch")
        return anchor

    @api.model
    def _claim(
        self,
        *,
        operation_id,
        request_id,
        capability_id,
        idempotency_scope,
        operation_digest,
        protocol_version,
        precheck_digest,
        principal,
        requester_id,
        approver_id,
        company_id,
        environment,
        capability_channel,
        registry_digest,
        release_digest,
    ):
        self._assert_claim_binding(requester_id, company_id)
        self._acquire_scope_lock(idempotency_scope)
        existing = self.search(
            [
                ("company_id", "=", company_id),
                ("capability_id", "=", capability_id),
                ("idempotency_scope", "=", idempotency_scope),
            ],
            limit=1,
        )
        if existing:
            if (
                existing.operation_id != operation_id
                or existing.request_id != request_id
                or existing.capability_id != capability_id
                or existing.idempotency_scope != idempotency_scope
                or existing.operation_digest != operation_digest
                or existing.protocol_version != protocol_version
                or existing.precheck_digest != precheck_digest
                or existing.principal != principal
                or existing.requester_id.id != requester_id
                or existing.approver_id.id != approver_id
                or existing.company_id.id != company_id
                or existing.environment != environment
                or existing.capability_channel != capability_channel
                or existing.registry_digest != registry_digest
                or existing.release_digest != release_digest
            ):
                raise ValidationError("idempotency scope has different immutable content")
            return existing
        return self._create_controlled(
            {
                "operation_id": operation_id,
                "request_id": request_id,
                "capability_id": capability_id,
                "idempotency_scope": idempotency_scope,
                "operation_digest": operation_digest,
                "protocol_version": protocol_version,
                "precheck_digest": precheck_digest,
                "principal": principal,
                "requester_id": requester_id,
                "approver_id": approver_id,
                "company_id": company_id,
                "environment": environment,
                "capability_channel": capability_channel,
                "registry_digest": registry_digest,
                "release_digest": release_digest,
                "state": "claimed",
            }
        )

    def _record_execution(
        self,
        *,
        evidence,
        evidence_digest,
        result,
        result_digest,
        succeeded=True,
    ):
        self.ensure_one()
        self._assert_bound_executor()
        if type(succeeded) is not bool:
            raise ValidationError("operation is not ready for execution evidence")
        encoded = self._canonical_evidence(evidence, evidence_digest)
        encoded_result = self._canonical_result_envelope(
            result=result,
            result_digest=result_digest,
            kind="execution",
            evidence_digest=evidence_digest,
            succeeded=succeeded,
            prior_evidence_digest=None,
        )
        if self._is_same_result_replay(
            kind="execution",
            encoded_evidence=encoded,
            evidence_digest=evidence_digest,
            encoded_result=encoded_result,
            result_digest=result_digest,
        ):
            return True
        if self.state != "claimed":
            raise ValidationError("operation is not ready for execution evidence")
        values = {
            "execution_evidence_json": encoded,
            "execution_evidence_digest": evidence_digest,
            "execution_result_json": encoded_result,
            "execution_result_digest": result_digest,
            "state": "committed" if succeeded else "failed",
        }
        if not succeeded:
            values.update(
                failure_evidence_json=encoded,
                failure_evidence_digest=evidence_digest,
            )
        self._write_controlled(values)
        return True

    def _record_verification(
        self,
        *,
        evidence,
        evidence_digest,
        result,
        result_digest,
        passed=True,
    ):
        self.ensure_one()
        self._assert_bound_executor()
        return self._record_verification_controlled(
            evidence=evidence,
            evidence_digest=evidence_digest,
            result=result,
            result_digest=result_digest,
            passed=passed,
            root_verification=False,
        )

    def _record_committed_verification_from_root(
        self,
        *,
        evidence,
        evidence_digest,
        result,
        result_digest,
        passed=True,
    ):
        """Finalize only an already-committed result from the root control plane."""

        self.ensure_one()
        if not self.env.su:
            raise AccessError(
                "committed verification finalization requires the root control plane"
            )
        return self._record_verification_controlled(
            evidence=evidence,
            evidence_digest=evidence_digest,
            result=result,
            result_digest=result_digest,
            passed=passed,
            root_verification=True,
        )

    def _record_verification_controlled(
        self,
        *,
        evidence,
        evidence_digest,
        result,
        result_digest,
        passed,
        root_verification,
    ):
        if type(passed) is not bool or not self.execution_evidence_digest:
            raise ValidationError("operation is not ready for verification evidence")
        encoded = self._canonical_evidence(evidence, evidence_digest)
        encoded_result = self._canonical_result_envelope(
            result=result,
            result_digest=result_digest,
            kind="verification",
            evidence_digest=evidence_digest,
            succeeded=passed,
            prior_evidence_digest=self.execution_evidence_digest,
        )
        if self._is_same_result_replay(
            kind="verification",
            encoded_evidence=encoded,
            evidence_digest=evidence_digest,
            encoded_result=encoded_result,
            result_digest=result_digest,
        ):
            return True
        if self.state != "committed":
            raise ValidationError("operation is not ready for verification evidence")
        values = {
            "verification_evidence_json": encoded,
            "verification_evidence_digest": evidence_digest,
            "verification_result_json": encoded_result,
            "verification_result_digest": result_digest,
            "state": "verified" if passed else "failed",
        }
        if not passed:
            values.update(
                failure_evidence_json=encoded,
                failure_evidence_digest=evidence_digest,
            )
        self._write_controlled(values, root_verification=root_verification)
        return True

    def _record_failure(self, *, evidence, evidence_digest, result, result_digest):
        self.ensure_one()
        self._assert_bound_executor()
        if self.state == "claimed" or (
            self.state == "failed"
            and self.execution_result_digest
            and not self.verification_result_digest
            and not self.recovery_result_digest
        ):
            return self._record_execution(
                evidence=evidence,
                evidence_digest=evidence_digest,
                result=result,
                result_digest=result_digest,
                succeeded=False,
            )
        if self.state == "committed" or (
            self.state == "failed"
            and self.verification_result_digest
            and not self.recovery_result_digest
        ):
            return self._record_verification(
                evidence=evidence,
                evidence_digest=evidence_digest,
                result=result,
                result_digest=result_digest,
                passed=False,
            )
        raise ValidationError("operation cannot record failure from its current state")

    def _begin_recovery(self, *, plan, plan_digest):
        self.ensure_one()
        self._assert_bound_executor()
        encoded = self._canonical_evidence(plan, plan_digest)
        if self.recovery_plan_digest:
            if (
                self.recovery_plan_json != encoded
                or self.recovery_plan_digest != plan_digest
            ):
                raise ValidationError("recovery plan is immutable")
            return True
        if self.state not in {"verified", "failed"}:
            raise ValidationError("operation is not recoverable from its current state")
        self._write_controlled(
            {
                "recovery_plan_json": encoded,
                "recovery_plan_digest": plan_digest,
                "state": "recovering",
            }
        )
        return True

    def _record_recovery(
        self,
        *,
        evidence,
        evidence_digest,
        result,
        result_digest,
        succeeded=True,
    ):
        self.ensure_one()
        self._assert_bound_executor()
        if type(succeeded) is not bool or not self.recovery_plan_digest:
            raise ValidationError("operation is not ready for recovery evidence")
        encoded = self._canonical_evidence(evidence, evidence_digest)
        encoded_result = self._canonical_result_envelope(
            result=result,
            result_digest=result_digest,
            kind="recovery",
            evidence_digest=evidence_digest,
            succeeded=succeeded,
            prior_evidence_digest=self.recovery_plan_digest,
        )
        if self._is_same_result_replay(
            kind="recovery",
            encoded_evidence=encoded,
            evidence_digest=evidence_digest,
            encoded_result=encoded_result,
            result_digest=result_digest,
        ):
            return True
        if self.state != "recovering":
            raise ValidationError("operation is not ready for recovery evidence")
        values = {
            "recovery_evidence_json": encoded,
            "recovery_evidence_digest": evidence_digest,
            "recovery_result_json": encoded_result,
            "recovery_result_digest": result_digest,
            "state": "recovered" if succeeded else "failed",
        }
        if not succeeded:
            values.update(
                failure_evidence_json=encoded,
                failure_evidence_digest=evidence_digest,
            )
        self._write_controlled(values)
        return True
