"""Private Odoo client for the independent V3 approval UDS boundary."""

from __future__ import annotations

import http.client
import re
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any

from odoo import api, models
from odoo.exceptions import AccessError, UserError

from . import session_client as sessions


_APPROVAL_REQUEST_PATH = "/v1/approval/request"
_APPROVAL_INSPECT_PATH = "/v1/approval/inspect"
_APPROVAL_DECIDE_PATH = "/v1/approval/decide"
_EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
_APPROVER_GROUP = "odoo_accounting_cli_v3_control.group_approver"
_APPROVAL_SOCKET_ENV = "ODOO_V3_TRUSTED_APPROVAL_SOCKET"
_APPROVAL_UDS_TIMEOUT_SECONDS = 35.0
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VIEW_FIELDS = frozenset(
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
_VIEW_STATES = frozenset({"pending", "approved", "denied", "expired", "stale"})


class ApprovalClientError(RuntimeError):
    """The local approval exchange failed without exposing credentials."""


def _approval_socket_path() -> str:
    value = sessions._required_root_value(_APPROVAL_SOCKET_ENV)
    parsed = PurePosixPath(value)
    if (
        sessions._SOCKET_PATH.fullmatch(value) is None
        or not value.isascii()
        or len(value.encode("ascii")) > 107
        or not parsed.is_absolute()
        or value.startswith("//")
        or str(parsed) != value
        or any(part in {".", ".."} for part in parsed.parts)
        or not parsed.name.endswith(".sock")
    ):
        raise ApprovalClientError("root-injected approval configuration is invalid")
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or sessions._IDENTIFIER.fullmatch(value) is None:
        raise ApprovalClientError("approval identifier is invalid")
    return value


def _request_payload(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"operation_id"}:
        raise ApprovalClientError("approval request contains forbidden fields")
    return {"operation_id": _identifier(value["operation_id"])}


def _inspection_payload(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"challenge_id"}:
        raise ApprovalClientError("approval inspection contains forbidden fields")
    return {"challenge_id": _identifier(value["challenge_id"])}


def _denial_reason(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ApprovalClientError("approval denial reason is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ApprovalClientError("approval denial reason is invalid") from exc
    if len(encoded) > 2048:
        raise ApprovalClientError("approval denial reason is invalid")
    return value


def _decision_payload(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "challenge_id",
        "decision",
        "reason",
    }:
        raise ApprovalClientError("approval decision contains forbidden fields")
    challenge_id = _identifier(value["challenge_id"])
    decision = value["decision"]
    reason = value["reason"]
    if decision == "approve":
        if reason is not None:
            raise ApprovalClientError("approval reason is invalid")
    elif decision == "deny":
        reason = _denial_reason(reason)
    else:
        raise ApprovalClientError("approval decision is invalid")
    return {
        "challenge_id": challenge_id,
        "decision": decision,
        "reason": reason,
    }


def _utc_timestamp(value: object) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value.isascii() or not 20 <= len(value) <= 40:
        raise ApprovalClientError("approval response timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ApprovalClientError("approval response timestamp is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != value
    ):
        raise ApprovalClientError("approval response timestamp is invalid")
    return value, parsed


def _challenge_view(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _VIEW_FIELDS:
        raise ApprovalClientError("approval response view is invalid")
    capability_id = _identifier(value["capability_id"])
    challenge_id = _identifier(value["challenge_id"])
    operation_id = _identifier(value["operation_id"])
    if any(
        type(value[field]) is not int or value[field] <= 0
        for field in ("company_id", "requester_user_id")
    ):
        raise ApprovalClientError("approval response view is invalid")
    if any(
        not isinstance(value[field], str) or _SHA256.fullmatch(value[field]) is None
        for field in ("operation_digest", "precheck_digest")
    ):
        raise ApprovalClientError("approval response view is invalid")
    issued_at, issued = _utc_timestamp(value["issued_at"])
    expires_at, expires = _utc_timestamp(value["expires_at"])
    state = value["state"]
    if expires <= issued or not isinstance(state, str) or state not in _VIEW_STATES:
        raise ApprovalClientError("approval response view is invalid")
    return {
        "capability_id": capability_id,
        "challenge_id": challenge_id,
        "company_id": value["company_id"],
        "expires_at": expires_at,
        "issued_at": issued_at,
        "operation_digest": value["operation_digest"],
        "operation_id": operation_id,
        "precheck_digest": value["precheck_digest"],
        "requester_user_id": value["requester_user_id"],
        "state": state,
    }


def _post_approval(
    settings: sessions._RootSettings,
    *,
    socket_path: str,
    route: str,
    handle: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    if route not in {
        _APPROVAL_REQUEST_PATH,
        _APPROVAL_INSPECT_PATH,
        _APPROVAL_DECIDE_PATH,
    }:
        raise ApprovalClientError("approval route is invalid")
    if not isinstance(handle, str) or sessions._HANDLE.fullmatch(handle) is None:
        raise ApprovalClientError("trusted session handle is invalid")
    if "session_handle" in payload:
        raise ApprovalClientError("approval request contains forbidden fields")
    body = sessions._json_bytes({"session_handle": handle, **payload})
    connection = sessions._UnixHTTPConnection(
        socket_path,
        settings.broker_uid,
        timeout_seconds=_APPROVAL_UDS_TIMEOUT_SECONDS,
    )
    try:
        response = sessions._send_fixed_post(
            connection,
            route,
            body,
            (
                ("Host", "odoo-approval-client"),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
            ),
        )
        sessions._validate_response_headers(
            response, max_bytes=sessions._MAX_RESPONSE_BYTES
        )
        value = sessions._read_response_json(
            response, max_bytes=sessions._MAX_RESPONSE_BYTES
        )
        return response.status, value
    except (sessions.SessionClientError, OSError, TimeoutError, http.client.HTTPException) as exc:
        raise ApprovalClientError("trusted approval service request failed") from exc
    finally:
        connection.close()


def _validated_response(
    status: int,
    value: object,
    *,
    response_field: str,
    expected_operation_id: str | None = None,
    expected_challenge_id: str | None = None,
    expected_state: str | None = None,
    expected_company_id: int | None = None,
    expected_requester_user_id: int | None = None,
    forbidden_requester_user_id: int | None = None,
) -> dict[str, Any]:
    if (
        status != 200
        or type(value) is not dict
        or set(value) != {"ok", response_field}
        or value.get("ok") is not True
    ):
        raise ApprovalClientError("trusted approval service response is invalid")
    view = _challenge_view(value[response_field])
    if expected_operation_id is not None and view["operation_id"] != expected_operation_id:
        raise ApprovalClientError("trusted approval service response is invalid")
    if expected_challenge_id is not None and view["challenge_id"] != expected_challenge_id:
        raise ApprovalClientError("trusted approval service response is invalid")
    if expected_state is not None and view["state"] != expected_state:
        raise ApprovalClientError("trusted approval service response is invalid")
    if expected_company_id is not None and view["company_id"] != expected_company_id:
        raise ApprovalClientError("trusted approval service response is invalid")
    if (
        expected_requester_user_id is not None
        and view["requester_user_id"] != expected_requester_user_id
    ):
        raise ApprovalClientError("trusted approval service response is invalid")
    if (
        forbidden_requester_user_id is not None
        and view["requester_user_id"] == forbidden_requester_user_id
    ):
        raise ApprovalClientError("trusted approval service response is invalid")
    return view


def _validated_inspection_response(
    status: int,
    value: object,
    *,
    expected_challenge_id: str,
    expected_company_id: int,
    forbidden_requester_user_id: int,
) -> dict[str, Any]:
    if (
        status != 200
        or type(value) is not dict
        or set(value) != {"ok", "inspection"}
        or value.get("ok") is not True
    ):
        raise ApprovalClientError("trusted approval service response is invalid")
    try:
        from .approval_wizard import _validated_inspection

        inspection = _validated_inspection(value["inspection"])
    except Exception as exc:
        raise ApprovalClientError(
            "trusted approval service response is invalid"
        ) from exc
    challenge = inspection["challenge"]
    operation = inspection["operation"]
    if (
        challenge["challenge_id"] != expected_challenge_id
        or operation["company_id"] != expected_company_id
        or operation["user_id"] == forbidden_requester_user_id
    ):
        raise ApprovalClientError("trusted approval service response is invalid")
    return inspection


class OdooAccountingCliV3ApprovalClient(models.AbstractModel):
    _name = "odoo.accounting.cli.v3.approval.client"
    _description = "Private Odoo Accounting CLI V3 Approval Client"

    def _identity(self, settings: sessions._RootSettings) -> dict[str, Any]:
        issuer = self.env["odoo.accounting.cli.v3.session.client"]
        release = sessions.verify_addon_release(sessions.__file__)
        return issuer._trusted_identity_payload(settings, release)

    def _call_with_session(
        self,
        *,
        route: str,
        payload: dict[str, Any],
        response_field: str,
        expected_operation_id: str | None = None,
        expected_challenge_id: str | None = None,
        expected_state: str | None = None,
        require_requester_identity: bool = False,
        forbid_requester_identity: bool = False,
        inspection_response: bool = False,
    ) -> dict[str, Any]:
        handle: str | None = None
        settings: sessions._RootSettings | None = None
        result: dict[str, Any] | None = None
        failed = False
        revoke_failed = False
        try:
            settings = sessions._root_settings()
            socket_path = _approval_socket_path()
            identity = self._identity(settings)
            mint_status, mint_value = sessions._post_uds_json(
                settings, sessions._MINT_PATH, identity
            )
            handle = sessions._candidate_handle(mint_status, mint_value)
            handle = sessions._validated_mint_handle(mint_status, mint_value)
            status, value = _post_approval(
                settings,
                socket_path=socket_path,
                route=route,
                handle=handle,
                payload=payload,
            )
            if inspection_response:
                if expected_challenge_id is None or not forbid_requester_identity:
                    raise ApprovalClientError(
                        "trusted approval inspection binding is invalid"
                    )
                result = _validated_inspection_response(
                    status,
                    value,
                    expected_challenge_id=expected_challenge_id,
                    expected_company_id=identity["company_id"],
                    forbidden_requester_user_id=identity["user_id"],
                )
            else:
                result = _validated_response(
                    status,
                    value,
                    response_field=response_field,
                    expected_operation_id=expected_operation_id,
                    expected_challenge_id=expected_challenge_id,
                    expected_state=expected_state,
                    expected_company_id=identity["company_id"],
                    expected_requester_user_id=(
                        identity["user_id"] if require_requester_identity else None
                    ),
                    forbidden_requester_user_id=(
                        identity["user_id"] if forbid_requester_identity else None
                    ),
                )
        except Exception:
            failed = True
        finally:
            if handle is not None and settings is not None:
                try:
                    revoke_status, revoke_value = sessions._post_uds_json(
                        settings,
                        sessions._REVOKE_PATH,
                        {"handle": handle},
                    )
                    sessions._validate_revoke_response(revoke_status, revoke_value)
                except Exception:
                    revoke_failed = True
        if failed or revoke_failed or result is None:
            raise UserError(
                "The V3 approval request could not be completed safely."
            ) from None
        return result

    @api.model
    def _odoo_v3_request_approval(self, payload: object) -> dict[str, Any]:
        """Create/reuse a challenge as its bound requester."""

        if not self.env.user.has_group(_EXECUTOR_GROUP):
            raise AccessError("Odoo Accounting CLI V3 executor access is required")
        try:
            request = _request_payload(payload)
        except ApprovalClientError:
            raise UserError("The V3 approval request was rejected.") from None
        return self._call_with_session(
            route=_APPROVAL_REQUEST_PATH,
            payload=request,
            response_field="challenge",
            expected_operation_id=request["operation_id"],
            require_requester_identity=True,
        )

    @api.model
    def _odoo_v3_decide_approval(self, payload: object) -> dict[str, Any]:
        """Approve or deny one challenge as an independent Odoo approver."""

        if not self.env.user.has_group(_APPROVER_GROUP):
            raise AccessError("Odoo Accounting CLI V3 approver access is required")
        try:
            decision = _decision_payload(payload)
        except ApprovalClientError:
            raise UserError("The V3 approval decision was rejected.") from None
        return self._call_with_session(
            route=_APPROVAL_DECIDE_PATH,
            payload=decision,
            response_field="decision",
            expected_challenge_id=decision["challenge_id"],
            expected_state=(
                "approved" if decision["decision"] == "approve" else "denied"
            ),
            forbid_requester_identity=True,
        )

    @api.model
    def _odoo_v3_inspect_approval(self, payload: object) -> dict[str, Any]:
        """Return one complete preview for the independently bound approver."""

        if self.env.su or not self.env.user.has_group(_APPROVER_GROUP):
            raise AccessError("Odoo Accounting CLI V3 approver access is required")
        try:
            inspection = _inspection_payload(payload)
        except ApprovalClientError:
            raise UserError("The V3 approval inspection was rejected.") from None
        return self._call_with_session(
            route=_APPROVAL_INSPECT_PATH,
            payload=inspection,
            response_field="inspection",
            expected_challenge_id=inspection["challenge_id"],
            forbid_requester_identity=True,
            inspection_response=True,
        )
