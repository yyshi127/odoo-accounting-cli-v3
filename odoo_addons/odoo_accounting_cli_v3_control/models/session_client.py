"""Private Odoo-to-Pi client with short-lived trusted-session lifecycle."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import stat
import struct
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any

from odoo import api, models
from odoo.exceptions import AccessError, UserError

from .release_binding import VerifiedAddonRelease, verify_addon_release


_MINT_PATH = "/v1/trusted-session/mint"
_RESULT_DELIVERY_MINT_PATH = "/v1/trusted-session/result-delivery/mint"
_REVOKE_PATH = "/v1/trusted-session/revoke"
_CHAT_PATH = "/chat"
_SESSION_HEADER = "X-Odoo-V3-Broker-Session"
_RESULT_DELIVERY_SESSION_HEADER = "X-Odoo-V3-Result-Delivery-Session"
_EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
# Server phases are bounded at 5 seconds preflight, 120 seconds child work, and
# 10 seconds parent-only result delivery.  The Odoo HTTP deadline leaves a
# 15-second transport margin, while a 170-second session lifetime also covers
# the second mint call before /chat.  The deployed root configuration is 180s.
_SESSION_UDS_TIMEOUT_SECONDS = 10.0
_PI_SERVER_TOTAL_BUDGET_SECONDS = 135.0
_PI_TIMEOUT_SECONDS = 150.0
_MIN_CHAT_SESSION_TTL_SECONDS = 170.0
_SESSION_CLOCK_SKEW_SECONDS = 5.0
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_HANDLE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SOCKET_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_CONTENT_LENGTH = re.compile(r"(?:0|[1-9][0-9]{0,6})\Z")
_PEER_CREDENTIAL_FORMAT = "iII"
_PEER_CREDENTIAL_SIZE = struct.calcsize(_PEER_CREDENTIAL_FORMAT)


class SessionClientError(RuntimeError):
    """A local credential or Pi exchange failed without exposing its secret."""


@dataclass(frozen=True)
class _RootSettings:
    instance_id: str
    environment: str
    mint_socket_path: str
    pi_bridge_port: int
    broker_uid: int


@dataclass(frozen=True)
class _MintedSession:
    handle: str
    session_id: str
    issued_at: datetime
    expires_at: datetime
    max_uses: int


def _required_root_value(name: str) -> str:
    value = os.environ.get(name)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    return value


def _root_settings() -> _RootSettings:
    """Read only process environment injected by the root service launcher."""

    instance_id = _required_root_value("ODOO_V3_INSTANCE_ID")
    environment = _required_root_value("ODOO_V3_ENVIRONMENT")
    mint_socket_path = _required_root_value("ODOO_V3_SESSION_MINT_SOCKET")
    port_text = _required_root_value("ODOO_V3_PI_BRIDGE_PORT")
    broker_uid_text = _required_root_value("ODOO_V3_BROKER_UID")
    if _IDENTIFIER.fullmatch(instance_id) is None:
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    if environment not in {"test", "sandbox", "production"}:
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    parsed = PurePosixPath(mint_socket_path)
    if (
        _SOCKET_PATH.fullmatch(mint_socket_path) is None
        or not parsed.is_absolute()
        or mint_socket_path.startswith("//")
        or str(parsed) != mint_socket_path
        or any(part in {".", ".."} for part in parsed.parts)
        or not parsed.name.endswith(".sock")
        or len(mint_socket_path.encode("ascii", errors="ignore")) > 107
        or not mint_socket_path.isascii()
    ):
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    try:
        pi_bridge_port = int(port_text)
    except ValueError as exc:
        raise SessionClientError(
            "root-injected Odoo V3 configuration is invalid"
        ) from exc
    if str(pi_bridge_port) != port_text or not 1 <= pi_bridge_port <= 65535:
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    try:
        broker_uid = int(broker_uid_text)
    except ValueError as exc:
        raise SessionClientError(
            "root-injected Odoo V3 configuration is invalid"
        ) from exc
    if (
        str(broker_uid) != broker_uid_text
        or not 1 <= broker_uid <= 2**32 - 2
    ):
        raise SessionClientError("root-injected Odoo V3 configuration is invalid")
    current_uid = os.geteuid() if hasattr(os, "geteuid") else None
    if current_uid is not None and broker_uid == current_uid:
        raise SessionClientError(
            "root-injected broker UID must differ from the Odoo process UID"
        )
    return _RootSettings(
        instance_id=instance_id,
        environment=environment,
        mint_socket_path=mint_socket_path,
        pi_bridge_port=pi_bridge_port,
        broker_uid=broker_uid,
    )


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise SessionClientError("local service returned invalid JSON")
        value[key] = child
    return value


def _reject_constant(_value: str) -> Any:
    raise SessionClientError("local service returned invalid JSON")


def _json_bytes(value: object) -> bytes:
    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise SessionClientError("local request JSON is invalid") from exc
    if len(body) > _MAX_REQUEST_BYTES:
        raise SessionClientError("local request is too large")
    return body


def _read_response_json(response: Any, *, max_bytes: int) -> dict[str, Any]:
    try:
        body = response.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise SessionClientError("local service response could not be read") from exc
    if not isinstance(body, bytes) or len(body) > max_bytes:
        raise SessionClientError("local service response is too large")
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise SessionClientError("local service returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise SessionClientError("local service returned invalid JSON")
    return value


def _validate_response_headers(response: Any, *, max_bytes: int) -> None:
    headers = response.headers
    content_types = headers.get_all("Content-Type", failobj=[])
    content_lengths = headers.get_all("Content-Length", failobj=[])
    if (
        len(content_types) != 1
        or content_types[0]
        not in {"application/json", "application/json; charset=utf-8"}
        or len(content_lengths) != 1
        or not isinstance(content_lengths[0], str)
        or _CONTENT_LENGTH.fullmatch(content_lengths[0]) is None
        or not 0 <= int(content_lengths[0]) <= max_bytes
        or headers.get_all("Transfer-Encoding", failobj=[])
        or headers.get_all("Content-Encoding", failobj=[])
    ):
        raise SessionClientError("local service response headers are invalid")


def _validate_mint_socket(path: str) -> None:
    if (
        sys.platform != "linux"
        or os.name != "posix"
        or not hasattr(socket, "AF_UNIX")
    ):
        raise SessionClientError("trusted session mint requires Linux UDS")
    try:
        parent_path = str(PurePosixPath(path).parent)
        parent = os.lstat(parent_path)
        target = os.lstat(path)
    except OSError as exc:
        raise SessionClientError("trusted session mint socket is unavailable") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) & 0o022
        or os.path.realpath(parent_path) != parent_path
        or not stat.S_ISSOCK(target.st_mode)
        or target.st_uid != 0
        or stat.S_IMODE(target.st_mode) & 0o007
    ):
        raise SessionClientError("trusted session mint socket is not secure")


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        path: str,
        expected_peer_uid: int,
        *,
        timeout_seconds: float,
    ) -> None:
        super().__init__("localhost", timeout=timeout_seconds)
        self._unix_path = path
        self._expected_peer_uid = expected_peer_uid
        self._timeout_seconds = timeout_seconds

    def connect(self) -> None:
        _validate_mint_socket(self._unix_path)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self._timeout_seconds)
            connection.connect(self._unix_path)
            if not hasattr(socket, "SO_PEERCRED"):
                raise SessionClientError("trusted session mint requires SO_PEERCRED")
            raw = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                _PEER_CREDENTIAL_SIZE,
            )
            if len(raw) != _PEER_CREDENTIAL_SIZE:
                raise SessionClientError("trusted session mint peer is invalid")
            pid, uid, gid = struct.unpack(_PEER_CREDENTIAL_FORMAT, raw)
            if pid <= 0 or uid != self._expected_peer_uid or gid < 0:
                raise SessionClientError(
                    "trusted session mint peer does not match configured broker UID"
                )
        except Exception:
            connection.close()
            raise
        self.sock = connection


def _send_fixed_post(
    connection: http.client.HTTPConnection,
    route: str,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
) -> Any:
    connection.putrequest(
        "POST",
        route,
        skip_host=True,
        skip_accept_encoding=True,
    )
    for name, value in headers:
        connection.putheader(name, value)
    connection.endheaders(body)
    return connection.getresponse()


def _post_uds_json(
    settings: _RootSettings,
    route: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    if route not in {_MINT_PATH, _RESULT_DELIVERY_MINT_PATH, _REVOKE_PATH}:
        raise SessionClientError("trusted session route is invalid")
    body = _json_bytes(payload)
    connection = _UnixHTTPConnection(
        settings.mint_socket_path,
        settings.broker_uid,
        timeout_seconds=_SESSION_UDS_TIMEOUT_SECONDS,
    )
    try:
        response = _send_fixed_post(
            connection,
            route,
            body,
            (
                ("Host", "odoo-session-issuer"),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
            ),
        )
        _validate_response_headers(response, max_bytes=_MAX_RESPONSE_BYTES)
        value = _read_response_json(response, max_bytes=_MAX_RESPONSE_BYTES)
        return response.status, value
    except SessionClientError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise SessionClientError("trusted session service request failed") from exc
    finally:
        connection.close()


def _post_pi_chat(
    settings: _RootSettings,
    payload: dict[str, Any],
    handle: str,
    result_delivery_handle: str,
) -> str:
    if (
        _HANDLE.fullmatch(handle) is None
        or _HANDLE.fullmatch(result_delivery_handle) is None
        or handle == result_delivery_handle
    ):
        raise SessionClientError("trusted session handles are invalid")
    body = _json_bytes(payload)
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        settings.pi_bridge_port,
        timeout=_PI_TIMEOUT_SECONDS,
    )
    try:
        response = _send_fixed_post(
            connection,
            _CHAT_PATH,
            body,
            (
                ("Host", "odoo-v3-pi-bridge"),
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                (_SESSION_HEADER, handle),
                (_RESULT_DELIVERY_SESSION_HEADER, result_delivery_handle),
                ("Connection", "close"),
            ),
        )
        _validate_response_headers(response, max_bytes=_MAX_RESPONSE_BYTES)
        value = _read_response_json(response, max_bytes=_MAX_RESPONSE_BYTES)
    except SessionClientError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise SessionClientError("Pi Bridge request failed") from exc
    finally:
        connection.close()
    answer = value.get("answer")
    try:
        answer_bytes = len(answer.encode("utf-8")) if isinstance(answer, str) else 0
    except UnicodeEncodeError:
        answer_bytes = _MAX_RESPONSE_BYTES + 1
    if (
        response.status != 200
        or set(value) != {"ok", "answer"}
        or value.get("ok") is not True
        or not isinstance(answer, str)
        or answer_bytes > _MAX_RESPONSE_BYTES
        or handle in answer
        or result_delivery_handle in answer
    ):
        raise SessionClientError("Pi Bridge returned an invalid response")
    return answer


def _validate_chat_payload(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"message"}:
        raise SessionClientError("business request contains forbidden fields")
    message = payload["message"]
    try:
        encoded_length = len(message.encode("utf-8")) if isinstance(message, str) else 0
    except UnicodeEncodeError as exc:
        raise SessionClientError("business request is invalid") from exc
    if (
        not isinstance(message, str)
        or not message.strip()
        or encoded_length > _MAX_REQUEST_BYTES // 2
        or "\x00" in message
    ):
        raise SessionClientError("business request is invalid")
    return {"message": message}


def _candidate_handle(status: int, value: object) -> str | None:
    del status
    if not isinstance(value, dict):
        return None
    session = value.get("session")
    if not isinstance(session, dict):
        return None
    handle = session.get("handle")
    if isinstance(handle, str) and _HANDLE.fullmatch(handle):
        return handle
    return None


def _validated_mint_handle(status: int, value: object) -> str:
    if (
        status != 201
        or not isinstance(value, dict)
        or set(value) != {"ok", "session"}
        or value.get("ok") is not True
        or not isinstance(value.get("session"), dict)
    ):
        raise SessionClientError("trusted session mint response is invalid")
    session = value["session"]
    if set(session) != {
        "handle",
        "session_id",
        "issued_at",
        "expires_at",
        "max_uses",
    }:
        raise SessionClientError("trusted session mint response is invalid")
    handle = session["handle"]
    try:
        session_id = str(uuid.UUID(session["session_id"]))
        issued_at = datetime.fromisoformat(session["issued_at"])
        expires_at = datetime.fromisoformat(session["expires_at"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise SessionClientError("trusted session mint response is invalid") from exc
    if (
        not isinstance(handle, str)
        or _HANDLE.fullmatch(handle) is None
        or session_id != session["session_id"]
        or issued_at.tzinfo is None
        or issued_at.utcoffset() is None
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(hours=1)
        or not isinstance(session["max_uses"], int)
        or isinstance(session["max_uses"], bool)
        or not 16 <= session["max_uses"] <= 64
    ):
        raise SessionClientError("trusted session mint response is invalid")
    return handle


def _validated_chat_mint_session(
    status: int,
    value: object,
    *,
    expected_max_uses: int | None,
) -> _MintedSession:
    if (
        status != 201
        or not isinstance(value, dict)
        or set(value) != {"ok", "session"}
        or value.get("ok") is not True
        or not isinstance(value.get("session"), dict)
    ):
        raise SessionClientError("trusted session mint response is invalid")
    session = value["session"]
    if set(session) != {
        "handle",
        "session_id",
        "issued_at",
        "expires_at",
        "max_uses",
    }:
        raise SessionClientError("trusted session mint response is invalid")
    handle = session["handle"]
    try:
        session_id = str(uuid.UUID(session["session_id"]))
        issued_at = datetime.fromisoformat(session["issued_at"])
        expires_at = datetime.fromisoformat(session["expires_at"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise SessionClientError("trusted session mint response is invalid") from exc
    now = datetime.now(timezone.utc)
    max_uses = session["max_uses"]
    valid_use_budget = type(max_uses) is int and (
        max_uses == expected_max_uses
        if expected_max_uses is not None
        else 16 <= max_uses <= 64
    )
    if (
        not isinstance(handle, str)
        or _HANDLE.fullmatch(handle) is None
        or session_id != session["session_id"]
        or issued_at.tzinfo is None
        or issued_at.utcoffset() is None
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or issued_at > now + timedelta(seconds=_SESSION_CLOCK_SKEW_SECONDS)
        or expires_at <= now + timedelta(seconds=_PI_TIMEOUT_SECONDS)
        or expires_at - issued_at
        < timedelta(seconds=_MIN_CHAT_SESSION_TTL_SECONDS)
        or expires_at - issued_at > timedelta(hours=1)
        or not valid_use_budget
    ):
        raise SessionClientError("trusted session mint response is invalid")
    return _MintedSession(
        handle=handle,
        session_id=session_id,
        issued_at=issued_at,
        expires_at=expires_at,
        max_uses=max_uses,
    )


def _validate_revoke_response(status: int, value: object) -> None:
    if status != 200 or value != {"ok": True, "revoked": True}:
        raise SessionClientError("trusted session revoke response is invalid")


class OdooAccountingCliV3SessionClient(models.AbstractModel):
    _name = "odoo.accounting.cli.v3.session.client"
    _description = "Private Odoo Accounting CLI V3 Session Client"

    def _trusted_identity_payload(
        self,
        settings: _RootSettings,
        release: VerifiedAddonRelease,
    ) -> dict[str, Any]:
        env = self.env
        database_name = env.cr.dbname
        user_id = env.user.id
        company_id = env.company.id
        allowed_company_ids = sorted(env.companies.ids)
        database_uuid = (
            env["ir.config_parameter"].sudo().get_param("database.uuid")
        )
        try:
            normalized_database_uuid = str(uuid.UUID(database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise SessionClientError("current Odoo identity is invalid") from exc
        if (
            type(release) is not VerifiedAddonRelease
            or not isinstance(database_name, str)
            or not database_name
            or len(database_name) > 512
            or type(user_id) is not int
            or user_id <= 0
            or type(company_id) is not int
            or company_id <= 0
            or not allowed_company_ids
            or any(
                type(allowed) is not int or allowed <= 0
                for allowed in allowed_company_ids
            )
            or len(set(allowed_company_ids)) != len(allowed_company_ids)
            or company_id not in allowed_company_ids
            or database_uuid != normalized_database_uuid
        ):
            raise SessionClientError("current Odoo identity is invalid")
        return {
            "principal": f"odoo:user:{user_id}",
            "odoo_instance_id": settings.instance_id,
            "database_name": database_name,
            "database_uuid": database_uuid,
            "user_id": user_id,
            "company_id": company_id,
            "allowed_company_ids": allowed_company_ids,
            "environment": settings.environment,
            "release_digest": release.release_digest,
            "registry_digest": release.registry_digest,
        }

    @api.model
    def _odoo_v3_chat(self, payload: object) -> str:
        """Private model call; never expose this as an unauthenticated route."""

        if not self.env.user.has_group(_EXECUTOR_GROUP):
            raise AccessError("Odoo Accounting CLI V3 executor access is required")
        try:
            chat_payload = _validate_chat_payload(payload)
        except SessionClientError:
            raise UserError("The V3 business request was rejected.") from None
        acquired_handles: list[str] = []
        settings: _RootSettings | None = None
        primary_error = False
        revoke_error = False
        answer: str | None = None
        try:
            settings = _root_settings()
            release = verify_addon_release(__file__)
            identity = self._trusted_identity_payload(settings, release)
            mint_status, mint_value = _post_uds_json(settings, _MINT_PATH, identity)
            candidate = _candidate_handle(mint_status, mint_value)
            if candidate is not None:
                acquired_handles.append(candidate)
            ordinary = _validated_chat_mint_session(
                mint_status,
                mint_value,
                expected_max_uses=None,
            )
            delivery_status, delivery_value = _post_uds_json(
                settings,
                _RESULT_DELIVERY_MINT_PATH,
                identity,
            )
            delivery_candidate = _candidate_handle(
                delivery_status,
                delivery_value,
            )
            if delivery_candidate is not None:
                acquired_handles.append(delivery_candidate)
            delivery = _validated_chat_mint_session(
                delivery_status,
                delivery_value,
                expected_max_uses=1,
            )
            if (
                ordinary.handle == delivery.handle
                or ordinary.session_id == delivery.session_id
            ):
                raise SessionClientError("trusted sessions are not independent")
            answer = _post_pi_chat(
                settings,
                chat_payload,
                ordinary.handle,
                delivery.handle,
            )
        except Exception:
            primary_error = True
        finally:
            for handle in reversed(acquired_handles):
                try:
                    if settings is None:
                        raise SessionClientError("trusted session settings are absent")
                    revoke_status, revoke_value = _post_uds_json(
                        settings,
                        _REVOKE_PATH,
                        {"handle": handle},
                    )
                    _validate_revoke_response(revoke_status, revoke_value)
                except Exception:
                    revoke_error = True
        if primary_error or revoke_error or answer is None:
            raise UserError(
                "The V3 accounting request could not be completed safely."
            ) from None
        return answer
