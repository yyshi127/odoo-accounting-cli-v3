"""Connected-FD-only Unix transport for the isolated effect finalizer.

Only the long-lived broker adapter may connect by pathname.  A canonical CLI
child receives an already-connected descriptor, duplicates it CLOEXEC, and
uses it once.  The Odoo grandchild inherits only explicitly passed payload
descriptors, so this finalizer channel is not part of its authority.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .effect_finalizer import (
    EFFECT_FINALIZATION_PROTOCOL_VERSION,
    EffectFinalizationError,
    EffectFinalizationIdentity,
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    validate_effect_finalization_evidence,
)
from .effect_finalizer_service import (
    EffectFinalizerService,
    FinalizedEffect,
    effect_finalization_intent_from_mapping,
)
from .operations import canonical_json


class EffectFinalizerUdsError(RuntimeError):
    """The finalizer peer, frame, or response was rejected."""


EFFECT_FINALIZER_UDS_PROTOCOL_VERSION = 1
_UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")
_REQUEST_FIELDS = frozenset({"protocol", "intent_digest", "intent"})
_RESPONSE_FIELDS = frozenset(
    {"protocol", "ok", "intent_digest", "request", "receipt"}
)
_ERROR_FIELDS = frozenset({"protocol", "ok", "error"})
_RECEIPT_FIELDS = frozenset(
    {
        "request_digest",
        "intent_digest",
        "attestation_id",
        "attestation_digest",
        "attestation_key_id",
        "guard_installation_id",
        "database_oid",
        "database_uuid",
        "operation_id",
        "resolution_operation_id",
        "resolution_kind",
        "resolved_anchor_count",
        "remaining_unresolved_count",
        "guard_epoch",
        "proof_verified_at",
        "proof_expires_at",
        "finalized_at",
        "finalized_txid",
        "replayed",
    }
)
_SYSTEMCTL_PATH = Path("/usr/bin/systemctl")
_LINUX_SCM_AVAILABLE = sys.platform == "linux" and os.name == "posix"


@dataclass(frozen=True)
class EffectFinalizerPeerCredentials:
    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.pid, self.uid, self.gid)
        ) or self.pid <= 1:
            raise EffectFinalizerUdsError("Linux peer credentials are invalid")


PeerPolicy = Callable[[EffectFinalizerPeerCredentials], bool]
PeerCredentialsReader = Callable[[socket.socket], EffectFinalizerPeerCredentials]
CredentialedChunkReceiver = Callable[
    [socket.socket, int],
    tuple[bytes, EffectFinalizerPeerCredentials | None],
]


def read_linux_peer_credentials(
    connection: socket.socket,
) -> EffectFinalizerPeerCredentials:
    if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
        raise EffectFinalizerUdsError("Linux SO_PEERCRED is unavailable")
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", raw)
        return EffectFinalizerPeerCredentials(pid=pid, uid=uid, gid=gid)
    except (OSError, struct.error, ValueError) as exc:
        raise EffectFinalizerUdsError(
            "Linux peer credentials are unavailable"
        ) from exc


def receive_linux_credentialed_chunk(
    connection: socket.socket,
    maximum: int,
) -> tuple[bytes, EffectFinalizerPeerCredentials | None]:
    """Receive one stream chunk and authenticate its actual sending process."""

    credential_size = struct.calcsize("3i")
    if (
        not _LINUX_SCM_AVAILABLE
        or not hasattr(socket, "SCM_CREDENTIALS")
        or not hasattr(socket, "SO_PASSCRED")
        or not hasattr(connection, "recvmsg")
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum <= 0
    ):
        raise EffectFinalizerUdsError("Linux response credentials are unavailable")
    rights_item_size = struct.calcsize("i")
    ancillary_size = socket.CMSG_SPACE(credential_size)
    if hasattr(socket, "SCM_RIGHTS"):
        ancillary_size += socket.CMSG_SPACE(rights_item_size * 16)
    try:
        chunk, ancillary, flags, _address = connection.recvmsg(
            maximum,
            ancillary_size,
            getattr(socket, "MSG_CMSG_CLOEXEC", 0),
        )
    except (OSError, socket.timeout) as exc:
        raise EffectFinalizerUdsError(
            "finalizer credentialed response receive failed"
        ) from exc
    rights_seen = False
    for level, kind, payload in ancillary:
        if (
            level == socket.SOL_SOCKET
            and hasattr(socket, "SCM_RIGHTS")
            and kind == socket.SCM_RIGHTS
        ):
            rights_seen = True
            if len(payload) % rights_item_size == 0:
                for offset in range(0, len(payload), rights_item_size):
                    try:
                        os.close(
                            struct.unpack(
                                "i", payload[offset : offset + rights_item_size]
                            )[0]
                        )
                    except (OSError, struct.error):
                        pass
    if flags & (
        getattr(socket, "MSG_CTRUNC", 0) | getattr(socket, "MSG_TRUNC", 0)
    ):
        raise EffectFinalizerUdsError(
            "finalizer response credentials were truncated"
        )
    if rights_seen:
        raise EffectFinalizerUdsError(
            "finalizer response descriptor injection was rejected"
        )
    credentials: list[EffectFinalizerPeerCredentials] = []
    for level, kind, payload in ancillary:
        if (
            level == socket.SOL_SOCKET
            and hasattr(socket, "SCM_RIGHTS")
            and kind == socket.SCM_RIGHTS
        ):
            raise EffectFinalizerUdsError(
                "finalizer response descriptor injection was rejected"
            )
        if (
            level != socket.SOL_SOCKET
            or kind != socket.SCM_CREDENTIALS
            or len(payload) != credential_size
        ):
            raise EffectFinalizerUdsError(
                "finalizer response ancillary data is invalid"
            )
        try:
            pid, uid, gid = struct.unpack("3i", payload)
            credentials.append(
                EffectFinalizerPeerCredentials(pid=pid, uid=uid, gid=gid)
            )
        except (struct.error, ValueError) as exc:
            raise EffectFinalizerUdsError(
                "finalizer response credentials are invalid"
            ) from exc
    if not chunk:
        if credentials:
            raise EffectFinalizerUdsError(
                "finalizer response EOF credentials are invalid"
            )
        return b"", None
    if len(credentials) > 1:
        raise EffectFinalizerUdsError(
            "finalizer response credentials are ambiguous"
        )
    return chunk, credentials[0] if credentials else None


def resolve_systemd_main_pid(
    systemd_unit: str, *, systemctl_path: Path = _SYSTEMCTL_PATH
) -> int:
    """Ask PID 1 for one unit's current MainPID using fixed, non-shell argv."""

    if (
        not isinstance(systemd_unit, str)
        or _UNIT_NAME.fullmatch(systemd_unit) is None
        or not isinstance(systemctl_path, Path)
        or not systemctl_path.is_absolute()
    ):
        raise EffectFinalizerUdsError("systemd main-PID query is invalid")
    try:
        metadata = systemctl_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or systemctl_path.is_symlink()
            or systemctl_path.resolve(strict=True) != systemctl_path
            or (os.name == "posix" and metadata.st_uid != 0)
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise EffectFinalizerUdsError("systemctl executable is untrusted")
        completed = subprocess.run(
            [
                str(systemctl_path),
                "show",
                "--property=MainPID",
                "--value",
                "--",
                systemd_unit,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1.0,
            check=False,
            shell=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except EffectFinalizerUdsError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise EffectFinalizerUdsError("systemd main PID is unavailable") from exc
    try:
        output = completed.stdout.decode("ascii")
        stderr = completed.stderr.decode("ascii")
        value = output.removesuffix("\n")
        pid = int(value)
    except (UnicodeError, ValueError) as exc:
        raise EffectFinalizerUdsError("systemd main PID is invalid") from exc
    if (
        completed.returncode != 0
        or stderr
        or not output.endswith("\n")
        or not value.isdecimal()
        or str(pid) != value
        or pid <= 1
    ):
        raise EffectFinalizerUdsError("systemd main PID is invalid")
    return pid


@dataclass(frozen=True)
class SystemdMainProcessPeerPolicy:
    """Require both the exact service UID and PID 1's current MainPID."""

    expected_uid: int
    systemd_unit: str
    expected_gid: int | None = None
    resolve_main_pid: Callable[[str], int] = resolve_systemd_main_pid

    def __post_init__(self) -> None:
        if (
            isinstance(self.expected_uid, bool)
            or not isinstance(self.expected_uid, int)
            or self.expected_uid <= 0
            or (
                self.expected_gid is not None
                and (
                    isinstance(self.expected_gid, bool)
                    or not isinstance(self.expected_gid, int)
                    or self.expected_gid <= 0
                )
            )
            or not isinstance(self.systemd_unit, str)
            or _UNIT_NAME.fullmatch(self.systemd_unit) is None
            or not callable(self.resolve_main_pid)
        ):
            raise EffectFinalizerUdsError("systemd peer policy is invalid")

    def __call__(self, peer: EffectFinalizerPeerCredentials) -> bool:
        if not isinstance(peer, EffectFinalizerPeerCredentials):
            return False
        if peer.uid != self.expected_uid or (
            self.expected_gid is not None and peer.gid != self.expected_gid
        ):
            return False
        try:
            main_pid = self.resolve_main_pid(self.systemd_unit)
        except Exception:
            return False
        return (
            isinstance(main_pid, int)
            and not isinstance(main_pid, bool)
            and main_pid == peer.pid
        )


def _strict_limits(
    timeout_seconds: float, max_request_bytes: int, max_response_bytes: int
) -> tuple[float, int, int]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0.05 <= float(timeout_seconds) <= 30.0
        or isinstance(max_request_bytes, bool)
        or not isinstance(max_request_bytes, int)
        or not 1024 <= max_request_bytes <= 65_536
        or isinstance(max_response_bytes, bool)
        or not isinstance(max_response_bytes, int)
        or not 1024 <= max_response_bytes <= 65_536
    ):
        raise EffectFinalizerUdsError("finalizer transport limits are invalid")
    return float(timeout_seconds), max_request_bytes, max_response_bytes


def _strict_handoff_idle_timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 90.0 <= float(value) <= 120.0
    ):
        raise EffectFinalizerUdsError(
            "finalizer handoff idle timeout is invalid"
        )
    return float(value)


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise EffectFinalizerUdsError(f"{label} frame is incomplete")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except EffectFinalizerUdsError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise EffectFinalizerUdsError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != raw:
        raise EffectFinalizerUdsError(f"{label} is not canonical")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EffectFinalizerUdsError("finalizer JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise EffectFinalizerUdsError("finalizer JSON contains a non-finite number")


def _receive_frame(
    connection: socket.socket,
    maximum: int,
    label: str,
    *,
    first_byte_timeout_seconds: float | None = None,
    io_timeout_seconds: float | None = None,
) -> dict[str, Any]:
    if (first_byte_timeout_seconds is None) != (io_timeout_seconds is None):
        raise EffectFinalizerUdsError(f"{label} timeout policy is invalid")
    if first_byte_timeout_seconds is not None:
        connection.settimeout(
            _strict_handoff_idle_timeout(first_byte_timeout_seconds)
        )
        io_timeout_seconds, _, _ = _strict_limits(
            io_timeout_seconds, 1024, 1024
        )
    chunks: list[bytes] = []
    total = 0
    first_chunk = True
    while True:
        try:
            chunk = connection.recv(min(4096, maximum + 1 - total))
        except (OSError, socket.timeout) as exc:
            raise EffectFinalizerUdsError(f"{label} receive failed") from exc
        if not chunk:
            raise EffectFinalizerUdsError(f"{label} closed before one frame")
        if first_chunk and io_timeout_seconds is not None:
            connection.settimeout(io_timeout_seconds)
        first_chunk = False
        newline = chunk.find(b"\n")
        if newline >= 0:
            total += newline + 1
            chunks.append(chunk[: newline + 1])
            if newline != len(chunk) - 1 or total > maximum:
                raise EffectFinalizerUdsError(f"{label} framing is invalid")
            return _strict_json(b"".join(chunks), label)
        total += len(chunk)
        if total >= maximum:
            raise EffectFinalizerUdsError(f"{label} is too large")
        chunks.append(chunk)


def _receive_credentialed_frame(
    connection: socket.socket,
    maximum: int,
    label: str,
    *,
    sender_policy: PeerPolicy,
    receive_chunk: CredentialedChunkReceiver,
) -> dict[str, Any]:
    if not callable(sender_policy) or not callable(receive_chunk):
        raise EffectFinalizerUdsError(
            "finalizer response credential policy is invalid"
        )
    chunks: list[bytes] = []
    total = 0
    observed_sender: EffectFinalizerPeerCredentials | None = None
    first_receive = True
    while True:
        try:
            chunk, sender = receive_chunk(
                connection,
                1 if first_receive else min(4096, maximum + 1 - total),
            )
        except EffectFinalizerUdsError:
            raise
        except (OSError, socket.timeout) as exc:
            raise EffectFinalizerUdsError(f"{label} receive failed") from exc
        if not chunk:
            raise EffectFinalizerUdsError(f"{label} closed before one frame")
        if first_receive:
            if (
                not isinstance(sender, EffectFinalizerPeerCredentials)
                or sender_policy(sender) is not True
            ):
                raise EffectFinalizerUdsError(
                    "finalizer response sender was rejected"
                )
            observed_sender = sender
            first_receive = False
        elif sender is not None and sender != observed_sender:
            raise EffectFinalizerUdsError(
                "finalizer response sender changed"
            )
        newline = chunk.find(b"\n")
        if newline >= 0:
            total += newline + 1
            chunks.append(chunk[: newline + 1])
            if newline != len(chunk) - 1 or total > maximum:
                raise EffectFinalizerUdsError(f"{label} framing is invalid")
            try:
                trailing, trailing_sender = receive_chunk(connection, 1)
            except EffectFinalizerUdsError:
                raise
            except (OSError, socket.timeout) as exc:
                raise EffectFinalizerUdsError(f"{label} receive failed") from exc
            if trailing or trailing_sender is not None:
                raise EffectFinalizerUdsError(f"{label} framing is invalid")
            return _strict_json(b"".join(chunks), label)
        total += len(chunk)
        if total >= maximum:
            raise EffectFinalizerUdsError(f"{label} is too large")
        chunks.append(chunk)


def _enable_linux_response_credentials(connection: socket.socket) -> None:
    if sys.platform != "linux" or os.name != "posix" or not hasattr(
        socket, "SO_PASSCRED"
    ):
        return
    try:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        if connection.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
            raise EffectFinalizerUdsError(
                "Linux response credentials were not enabled"
            )
    except EffectFinalizerUdsError:
        raise
    except OSError as exc:
        raise EffectFinalizerUdsError(
            "Linux response credentials could not be enabled"
        ) from exc


def _send_frame(connection: socket.socket, value: Mapping[str, Any], maximum: int) -> None:
    try:
        frame = canonical_json(dict(value)) + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EffectFinalizerUdsError("finalizer response is invalid") from exc
    if len(frame) > maximum:
        raise EffectFinalizerUdsError("finalizer response is too large")
    try:
        connection.sendall(frame)
    except (OSError, socket.timeout) as exc:
        raise EffectFinalizerUdsError("finalizer response send failed") from exc


def _utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EffectFinalizerUdsError("finalizer timestamp is invalid")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EffectFinalizerUdsError("finalizer timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EffectFinalizerUdsError("finalizer timestamp is invalid") from exc
    if _utc_text(parsed) != value:
        raise EffectFinalizerUdsError("finalizer timestamp is not canonical")
    return parsed.astimezone(timezone.utc)


def _request_from_payload(value: Any) -> EffectFinalizationRequest:
    if not isinstance(value, Mapping):
        raise EffectFinalizerUdsError("finalizer proof request is invalid")
    try:
        fields = dict(value)
        if fields.pop("protocol_version") != EFFECT_FINALIZATION_PROTOCOL_VERSION:
            raise EffectFinalizerUdsError("finalizer proof protocol is invalid")
        fields["verified_at"] = _parse_utc(fields["verified_at"])
        fields["expires_at"] = _parse_utc(fields["expires_at"])
        return EffectFinalizationRequest(**fields)
    except (KeyError, TypeError, EffectFinalizationError) as exc:
        raise EffectFinalizerUdsError("finalizer proof request is invalid") from exc


def _receipt_payload(receipt: EffectFinalizationReceipt) -> dict[str, Any]:
    return {
        "request_digest": receipt.request_digest,
        "intent_digest": receipt.intent_digest,
        "attestation_id": receipt.attestation_id,
        "attestation_digest": receipt.attestation_digest,
        "attestation_key_id": receipt.attestation_key_id,
        "guard_installation_id": receipt.guard_installation_id,
        "database_oid": receipt.database_oid,
        "database_uuid": receipt.database_uuid,
        "operation_id": receipt.operation_id,
        "resolution_operation_id": receipt.resolution_operation_id,
        "resolution_kind": receipt.resolution_kind,
        "resolved_anchor_count": receipt.resolved_anchor_count,
        "remaining_unresolved_count": receipt.remaining_unresolved_count,
        "guard_epoch": receipt.guard_epoch,
        "proof_verified_at": _utc_text(receipt.proof_verified_at),
        "proof_expires_at": _utc_text(receipt.proof_expires_at),
        "finalized_at": _utc_text(receipt.finalized_at),
        "finalized_txid": receipt.finalized_txid,
        "replayed": receipt.replayed,
    }


def _receipt_from_payload(
    value: Any,
    *,
    request: EffectFinalizationRequest,
    expected_identity: EffectFinalizationIdentity,
) -> EffectFinalizationReceipt:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise EffectFinalizerUdsError("finalizer receipt fields are invalid")
    try:
        receipt = EffectFinalizationReceipt(
            **{
                **dict(value),
                "proof_verified_at": _parse_utc(value["proof_verified_at"]),
                "proof_expires_at": _parse_utc(value["proof_expires_at"]),
                "finalized_at": _parse_utc(value["finalized_at"]),
            }
        )
        receipt.validate_for(request)
        validate_effect_finalization_evidence(
            receipt.evidence,
            intent=request.intent,
            expected_attestation_key_id=(
                expected_identity.attestation_key_id
            ),
            expected_guard_installation_id=(
                expected_identity.guard_installation_id
            ),
            expected_database_oid=expected_identity.database_oid,
        )
    except (TypeError, EffectFinalizationError) as exc:
        raise EffectFinalizerUdsError("finalizer receipt is invalid") from exc
    return receipt


class EffectFinalizerConnectedClient:
    """One-use client over an owned, connected, non-inheritable Unix FD."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        expected_identity: EffectFinalizationIdentity,
        response_sender_policy: PeerPolicy,
        request_io_timeout_seconds: float,
        max_request_bytes: int,
        max_response_bytes: int,
        receive_credentialed_chunk: CredentialedChunkReceiver = (
            receive_linux_credentialed_chunk
        ),
    ) -> None:
        limits = _strict_limits(
            request_io_timeout_seconds, max_request_bytes, max_response_bytes
        )
        if (
            not isinstance(connection, socket.socket)
            or not isinstance(expected_identity, EffectFinalizationIdentity)
            or not callable(response_sender_policy)
            or not callable(receive_credentialed_chunk)
        ):
            raise EffectFinalizerUdsError("connected finalizer client is invalid")
        _enable_linux_response_credentials(connection)
        self._connection = connection
        self._expected_identity = expected_identity
        self._response_sender_policy = response_sender_policy
        self._receive_credentialed_chunk = receive_credentialed_chunk
        (
            self._request_io_timeout_seconds,
            self._max_request_bytes,
            self._max_response_bytes,
        ) = limits
        self._used = False

    @classmethod
    def from_inherited_fd(
        cls,
        descriptor: int,
        *,
        expected_identity: EffectFinalizationIdentity,
        response_sender_policy: PeerPolicy,
        request_io_timeout_seconds: float,
        max_request_bytes: int,
        max_response_bytes: int,
        receive_credentialed_chunk: CredentialedChunkReceiver = (
            receive_linux_credentialed_chunk
        ),
    ) -> "EffectFinalizerConnectedClient":
        if (
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor <= 2
            or not callable(response_sender_policy)
            or not callable(receive_credentialed_chunk)
        ):
            raise EffectFinalizerUdsError("inherited finalizer descriptor is invalid")
        duplicate = -1
        connection = None
        try:
            if os.name == "nt":  # Local protocol tests; production is Linux.
                borrowed = socket.socket(fileno=descriptor)
                try:
                    connection = borrowed.dup()
                finally:
                    borrowed.close()
                connection.set_inheritable(False)
            else:
                try:
                    duplicate = os.dup(descriptor)
                finally:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                os.set_inheritable(duplicate, False)
                connection = socket.socket(fileno=duplicate)
                duplicate = -1
            if (
                connection.family != socket.AF_UNIX
                or connection.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            ):
                raise EffectFinalizerUdsError(
                    "inherited finalizer descriptor is not a Unix stream"
                )
            connection.getpeername()
            connection.settimeout(float(request_io_timeout_seconds))
            return cls(
                connection,
                expected_identity=expected_identity,
                response_sender_policy=response_sender_policy,
                request_io_timeout_seconds=request_io_timeout_seconds,
                max_request_bytes=max_request_bytes,
                max_response_bytes=max_response_bytes,
                receive_credentialed_chunk=receive_credentialed_chunk,
            )
        except EffectFinalizerUdsError:
            if connection is not None:
                connection.close()
            if duplicate >= 0:
                os.close(duplicate)
            raise
        except OSError as exc:
            if connection is not None:
                connection.close()
            if duplicate >= 0:
                os.close(duplicate)
            raise EffectFinalizerUdsError(
                "inherited finalizer descriptor was rejected"
            ) from exc

    def fileno(self) -> int:
        return self._connection.fileno()

    def is_inheritable(self) -> bool:
        return self._connection.get_inheritable()

    def close(self) -> None:
        self._connection.close()

    def finalize(self, intent: EffectFinalizationIntent) -> EffectFinalizationReceipt:
        if self._used or not isinstance(intent, EffectFinalizationIntent):
            raise EffectFinalizerUdsError("connected finalizer client is not reusable")
        self._used = True
        _send_frame(
            self._connection,
            {
                "protocol": EFFECT_FINALIZER_UDS_PROTOCOL_VERSION,
                "intent_digest": intent.intent_digest,
                "intent": intent.payload(),
            },
            self._max_request_bytes,
        )
        try:
            self._connection.shutdown(socket.SHUT_WR)
        except OSError as exc:
            raise EffectFinalizerUdsError("finalizer request shutdown failed") from exc
        response = _receive_credentialed_frame(
            self._connection,
            self._max_response_bytes,
            "finalizer response",
            sender_policy=self._response_sender_policy,
            receive_chunk=self._receive_credentialed_chunk,
        )
        if set(response) == _ERROR_FIELDS:
            if response != {
                "protocol": EFFECT_FINALIZER_UDS_PROTOCOL_VERSION,
                "ok": False,
                "error": "effect_finalization_failed",
            }:
                raise EffectFinalizerUdsError("finalizer error response is invalid")
            raise EffectFinalizerUdsError("effect finalization failed")
        if (
            set(response) != _RESPONSE_FIELDS
            or response.get("protocol") != EFFECT_FINALIZER_UDS_PROTOCOL_VERSION
            or response.get("ok") is not True
            or response.get("intent_digest") != intent.intent_digest
        ):
            raise EffectFinalizerUdsError("finalizer response fields are invalid")
        request = _request_from_payload(response["request"])
        ttl = request.expires_at - request.verified_at
        if (
            ttl.total_seconds() != int(ttl.total_seconds())
            or not 0 < int(ttl.total_seconds()) <= 300
            or EffectFinalizationRequest.from_intent(
                intent,
                verified_at=request.verified_at,
                expires_at=request.expires_at,
            ) != request
        ):
            raise EffectFinalizerUdsError(
                "finalizer proof request differs from intent"
            )
        receipt = _receipt_from_payload(
            response["receipt"],
            request=request,
            expected_identity=self._expected_identity,
        )
        if receipt.request_digest != request.request_digest:
            raise EffectFinalizerUdsError("finalizer receipt request binding differs")
        return receipt


def serve_effect_finalizer_connection(
    connection: socket.socket,
    service: EffectFinalizerService,
    *,
    peer_policy: PeerPolicy,
    handoff_idle_timeout_seconds: float,
    request_io_timeout_seconds: float,
    max_request_bytes: int,
    max_response_bytes: int,
    peer_credentials_reader: PeerCredentialsReader = read_linux_peer_credentials,
) -> None:
    """Serve exactly one intent; errors are fixed and contain no request data."""

    request_io_timeout_seconds, max_request_bytes, max_response_bytes = _strict_limits(
        request_io_timeout_seconds, max_request_bytes, max_response_bytes
    )
    handoff_idle_timeout_seconds = _strict_handoff_idle_timeout(
        handoff_idle_timeout_seconds
    )
    if not isinstance(connection, socket.socket) or not callable(peer_policy):
        raise EffectFinalizerUdsError("finalizer server connection is invalid")
    try:
        connection.settimeout(handoff_idle_timeout_seconds)
        peer = peer_credentials_reader(connection)
        if not isinstance(peer, EffectFinalizerPeerCredentials) or peer_policy(peer) is not True:
            return
        try:
            request = _receive_frame(
                connection,
                max_request_bytes,
                "finalizer request",
                first_byte_timeout_seconds=handoff_idle_timeout_seconds,
                io_timeout_seconds=request_io_timeout_seconds,
            )
            if (
                set(request) != _REQUEST_FIELDS
                or request.get("protocol") != EFFECT_FINALIZER_UDS_PROTOCOL_VERSION
            ):
                raise EffectFinalizerUdsError("finalizer request fields are invalid")
            intent = effect_finalization_intent_from_mapping(request["intent"])
            if request.get("intent_digest") != intent.intent_digest:
                raise EffectFinalizerUdsError("finalizer intent digest differs")
            if not hasattr(service, "finalize_with_attempt"):
                raise EffectFinalizerUdsError("finalizer service is invalid")
            finalized = service.finalize_with_attempt(intent)
            if not isinstance(finalized, FinalizedEffect):
                raise EffectFinalizerUdsError("finalizer service result is invalid")
            _send_frame(
                connection,
                {
                    "protocol": EFFECT_FINALIZER_UDS_PROTOCOL_VERSION,
                    "ok": True,
                    "intent_digest": intent.intent_digest,
                    "request": finalized.request.payload(),
                    "receipt": _receipt_payload(finalized.receipt),
                },
                max_response_bytes,
            )
        except Exception:
            try:
                _send_frame(
                    connection,
                    {
                        "protocol": EFFECT_FINALIZER_UDS_PROTOCOL_VERSION,
                        "ok": False,
                        "error": "effect_finalization_failed",
                    },
                    max_response_bytes,
                )
            except Exception:
                pass
    finally:
        connection.close()


if hasattr(socketserver, "UnixStreamServer"):

    class _EffectFinalizerHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            serve_effect_finalizer_connection(
                self.request,
                self.server.finalizer_service,
                peer_policy=self.server.peer_policy,
                handoff_idle_timeout_seconds=(
                    self.server.runtime.uds.handoff_idle_timeout_seconds
                ),
                request_io_timeout_seconds=(
                    self.server.runtime.uds.request_io_timeout_seconds
                ),
                max_request_bytes=self.server.runtime.uds.max_request_bytes,
                max_response_bytes=self.server.runtime.uds.max_response_bytes,
            )


    class EffectFinalizerUnixServer(
        socketserver.ThreadingMixIn,
        socketserver.UnixStreamServer,
    ):
        daemon_threads = False
        block_on_close = True
        allow_reuse_address = False

        def __init__(
            self,
            runtime: Any,
            service: EffectFinalizerService,
            peer_policy: PeerPolicy,
        ) -> None:
            if not callable(peer_policy):
                raise EffectFinalizerUdsError("finalizer peer policy is invalid")
            self.runtime = runtime
            self.finalizer_service = service
            self.peer_policy = peer_policy
            self._capacity = threading.BoundedSemaphore(
                runtime.uds.max_inflight_requests
            )
            super().__init__(
                runtime.uds.socket_path,
                _EffectFinalizerHandler,
                bind_and_activate=False,
            )

        def verify_request(self, request: Any, client_address: Any) -> bool:
            return self._capacity.acquire(blocking=False)

        def process_request(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._capacity.release()
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._capacity.release()

        def handle_error(self, request: Any, client_address: Any) -> None:
            # Request content and tracebacks must never escape the service.
            return None

else:  # pragma: no cover - production service requires Linux AF_UNIX.

    class EffectFinalizerUnixServer:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise EffectFinalizerUdsError("Unix stream servers are unavailable")


def create_effect_finalizer_uds_server_from_fd(
    runtime: Any,
    service: EffectFinalizerService,
    descriptor: int,
    *,
    peer_policy: PeerPolicy | None = None,
) -> EffectFinalizerUnixServer:
    """Adopt one systemd socket only under the dedicated finalizer identity."""

    from .effect_finalizer_runtime import EffectFinalizerRuntimeConfig
    from .systemd_activation import adopt_activated_unix_server

    if (
        sys.platform != "linux"
        or os.name != "posix"
        or not isinstance(runtime, EffectFinalizerRuntimeConfig)
        or not isinstance(service, EffectFinalizerService)
        or os.geteuid() != runtime.service_uid
        or os.getegid() != runtime.service_gid
        or runtime.service_uid == 0
        or isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor <= 2
    ):
        raise EffectFinalizerUdsError(
            "activated finalizer server identity is invalid"
        )
    policy = peer_policy or SystemdMainProcessPeerPolicy(
        expected_uid=runtime.uds.broker_service_uid,
        systemd_unit=runtime.uds.broker_systemd_unit,
    )
    server = EffectFinalizerUnixServer(runtime, service, policy)
    try:
        adopt_activated_unix_server(
            server,
            descriptor,
            socket_path=runtime.uds.socket_path,
            expected_owner_uid=runtime.uds.socket_owner_uid,
            expected_group_gid=runtime.uds.socket_group_gid,
            expected_mode=runtime.uds.socket_mode,
        )
    except Exception as exc:
        try:
            server.server_close()
        except Exception:
            pass
        raise EffectFinalizerUdsError(
            "activated finalizer socket was rejected"
        ) from exc
    return server


def _validate_socket_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or current.is_symlink()
            or current.resolve(strict=True) != current
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise EffectFinalizerUdsError("finalizer socket ancestors are unsafe")
        if current.parent == current:
            return
        current = current.parent


def preconnect_effect_finalizer_socket(
    socket_path: str,
    *,
    expected_owner_uid: int,
    expected_group_gid: int,
    expected_mode: int,
    timeout_seconds: float,
) -> socket.socket:
    """Connect to a root-controlled listener; sender identity is checked later."""

    if os.name != "posix":
        raise EffectFinalizerUdsError("finalizer pathname preconnect requires POSIX")
    parsed = PurePosixPath(socket_path) if isinstance(socket_path, str) else None
    if (
        parsed is None
        or not parsed.is_absolute()
        or str(parsed) != socket_path
        or socket_path.startswith("//")
        or any(part in {".", ".."} for part in parsed.parts)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (expected_owner_uid, expected_group_gid, expected_mode)
        )
        or expected_mode & ~0o777
    ):
        raise EffectFinalizerUdsError("finalizer pathname preconnect is invalid")
    timeout_seconds, _, _ = _strict_limits(timeout_seconds, 1024, 1024)
    path = Path(socket_path)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _validate_socket_ancestors(path)
        before = path.lstat()
        if (
            not stat.S_ISSOCK(before.st_mode)
            or path.is_symlink()
            or before.st_uid != expected_owner_uid
            or before.st_gid != expected_group_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
        ):
            raise EffectFinalizerUdsError("finalizer socket metadata is invalid")
        connection.settimeout(timeout_seconds)
        connection.connect(socket_path)
        os.set_inheritable(connection.fileno(), False)
        _enable_linux_response_credentials(connection)
        after = path.lstat()
        if (
            path.is_symlink()
            or (before.st_dev, before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
            != (after.st_dev, after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode))
        ):
            raise EffectFinalizerUdsError("finalizer socket changed during connect")
        return connection
    except EffectFinalizerUdsError:
        connection.close()
        raise
    except OSError as exc:
        connection.close()
        raise EffectFinalizerUdsError("finalizer socket preconnect failed") from exc


__all__ = [
    "EFFECT_FINALIZER_UDS_PROTOCOL_VERSION",
    "EffectFinalizerConnectedClient",
    "EffectFinalizerPeerCredentials",
    "EffectFinalizerUnixServer",
    "EffectFinalizerUdsError",
    "SystemdMainProcessPeerPolicy",
    "create_effect_finalizer_uds_server_from_fd",
    "preconnect_effect_finalizer_socket",
    "read_linux_peer_credentials",
    "resolve_systemd_main_pid",
    "serve_effect_finalizer_connection",
]
