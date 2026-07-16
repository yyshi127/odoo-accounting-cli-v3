"""Strict systemd socket-activation descriptor intake."""

from __future__ import annotations

import os
import re
import socket
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable


SYSTEMD_FD_START = 3
PI_BROKER_SOCKET_NAME = "odoo-v3-pi-broker"
SESSION_MINT_SOCKET_NAME = "odoo-v3-session-mint"
TRUSTED_APPROVAL_SOCKET_NAME = "odoo-v3-trusted-approval"
BROKER_SOCKET_NAMES = frozenset(
    {
        PI_BROKER_SOCKET_NAME,
        SESSION_MINT_SOCKET_NAME,
        TRUSTED_APPROVAL_SOCKET_NAME,
    }
)
_FD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ACTIVATION_ENVIRONMENT = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")


class SystemdActivationError(RuntimeError):
    """Socket activation did not exactly match the immutable service contract."""


def _validate_ancestors(path: Path, *, require_root: bool) -> None:
    current = path.parent
    while True:
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or current.is_symlink()
            or metadata.st_mode & 0o022
            or (require_root and metadata.st_uid != 0)
        ):
            raise SystemdActivationError(
                "activated socket ancestors are not trusted"
            )
        if current.parent == current:
            return
        current = current.parent


def adopt_activated_unix_server(
    server: object,
    descriptor: int,
    *,
    socket_path: str,
    expected_owner_uid: int,
    expected_group_gid: int,
    expected_mode: int,
    require_root_ancestors: bool = True,
) -> object:
    """Replace one unbound socketserver socket with a verified listening FD."""

    if sys.platform != "linux" or os.name != "posix":
        raise SystemdActivationError("activated Unix servers require Linux")
    if (
        type(descriptor) is not int
        or descriptor < SYSTEMD_FD_START
        or type(socket_path) is not str
        or not socket_path.startswith("/")
        or "\x00" in socket_path
        or type(expected_owner_uid) is not int
        or expected_owner_uid < 0
        or type(expected_group_gid) is not int
        or expected_group_gid < 0
        or type(expected_mode) is not int
        or expected_mode & ~0o777
        or type(require_root_ancestors) is not bool
        or not hasattr(server, "socket")
    ):
        raise SystemdActivationError("activated Unix server arguments are invalid")
    parsed = PurePosixPath(socket_path)
    if (
        not parsed.is_absolute()
        or socket_path.startswith("//")
        or str(parsed) != socket_path
        or any(part in {".", ".."} for part in parsed.parts)
    ):
        raise SystemdActivationError("activated socket path is not canonical")
    path = Path(socket_path)
    candidate: socket.socket | None = None
    duplicate = -1
    try:
        _validate_ancestors(path, require_root=require_root_ancestors)
        before = path.lstat()
        # Linux exposes the bound pathname inode and the socket FD's kernel
        # (sockfs) inode in different namespaces, so they must not be compared.
        # The root-owned, non-writable ancestor chain prevents pathname
        # replacement; getsockname below binds the verified FD to the exact path.
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISSOCK(before.st_mode)
            or path.is_symlink()
            or not stat.S_ISSOCK(descriptor_stat.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_gid != expected_group_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
        ):
            raise SystemdActivationError(
                "activated socket path, owner, group, mode, or type differs"
            )
        duplicate = os.dup(descriptor)
        os.set_inheritable(duplicate, False)
        candidate = socket.socket(fileno=duplicate)
        duplicate = -1
        if (
            candidate.family != socket.AF_UNIX
            or candidate.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or candidate.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or candidate.getsockname() != socket_path
        ):
            raise SystemdActivationError(
                "activated descriptor is not the expected listening Unix stream"
            )
        after = path.lstat()
        if (
            path.is_symlink()
            or (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                stat.S_IMODE(before.st_mode),
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                after.st_gid,
                stat.S_IMODE(after.st_mode),
            )
        ):
            raise SystemdActivationError(
                "activated socket changed during adoption"
            )
        original = getattr(server, "socket")
        if not isinstance(original, socket.socket):
            raise SystemdActivationError("unbound server socket is invalid")
        original.close()
        setattr(server, "socket", candidate)
        candidate = None
        return server
    except SystemdActivationError:
        raise
    except OSError as exc:
        raise SystemdActivationError("activated Unix socket was rejected") from exc
    finally:
        if candidate is not None:
            candidate.close()
        if duplicate >= 0:
            os.close(duplicate)


def activated_socket_fds(
    expected_names: Iterable[str] = BROKER_SOCKET_NAMES,
    *,
    unset_environment: bool = True,
) -> dict[str, int]:
    """Return the exact named AF_UNIX descriptors passed to this process.

    Socket type/path/owner/mode and listening state remain the responsibility
    of each transport's ``create_*_server_from_fd`` verifier.
    """

    if sys.platform != "linux" or os.name != "posix":
        raise SystemdActivationError("systemd activation requires Linux")
    if type(unset_environment) is not bool:
        raise SystemdActivationError("activation options are invalid")
    try:
        names = tuple(expected_names)
    except TypeError as exc:
        raise SystemdActivationError("expected socket names are invalid") from exc
    if (
        not names
        or len(set(names)) != len(names)
        or any(type(name) is not str or _FD_NAME.fullmatch(name) is None for name in names)
    ):
        raise SystemdActivationError("expected socket names are invalid")
    try:
        listen_pid = os.environ["LISTEN_PID"]
        listen_fds = os.environ["LISTEN_FDS"]
        listen_names = os.environ["LISTEN_FDNAMES"]
        if (
            not listen_pid.isascii()
            or not listen_pid.isdecimal()
            or str(int(listen_pid)) != listen_pid
            or int(listen_pid) != os.getpid()
            or not listen_fds.isascii()
            or not listen_fds.isdecimal()
            or str(int(listen_fds)) != listen_fds
            or int(listen_fds) != len(names)
        ):
            raise SystemdActivationError("systemd activation identity is invalid")
        observed_names = tuple(listen_names.split(":"))
        if (
            len(observed_names) != len(names)
            or set(observed_names) != set(names)
            or len(set(observed_names)) != len(observed_names)
            or any(_FD_NAME.fullmatch(name) is None for name in observed_names)
        ):
            raise SystemdActivationError("systemd socket names are invalid")
        result = {
            name: SYSTEMD_FD_START + index
            for index, name in enumerate(observed_names)
        }
        for descriptor in result.values():
            metadata = os.fstat(descriptor)
            if not stat.S_ISSOCK(metadata.st_mode):
                raise SystemdActivationError(
                    "systemd passed a non-socket descriptor"
                )
        return result
    except SystemdActivationError:
        raise
    except (KeyError, OSError, ValueError) as exc:
        raise SystemdActivationError("systemd activation was rejected") from exc
    finally:
        if unset_environment:
            for name in _ACTIVATION_ENVIRONMENT:
                os.environ.pop(name, None)


__all__ = [
    "BROKER_SOCKET_NAMES",
    "PI_BROKER_SOCKET_NAME",
    "SESSION_MINT_SOCKET_NAME",
    "SYSTEMD_FD_START",
    "TRUSTED_APPROVAL_SOCKET_NAME",
    "SystemdActivationError",
    "adopt_activated_unix_server",
    "activated_socket_fds",
]
