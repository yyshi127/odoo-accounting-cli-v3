"""Verify purpose-bound SSHSIG signatures without exposing signing keys."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SSHSigError(ValueError):
    """Raised when an SSHSIG input or verification result is not trusted."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,254}$")
_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_ALLOWED_SIGNERS_BYTES = 64 * 1024
_MAX_REVOCATIONS_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 64 * 1024
_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 30.0
_SIGNATURE_HEADER = b"-----BEGIN SSH SIGNATURE-----"
_SIGNATURE_FOOTER = b"-----END SSH SIGNATURE-----"
VERIFICATION_REPORT_FIELDS = frozenset(
    {
        "algorithm",
        "allowed_signers_sha256",
        "message_sha256",
        "namespace",
        "principal",
        "public_key_sha256",
        "revocations_sha256",
        "signature_sha256",
        "ssh_keygen_sha256",
        "verification_boundary",
        "verified",
    }
)


@dataclass(frozen=True)
class _StableFile:
    path: Path
    descriptor: int
    raw: bytes
    sha256: str


def _is_supported_posix() -> bool:
    return (
        os.name == "posix"
        and sys.platform.startswith("linux")
        and Path("/proc/self/fd").is_dir()
    )


def _no_follow_flag() -> int:
    return int(getattr(os, "O_NOFOLLOW", 0))


def _root_managed_mode_is_safe(mode: int, *, directory: bool) -> bool:
    expected_type = stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)
    return (
        expected_type
        and stat.S_IMODE(mode) & (stat.S_IWGRP | stat.S_IWOTH) == 0
    )


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise SSHSigError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _fixed_path(value: Any, label: str) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError) as exc:
        raise SSHSigError(f"{label} must be an absolute path") from exc
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise SSHSigError(f"{label} must be an absolute canonical path")
    return path


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    stable_mode = (
        int(metadata.st_mode)
        if os.name == "posix"
        else int(stat.S_IFMT(metadata.st_mode))
    )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stable_mode,
        int(metadata.st_nlink),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _validate_posix_policy(path: Path, *, executable: bool) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise SSHSigError("SSHSIG trusted path cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise SSHSigError("SSHSIG trusted path must not contain a symbolic link")
        if metadata.st_uid != 0:
            raise SSHSigError("SSHSIG trusted path must be owned by root")
        is_directory = current != path
        if not _root_managed_mode_is_safe(
            metadata.st_mode,
            directory=is_directory,
        ):
            if current == path and not stat.S_ISREG(metadata.st_mode):
                raise SSHSigError("SSHSIG trusted file must be regular")
            if current != path and not stat.S_ISDIR(metadata.st_mode):
                raise SSHSigError("SSHSIG trusted parent must be a directory")
            raise SSHSigError(
                "SSHSIG trusted path must not be group- or world-writable"
            )
        if current == path:
            if executable and stat.S_IMODE(metadata.st_mode) & 0o111 == 0:
                raise SSHSigError("SSHSIG verifier is not executable")
        parent = current.parent
        if parent == current:
            break
        current = parent


def _read_stable_file(
    path: Path,
    *,
    maximum: int,
    label: str,
    executable: bool,
) -> _StableFile:
    _validate_posix_policy(path, executable=executable)
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise SSHSigError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise SSHSigError(f"{label} must be a regular non-link file")
    if before_path.st_nlink != 1:
        raise SSHSigError(f"{label} must have exactly one hard link")
    if before_path.st_size < 0 or before_path.st_size > maximum:
        raise SSHSigError(f"{label} exceeds its size limit")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= _no_follow_flag()
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SSHSigError(f"{label} cannot be opened safely") from exc
    try:
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or _stat_identity(before_fd) != _stat_identity(before_path)
        ):
            raise SSHSigError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise SSHSigError(f"{label} exceeds its size limit")
        after_fd = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        os.close(descriptor)
        raise SSHSigError(f"{label} cannot be read safely") from exc
    except BaseException:
        os.close(descriptor)
        raise
    identity = _stat_identity(before_fd)
    if (
        identity != _stat_identity(after_fd)
        or after_fd.st_size != total
    ):
        os.close(descriptor)
        raise SSHSigError(f"{label} changed while it was read")
    raw = b"".join(chunks)
    return _StableFile(
        path=path,
        descriptor=descriptor,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _read_pinned_file(
    value: Any,
    expected_sha256: Any,
    *,
    maximum: int,
    label: str,
    executable: bool = False,
) -> _StableFile:
    path = _fixed_path(value, f"{label} path")
    expected = _digest(expected_sha256, f"{label} digest")
    observed = _read_stable_file(
        path,
        maximum=maximum,
        label=label,
        executable=executable,
    )
    if not hmac.compare_digest(observed.sha256, expected):
        os.close(observed.descriptor)
        raise SSHSigError(f"{label} digest mismatch")
    return observed


def _ed25519_public_key(raw: bytes, principal: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SSHSigError("allowed signers must be canonical ASCII") from exc
    if not text.endswith("\n") or "\r" in text or text.count("\n") != 1:
        raise SSHSigError("allowed signers must contain exactly one canonical line")
    fields = text[:-1].split(" ")
    if len(fields) != 3 or any(not field for field in fields):
        raise SSHSigError("allowed signers entry is not canonical")
    if fields[0] != principal or fields[1] != "ssh-ed25519":
        raise SSHSigError("allowed signer principal or algorithm mismatch")
    try:
        blob = base64.b64decode(fields[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SSHSigError("allowed signer public key is invalid") from exc
    if base64.b64encode(blob).decode("ascii") != fields[2]:
        raise SSHSigError("allowed signer public key is not canonical")

    def ssh_string(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            raise SSHSigError("allowed signer public key is truncated")
        length = int.from_bytes(blob[offset : offset + 4], "big")
        start = offset + 4
        end = start + length
        if length > len(blob) or end > len(blob):
            raise SSHSigError("allowed signer public key is truncated")
        return blob[start:end], end

    algorithm, offset = ssh_string(0)
    key, offset = ssh_string(offset)
    if algorithm != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        raise SSHSigError("allowed signer must be an Ed25519 public key")
    return hashlib.sha256(blob).hexdigest()


def _minimal_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _descriptor_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def verify_sshsig(
    message: bytes,
    *,
    ssh_keygen_path: Path,
    ssh_keygen_sha256: str,
    allowed_signers_path: Path,
    allowed_signers_sha256: str,
    revocations_path: Path,
    revocations_sha256: str,
    signature_path: Path,
    signature_sha256: str,
    principal: str,
    namespace: str,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Verify exact bytes inside the production Linux root-managed boundary."""

    if not _is_supported_posix():
        raise SSHSigError(
            "production SSHSIG verification requires Linux POSIX /proc/self/fd"
        )
    if _no_follow_flag() == 0:
        raise SSHSigError("production SSHSIG verification requires O_NOFOLLOW")

    if type(message) is not bytes or not 0 < len(message) <= _MAX_MESSAGE_BYTES:
        raise SSHSigError("SSHSIG message must be bounded non-empty bytes")
    if type(principal) is not str or _PRINCIPAL.fullmatch(principal) is None:
        raise SSHSigError("SSHSIG principal is invalid")
    if type(namespace) is not str or _NAMESPACE.fullmatch(namespace) is None:
        raise SSHSigError("SSHSIG namespace is invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < float(timeout_seconds) <= _MAX_TIMEOUT_SECONDS
    ):
        raise SSHSigError("SSHSIG timeout is invalid")
    opened: list[_StableFile] = []
    try:
        executable = _read_pinned_file(
            ssh_keygen_path,
            ssh_keygen_sha256,
            maximum=_MAX_EXECUTABLE_BYTES,
            label="ssh-keygen",
            executable=True,
        )
        opened.append(executable)
        if executable.path.name != "ssh-keygen":
            raise SSHSigError("SSHSIG verifier must be the fixed ssh-keygen executable")
        allowed_signers = _read_pinned_file(
            allowed_signers_path,
            allowed_signers_sha256,
            maximum=_MAX_ALLOWED_SIGNERS_BYTES,
            label="allowed signers",
        )
        opened.append(allowed_signers)
        public_key_sha256 = _ed25519_public_key(allowed_signers.raw, principal)
        revocations = _read_pinned_file(
            revocations_path,
            revocations_sha256,
            maximum=_MAX_REVOCATIONS_BYTES,
            label="revocations",
        )
        opened.append(revocations)
        signature = _read_pinned_file(
            signature_path,
            signature_sha256,
            maximum=_MAX_SIGNATURE_BYTES,
            label="SSHSIG signature",
        )
        opened.append(signature)
        if (
            not signature.raw.startswith(_SIGNATURE_HEADER + b"\n")
            or not signature.raw.rstrip(b"\n").endswith(_SIGNATURE_FOOTER)
        ):
            raise SSHSigError("SSHSIG signature envelope is invalid")

        command = [
            _descriptor_path(executable.descriptor),
            "-Y",
            "verify",
            "-f",
            _descriptor_path(allowed_signers.descriptor),
            "-I",
            principal,
            "-n",
            namespace,
            "-r",
            _descriptor_path(revocations.descriptor),
            "-s",
            _descriptor_path(signature.descriptor),
        ]
        try:
            completed = subprocess.run(
                command,
                input=message,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                close_fds=True,
                pass_fds=tuple(item.descriptor for item in opened),
                timeout=float(timeout_seconds),
                env=_minimal_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SSHSigError(
                "ssh-keygen SSHSIG verification could not run"
            ) from exc
        if completed.returncode != 0:
            raise SSHSigError("ssh-keygen rejected the SSHSIG signature")

        return {
            "algorithm": "ssh-ed25519-sshsig",
            "allowed_signers_sha256": allowed_signers.sha256,
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "namespace": namespace,
            "principal": principal,
            "public_key_sha256": public_key_sha256,
            "revocations_sha256": revocations.sha256,
            "signature_sha256": signature.sha256,
            "ssh_keygen_sha256": executable.sha256,
            "verification_boundary": "posix-root-managed-pinned-fd",
            "verified": True,
        }
    finally:
        for item in opened:
            try:
                os.close(item.descriptor)
            except OSError:
                pass


__all__ = ["SSHSigError", "VERIFICATION_REPORT_FIELDS", "verify_sshsig"]
