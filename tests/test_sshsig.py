from __future__ import annotations

import base64
import hashlib
import inspect
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

import odoo_accounting_cli_v3.sshsig as sshsig


PRINCIPAL = "read-verifier.live-odoo"
NAMESPACE = "odoo-accounting-cli-v3/read-evidence/verify/live_odoo/v1"
MESSAGE = b'{"capability_id":"acct.gl.trial_balance.v1"}\n'
LINUX_FD_HOST = (
    sys.platform.startswith("linux")
    and os.name == "posix"
    and Path("/proc/self/fd").is_dir()
)
linux_fd_only = pytest.mark.skipif(
    not LINUX_FD_HOST,
    reason="production SSHSIG subprocess tests require Linux /proc/self/fd",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _public_blob(seed: int = 0) -> str:
    algorithm = b"ssh-ed25519"
    key = bytes((seed + index) % 256 for index in range(32))
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key).to_bytes(4, "big")
        + key
    )
    return base64.b64encode(blob).decode("ascii")


def _allowed_bytes(principal: str = PRINCIPAL, seed: int = 0) -> bytes:
    return f"{principal} ssh-ed25519 {_public_blob(seed)}\n".encode("ascii")


def _ssh_keygen() -> Path:
    override = os.environ.get("ODOO_CLI_TEST_SSH_KEYGEN")
    candidate = shutil.which(override or "ssh-keygen")
    if candidate is None:
        if sys.platform.startswith("linux"):
            pytest.fail("Linux CI must provide ssh-keygen with SSHSIG support")
        pytest.skip("ssh-keygen is unavailable")
    return Path(candidate).resolve()


def _run_fixture(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.fail(
            "ssh-keygen fixture command failed: "
            + completed.stderr.decode("utf-8", "replace")
        )


def _generate_key(executable: Path, path: Path) -> None:
    _run_fixture(
        [
            str(executable),
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            str(path),
        ]
    )


def _sign(
    executable: Path,
    key: Path,
    directory: Path,
    *,
    name: str,
    namespace: str,
    message: bytes,
) -> Path:
    message_path = directory / f"{name}.json"
    message_path.write_bytes(message)
    _run_fixture(
        [
            str(executable),
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            namespace,
            str(message_path),
        ]
    )
    return Path(str(message_path) + ".sig")


def _allowed_signers(path: Path, principal: str, public_key: Path) -> None:
    fields = public_key.read_text("ascii").strip().split()
    path.write_text(
        f"{principal} {fields[0]} {fields[1]}\n",
        encoding="ascii",
        newline="\n",
    )


@pytest.fixture(scope="module")
def material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if not LINUX_FD_HOST:
        pytest.skip("real verification is Linux /proc/self/fd only")
    directory = tmp_path_factory.mktemp("sshsig")
    executable = _ssh_keygen()
    first_key = directory / "first"
    second_key = directory / "second"
    _generate_key(executable, first_key)
    _generate_key(executable, second_key)
    allowed = directory / "allowed-signers"
    _allowed_signers(allowed, PRINCIPAL, Path(str(first_key) + ".pub"))
    revocations = directory / "revocations"
    revocations.write_text("# no revoked keys\n", encoding="ascii", newline="\n")
    signature = _sign(
        executable,
        first_key,
        directory,
        name="message",
        namespace=NAMESPACE,
        message=MESSAGE,
    )
    return {
        "directory": directory,
        "executable": executable,
        "first_key": first_key,
        "second_key": second_key,
        "allowed": allowed,
        "revocations": revocations,
        "signature": signature,
    }


def _arguments(material: dict[str, Any], **changes: Any) -> dict[str, Any]:
    values = {
        "message": MESSAGE,
        "ssh_keygen_path": material["executable"],
        "ssh_keygen_sha256": _digest(material["executable"]),
        "allowed_signers_path": material["allowed"],
        "allowed_signers_sha256": _digest(material["allowed"]),
        "revocations_path": material["revocations"],
        "revocations_sha256": _digest(material["revocations"]),
        "signature_path": material["signature"],
        "signature_sha256": _digest(material["signature"]),
        "principal": PRINCIPAL,
        "namespace": NAMESPACE,
        "timeout_seconds": 5.0,
    }
    values.update(changes)
    return values


def _bypass_root_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sshsig,
        "_validate_posix_policy",
        lambda _path, *, executable: None,
    )


def _require_root_test_host() -> Path:
    if getattr(os, "geteuid", lambda: -1)() != 0:
        pytest.skip("root-managed SSHSIG policy test requires uid 0")
    base = Path("/run")
    try:
        metadata = base.lstat()
    except OSError:
        pytest.skip("root-managed test base is unavailable")
    if (
        metadata.st_uid != 0
        or not sshsig._root_managed_mode_is_safe(metadata.st_mode, directory=True)
    ):
        pytest.skip("/run is not a root-managed test base")
    return base


def _dummy_arguments(**changes: Any) -> dict[str, Any]:
    values = {
        "message": MESSAGE,
        "ssh_keygen_path": Path("/usr/bin/ssh-keygen"),
        "ssh_keygen_sha256": "1" * 64,
        "allowed_signers_path": Path("/etc/example/allowed-signers"),
        "allowed_signers_sha256": "2" * 64,
        "revocations_path": Path("/etc/example/revocations"),
        "revocations_sha256": "3" * 64,
        "signature_path": Path("/var/lib/example/message.sshsig"),
        "signature_sha256": "4" * 64,
        "principal": PRINCIPAL,
        "namespace": NAMESPACE,
    }
    values.update(changes)
    return values


def test_allowed_signer_parser_accepts_only_one_canonical_ed25519_key() -> None:
    expected = hashlib.sha256(base64.b64decode(_public_blob())).hexdigest()
    assert sshsig._ed25519_public_key(_allowed_bytes(), PRINCIPAL) == expected

    invalid = [
        _allowed_bytes().replace(b"ssh-ed25519", b"ssh-rsa"),
        _allowed_bytes() + _allowed_bytes("another", 1),
        _allowed_bytes().replace(b" ", b"  ", 1),
        _allowed_bytes().replace(PRINCIPAL.encode(), b"other"),
    ]
    for document in invalid:
        with pytest.raises(sshsig.SSHSigError):
            sshsig._ed25519_public_key(document, PRINCIPAL)


def test_public_verifier_has_no_test_only_or_private_key_switch() -> None:
    parameters = inspect.signature(sshsig.verify_sshsig).parameters
    assert "require_root_owner" not in parameters
    assert all("private" not in name and "secret" not in name for name in parameters)

    with pytest.raises(TypeError):
        sshsig.verify_sshsig(  # type: ignore[call-arg]
            **_dummy_arguments(), require_root_owner=False
        )


def test_non_posix_is_rejected_before_any_file_or_subprocess_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sshsig, "_is_supported_posix", lambda: False)
    monkeypatch.setattr(
        sshsig.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )
    with pytest.raises(sshsig.SSHSigError, match="POSIX"):
        sshsig.verify_sshsig(**_dummy_arguments())


def test_missing_o_nofollow_is_rejected_before_file_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sshsig, "_is_supported_posix", lambda: True)
    monkeypatch.setattr(sshsig, "_no_follow_flag", lambda: 0)
    with pytest.raises(sshsig.SSHSigError, match="O_NOFOLLOW"):
        sshsig.verify_sshsig(**_dummy_arguments())


def test_unsafe_posix_modes_are_never_considered_root_managed() -> None:
    assert sshsig._root_managed_mode_is_safe(stat.S_IFREG | 0o644, directory=False)
    assert sshsig._root_managed_mode_is_safe(stat.S_IFDIR | 0o755, directory=True)
    assert not sshsig._root_managed_mode_is_safe(
        stat.S_IFREG | 0o666, directory=False
    )
    assert not sshsig._root_managed_mode_is_safe(
        stat.S_IFDIR | 0o777, directory=True
    )


@linux_fd_only
def test_real_subprocess_verifies_through_pinned_proc_fds(
    material: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _bypass_root_policy(monkeypatch)
    report = sshsig.verify_sshsig(**_arguments(material))

    assert report["verified"] is True
    assert report["algorithm"] == "ssh-ed25519-sshsig"
    assert report["verification_boundary"] == "posix-root-managed-pinned-fd"
    assert report["message_sha256"] == hashlib.sha256(MESSAGE).hexdigest()
    assert frozenset(report) == sshsig.VERIFICATION_REPORT_FIELDS


@linux_fd_only
def test_real_root_managed_chain_verifies_without_policy_bypass(
    material: dict[str, Any],
) -> None:
    base = _require_root_test_host()
    directory = Path(tempfile.mkdtemp(prefix="odoo-cli-sshsig-", dir=base))
    try:
        allowed = directory / "allowed-signers"
        revocations = directory / "revocations"
        signature = directory / "message.sig"
        for source, destination in (
            (material["allowed"], allowed),
            (material["revocations"], revocations),
            (material["signature"], signature),
        ):
            shutil.copyfile(source, destination)
            destination.chmod(0o600)

        report = sshsig.verify_sshsig(
            **_arguments(
                material,
                allowed_signers_path=allowed,
                allowed_signers_sha256=_digest(allowed),
                revocations_path=revocations,
                revocations_sha256=_digest(revocations),
                signature_path=signature,
                signature_sha256=_digest(signature),
            )
        )
        assert report["verified"] is True
        assert frozenset(report) == sshsig.VERIFICATION_REPORT_FIELDS
    finally:
        shutil.rmtree(directory)


@linux_fd_only
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("message", MESSAGE + b" "),
        ("namespace", NAMESPACE + ".other"),
        ("principal", PRINCIPAL + ".other"),
    ],
)
def test_message_namespace_and_principal_interchange_are_rejected(
    material: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: object,
) -> None:
    _bypass_root_policy(monkeypatch)
    with pytest.raises(sshsig.SSHSigError):
        sshsig.verify_sshsig(**_arguments(material, **{field: replacement}))


@linux_fd_only
def test_key_signature_and_revocation_interchange_are_rejected(
    material: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_root_policy(monkeypatch)
    allowed = tmp_path / "allowed-signers"
    _allowed_signers(allowed, PRINCIPAL, Path(str(material["second_key"]) + ".pub"))
    with pytest.raises(sshsig.SSHSigError):
        sshsig.verify_sshsig(
            **_arguments(
                material,
                allowed_signers_path=allowed,
                allowed_signers_sha256=_digest(allowed),
            )
        )

    signature = _sign(
        material["executable"],
        material["second_key"],
        tmp_path,
        name="other-key",
        namespace=NAMESPACE,
        message=MESSAGE,
    )
    with pytest.raises(sshsig.SSHSigError):
        sshsig.verify_sshsig(
            **_arguments(
                material,
                signature_path=signature,
                signature_sha256=_digest(signature),
            )
        )

    revocations = tmp_path / "revocations"
    revocations.write_bytes(Path(str(material["first_key"]) + ".pub").read_bytes())
    with pytest.raises(sshsig.SSHSigError):
        sshsig.verify_sshsig(
            **_arguments(
                material,
                revocations_path=revocations,
                revocations_sha256=_digest(revocations),
            )
        )


@linux_fd_only
def test_subprocess_contract_uses_only_pinned_fds_and_raw_stdin(
    material: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _bypass_root_policy(monkeypatch)
    observed: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(sshsig.subprocess, "run", run)
    sshsig.verify_sshsig(**_arguments(material, timeout_seconds=3.25))

    command = observed["command"]
    proc_paths = [command[0], command[4], command[10], command[12]]
    assert all(path.startswith("/proc/self/fd/") for path in proc_paths)
    assert {int(path.rsplit("/", 1)[1]) for path in proc_paths} == set(
        observed["pass_fds"]
    )
    assert observed["input"] == MESSAGE
    assert observed["shell"] is False
    assert observed["timeout"] == 3.25
    assert observed["close_fds"] is True
    assert observed["stdout"] is subprocess.DEVNULL
    assert observed["stderr"] is subprocess.DEVNULL
    for descriptor in observed["pass_fds"]:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@linux_fd_only
def test_change_use_restore_cannot_change_the_child_signature_bytes(
    material: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bypass_root_policy(monkeypatch)
    signature = tmp_path / "message.sig"
    original = material["signature"].read_bytes()
    signature.write_bytes(original)
    parked = tmp_path / "parked.sig"

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        os.replace(signature, parked)
        signature.write_bytes(b"attacker replacement")
        try:
            assert Path(command[12]).read_bytes() == original
            assert int(command[12].rsplit("/", 1)[1]) in kwargs["pass_fds"]
        finally:
            signature.unlink()
            os.replace(parked, signature)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(sshsig.subprocess, "run", run)
    report = sshsig.verify_sshsig(
        **_arguments(
            material,
            signature_path=signature,
            signature_sha256=_digest(signature),
        )
    )
    assert report["verified"] is True


@linux_fd_only
def test_unsafe_mode_fails_before_subprocess(
    material: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_root_test_host()
    unsafe = tmp_path / "unsafe-allowed-signers"
    unsafe.write_bytes(material["allowed"].read_bytes())
    unsafe.chmod(0o666)
    monkeypatch.setattr(
        sshsig.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )
    with pytest.raises(
        sshsig.SSHSigError,
        match="group- or world-writable",
    ):
        sshsig.verify_sshsig(
            **_arguments(
                material,
                allowed_signers_path=unsafe,
                allowed_signers_sha256=_digest(unsafe),
            )
        )


@linux_fd_only
def test_world_writable_ancestor_fails_before_subprocess(
    material: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_root_test_host()
    temporary_root = Path(tempfile.gettempdir())
    if stat.S_IMODE(temporary_root.stat().st_mode) & (
        stat.S_IWGRP | stat.S_IWOTH
    ) == 0:
        pytest.skip("system temporary directory is not group- or world-writable")
    allowed = tmp_path / "safe-file-under-unsafe-ancestor"
    allowed.write_bytes(material["allowed"].read_bytes())
    allowed.chmod(0o600)
    monkeypatch.setattr(
        sshsig.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )
    with pytest.raises(
        sshsig.SSHSigError,
        match="group- or world-writable",
    ):
        sshsig.verify_sshsig(
            **_arguments(
                material,
                allowed_signers_path=allowed,
                allowed_signers_sha256=_digest(allowed),
            )
        )


def test_report_schema_contains_no_path_private_key_or_secret() -> None:
    expected = {
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
    assert sshsig.VERIFICATION_REPORT_FIELDS == frozenset(expected)
    assert all(
        all(token not in field for token in ("path", "private", "secret"))
        for field in expected
    )
