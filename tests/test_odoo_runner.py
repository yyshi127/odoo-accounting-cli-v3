import ast
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from odoo_accounting_cli_v3.domain.ar_open_items import OpenItemsError
from odoo_accounting_cli_v3.domain.multicurrency_balance import MulticurrencyBalanceError
from odoo_accounting_cli_v3.domain.trial_balance import TrialBalanceError
from odoo_accounting_cli_v3.odoo.runner import (
    FIXED_CHILD_ENVIRONMENT,
    OdooRunnerError,
    RuntimeConfig,
    _child_main,
    _classify_trusted_read_rejection,
    _force_kill_linux_supervisor_tree,
    _install_linux_parent_death_guard,
    _kill_adopted_linux_descendants,
    _record_verified_read_audit,
    _require_immutable_dependency_mounts,
    _run_child_process,
    _safe_environment,
    _validate_child_environment,
    _validate_child_home,
    _verify_child_release,
    load_runtime_config,
    run_odoo_shell,
)
from odoo_accounting_cli_v3.auth import AuthenticationError
from odoo_accounting_cli_v3.gateway import GatewayError
from odoo_accounting_cli_v3.odoo.bootstrap import OdooBootstrapError
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.release import ReleaseIdentity, source_manifest


class AccessError(Exception):
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
AUTH_SECRET = b"test-only-auth-secret-32-bytes!!"
RECEIPT_SECRET = b"test-only-receipt-secret-32-byte"
AUTH_KEY_ID = "test-auth-2026-07"
RECEIPT_KEY_ID = "test-receipt-2026-07"
RELEASE_DIGEST = "d" * 64
MARKER_TOKEN = "1" * 48
MARKER = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{MARKER_TOKEN}__:"


def test_fixed_child_home_is_the_managed_private_state_directory() -> None:
    assert FIXED_CHILD_ENVIRONMENT["HOME"] == (
        "/var/lib/odoo-accounting-cli-v3-broker"
    )


def test_child_home_rejects_missing_file_symlink_and_non_private_mode(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(OdooRunnerError, match="HOME directory is not trustworthy"):
        _validate_child_home(str(missing))

    regular_file = tmp_path / "regular-file"
    regular_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(OdooRunnerError, match="HOME directory is not trustworthy"):
        _validate_child_home(str(regular_file))

    private_home = tmp_path / "private-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    _validate_child_home(str(private_home))

    if os.name == "posix":
        private_home.chmod(0o750)
        try:
            with pytest.raises(OdooRunnerError, match="mode 0700"):
                _validate_child_home(str(private_home))
        finally:
            private_home.chmod(0o700)

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    linked_home = tmp_path / "linked-home"
    try:
        linked_home.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    with pytest.raises(OdooRunnerError, match="HOME directory is not trustworthy"):
        _validate_child_home(str(linked_home))


def test_child_environment_rejects_mutation_before_spawn(
    tmp_path: Path,
) -> None:
    mutated = dict(FIXED_CHILD_ENVIRONMENT)
    mutated["UNTRUSTED"] = "1"
    with pytest.raises(OdooRunnerError, match="environment is invalid"):
        _validate_child_environment(mutated)

    with patch("odoo_accounting_cli_v3.odoo.runner.sys.platform", "linux"), patch(
        "odoo_accounting_cli_v3.odoo.runner.subprocess.Popen"
    ) as spawn:
        with pytest.raises(OdooRunnerError, match="environment is invalid"):
            _run_child_process(
                [sys.executable, "-c", "pass"],
                source="# trusted bootstrap\n",
                payload_fd=3,
                timeout_seconds=1,
                cwd=str(tmp_path),
                env=mutated,
            )
    spawn.assert_not_called()


def test_child_environment_accepts_private_runtime_gcov_directory(tmp_path: Path) -> None:
    gcov = tmp_path / "state" / "gcov"
    gcov.mkdir(parents=True, mode=0o700)
    gcov.chmod(0o700)
    environment = dict(FIXED_CHILD_ENVIRONMENT)
    environment.update(
        {
            "GCOV_ERROR_FILE": str(gcov / "gcov-error.log"),
            "GCOV_EXIT_AT_ERROR": "0",
            "GCOV_PREFIX": str(gcov),
            "GCOV_PREFIX_STRIP": "0",
        }
    )

    with patch("odoo_accounting_cli_v3.odoo.runner._validate_child_home") as home:
        _validate_child_environment(environment)
    home.assert_called_once_with(FIXED_CHILD_ENVIRONMENT["HOME"])

    environment["GCOV_PREFIX_STRIP"] = "1"
    with pytest.raises(OdooRunnerError, match="gcov environment is invalid"):
        _validate_child_environment(environment)


def test_safe_environment_can_pin_gcov_to_runtime_state(tmp_path: Path) -> None:
    config = RuntimeConfig(
        instance_id="odoo19@test",
        environment="test",
        capability_channel="staged",
        database_name="odoo_test",
        database_uuid=DATABASE_UUID,
        odoo_python=tmp_path / "bin" / "python",
        odoo_python_sha256="1" * 64,
        odoo_bin=tmp_path / "bin" / "odoo-bin",
        odoo_bin_sha256="2" * 64,
        odoo_config=tmp_path / "etc" / "odoo.conf",
        odoo_config_sha256="3" * 64,
        release_root=tmp_path / "releases" / "0.1.0.dev84-123456789abc",
        canonical_package_path=tmp_path / "packages" / "pkg.tar.gz",
        canonical_package_sha256="4" * 64,
        auth_state_path=tmp_path / "state" / "auth.sqlite3",
        receipt_state_path=tmp_path / "state" / "receipt.sqlite3",
        auth_key_id="auth-v1",
        receipt_key_id="receipt-v1",
        auth_secret_path=tmp_path / "secrets" / "auth.hmac",
        receipt_secret_path=tmp_path / "secrets" / "receipt.hmac",
    )
    config.auth_state_path.parent.mkdir(parents=True)
    (config.auth_state_path.parent.parent / "gcov").mkdir(mode=0o700)

    environment = _safe_environment(config)

    assert environment["GCOV_PREFIX"] == str(config.auth_state_path.parent.parent / "gcov")
    assert environment["GCOV_ERROR_FILE"] == str(
        config.auth_state_path.parent.parent / "gcov" / "gcov-error.log"
    )
    assert environment["GCOV_EXIT_AT_ERROR"] == "0"
    assert environment["GCOV_PREFIX_STRIP"] == "0"
    with patch("odoo_accounting_cli_v3.odoo.runner._validate_child_home"):
        _validate_child_environment(environment)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mount flags required")
def test_dependency_mount_attestation_requires_exact_readonly_and_writable_sets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dependency_paths = {
        "release_root": tmp_path / "release",
        "canonical_package_path": tmp_path / "package.tar.gz",
        "odoo_python": tmp_path / "venv" / "bin" / "python",
        "odoo_bin": tmp_path / "server" / "odoo-bin",
        "odoo_config": tmp_path / "addons" / "odoo.conf",
        "auth_secret_path": tmp_path / "secrets" / "auth.hmac",
        "receipt_secret_path": tmp_path / "secrets" / "receipt.hmac",
        "auth_state_path": tmp_path / "state" / "auth" / "state.sqlite3",
        "receipt_state_path": tmp_path / "state" / "receipt" / "state.sqlite3",
    }
    config = SimpleNamespace(**dependency_paths)
    readonly = os.ST_RDONLY
    writable = {
        dependency_paths["auth_state_path"].parent,
        dependency_paths["receipt_state_path"].parent,
        Path(FIXED_CHILD_ENVIRONMENT["HOME"]),
    }

    def flags(path: os.PathLike[str] | str) -> SimpleNamespace:
        return SimpleNamespace(f_flag=0 if Path(path) in writable else readonly)

    monkeypatch.setattr(os, "statvfs", flags)
    _require_immutable_dependency_mounts(config)

    monkeypatch.setattr(
        os,
        "statvfs",
        lambda path: SimpleNamespace(
            f_flag=0
            if Path(path) == dependency_paths["odoo_bin"].parent
            or Path(path) in writable
            else readonly
        ),
    )
    with pytest.raises(OdooRunnerError, match="odoo_server_root.*read-only"):
        _require_immutable_dependency_mounts(config)

    monkeypatch.setattr(
        os,
        "statvfs",
        lambda path: SimpleNamespace(
            f_flag=readonly
            if Path(path) == dependency_paths["auth_state_path"].parent
            or Path(path) not in writable
            else 0
        ),
    )
    with pytest.raises(OdooRunnerError, match="auth_state_parent.*writable"):
        _require_immutable_dependency_mounts(config)


def request_document():
    return {
        "capability_id": "acct.gl.trial_balance.v1",
        "context": {
            "database_name": "odoo_test",
            "company_id": 7,
            "supplier_id": 901,
            "currency_id": 12,
        },
        "parameters": {
            "company_id": 7,
            "date_from": "2026-01-01",
            "date_to": "2026-12-31",
            "supplier_id": 901,
            "currency_id": 12,
        },
    }


def test_linux_parent_death_guard_arms_before_parent_recheck() -> None:
    events: list[str] = []

    class FakePrctl:
        argtypes = None
        restype = None

        def __call__(self, option, signum, arg3, arg4, arg5):
            events.append(f"prctl:{option}")
            expected = (
                (1, signal.SIGTERM, 0, 0, 0)
                if option == 1
                else (36, 1, 0, 0, 0)
            )
            assert (option, signum, arg3, arg4, arg5) == expected
            return 0

    libc = SimpleNamespace(prctl=FakePrctl())

    def install_handler(signum, _handler):
        events.append("handler")
        assert signum == signal.SIGTERM

    def current_parent():
        events.append("getppid")
        return 4321

    with patch("odoo_accounting_cli_v3.odoo.runner.sys.platform", "linux"), patch(
        "ctypes.CDLL", return_value=libc
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.signal",
        side_effect=install_handler,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.pthread_sigmask",
        return_value=set(),
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.SIG_UNBLOCK",
        1,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.os.getppid",
        side_effect=current_parent,
    ):
        _install_linux_parent_death_guard(4321)

    assert events == ["handler", "prctl:1", "getppid", "prctl:36"]


def test_linux_parent_death_guard_kills_group_if_parent_changed() -> None:
    class GroupKilled(Exception):
        pass

    class FakePrctl:
        argtypes = None
        restype = None

        def __call__(self, *_args):
            return 0

    libc = SimpleNamespace(prctl=FakePrctl())
    with patch("odoo_accounting_cli_v3.odoo.runner.sys.platform", "linux"), patch(
        "ctypes.CDLL", return_value=libc
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.signal"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.pthread_sigmask",
        return_value=set(),
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.SIG_UNBLOCK",
        1,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.os.getppid", return_value=4322
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._request_supervised_tree_termination"
    ) as request_termination:
        request_termination.side_effect = GroupKilled
        with pytest.raises(GroupKilled):
            _install_linux_parent_death_guard(4321)

    request_termination.assert_called_once_with(signal.SIGTERM, None)


def test_adopted_descendant_cleanup_retries_and_has_no_count_escape() -> None:
    children = tuple(range(10_000, 14_097))
    listed = " ".join(str(pid) for pid in children)
    with patch(
        "odoo_accounting_cli_v3.odoo.runner.Path.read_text",
        side_effect=[OSError("transient procfs read"), listed, ""],
    ) as read_children, patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.SIGKILL",
        9,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.os.kill"
    ) as kill, patch(
        "odoo_accounting_cli_v3.odoo.runner.os.waitpid",
        side_effect=lambda pid, _options: (pid, 0),
    ) as waitpid:
        _kill_adopted_linux_descendants()

    assert read_children.call_count == 3
    assert kill.call_count == len(children)
    assert waitpid.call_count == len(children)


def test_timeout_fallback_kills_cross_session_child_before_supervisor() -> None:
    events: list[str] = []
    process = SimpleNamespace(
        pid=5000,
        send_signal=Mock(side_effect=lambda _signal: events.append("stop")),
        poll=Mock(side_effect=[None, None, None]),
        wait=Mock(return_value=-9),
    )
    reads = [
        OSError("transient procfs read"),
        "6000",
        "6000 (escaped child) S 1 2 3",
        "6000",
        "6000 (escaped child) Z 1 2 3",
    ]
    with patch(
        "odoo_accounting_cli_v3.odoo.runner.Path.read_text",
        side_effect=reads,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.SIGSTOP",
        19,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.SIGKILL",
        9,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.os.pidfd_open",
        return_value=77,
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.signal.pidfd_send_signal",
        side_effect=lambda _fd, _signal: events.append("child"),
        create=True,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.os.killpg",
        side_effect=lambda _pid, _signal: events.append("supervisor"),
        create=True,
    ), patch("odoo_accounting_cli_v3.odoo.runner.os.close"):
        _force_kill_linux_supervisor_tree(process)

    assert events == ["stop", "child", "supervisor"]
    process.wait.assert_called_once_with(timeout=5)


def response(runtime, result=None):
    return json.dumps(
        {"ok": True, "runtime": runtime, "result": result or {"verified": True}},
        ensure_ascii=False,
        separators=(",", ":"),
    )


@pytest.mark.parametrize(
    ("error", "replay_rejected", "expected"),
    (
        (
            AuthenticationError("authentication context is not currently valid"),
            False,
            "authentication_expired",
        ),
        (
            AuthenticationError("authentication signature mismatch"),
            False,
            "authentication_tampered",
        ),
        (
            OdooBootstrapError("signed request does not match the Odoo runtime"),
            False,
            "database_binding_rejected",
        ),
        (
            OdooBootstrapError(
                "signed allowed companies exceed the Odoo user companies"
            ),
            False,
            "company_binding_rejected",
        ),
        (
            GatewayError("Odoo ACL rejected capability"),
            False,
            "odoo_acl_denied",
        ),
        (
            GatewayError("request context authentication failed"),
            True,
            "authentication_replayed",
        ),
        (
            TrialBalanceError("company is outside the authenticated allowed companies"),
            False,
            "company_binding_rejected",
        ),
        (
            OpenItemsError("company does not exist or is not visible"),
            False,
            "company_binding_rejected",
        ),
        (
            MulticurrencyBalanceError("company does not exist or is not visible"),
            False,
            "company_binding_rejected",
        ),
        (
            AccessError("Access to unauthorized or invalid companies."),
            False,
            "company_binding_rejected",
        ),
    ),
)
def test_trusted_read_rejection_classifier_maps_only_fixed_plan_failures(
    error: BaseException, replay_rejected: bool, expected: str
) -> None:
    assert (
        _classify_trusted_read_rejection(error, replay_rejected=replay_rejected)
        == expected
    )


def test_trusted_read_rejection_classifier_rejects_near_matches_and_subclasses() -> None:
    class DerivedAuthenticationError(AuthenticationError):
        pass

    failures = (
        (AuthenticationError("authentication signature mismatch "), False),
        (DerivedAuthenticationError("authentication signature mismatch"), False),
        (GatewayError("request context authentication failed"), False),
        (RuntimeError("Odoo ACL rejected capability"), False),
        (OdooRunnerError("Odoo shell timed out"), False),
        (TrialBalanceError("company does not exist or is not visible "), False),
        (AccessError("Access to unauthorized or invalid companies"), False),
    )
    for error, replay_rejected in failures:
        assert (
            _classify_trusted_read_rejection(
                error, replay_rejected=replay_rejected
            )
            is None
        )


class OdooRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        release_verification = patch(
            "odoo_accounting_cli_v3.odoo.runner._verify_child_release",
            return_value=(),
        )
        self.verify_parent_release = release_verification.start()
        self.addCleanup(release_verification.stop)
        mount_attestation = patch(
            "odoo_accounting_cli_v3.odoo.runner._require_immutable_dependency_mounts"
        )
        mount_attestation.start()
        self.addCleanup(mount_attestation.stop)
        root = Path(self.temp.name)
        self.odoo_python = root / "python"
        self.odoo_bin = root / "odoo-bin"
        self.odoo_config = root / "odoo.conf"
        for path in (self.odoo_python, self.odoo_bin, self.odoo_config):
            path.write_text("test", encoding="utf-8")
        runtime_file_digest = hashlib.sha256(b"test").hexdigest()
        self.canonical_package_path = (
            PROJECT_ROOT.parent.parent
            / "packages"
            / f"odoo-accounting-cli-v3-{PROJECT_ROOT.name}.tar.gz"
        )
        self.canonical_package_sha256 = hashlib.sha256(
            b"canonical release package"
        ).hexdigest()
        self.auth_secret_path = root / "auth.secret"
        self.receipt_secret_path = root / "receipt.secret"
        self.gcov_state_path = root / "gcov"
        self.auth_secret_path.write_bytes(AUTH_SECRET)
        self.receipt_secret_path.write_bytes(RECEIPT_SECRET)
        self.gcov_state_path.mkdir(mode=0o700)

        def read_test_secret(path, label):
            value = path.read_bytes()
            if len(value) < 32:
                raise OdooRunnerError(f"{label} must contain at least 32 bytes")
            return value

        # These orchestration tests use caller-owned temporary files; the
        # production ownership and mode checker itself remains unmodified.
        secret_reader = patch(
            "odoo_accounting_cli_v3.odoo.runner._read_private_secret",
            side_effect=read_test_secret,
        )
        secret_reader.start()
        self.addCleanup(secret_reader.stop)
        package_verification = patch(
            "odoo_accounting_cli_v3.odoo.runner._verify_canonical_package"
        )
        self.verify_canonical_package = package_verification.start()
        self.addCleanup(package_verification.stop)
        self.config = RuntimeConfig(
            instance_id="odoo19@tokyo2",
            environment="test",
            capability_channel="staged",
            database_name="odoo_test",
            database_uuid=DATABASE_UUID,
            odoo_python=self.odoo_python,
            odoo_python_sha256=runtime_file_digest,
            odoo_bin=self.odoo_bin,
            odoo_bin_sha256=runtime_file_digest,
            odoo_config=self.odoo_config,
            odoo_config_sha256=runtime_file_digest,
            release_root=PROJECT_ROOT,
            canonical_package_path=self.canonical_package_path,
            canonical_package_sha256=self.canonical_package_sha256,
            auth_state_path=root / "auth.state",
            receipt_state_path=root / "receipt.state",
            gcov_state_path=self.gcov_state_path,
            auth_key_id=AUTH_KEY_ID,
            receipt_key_id=RECEIPT_KEY_ID,
            auth_secret_path=self.auth_secret_path,
            receipt_secret_path=self.receipt_secret_path,
        )

    def completed(self, *, stdout=None, returncode=0):
        stdout = stdout if stdout is not None else MARKER + response(self.config.runtime_identity)
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="odoo log")

    def test_loads_exact_root_managed_config_and_rejects_bad_contracts(self):
        path = Path(self.temp.name) / "runtime.json"
        document = {
            "instance_id": self.config.instance_id,
            "environment": self.config.environment,
            "capability_channel": self.config.capability_channel,
            "database_name": self.config.database_name,
            "database_uuid": self.config.database_uuid,
            "odoo_python": str(self.config.odoo_python),
            "odoo_python_sha256": self.config.odoo_python_sha256,
            "odoo_bin": str(self.config.odoo_bin),
            "odoo_bin_sha256": self.config.odoo_bin_sha256,
            "odoo_config": str(self.config.odoo_config),
            "odoo_config_sha256": self.config.odoo_config_sha256,
            "release_root": str(self.config.release_root),
            "canonical_package_path": str(self.config.canonical_package_path),
            "canonical_package_sha256": self.config.canonical_package_sha256,
            "auth_state_path": str(self.config.auth_state_path),
            "receipt_state_path": str(self.config.receipt_state_path),
            "gcov_state_path": str(self.config.gcov_state_path),
            "auth_key_id": self.config.auth_key_id,
            "receipt_key_id": self.config.receipt_key_id,
            "auth_secret_path": str(self.config.auth_secret_path),
            "receipt_secret_path": str(self.config.receipt_secret_path),
        }
        path.write_text(json.dumps(document), encoding="utf-8")
        loaded = load_runtime_config(path, require_root_owner=False)
        self.assertEqual(loaded, self.config)

        invalid_documents = (
            {**document, "db_password": "must-not-be-accepted"},
            {**document, "environment": "staging"},
            {**document, "database_uuid": "not-a-uuid"},
            {**document, "odoo_python": "relative/python"},
            {**document, "canonical_package_path": "relative/package.tar.gz"},
            {**document, "canonical_package_sha256": "A" * 64},
            {key: value for key, value in document.items() if key != "instance_id"},
            {
                key: value
                for key, value in document.items()
                if key != "canonical_package_path"
            },
        )
        for invalid in invalid_documents:
            with self.subTest(invalid=invalid):
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises(OdooRunnerError):
                    load_runtime_config(path, require_root_owner=False)

        path.write_text('{"instance_id":"first","instance_id":"second"}', encoding="utf-8")
        with self.assertRaisesRegex(OdooRunnerError, "duplicate JSON key"):
            load_runtime_config(path, require_root_owner=False)

    @patch("odoo_accounting_cli_v3.odoo.runner.secrets.token_hex", return_value=MARKER_TOKEN)
    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_fixed_argv_private_stdin_complete_parameters_and_sanitized_env(
        self, run, _token_hex
    ):
        captured = {}

        def execute(_argv, **options):
            payload_fd = options["payload_fd"]
            position = os.lseek(payload_fd, 0, os.SEEK_CUR)
            os.lseek(payload_fd, 0, os.SEEK_SET)
            captured["payload"] = json.loads(os.read(payload_fd, 1024 * 1024))
            os.lseek(payload_fd, position, os.SEEK_SET)
            return self.completed(
                stdout=(
                    'odoo log {"ok":true,"result":{"forged":true}}\n'
                    + MARKER
                    + response(self.config.runtime_identity, {"verified": True})
                    + "\nmore logs"
                )
            )

        run.side_effect = execute
        request = request_document()
        with patch.dict(
            os.environ,
            {
                "PGPASSWORD": "database-password",
                "DATABASE_URL": "postgres://secret",
                "AUTH_SECRET": "environment-secret",
                "HOME": "C:/attacker-home",
                "LANG": "attacker-locale",
                "LC_ALL": "attacker-locale",
                "PATH": "C:/attacker-bin",
                "TZ": "Attacker/Timezone",
            },
            clear=False,
        ):
            result = run_odoo_shell(
                self.config,
                request,
                release_digest=RELEASE_DIGEST,
                timeout_seconds=17,
            )
        self.assertEqual(result, {"verified": True})

        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(
            argv,
            [
                str(self.config.odoo_python),
                str(self.config.odoo_bin),
                "shell",
                "-c",
                str(self.config.odoo_config),
                "-d",
                "odoo_test",
                "--no-http",
                "--logfile=/dev/null",
            ],
        )
        self.assertEqual(options["timeout_seconds"], 17.0)
        expected_environment = {
            **FIXED_CHILD_ENVIRONMENT,
            "GCOV_ERROR_FILE": str(
                self.config.gcov_state_path / "gcov-error.log"
            ),
            "GCOV_EXIT_AT_ERROR": "0",
            "GCOV_PREFIX": str(self.config.gcov_state_path),
            "GCOV_PREFIX_STRIP": "0",
        }
        self.assertEqual(options["env"], expected_environment)
        self.assertNotIn("PGPASSWORD", options["env"])
        self.assertNotIn("DATABASE_URL", options["env"])
        self.assertNotIn("AUTH_SECRET", options["env"])

        payload = captured["payload"]
        self.assertEqual(json.loads(payload["request_json"]), request)
        import base64

        self.assertEqual(base64.b64decode(payload["auth_secret"]), AUTH_SECRET)
        self.assertEqual(base64.b64decode(payload["receipt_secret"]), RECEIPT_SECRET)
        self.assertEqual(payload["release_digest"], RELEASE_DIGEST)
        self.assertEqual(
            payload["canonical_package_path"],
            str(self.config.canonical_package_path),
        )
        self.assertEqual(
            payload["canonical_package_sha256"],
            self.config.canonical_package_sha256,
        )
        self.assertEqual(payload["runtime"], self.config.runtime_identity)
        exposed = json.dumps({"argv": argv, "env": options["env"]}, ensure_ascii=False)
        self.assertNotIn("2026-01-01", exposed)
        self.assertNotIn("supplier_id", exposed)
        self.assertNotIn(AUTH_SECRET.decode(), exposed)
        self.assertNotIn(RECEIPT_SECRET.decode(), exposed)
        self.assertNotIn("database-password", exposed)
        bootstrap = options["source"]
        ast.parse(bootstrap)
        self.assertNotIn("2026-01-01", bootstrap)
        self.assertNotIn("supplier_id", bootstrap)
        self.assertNotIn(AUTH_SECRET.decode(), bootstrap)
        self.assertNotIn(RECEIPT_SECRET.decode(), bootstrap)

    @patch("odoo_accounting_cli_v3.odoo.runner.secrets.token_hex", return_value=MARKER_TOKEN)
    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_nonzero_timeout_and_start_failure_are_fail_closed(self, run, _token_hex):
        run.return_value = self.completed(returncode=2)
        with self.assertRaisesRegex(OdooRunnerError, "status 2") as failure:
            self.execute()
        self.assertIsNone(failure.exception.rejection_code)

        run.side_effect = OdooRunnerError("Odoo shell timed out")
        with self.assertRaisesRegex(OdooRunnerError, "timed out"):
            self.execute()

        run.side_effect = OdooRunnerError("Odoo shell could not be started")
        with self.assertRaisesRegex(OdooRunnerError, "could not be started"):
            self.execute()

    @patch("odoo_accounting_cli_v3.odoo.runner.secrets.token_hex", return_value=MARKER_TOKEN)
    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_allowlisted_child_rejection_is_transported_from_same_execution(
        self, run, _token_hex
    ):
        response = {
            "ok": False,
            "runtime": self.config.runtime_identity,
            "rejection_code": "authentication_replayed",
        }
        run.return_value = self.completed(
            stdout=MARKER + json.dumps(response, separators=(",", ":"))
        )
        with self.assertRaisesRegex(OdooRunnerError, "request was rejected") as failure:
            self.execute()
        self.assertEqual(failure.exception.rejection_code, "authentication_replayed")

        response["rejection_code"] = "infrastructure_failed"
        run.return_value = self.completed(
            stdout=MARKER + json.dumps(response, separators=(",", ":"))
        )
        with self.assertRaisesRegex(OdooRunnerError, "response fields") as failure:
            self.execute()
        self.assertIsNone(failure.exception.rejection_code)

    @patch("odoo_accounting_cli_v3.odoo.runner.secrets.token_hex", return_value=MARKER_TOKEN)
    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_missing_duplicate_and_malformed_markers_are_rejected(self, run, _token_hex):
        invalid_outputs = (
            'odoo log {"ok":true,"result":{"forged":true}}',
            MARKER + response(self.config.runtime_identity) + "\n" + MARKER + response(self.config.runtime_identity),
            MARKER + "not-json",
            "prefix " + MARKER + response(self.config.runtime_identity),
            MARKER + '{"ok":true,"ok":true}',
            MARKER + '{"ok":true,"runtime":{},"result":{"amount":NaN}}',
        )
        for stdout in invalid_outputs:
            with self.subTest(stdout=stdout):
                run.side_effect = None
                run.return_value = self.completed(stdout=stdout)
                with self.assertRaises(OdooRunnerError):
                    self.execute()

    @patch("odoo_accounting_cli_v3.odoo.runner.secrets.token_hex", return_value=MARKER_TOKEN)
    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_every_runtime_identity_field_is_bound(self, run, _token_hex):
        changes = {
            "instance_id": "other-instance",
            "environment": "sandbox",
            "capability_channel": "enabled",
            "database_name": "other_db",
            "database_uuid": "22222222-2222-4222-8222-222222222222",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                runtime = {**self.config.runtime_identity, field: value}
                run.return_value = self.completed(stdout=MARKER + response(runtime))
                with self.assertRaisesRegex(OdooRunnerError, "identity does not match"):
                    self.execute()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_invalid_request_and_missing_runtime_files_do_not_start_child(self, run):
        with self.assertRaisesRegex(OdooRunnerError, "duplicate JSON key"):
            self.execute(request='{"context":{},"context":{}}')
        self.odoo_bin.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(OdooRunnerError, "root-managed digest"):
            self.execute()
        self.odoo_bin.unlink()
        with self.assertRaisesRegex(OdooRunnerError, "odoo_bin"):
            self.execute()
        run.assert_not_called()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    @patch("odoo_accounting_cli_v3.odoo.runner.load_runtime_secrets")
    def test_package_path_outside_the_release_slot_is_rejected_before_action(
        self, load_secrets, run
    ):
        config = replace(
            self.config,
            canonical_package_path=Path(self.temp.name) / "same-digest-other-path.tar.gz",
        )

        with self.assertRaisesRegex(OdooRunnerError, "path does not match release_root"):
            run_odoo_shell(
                config,
                request_document(),
                release_digest=RELEASE_DIGEST,
                timeout_seconds=10,
            )

        self.verify_canonical_package.assert_not_called()
        load_secrets.assert_not_called()
        self.verify_parent_release.assert_not_called()
        run.assert_not_called()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    @patch("odoo_accounting_cli_v3.odoo.runner.load_runtime_secrets")
    def test_untrusted_canonical_package_is_rejected_before_secrets_or_child(
        self, load_secrets, run
    ):
        self.verify_canonical_package.side_effect = OdooRunnerError(
            "canonical release package cannot be verified"
        )

        with self.assertRaisesRegex(OdooRunnerError, "canonical release package"):
            self.execute()

        self.verify_canonical_package.assert_called_once_with(
            self.config.canonical_package_path,
            self.config.canonical_package_sha256,
        )
        load_secrets.assert_not_called()
        self.verify_parent_release.assert_not_called()
        run.assert_not_called()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    @patch("odoo_accounting_cli_v3.odoo.runner.load_runtime_secrets")
    def test_untrusted_parent_release_is_rejected_before_secrets_or_child(
        self, load_secrets, run
    ):
        self.verify_parent_release.side_effect = OdooRunnerError(
            "release root is not root-managed"
        )

        with self.assertRaisesRegex(OdooRunnerError, "not root-managed"):
            self.execute()

        self.verify_parent_release.assert_called_once_with(
            self.config.release_root,
            RELEASE_DIGEST,
            self.config.canonical_package_path,
            self.config.canonical_package_sha256,
        )
        load_secrets.assert_not_called()
        run.assert_not_called()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_short_secrets_do_not_start_child(self, run):
        self.auth_secret_path.write_bytes(b"short")
        with self.assertRaisesRegex(OdooRunnerError, "at least 32 bytes"):
            self.execute()
        self.auth_secret_path.write_bytes(AUTH_SECRET)
        self.receipt_secret_path.write_bytes(b"short")
        with self.assertRaisesRegex(OdooRunnerError, "at least 32 bytes"):
            self.execute()
        run.assert_not_called()

    @patch("odoo_accounting_cli_v3.odoo.runner._run_child_process")
    def test_timeout_policy_is_bounded_before_child_start(self, run):
        for timeout in (0, float("nan"), 121, True):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(
                OdooRunnerError, "no greater than 120"
            ):
                run_odoo_shell(
                    self.config,
                    request_document(),
                    release_digest=RELEASE_DIGEST,
                    timeout_seconds=timeout,
                )
        run.assert_not_called()

    def test_verified_read_is_appended_to_durable_audit_chain(self):
        observed_at = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
        registry_digest = "c" * 64
        request = {
            "capability_id": "acct.gl.trial_balance.v1",
            "context": {
                "auth_token_id": "token-audit-1",
                "company_id": 7,
                "database_name": "odoo_test",
                "database_uuid": DATABASE_UUID,
                "odoo_instance_id": "odoo19@tokyo2",
                "principal": "pi:user-42",
                "user_id": 42,
            },
            "parameters": {"company_id": 7, "date_to": "2026-07-13"},
        }
        result_body = {"lines": [], "page": {"total_count": 0}}
        receipt = create_read_receipt(
            receipt_id="receipt-audit-1",
            capability_id=request["capability_id"],
            parameters=request["parameters"],
            result_body=result_body,
            auth_token_id=request["context"]["auth_token_id"],
            principal=request["context"]["principal"],
            odoo_instance_id=request["context"]["odoo_instance_id"],
            database_name=request["context"]["database_name"],
            database_uuid=DATABASE_UUID,
            company_id=7,
            user_id=42,
            registry_digest=registry_digest,
            release_digest=RELEASE_DIGEST,
            environment=self.config.environment,
            capability_channel=self.config.capability_channel,
            record_count=0,
            observed_at=observed_at,
            key_id=RECEIPT_KEY_ID,
            secret=RECEIPT_SECRET,
        )
        store = SQLitePersistence(
            Path(self.temp.name) / "receipt-audit.sqlite3",
            receipt_key_id=RECEIPT_KEY_ID,
            receipt_secret=RECEIPT_SECRET,
        )

        _record_verified_read_audit(
            store,
            json.dumps(request),
            {**result_body, "receipt": receipt},
            registry_digest=registry_digest,
            release_digest=RELEASE_DIGEST,
            environment=self.config.environment,
            capability_channel=self.config.capability_channel,
            now=observed_at + timedelta(seconds=1),
        )

        self.assertEqual(store.verify_chain(), 1)
        event = store.audit_events()[0]
        self.assertEqual(event.event_type, "read.verified")
        self.assertEqual(event.event_id, "read:receipt-audit-1")
        self.assertEqual(event.payload["auth_token_id"], "token-audit-1")
        self.assertEqual(event.payload["principal"], "pi:user-42")
        self.assertEqual(event.payload["request_digest"], receipt["request_digest"])
        self.assertEqual(event.payload["receipt"], receipt)

    @patch("odoo_accounting_cli_v3.odoo.runner._read_small_json_file")
    @patch("odoo_accounting_cli_v3.odoo.runner._assert_root_managed_path")
    def test_child_reverifies_external_anchor_manifest_and_registry(
        self, _managed, read_json
    ):
        trusted_root = Path(self.temp.name) / "trusted-v3"
        release_root = trusted_root / "releases" / "0.1.0.dev3-aaaaaaaaaaaa"
        registry_path = release_root / "registry" / "capabilities.json"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_bytes((PROJECT_ROOT / "registry" / "capabilities.json").read_bytes())
        release_identity = ReleaseIdentity(version="0.1.0.dev3", commit="a" * 40)
        manifest = source_manifest(release_root, [registry_path], release_identity)
        (release_root / "RELEASE-MANIFEST.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        anchor_directory = trusted_root / "trusted-artifacts"
        anchor_directory.mkdir()
        anchor_path = anchor_directory / f"{release_root.name}.json"
        anchor_document = {
            "commit": "a" * 40,
            "manifest_sha256": manifest["manifest_sha256"],
            "package_sha256": "b" * 64,
            "release": release_root.name,
        }
        anchor_path.write_text(json.dumps(anchor_document), encoding="utf-8")
        read_json.side_effect = lambda path, _label: json.loads(
            path.read_text(encoding="utf-8")
        )

        capabilities = _verify_child_release(
            release_root,
            manifest["manifest_sha256"],
            trusted_root
            / "packages"
            / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz",
            "b" * 64,
        )
        self.assertIn("acct.gl.trial_balance.v1", {item.id for item in capabilities})
        self.assertIn(
            registry_path,
            {call.args[0] for call in _managed.call_args_list},
        )

        anchor_path.write_text(
            json.dumps({**anchor_document, "package_sha256": "c" * 64}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(OdooRunnerError, "anchor"):
            _verify_child_release(
                release_root,
                manifest["manifest_sha256"],
                trusted_root
                / "packages"
                / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz",
                "b" * 64,
            )
        anchor_path.write_text(json.dumps(anchor_document), encoding="utf-8")

        with self.assertRaisesRegex(OdooRunnerError, "anchor"):
            _verify_child_release(
                release_root,
                manifest["manifest_sha256"],
                trusted_root / "packages" / "same-bytes-wrong-name.tar.gz",
                "b" * 64,
            )

        registry_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(OdooRunnerError, "integrity"):
            _verify_child_release(
                release_root,
                manifest["manifest_sha256"],
                trusted_root
                / "packages"
                / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz",
                "b" * 64,
            )

    def test_child_package_or_release_failure_precedes_sqlite_construction(self):
        import base64

        payload = {
            "protocol": 1,
            "runtime": self.config.runtime_identity,
            "request_json": json.dumps(request_document()),
            "auth_secret": base64.b64encode(AUTH_SECRET).decode("ascii"),
            "auth_key_id": self.config.auth_key_id,
            "receipt_secret": base64.b64encode(RECEIPT_SECRET).decode("ascii"),
            "receipt_key_id": self.config.receipt_key_id,
            "release_digest": RELEASE_DIGEST,
            "canonical_package_path": str(self.config.canonical_package_path),
            "canonical_package_sha256": self.config.canonical_package_sha256,
            "release_root": str(self.config.release_root),
            "auth_state_path": str(self.config.auth_state_path),
            "receipt_state_path": str(self.config.receipt_state_path),
        }

        def payload_fd() -> int:
            stream = tempfile.TemporaryFile()
            stream.write(json.dumps(payload).encode("utf-8"))
            stream.seek(0)
            descriptor = os.dup(stream.fileno())
            stream.close()
            return descriptor

        failures = (
            ("package rejected", "_validate_canonical_package_binding"),
            ("release rejected", "_verify_child_release"),
        )
        for message, failing_check in failures:
            with self.subTest(failing_check=failing_check), patch(
                "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
            ) as package_binding, patch(
                "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
            ) as release_verification, patch(
                "odoo_accounting_cli_v3.odoo.runner.RuntimeConfig",
                return_value=self.config,
            ), patch(
                "odoo_accounting_cli_v3.persistence.SQLitePersistence"
            ) as persistence:
                failing = (
                    package_binding
                    if failing_check == "_validate_canonical_package_binding"
                    else release_verification
                )
                failing.side_effect = OdooRunnerError(message)

                with self.assertRaisesRegex(OdooRunnerError, message):
                    _child_main(None, payload_fd(), MARKER)

                persistence.assert_not_called()
                if failing_check == "_validate_canonical_package_binding":
                    release_verification.assert_not_called()
                else:
                    release_verification.assert_called_once_with(
                        self.config.release_root.resolve(),
                        RELEASE_DIGEST,
                        self.config.canonical_package_path,
                        self.config.canonical_package_sha256,
                    )

    def execute(self, *, request=None):
        return run_odoo_shell(
            self.config,
            request if request is not None else request_document(),
            release_digest=RELEASE_DIGEST,
            timeout_seconds=10,
        )


_NESTED_ODOO_RUNNER_SOURCE = r"""
import os
import sys

from odoo_accounting_cli_v3.odoo.runner import (
    FIXED_CHILD_ENVIRONMENT,
    OdooRunnerError,
    _run_child_process,
)

payload_fd = int(sys.argv[1])
commit_path = sys.argv[2]
timeout_seconds = float(sys.argv[3])
direct_exit_code = int(sys.argv[4])
grandchild_source = (
    "import os,socket,sys\n"
    "payload_fd=int(sys.argv[1])\n"
    "commit_path=sys.argv[2]\n"
    "ready_fd=int(sys.argv[3])\n"
    "os.setsid()\n"
    "for descriptor in (0,1,2):\n"
    "    try:\n"
    "        os.close(descriptor)\n"
    "    except OSError:\n"
    "        pass\n"
    "stream=socket.socket(fileno=payload_fd)\n"
    "stream.sendall(f'READY:{os.getpid()}:{os.getpgrp()}\\n'.encode('ascii'))\n"
    "if stream.recv(1) != b'A':\n"
    "    raise SystemExit(90)\n"
    "os.write(ready_fd, b'R')\n"
    "os.close(ready_fd)\n"
    "if stream.recv(1) == b'C':\n"
    "    with open(commit_path, 'xb') as output:\n"
    "        output.write(b'committed')\n"
    "    stream.sendall(b'COMMITTED\\n')\n"
)
inner_source = (
    "import os,subprocess,sys\n"
    f"payload_fd={payload_fd!r}\n"
    f"commit_path={commit_path!r}\n"
    f"direct_exit_code={direct_exit_code!r}\n"
    f"grandchild_source={grandchild_source!r}\n"
    "ready_read,ready_write=os.pipe()\n"
    "child=subprocess.Popen(\n"
    "    [sys.executable, '-c', grandchild_source, str(payload_fd), "
    "commit_path, str(ready_write)],\n"
    "    close_fds=True, pass_fds=(payload_fd,ready_write),\n"
    ")\n"
    "os.close(ready_write)\n"
    "if os.read(ready_read, 1) != b'R':\n"
    "    raise SystemExit(91)\n"
    "os.close(ready_read)\n"
    "os.close(payload_fd)\n"
    "if direct_exit_code >= 0:\n"
    "    raise SystemExit(direct_exit_code)\n"
    "if direct_exit_code < -1:\n"
    "    os.kill(os.getpid(), -direct_exit_code)\n"
    "raise SystemExit(child.wait())\n"
)
try:
    completed = _run_child_process(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "exec(compile(sys.stdin.buffer.read(), '<odoo-test-child>', 'exec'))"
            ),
        ],
        source=inner_source,
        payload_fd=payload_fd,
        timeout_seconds=timeout_seconds,
        cwd="/",
        env=dict(FIXED_CHILD_ENVIRONMENT),
    )
except OdooRunnerError as exc:
    os.write(payload_fd, f"RUNNER_ERROR:{exc}\n".encode("utf-8", "replace"))
    raise SystemExit(23)
os.write(
    payload_fd,
    f"CHILD_RESULT:{completed.returncode}\n".encode("utf-8", "replace"),
)
if completed.returncode < 0:
    os.kill(os.getpid(), -completed.returncode)
raise SystemExit(completed.returncode)
"""


def _start_nested_odoo_runner(
    commit_marker: Path,
    *,
    timeout_seconds: float,
    direct_exit_code: int = -1,
) -> tuple[subprocess.Popen[bytes], socket.socket]:
    control, inherited_control = socket.socketpair()
    caller = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _NESTED_ODOO_RUNNER_SOURCE,
            str(inherited_control.fileno()),
            str(commit_marker),
            str(timeout_seconds),
            str(direct_exit_code),
        ],
        close_fds=True,
        pass_fds=(inherited_control.fileno(),),
        start_new_session=True,
    )
    inherited_control.close()
    return caller, control


def _read_control_line(control: socket.socket, *, timeout_seconds: float) -> bytes:
    control.settimeout(timeout_seconds)
    result = bytearray()
    while not result.endswith(b"\n"):
        chunk = control.recv(128)
        assert chunk, f"nested process tree closed before a full message: {bytes(result)!r}"
        result.extend(chunk)
    return bytes(result)


def _ready_process_handles(control: socket.socket) -> tuple[int, int]:
    ready = _read_control_line(control, timeout_seconds=10.0)
    assert ready.startswith(b"READY:"), ready
    label, inner_pid_text, inner_group_text = ready.strip().split(b":")
    assert label == b"READY"
    inner_pid = int(inner_pid_text)
    inner_process_group = int(inner_group_text)
    assert inner_pid > 1
    assert inner_process_group != os.getpgrp()
    inner_pidfd = os.pidfd_open(inner_pid)
    try:
        group_leader_pidfd = os.pidfd_open(inner_process_group)
    except BaseException:
        os.close(inner_pidfd)
        raise
    control.sendall(b"A")
    return inner_pidfd, group_leader_pidfd


def _assert_tree_closed_without_commit(
    control: socket.socket, commit_marker: Path
) -> None:
    readable, _writable, _exceptional = select.select([control], [], [], 5.0)
    if not readable:
        # A surviving Odoo grandchild receives an explicit commit gate, making
        # the old orphan behavior observable without any timing sleep.
        control.sendall(b"C")
        evidence = _read_control_line(control, timeout_seconds=5.0)
        pytest.fail(
            "escaped Odoo grandchild survived and replied "
            f"{evidence!r}; commit_exists={commit_marker.exists()}"
        )
    assert control.recv(1) == b""
    assert not commit_marker.exists()


def _cleanup_nested_processes(
    caller: subprocess.Popen[bytes], process_pidfds: tuple[int, int] | None
) -> None:
    if caller.poll() is None:
        try:
            os.killpg(caller.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        caller.wait(timeout=5.0)
    if process_pidfds is not None:
        for descriptor in process_pidfds:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(descriptor)


@pytest.mark.skipif(
    sys.platform != "linux", reason="parent-death process-tree boundary is Linux-only"
)
def test_outer_historical_kill_cannot_leave_odoo_grandchild_to_commit(
    tmp_path: Path,
) -> None:
    """Kill a historical parent and prove an Odoo grandchild cannot commit."""

    commit_marker = tmp_path / "outer-timeout-orphan-commit"
    historical, control = _start_nested_odoo_runner(
        commit_marker, timeout_seconds=30.0
    )
    process_pidfds: tuple[int, int] | None = None
    try:
        process_pidfds = _ready_process_handles(control)
        os.killpg(historical.pid, signal.SIGKILL)
        historical.wait(timeout=5.0)
        _assert_tree_closed_without_commit(control, commit_marker)
    finally:
        control.close()
        _cleanup_nested_processes(historical, process_pidfds)


@pytest.mark.skipif(
    sys.platform != "linux", reason="Odoo timeout process-tree boundary is Linux-only"
)
def test_inner_runner_timeout_kills_odoo_grandchild_process_tree(
    tmp_path: Path,
) -> None:
    """Preserve runner timeout cleanup after adding the persistent supervisor."""

    commit_marker = tmp_path / "inner-timeout-orphan-commit"
    caller, control = _start_nested_odoo_runner(commit_marker, timeout_seconds=2.0)
    process_pidfds: tuple[int, int] | None = None
    try:
        process_pidfds = _ready_process_handles(control)
        error = _read_control_line(control, timeout_seconds=10.0)
        assert error == b"RUNNER_ERROR:Odoo shell timed out\n"
        assert caller.wait(timeout=5.0) == 23
        _assert_tree_closed_without_commit(control, commit_marker)
    finally:
        control.close()
        _cleanup_nested_processes(caller, process_pidfds)


@pytest.mark.skipif(
    sys.platform != "linux", reason="Odoo descendant reaping boundary is Linux-only"
)
@pytest.mark.parametrize("direct_exit_code", [0, 7, -9])
def test_direct_odoo_exit_reaps_daemonized_grandchild_and_preserves_status(
    tmp_path: Path, direct_exit_code: int
) -> None:
    """Do not report the direct child status until adopted descendants are gone."""

    commit_marker = tmp_path / f"direct-{direct_exit_code}-orphan-commit"
    caller, control = _start_nested_odoo_runner(
        commit_marker,
        timeout_seconds=5.0,
        direct_exit_code=direct_exit_code,
    )
    process_pidfds: tuple[int, int] | None = None
    try:
        process_pidfds = _ready_process_handles(control)
        result = _read_control_line(control, timeout_seconds=5.0)
        assert result == f"CHILD_RESULT:{direct_exit_code}\n".encode("ascii")
        assert caller.wait(timeout=5.0) == direct_exit_code
        _assert_tree_closed_without_commit(control, commit_marker)
    finally:
        control.close()
        _cleanup_nested_processes(caller, process_pidfds)


class CanonicalPackageVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "odoo-accounting-cli-v3.tar.gz"
        self.package.write_bytes(b"one immutable package")
        self.digest = hashlib.sha256(b"one immutable package").hexdigest()

    @staticmethod
    def _metadata(value, *, uid=0, writable=False, inode_delta=0):
        mode = value.st_mode | (0o020 if writable else 0)
        if not writable:
            mode &= ~0o022
        return SimpleNamespace(
            st_dev=value.st_dev,
            st_ino=value.st_ino + inode_delta,
            st_mode=mode,
            st_uid=uid,
        )

    @contextmanager
    def trusted_metadata(
        self,
        *,
        bad_ancestor: Path | None = None,
        bad_uid: int = 0,
        writable_ancestor: bool = False,
        opened_inode_delta: int = 0,
    ):
        real_lstat = Path.lstat
        real_fstat = os.fstat

        def lstat(path):
            observed = real_lstat(path)
            is_bad = bad_ancestor is not None and path == bad_ancestor
            return self._metadata(
                observed,
                uid=bad_uid if is_bad else 0,
                writable=writable_ancestor and is_bad,
            )

        def fstat(descriptor):
            return self._metadata(
                real_fstat(descriptor),
                inode_delta=opened_inode_delta,
            )

        with patch.object(Path, "lstat", autospec=True, side_effect=lstat), patch(
            "odoo_accounting_cli_v3.odoo.runner.os.fstat",
            side_effect=fstat,
        ):
            yield

    def verify(self, path: Path | None = None, digest: str | None = None) -> None:
        from odoo_accounting_cli_v3.odoo.runner import _verify_canonical_package

        _verify_canonical_package(path or self.package, digest or self.digest)

    def test_accepts_the_exact_regular_package_digest(self) -> None:
        with self.trusted_metadata():
            self.verify()

    def test_rejects_missing_package_and_wrong_digest(self) -> None:
        missing = self.package.with_name("missing.tar.gz")
        with self.trusted_metadata(), self.assertRaisesRegex(
            OdooRunnerError, "cannot be verified"
        ):
            self.verify(path=missing)

        with self.trusted_metadata(), self.assertRaisesRegex(
            OdooRunnerError, "digest does not match"
        ):
            self.verify(digest="0" * 64)

    def test_rejects_package_symlink(self) -> None:
        target = self.package.with_name("target.tar.gz")
        target.write_bytes(self.package.read_bytes())
        self.package.unlink()
        try:
            self.package.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.trusted_metadata(), self.assertRaisesRegex(
            OdooRunnerError, "not a regular canonical file"
        ):
            self.verify()

    @unittest.skipUnless(os.name == "posix", "POSIX ownership policy")
    def test_rejects_non_root_or_writable_ancestor(self) -> None:
        ancestor = self.package.parent
        conditions = (
            {"bad_uid": 1001},
            {"writable_ancestor": True},
        )
        for condition in conditions:
            with self.subTest(condition=condition), self.trusted_metadata(
                bad_ancestor=ancestor,
                **condition,
            ), self.assertRaisesRegex(OdooRunnerError, "ancestors are not root-managed"):
                self.verify()

    def test_rejects_opened_inode_that_differs_from_lstat(self) -> None:
        with self.trusted_metadata(opened_inode_delta=1), self.assertRaisesRegex(
            OdooRunnerError, "changed while it was opened"
        ):
            self.verify()


if __name__ == "__main__":
    unittest.main()
