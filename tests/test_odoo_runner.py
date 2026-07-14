import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from odoo_accounting_cli_v3.odoo.runner import (
    FIXED_CHILD_ENVIRONMENT,
    OdooRunnerError,
    RuntimeConfig,
    _child_main,
    _record_verified_read_audit,
    _verify_child_release,
    load_runtime_config,
    run_odoo_shell,
)
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.release import ReleaseIdentity, source_manifest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
AUTH_SECRET = b"test-only-auth-secret-32-bytes!!"
RECEIPT_SECRET = b"test-only-receipt-secret-32-byte"
AUTH_KEY_ID = "test-auth-2026-07"
RECEIPT_KEY_ID = "test-receipt-2026-07"
RELEASE_DIGEST = "d" * 64
MARKER_TOKEN = "1" * 48
MARKER = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{MARKER_TOKEN}__:"


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


def response(runtime, result=None):
    return json.dumps(
        {"ok": True, "runtime": runtime, "result": result or {"verified": True}},
        ensure_ascii=False,
        separators=(",", ":"),
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
        self.auth_secret_path.write_bytes(AUTH_SECRET)
        self.receipt_secret_path.write_bytes(RECEIPT_SECRET)

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
            ],
        )
        self.assertEqual(options["timeout_seconds"], 17.0)
        self.assertEqual(options["env"], FIXED_CHILD_ENVIRONMENT)
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
        with self.assertRaisesRegex(OdooRunnerError, "status 2"):
            self.execute()

        run.side_effect = OdooRunnerError("Odoo shell timed out")
        with self.assertRaisesRegex(OdooRunnerError, "timed out"):
            self.execute()

        run.side_effect = OdooRunnerError("Odoo shell could not be started")
        with self.assertRaisesRegex(OdooRunnerError, "could not be started"):
            self.execute()

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
