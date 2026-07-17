from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from tools import build_release as release_builder


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
    }
)
EXECUTABLE_RELEASE_MEMBERS = LAUNCHERS | frozenset(
    {"deployment/dev9/run-private-mount-gate.sh"}
)
DEPLOYMENT_REFERENCED_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "deployment/dev9/README.md",
        "deployment/dev9/render-systemd-service.py",
        "deployment/dev9/run-private-mount-gate.sh",
        "deployment/dev11/README.md",
        "tools/build_release.py",
        "tools/check_source_boundary.py",
        "tools/verify_release.py",
    }
)
PRODUCTION_TOOL_IMPORT_CLOSURE = frozenset(
    {
        "tools/__init__.py",
        "tools/build_release.py",
        "tools/check_source_boundary.py",
        "tools/verify_release.py",
    }
)
PI_SCENARIO_ACCEPTANCE_RELEASE_MEMBERS = frozenset(
    {
        "tests/TEST.md",
        "tests/fixtures/pi_scenarios.v1.json",
        "tests/test_pi_scenario_gate.py",
        "tools/pi_scenario_gate.py",
    }
)
DEV9_SECURITY_RELEASE_MEMBERS = frozenset(
    {
        ".github/workflows/quality.yml",
        "deployment/dev11/README.md",
        "deployment/dev11/render-pi-bridge-service.py",
        "deployment/dev11/systemd/odoo-accounting-cli-v3-pi-bridge.service",
        "deployment/dev11/systemd/odoo-accounting-cli-v3-pi-bridge.socket",
        "deployment/dev9/README.md",
        "deployment/dev9/broker-runtime.example.json",
        "deployment/dev9/render-systemd-service.py",
        "deployment/dev9/run-private-mount-gate.sh",
        "deployment/dev9/systemd/odoo-accounting-cli-v3-broker.service",
        "deployment/dev9/systemd/odoo-accounting-cli-v3-pi-broker.socket",
        "deployment/dev9/systemd/odoo-accounting-cli-v3-session-mint.socket",
        "deployment/dev9/systemd/odoo-accounting-cli-v3-tmpfiles.conf",
        "deployment/dev9/systemd/odoo-accounting-cli-v3-trusted-approval.socket",
        "docs/HISTORICAL_RELEASE_ROUTING.md",
        "docs/TARGET_HOST_INCIDENT_2026-07-16.md",
        "docs/TRUSTED_APPROVAL_UDS.md",
        "docs/TRUSTED_SESSION_MINT_UDS.md",
        "pi_bridge/bootstrap.mjs",
        "pi_bridge/create-runtime-binding.mjs",
        "pi_bridge/odoo-session-header-resolver.mjs",
        "pi_bridge/release-binding.mjs",
        "pi_bridge/tests/bootstrap.test.mjs",
        "pi_bridge/tests/release-binding.test.mjs",
        "pi_bridge/tests/tool-policy.test.mjs",
        "pi_bridge/tool-policy.mjs",
        "src/odoo_accounting_cli_v3/broker_audit.py",
        "src/odoo_accounting_cli_v3/historical_router.py",
        "src/odoo_accounting_cli_v3/monotonic_deadline.py",
        "src/odoo_accounting_cli_v3/odoo_approver_authorizer.py",
        "src/odoo_accounting_cli_v3/sqlite_process_lifecycle.py",
        "src/odoo_accounting_cli_v3/systemd_activation.py",
        "src/odoo_accounting_cli_v3/trusted_approval_uds.py",
        "src/odoo_accounting_cli_v3/trusted_authority.py",
        "src/odoo_accounting_cli_v3/trusted_authority_bootstrap.py",
        "src/odoo_accounting_cli_v3/trusted_authority_sqlite.py",
        "src/odoo_accounting_cli_v3/trusted_broker.py",
        "src/odoo_accounting_cli_v3/trusted_broker_app.py",
        "src/odoo_accounting_cli_v3/trusted_broker_main.py",
        "src/odoo_accounting_cli_v3/trusted_broker_uds.py",
        "src/odoo_accounting_cli_v3/trusted_idempotency.py",
        "src/odoo_accounting_cli_v3/trusted_read.py",
        "src/odoo_accounting_cli_v3/trusted_response_verifier.py",
        "src/odoo_accounting_cli_v3/trusted_session_mint_uds.py",
        "src/odoo_accounting_cli_v3/trusted_session_sqlite.py",
        "src/odoo_accounting_cli_v3/verified_release.py",
        "tests/test_broker_audit.py",
        "tests/test_dev11_pi_bridge_systemd.py",
        "tests/test_dev9_systemd_units.py",
        "tests/test_dev9_private_mount_gate.py",
        "tests/test_historical_release_router.py",
        "tests/test_monotonic_deadline.py",
        "tests/test_odoo_approver_authorizer.py",
        "tests/test_sqlite_process_lifecycle.py",
        "tests/test_systemd_activation.py",
        "tests/test_trusted_approval_uds.py",
        "tests/test_trusted_authority.py",
        "tests/test_trusted_authority_bootstrap.py",
        "tests/test_trusted_authority_sqlite.py",
        "tests/test_trusted_broker.py",
        "tests/test_trusted_broker_app.py",
        "tests/test_trusted_broker_main.py",
        "tests/test_trusted_broker_uds.py",
        "tests/test_trusted_idempotency.py",
        "tests/test_trusted_read.py",
        "tests/test_trusted_response_verifier.py",
        "tests/test_trusted_session_mint_uds.py",
        "tests/test_trusted_session_sqlite.py",
        "tests/test_verified_release.py",
    }
)
DEV15_READ_TOOLCHAIN_RELEASE_MEMBERS = frozenset(
    {
        "deployment/dev15/README.md",
        "deployment/dev15/TOOLCHAIN-MANIFEST.json",
        "deployment/dev15/check_toolchain.py",
        "deployment/dev15/install_toolchain.py",
        "deployment/dev15/runtime_setup.py",
        "deployment/dev15/sign_read.py",
        "deployment/dev15/run_multicurrency_read.py",
        "deployment/dev15/multicurrency_sql_oracle.py",
        "deployment/dev15/verify_evidence.py",
        "deployment/dev15/read_plan.json",
    }
)
WRITE_RUNTIME_RELEASE_MEMBERS = frozenset(
    {
        "VERSION",
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "docs/DEPLOYMENT.md",
        "docs/RUNTIME_CONFIGURATION.md",
        "pyproject.toml",
        "registry/capabilities.json",
        "src/odoo_accounting_cli_v3/__init__.py",
        "src/odoo_accounting_cli_v3/audit.py",
        "src/odoo_accounting_cli_v3/auth.py",
        "src/odoo_accounting_cli_v3/cli.py",
        "src/odoo_accounting_cli_v3/contracts.py",
        "src/odoo_accounting_cli_v3/draft_invoice_recovery.py",
        "src/odoo_accounting_cli_v3/domain/__init__.py",
        "src/odoo_accounting_cli_v3/domain/ap_open_items.py",
        "src/odoo_accounting_cli_v3/domain/ar_open_items.py",
        "src/odoo_accounting_cli_v3/domain/multicurrency_balance.py",
        "src/odoo_accounting_cli_v3/domain/trial_balance.py",
        "src/odoo_accounting_cli_v3/domain/write_semantics.py",
        "src/odoo_accounting_cli_v3/gateway.py",
        "src/odoo_accounting_cli_v3/odoo/__init__.py",
        "src/odoo_accounting_cli_v3/odoo/ap_open_items.py",
        "src/odoo_accounting_cli_v3/odoo/ar_open_items.py",
        "src/odoo_accounting_cli_v3/odoo/bootstrap.py",
        "src/odoo_accounting_cli_v3/odoo/executor.py",
        "src/odoo_accounting_cli_v3/odoo/multicurrency_balance.py",
        "src/odoo_accounting_cli_v3/odoo/runner.py",
        "src/odoo_accounting_cli_v3/odoo/trial_balance.py",
        "src/odoo_accounting_cli_v3/odoo/write_bootstrap.py",
        "src/odoo_accounting_cli_v3/odoo/write_handlers.py",
        "src/odoo_accounting_cli_v3/odoo/write_precheck.py",
        "src/odoo_accounting_cli_v3/odoo/write_runner.py",
        "src/odoo_accounting_cli_v3/operations.py",
        "src/odoo_accounting_cli_v3/persistence.py",
        "src/odoo_accounting_cli_v3/receipts.py",
        "src/odoo_accounting_cli_v3/registry.py",
        "src/odoo_accounting_cli_v3/release.py",
        "src/odoo_accounting_cli_v3/write_api.py",
        "src/odoo_accounting_cli_v3/write_app.py",
        "src/odoo_accounting_cli_v3/write_protocol.py",
        "src/odoo_accounting_cli_v3/write_receipts.py",
        "src/odoo_accounting_cli_v3/write_runtime.py",
        "src/odoo_accounting_cli_v3/write_service.py",
        "tests/test_auth.py",
        "tests/test_accounting_metadata_guard.py",
        "tests/test_cli_write.py",
        "tests/test_gateway.py",
        "tests/test_multicurrency_balance.py",
        "tests/test_odoo_approval_client.py",
        "tests/test_odoo_approval_wizard.py",
        "tests/test_odoo_bootstrap.py",
        "tests/test_odoo_control_addon.py",
        "tests/test_odoo_multicurrency_balance_backend.py",
        "tests/test_odoo_release_binding.py",
        "tests/test_odoo_session_client.py",
        "tests/test_odoo_write_bootstrap.py",
        "tests/test_odoo_write_handlers.py",
        "tests/test_odoo_write_precheck.py",
        "tests/test_odoo_write_runner.py",
        "tests/test_operations.py",
        "tests/test_persistence.py",
        "tests/test_pi_bridge_source.py",
        "tests/test_registry.py",
        "tests/test_source_boundary.py",
        "tests/test_write_api.py",
        "tests/test_write_app.py",
        "tests/test_write_protocol.py",
        "tests/test_write_receipts.py",
        "tests/test_write_registry_contracts.py",
        "tests/test_write_runtime.py",
        "tests/test_write_semantics.py",
        "tests/test_write_service.py",
        "tools/build_release.py",
        "tools/check_source_boundary.py",
        "tools/__init__.py",
        "tools/verify_release.py",
        "odoo_addons/odoo_accounting_cli_v3_control/__init__.py",
        "odoo_addons/odoo_accounting_cli_v3_control/__manifest__.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/__init__.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/accounting_metadata.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/approval_client.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/approval_wizard.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/execution_scope.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/operation.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/release_binding.py",
        "odoo_addons/odoo_accounting_cli_v3_control/models/session_client.py",
        "odoo_addons/odoo_accounting_cli_v3_control/security/ir.model.access.csv",
        "odoo_addons/odoo_accounting_cli_v3_control/security/odoo_accounting_cli_v3_security.xml",
        "odoo_addons/odoo_accounting_cli_v3_control/views/approval_wizard_views.xml",
        "pi_bridge/extensions/odoo-tools.ts",
        "pi_bridge/extensions/odoo-v3-cli.mjs",
        "pi_bridge/package-lock.json",
        "pi_bridge/package.json",
        "pi_bridge/README.md",
        "pi_bridge/server.mjs",
        "pi_bridge/tests/odoo-v3-cli.test.mjs",
        "pi_bridge/tests/trusted-broker.test.mjs",
        "pi_bridge/trusted-session.mjs",
    }
)
REQUIRED_WRITE_RELEASE_MEMBERS = (
    DEV15_READ_TOOLCHAIN_RELEASE_MEMBERS
    | DEV9_SECURITY_RELEASE_MEMBERS
    | PI_SCENARIO_ACCEPTANCE_RELEASE_MEMBERS
    | WRITE_RUNTIME_RELEASE_MEMBERS
)


class ReleaseArchiveTest(unittest.TestCase):
    def test_dev9_security_runtime_and_evidence_are_explicit_release_members(
        self,
    ) -> None:
        missing_sources = {
            name
            for name in DEV9_SECURITY_RELEASE_MEMBERS
            if not (PROJECT_ROOT / name).is_file()
        }
        self.assertFalse(
            missing_sources,
            "declared Dev9 security runtime or evidence is absent from source: "
            f"{sorted(missing_sources)}",
        )

        production_trees = (
            "deployment/dev15",
            "deployment/dev9",
            "odoo_addons/odoo_accounting_cli_v3_control",
            "pi_bridge",
            "src/odoo_accounting_cli_v3",
        )
        discovered = set(
            subprocess.run(
                [
                    "git",
                    "ls-files",
                    "-co",
                    "--exclude-standard",
                    "--",
                    *production_trees,
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                check=True,
                text=True,
                encoding="utf-8",
            ).stdout.splitlines()
        )
        discovered.update(PRODUCTION_TOOL_IMPORT_CLOSURE)
        for pattern in (
            "src/odoo_accounting_cli_v3/trusted_*.py",
            "src/odoo_accounting_cli_v3/write_*.py",
            "src/odoo_accounting_cli_v3/odoo/write_*.py",
            "src/odoo_accounting_cli_v3/domain/write_semantics.py",
            "src/odoo_accounting_cli_v3/broker_audit.py",
            "src/odoo_accounting_cli_v3/historical_router.py",
            "src/odoo_accounting_cli_v3/monotonic_deadline.py",
            "src/odoo_accounting_cli_v3/odoo_approver_authorizer.py",
            "src/odoo_accounting_cli_v3/systemd_activation.py",
            "src/odoo_accounting_cli_v3/verified_release.py",
        ):
            discovered.update(
                path.relative_to(PROJECT_ROOT).as_posix()
                for path in PROJECT_ROOT.glob(pattern)
                if path.is_file()
            )
        undeclared = discovered - REQUIRED_WRITE_RELEASE_MEMBERS
        self.assertFalse(
            undeclared,
            "production asset is not an explicit canonical release member: "
            f"{sorted(undeclared)}",
        )

    def test_dev15_read_toolchain_is_an_exact_release_member_set(self) -> None:
        directory = PROJECT_ROOT / "deployment" / "dev15"
        discovered = {
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in directory.iterdir()
            if path.is_file() and not path.name.endswith((".pyc", ".pyo"))
        }
        self.assertEqual(discovered, DEV15_READ_TOOLCHAIN_RELEASE_MEMBERS)
        self.assertTrue(
            DEV15_READ_TOOLCHAIN_RELEASE_MEMBERS.issubset(
                REQUIRED_WRITE_RELEASE_MEMBERS
            )
        )

    def test_deployment_document_references_only_declared_release_dependencies(
        self,
    ) -> None:
        deployment = (PROJECT_ROOT / "docs" / "DEPLOYMENT.md").read_text("utf-8")
        for name in DEPLOYMENT_REFERENCED_RELEASE_MEMBERS:
            with self.subTest(name=name):
                self.assertIn(name, deployment)
                self.assertIn(name, REQUIRED_WRITE_RELEASE_MEMBERS)
                self.assertTrue((PROJECT_ROOT / name).is_file())

    def test_release_rejects_credentials_and_host_local_runtime_state(self) -> None:
        private_key = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nprivate\n"
        github_token = ("gh" + "p_" + "A" * 36).encode("ascii")
        candidates = (
            (Path("local/.env.production"), b"PLACEHOLDER=1"),
            (Path("local/id_ed25519"), b"private"),
            (Path("local/private.pem"), b"private"),
            (Path("local/private.ppk"), b"private"),
            (Path("local/write-runtime.json"), b"{}"),
            (Path("local/pi-attestation-keys.json"), b"{}"),
            (Path("local/state.sqlite3"), b"SQLite format 3"),
            (Path("local/state.sqlite3-wal"), b"mutable"),
            (Path("local/state.db"), b"SQLite format 3\x00mutable"),
            (Path("local/non-sqlite.db"), b"not a SQLite database"),
            (Path("docs/private-key.txt"), private_key),
            (Path("docs/token.txt"), github_token),
        )
        for relative, payload in candidates:
            with self.subTest(relative=relative):
                with self.assertRaises(release_builder.ReleaseError):
                    release_builder.validate_release_member(relative, payload)

        with self.assertRaises(release_builder.ReleaseError):
            release_builder.validate_release_member(
                Path("local/custom-trusted-capture.json"),
                json.dumps(
                    {
                        "schema_version": (
                            "odoo-accounting-cli-v3.pi-attestation-keys.v1"
                        ),
                        "keys": {"capture-v1": {"secret_hex": "a" * 64}},
                    }
                ).encode("utf-8"),
            )

        release_builder.validate_release_member(
            Path("deployment/dev9/broker-runtime.example.json"),
            b'{"current_release_digest":"' + b"a" * 64 + b'"}',
        )

    def test_gitignore_covers_host_local_release_inputs(self) -> None:
        ignored = set((PROJECT_ROOT / ".gitignore").read_text("utf-8").splitlines())
        self.assertTrue(
            {
                ".env",
                ".env.*",
                "*.key",
                "*.pem",
                "*.ppk",
                "id_ecdsa_sk",
                "id_ed25519_sk",
                "*.db",
                "*.sqlite3",
                "*.sqlite3-wal",
                "**/authority-runtime.json",
                "**/broker-runtime.json",
                "**/read-runtime.json",
                "**/write-runtime.json",
                "**/pi-attestation-keys*.json",
            }.issubset(ignored)
        )
        for name in (
            ".env.production",
            "local/private.pem",
            "local/private.ppk",
            "local/id_ed25519_sk",
            "local/state.db",
            "local/state.sqlite3-wal",
            "local/write-runtime.json",
            "local/broker-runtime.json",
            "local/pi-attestation-keys.json",
            "local/pi-attestation-keys-v2.json",
        ):
            with self.subTest(name=name):
                completed = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", "--", name],
                    cwd=PROJECT_ROOT,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0)

    def test_clean_commit_build_is_deterministic_and_normalizes_archive_metadata(
        self,
    ) -> None:
        listed = subprocess.run(
            ["git", "ls-files", "-co", "--exclude-standard"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        ).stdout.splitlines()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            for name in dict.fromkeys(listed):
                source = PROJECT_ROOT / name
                if source.is_file():
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
            for command in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "release-test@example.invalid"],
                ["git", "config", "user.name", "Release Test"],
                ["git", "add", "--all"],
                ["git", "commit", "-qm", "release test"],
            ):
                subprocess.run(command, cwd=root, check=True, capture_output=True)

            environment = {**os.environ, "PYTHONPATH": str(root / "src")}

            def build() -> tuple[dict, bytes]:
                completed = subprocess.run(
                    [sys.executable, "tools/build_release.py"],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    check=True,
                    text=True,
                    encoding="utf-8",
                )
                identity = json.loads(completed.stdout)
                payload = Path(identity["package"]).read_bytes()
                self.assertEqual(
                    identity["package_sha256"], hashlib.sha256(payload).hexdigest()
                )
                return identity, payload

            first_identity, first_payload = build()
            second_identity, second_payload = build()
            self.assertEqual(first_identity, second_identity)
            self.assertEqual(first_payload, second_payload)

            with tarfile.open(fileobj=io.BytesIO(first_payload), mode="r:gz") as archive:
                members = archive.getmembers()
                member_names = {member.name for member in members}
                expected = set(
                    subprocess.run(
                        ["git", "ls-files"],
                        cwd=root,
                        capture_output=True,
                        check=True,
                        text=True,
                        encoding="utf-8",
                    ).stdout.splitlines()
                ) | {"RELEASE-MANIFEST.json"}
                self.assertEqual(member_names, expected)
                missing_write_members = REQUIRED_WRITE_RELEASE_MEMBERS - member_names
                self.assertFalse(
                    missing_write_members,
                    "canonical release is missing required production members: "
                    f"{sorted(missing_write_members)}",
                )
                for member in members:
                    with self.subTest(member=member.name):
                        self.assertTrue(member.isreg())
                        self.assertEqual(member.uid, 0)
                        self.assertEqual(member.gid, 0)
                        self.assertEqual(member.uname, "root")
                        self.assertEqual(member.gname, "root")
                        self.assertEqual(member.mtime, 0)
                        self.assertEqual(
                            member.mode,
                            0o755
                            if member.name in EXECUTABLE_RELEASE_MEMBERS
                            else 0o644,
                        )
                for launcher_name in LAUNCHERS:
                    launcher = archive.extractfile(launcher_name)
                    self.assertIsNotNone(launcher)
                    launcher_bytes = launcher.read()
                    self.assertTrue(
                        launcher_bytes.startswith(b"#!/usr/bin/python3 -I\n")
                    )
                    self.assertNotIn(b"\r", launcher_bytes)

                if os.name == "posix":
                    candidate = Path(directory) / "installed-release"
                    archive.extractall(candidate, filter="data")
                    paths = [candidate, *candidate.rglob("*")]
                    for path in paths:
                        if path.is_file():
                            path.chmod(0o444)
                    for executable_name in EXECUTABLE_RELEASE_MEMBERS:
                        (candidate / executable_name).chmod(0o555)
                    for path in sorted(
                        (item for item in paths if item.is_dir()),
                        key=lambda item: len(item.parts),
                        reverse=True,
                    ):
                        path.chmod(0o555)

                    broker = candidate / "bin" / "odoo-accounting-cli-v3-broker"
                    try:
                        completed = subprocess.run(
                            [str(broker), "--help"],
                            cwd=Path(directory),
                            env={
                                "HOME": "/tmp",
                                "LANG": "C.UTF-8",
                                "LC_ALL": "C.UTF-8",
                                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                "PYTHONDONTWRITEBYTECODE": "1",
                                "PYTHONNOUSERSITE": "1",
                                "TZ": "UTC",
                            },
                            capture_output=True,
                            check=False,
                            text=True,
                            encoding="utf-8",
                            timeout=10,
                        )
                    finally:
                        for path in (item for item in paths if item.is_dir()):
                            path.chmod(0o755)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stderr, "")
                    self.assertIn(
                        "usage: odoo-accounting-cli-v3-broker --config ABSOLUTE_PATH",
                        completed.stdout.splitlines(),
                    )

    def test_release_rejects_clean_filtered_bytes_that_differ_from_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            (root / ".gitattributes").write_bytes(b"* text=auto eol=lf\n")
            source = root / "source.txt"
            source.write_bytes(b"first\nsecond\n")
            for command in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "release-test@example.invalid"],
                ["git", "config", "user.name", "Release Test"],
                ["git", "add", "--all"],
                ["git", "commit", "-qm", "release byte test"],
            ):
                subprocess.run(command, cwd=root, check=True, capture_output=True)

            source.write_bytes(b"first\r\nsecond\r\n")
            subprocess.run(
                ["git", "add", "--", "source.txt"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            self.assertEqual(status.stdout, b"")
            head_blob = subprocess.run(
                ["git", "rev-parse", "HEAD:source.txt"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            index_blob = subprocess.run(
                ["git", "rev-parse", ":source.txt"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            self.assertEqual(index_blob, head_blob)
            self.assertIn(b"\r\n", source.read_bytes())

            with mock.patch.object(release_builder, "ROOT", root):
                sources = release_builder.tracked_sources()
                with self.assertRaisesRegex(
                    release_builder.ReleaseError,
                    "worktree bytes differ from committed blob: source.txt",
                ):
                    release_builder.committed_source_payloads(sources)


if __name__ == "__main__":
    unittest.main()
