import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from odoo_accounting_cli_v3.cli import CliFailure, _load_release_identity, main
from odoo_accounting_cli_v3.registry import load_registry, registry_digest
from odoo_accounting_cli_v3.release import ReleaseIdentity, source_manifest


COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _installed_release(base: Path):
    root = base / "releases" / "1.2.3-0123456789ab"
    registry_path = root / "registry" / "capabilities.json"
    registry_path.parent.mkdir(parents=True)
    source_registry = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
    registry_path.write_bytes(source_registry.read_bytes())
    version_path = root / "VERSION"
    version_path.write_text("1.2.3\n", encoding="utf-8")
    manifest = source_manifest(
        root,
        [registry_path, version_path],
        ReleaseIdentity("1.2.3", COMMIT),
    )
    (root / "RELEASE-MANIFEST.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    anchors = base / "trusted-artifacts"
    anchors.mkdir()
    (anchors / f"{root.name}.json").write_text(
        json.dumps(
            {
                "commit": COMMIT,
                "manifest_sha256": manifest["manifest_sha256"],
                "package_sha256": "a" * 64,
                "release": root.name,
            }
        ),
        encoding="utf-8",
    )
    return root, manifest, registry_path


class CliReleaseIdentityTest(unittest.TestCase):
    def test_external_anchor_and_release_files_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, _manifest, registry_path = _installed_release(base)

            identity = _load_release_identity(root)

            self.assertTrue(identity["verified"])
            self.assertEqual(identity["version"], "1.2.3")
            self.assertEqual(
                identity["registry_digest"],
                registry_digest(load_registry(registry_path)),
            )

    def test_anchor_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "releases" / "missing"
            root.mkdir(parents=True)
            with self.assertRaisesRegex(CliFailure, "unavailable"):
                _load_release_identity(root)

    def test_current_route_reports_verified_expected_release(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, manifest, registry_path = _installed_release(base)
            current = base / "current"
            try:
                current.symlink_to(root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            result = CliRunner().invoke(
                main,
                [
                    "release",
                    "current-route",
                    "--current-path",
                    str(current),
                    "--expected-release",
                    root.name,
                    "--expected-commit",
                    COMMIT,
                    "--expected-manifest-sha256",
                    manifest["manifest_sha256"],
                    "--expected-package-sha256",
                    "a" * 64,
                    "--expected-registry-digest",
                    registry_digest(load_registry(registry_path)),
                ],
            )

            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.output)
            self.assertTrue(payload["data"]["current_route_ready"])
            self.assertEqual(payload["data"]["blockers"], [])
            self.assertEqual(payload["data"]["resolved_release_path"], str(root.resolve()))

    def test_current_route_reports_expected_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, _manifest, _registry_path = _installed_release(base)
            current = base / "current"
            try:
                current.symlink_to(root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            result = CliRunner().invoke(
                main,
                [
                    "release",
                    "current-route",
                    "--current-path",
                    str(current),
                    "--expected-commit",
                    "f" * 40,
                ],
            )

            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.output)
            self.assertFalse(payload["data"]["current_route_ready"])
            self.assertEqual(
                payload["data"]["blockers"],
                ["current route commit does not match expected value"],
            )


if __name__ == "__main__":
    unittest.main()
