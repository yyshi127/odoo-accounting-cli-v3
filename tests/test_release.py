import tempfile
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.release import ReleaseError, ReleaseIdentity, source_manifest, verify_manifest


COMMIT = "0123456789abcdef0123456789abcdef01234567"


class ReleaseTest(unittest.TestCase):
    def test_package_name_contains_version_and_commit(self) -> None:
        identity = ReleaseIdentity("1.2.3", COMMIT)
        self.assertEqual(identity.package_name, "odoo-accounting-cli-v3-1.2.3-0123456789ab.tar.gz")

    def test_manifest_detects_changed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            verify_manifest(root, manifest)
            source.write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "file mismatch"):
                verify_manifest(root, manifest)

    def test_manifest_digest_detects_metadata_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            manifest["version"] = "9.9.9"
            with self.assertRaisesRegex(ReleaseError, "manifest digest mismatch"):
                verify_manifest(root, manifest)

    def test_source_cannot_escape_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "secret.txt"
            external.write_text("secret", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "escapes"):
                source_manifest(root, [external], ReleaseIdentity("1.2.3", COMMIT))


if __name__ == "__main__":
    unittest.main()
