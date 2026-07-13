import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.release import ReleaseError, ReleaseIdentity, source_manifest, verify_manifest


COMMIT = "0123456789abcdef0123456789abcdef01234567"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
            anchor = manifest["manifest_sha256"]
            verify_manifest(root, manifest, expected_manifest_sha256=anchor)
            source.write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "file mismatch"):
                verify_manifest(root, manifest, expected_manifest_sha256=anchor)

    def test_manifest_digest_detects_metadata_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            anchor = manifest["manifest_sha256"]
            manifest["version"] = "9.9.9"
            with self.assertRaisesRegex(ReleaseError, "manifest digest mismatch"):
                verify_manifest(root, manifest, expected_manifest_sha256=anchor)

    def test_source_cannot_escape_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "secret.txt"
            external.write_text("secret", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "escapes"):
                source_manifest(root, [external], ReleaseIdentity("1.2.3", COMMIT))

    def test_manifest_rejects_unlisted_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            anchor = manifest["manifest_sha256"]
            (root / "unlisted.py").write_text("print('unexpected')", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "file set mismatch"):
                verify_manifest(root, manifest, expected_manifest_sha256=anchor)

    def test_manifest_rejects_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            anchor = manifest["manifest_sha256"]
            manifest["files"].append(dict(manifest["files"][0]))
            unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
            import hashlib
            import json
            manifest["manifest_sha256"] = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            with self.assertRaisesRegex(ReleaseError, "external trust anchor"):
                verify_manifest(root, manifest, expected_manifest_sha256=anchor)

    def test_recomputed_manifest_cannot_replace_external_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("original", encoding="utf-8")
            manifest = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            anchor = manifest["manifest_sha256"]

            source.write_text("attacker replacement", encoding="utf-8")
            forged = source_manifest(root, [source], ReleaseIdentity("1.2.3", COMMIT))
            with self.assertRaisesRegex(ReleaseError, "external trust anchor"):
                verify_manifest(root, forged, expected_manifest_sha256=anchor)

    def test_verifier_does_not_invalidate_release_with_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "src" / "odoo_accounting_cli_v3"
            tools = root / "tools"
            package.mkdir(parents=True)
            tools.mkdir()
            sources = []
            for relative in (
                Path("src/odoo_accounting_cli_v3/__init__.py"),
                Path("src/odoo_accounting_cli_v3/release.py"),
                Path("tools/verify_release.py"),
            ):
                destination = root / relative
                shutil.copy2(PROJECT_ROOT / relative, destination)
                sources.append(destination)
            manifest = source_manifest(
                root, sources, ReleaseIdentity("1.2.3", COMMIT)
            )
            (root / "RELEASE-MANIFEST.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            environment = {**os.environ, "PYTHONPATH": str(root / "src")}
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(tools / "verify_release.py"),
                    str(root),
                    manifest["manifest_sha256"],
                ],
                capture_output=True,
                check=False,
                text=True,
                env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(list(root.rglob("__pycache__")), [])


if __name__ == "__main__":
    unittest.main()
