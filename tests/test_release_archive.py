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
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = "bin/odoo-accounting-cli-v3"


class ReleaseArchiveTest(unittest.TestCase):
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
                self.assertEqual({member.name for member in members}, expected)
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
                            0o755 if member.name == LAUNCHER else 0o644,
                        )
                launcher = archive.extractfile(LAUNCHER)
                self.assertIsNotNone(launcher)
                launcher_bytes = launcher.read()
                self.assertTrue(launcher_bytes.startswith(b"#!/usr/bin/python3 -I\n"))
                self.assertNotIn(b"\r", launcher_bytes)


if __name__ == "__main__":
    unittest.main()
