from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.release import ReleaseIdentity, source_manifest
from tools.build_release import tracked_sources


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_RELATIVE = Path("bin/odoo-accounting-cli-v3")
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class ReleaseLauncherTest(unittest.TestCase):
    def test_launcher_is_a_manifest_covered_release_file(self) -> None:
        launcher = PROJECT_ROOT / LAUNCHER_RELATIVE

        self.assertTrue(launcher.is_file())
        self.assertIn(launcher, tracked_sources())
        manifest = source_manifest(
            PROJECT_ROOT,
            [launcher],
            ReleaseIdentity("1.2.3", COMMIT),
        )
        self.assertEqual(
            [item["path"] for item in manifest["files"]],
            [LAUNCHER_RELATIVE.as_posix()],
        )

    def test_launcher_uses_its_exact_release_from_any_cwd_without_losing_io(
        self,
    ) -> None:
        launcher_source = PROJECT_ROOT / LAUNCHER_RELATIVE
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_root = root / "releases" / "1.2.3-0123456789ab"
            launcher = release_root / LAUNCHER_RELATIVE
            package = release_root / "src" / "odoo_accounting_cli_v3"
            attacker_root = root / "attacker-cwd"
            attacker_package = attacker_root / "odoo_accounting_cli_v3"
            attacker_marker = root / "sitecustomize-ran"
            package.mkdir(parents=True)
            attacker_package.mkdir(parents=True)
            launcher.parent.mkdir(parents=True)
            launcher.write_bytes(launcher_source.read_bytes())
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "cli.py").write_text(
                """\
import json
import sys
from pathlib import Path


def main():
    print(json.dumps({
        "argv": sys.argv,
        "cli_file": str(Path(__file__).resolve()),
        "stdin": sys.stdin.read(),
        "source": "release",
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
""",
                encoding="utf-8",
            )
            (attacker_package / "__init__.py").write_text("", encoding="utf-8")
            (attacker_package / "cli.py").write_text(
                'raise AssertionError("cwd/PYTHONPATH package was imported")\n',
                encoding="utf-8",
            )
            (attacker_root / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(attacker_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )

            arguments = [
                "read",
                "--runtime-config",
                "/etc/odoo-accounting-cli-v3/runtime test.json",
                "--request-json",
                '{"date":"2026-07-14","supplier":"东京 供应商"}',
            ]
            input_text = '{"stdin":"完整 参数 ✓"}\n'
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONPATH": str(attacker_root),
                "PYTHONUTF8": "1",
            }
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    "utf8",
                    str(launcher),
                    *arguments,
                ],
                cwd=attacker_root,
                env=environment,
                input=input_text,
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertFalse(attacker_marker.exists())
            observed = json.loads(completed.stdout)
            self.assertEqual(observed["source"], "release")
            self.assertEqual(observed["argv"], [str(launcher), *arguments])
            self.assertEqual(observed["stdin"], input_text)
            self.assertEqual(
                Path(observed["cli_file"]),
                (package / "cli.py").resolve(),
            )
            self.assertTrue(
                Path(observed["cli_file"]).is_relative_to(release_root.resolve())
            )

    def test_launcher_rejects_a_symlink_entry_path(self) -> None:
        launcher = PROJECT_ROOT / LAUNCHER_RELATIVE
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "odoo-accounting-cli-v3"
            try:
                link.symlink_to(launcher)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(link), "--version"],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "")
            self.assertIn("must not be reached through a symlink", completed.stderr)

    def test_launcher_rejects_a_nonisolated_interpreter(self) -> None:
        launcher = PROJECT_ROOT / LAUNCHER_RELATIVE
        completed = subprocess.run(
            [sys.executable, str(launcher), "--version"],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("requires Python isolated mode", completed.stderr)

    @unittest.skipUnless(os.name == "posix", "direct launcher execution is POSIX-only")
    def test_launcher_is_directly_executable_in_isolated_mode(self) -> None:
        launcher = PROJECT_ROOT / LAUNCHER_RELATIVE
        completed = subprocess.run(
            [str(launcher), "--version"],
            cwd=Path(tempfile.gettempdir()),
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("odoo-accounting-cli-v3, version ", completed.stdout)


if __name__ == "__main__":
    unittest.main()
