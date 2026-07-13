from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.odoo.runner import (
    FIXED_CHILD_ENVIRONMENT,
    MAX_CHILD_STDERR_BYTES,
    MAX_CHILD_STDOUT_BYTES,
    OdooRunnerError,
    _private_payload_fd,
    _run_child_process,
)


LINUX_GATE = os.environ.get("ODOO_CLI_V3_LINUX_GATE") == "1"


@unittest.skipUnless(LINUX_GATE, "set ODOO_CLI_V3_LINUX_GATE=1 on the target Linux runtime")
class LinuxRunnerGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "posix":
            raise AssertionError("the target runner gate requires POSIX")
        if os.geteuid() == 0:
            raise AssertionError("the target runner gate must run as the non-root Odoo service user")
        if not hasattr(os, "memfd_create"):
            raise AssertionError("the target runner gate requires memfd_create")
        if not Path(FIXED_CHILD_ENVIRONMENT["HOME"]).is_dir():
            raise AssertionError("the fixed Odoo HOME directory does not exist")

    def run_helper(
        self,
        code: str,
        *,
        payload: bytes = b"linux-runner-gate-payload-32-bytes",
        arguments: tuple[str, ...] = (),
        timeout_seconds: float = 10.0,
    ):
        with _private_payload_fd(payload) as payload_fd:
            return _run_child_process(
                [sys.executable, "-c", code, str(payload_fd), *arguments],
                source="# fixed runner gate bootstrap\n",
                payload_fd=payload_fd,
                timeout_seconds=timeout_seconds,
                cwd=tempfile.gettempdir(),
                env=dict(FIXED_CHILD_ENVIRONMENT),
            )

    def test_sealed_payload_crosses_exec_without_argv_env_or_stdin_exposure(self) -> None:
        import fcntl

        sentinel = secrets.token_bytes(32)
        payload = sentinel + b"|2026-01-01|supplier_id|currency_id"
        with _private_payload_fd(payload) as payload_fd:
            seals = fcntl.fcntl(payload_fd, fcntl.F_GET_SEALS)
            required = (
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE
            )
            self.assertEqual(seals & required, required)
            for mutation in (
                lambda: os.pwrite(payload_fd, b"x", 0),
                lambda: os.ftruncate(payload_fd, 0),
            ):
                with self.assertRaises(OSError) as rejected:
                    mutation()
                self.assertEqual(rejected.exception.errno, errno.EPERM)

            code = (
                "import hashlib,json,os,sys;"
                "fd=int(sys.argv[1]);"
                "payload=os.read(fd,1048577);"
                "sentinel=payload[:32];"
                "cmd=open('/proc/self/cmdline','rb').read();"
                "env=open('/proc/self/environ','rb').read();"
                "bootstrap=sys.stdin.buffer.read();"
                "print(json.dumps({'digest':hashlib.sha256(payload).hexdigest(),"
                "'cmd_hits':cmd.count(sentinel),'env_hits':env.count(sentinel),"
                "'stdin_hits':bootstrap.count(sentinel),'env':dict(os.environ)},sort_keys=True))"
            )
            completed = _run_child_process(
                [sys.executable, "-c", code, str(payload_fd)],
                source="# fixed runner gate bootstrap\n",
                payload_fd=payload_fd,
                timeout_seconds=10,
                cwd=tempfile.gettempdir(),
                env=dict(FIXED_CHILD_ENVIRONMENT),
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed["digest"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(observed["cmd_hits"], 0)
        self.assertEqual(observed["env_hits"], 0)
        self.assertEqual(observed["stdin_hits"], 0)
        self.assertEqual(observed["env"], FIXED_CHILD_ENVIRONMENT)

    def test_output_limits_do_not_limit_unrelated_state_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.bin"
            code = (
                "import os,sys;"
                "p=sys.argv[2];"
                "f=open(p,'wb');f.write(b's'*(5*1024*1024));f.close();"
                "os.write(1,b'ok')"
            )
            completed = self.run_helper(code, arguments=(str(state_path),))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "ok")
            self.assertEqual(state_path.stat().st_size, 5 * 1024 * 1024)

    def test_stdout_and_stderr_limits_are_enforced_across_exec(self) -> None:
        for descriptor, maximum, label in (
            (1, MAX_CHILD_STDOUT_BYTES, "stdout"),
            (2, MAX_CHILD_STDERR_BYTES, "stderr"),
        ):
            with self.subTest(label=label):
                code = (
                    "import os,sys;"
                    "fd=int(sys.argv[2]);size=int(sys.argv[3]);"
                    "chunk=b'x'*65536;written=0;"
                    "\nwhile written<=size:\n os.write(fd,chunk);written+=len(chunk)"
                )
                with self.assertRaisesRegex(OdooRunnerError, f"{label} exceeded"):
                    self.run_helper(
                        code,
                        arguments=(str(descriptor), str(maximum)),
                    )

    def test_timeout_kills_same_process_group_grandchild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "grandchild.pid"
            code = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                "pathlib.Path(sys.argv[2]).write_text(str(child.pid));"
                "time.sleep(60)"
            )
            with self.assertRaisesRegex(OdooRunnerError, "timed out"):
                self.run_helper(
                    code,
                    arguments=(str(pid_path),),
                    timeout_seconds=0.8,
                )
            self.assertTrue(pid_path.is_file())
            grandchild_pid = int(pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            live = True
            while time.monotonic() < deadline:
                stat_path = Path(f"/proc/{grandchild_pid}/stat")
                if not stat_path.exists():
                    live = False
                    break
                try:
                    state = stat_path.read_text(encoding="utf-8").split()[2]
                except (OSError, IndexError):
                    live = False
                    break
                if state == "Z":
                    live = False
                    break
                time.sleep(0.05)
            self.assertFalse(live, "grandchild remained live after process-group timeout")


if __name__ == "__main__":
    unittest.main()
