from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev9" / "run-private-mount-gate.sh"


def test_private_mount_gate_has_fail_closed_namespace_contract() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "--mount" in source
    assert "--propagation private" in source
    assert "--fork" in source
    assert "--kill-child=KILL" in source
    assert 'test "$self_namespace" != "$init_namespace"' in source
    assert "private|unbindable" in source
    assert "/proc/self/mountinfo" in source
    assert 'if [[ "$after" != "$before" ]]' in source
    assert "/(tmp|var/tmp)/" in source
    assert "fake-var-lib" in source


@pytest.mark.skipif(os.name != "posix", reason="requires Linux mount namespaces")
def test_private_mount_gate_executes_only_when_unshare_is_available() -> None:
    if shutil.which("unshare") is None or shutil.which("findmnt") is None:
        pytest.skip("util-linux namespace tools are unavailable")

    probe = subprocess.run(
        ["bash", str(SCRIPT), "/usr/bin/true"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if probe.returncode == 1 and "Operation not permitted" in probe.stderr:
        pytest.skip("the test host does not permit a mount namespace")
    assert probe.returncode == 0, probe.stderr


@pytest.mark.skipif(os.name != "posix", reason="requires Linux procfs")
def test_private_mount_gate_rejects_direct_inside_entry() -> None:
    direct = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "__odoo_v3_private_mount_gate_inside__",
            "/usr/bin/true",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert direct.returncode == 70
    assert direct.stdout == ""
    assert "rejected the host state" in direct.stderr
