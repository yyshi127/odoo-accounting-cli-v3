"""Fail when V3 source leaks into known V2 or snapshot directories."""

from __future__ import annotations

import sys
from pathlib import Path


V3_MARKERS = ("odoo_accounting_cli_v3", "odoo-accounting-cli-v3")
FORBIDDEN_ROOTS = (
    "sudo_ai_bot",
    "_remote_current_sudo_ai_bot",
    "_remote_sudo_ai_bot",
    "_remote_pi_agent_bridge",
    "_deploy_stage",
)


def leaked_paths(workspace: Path) -> list[Path]:
    leaks: list[Path] = []
    for root_name in FORBIDDEN_ROOTS:
        root = workspace / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if any(marker in path.name.lower() for marker in V3_MARKERS):
                leaks.append(path)
    return leaks


def main() -> int:
    workspace = Path(__file__).resolve().parents[2]
    leaks = leaked_paths(workspace)
    if leaks:
        for path in leaks:
            print(path.relative_to(workspace))
        return 1
    print("V3 source boundary is clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
