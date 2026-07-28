#!/usr/bin/env python3
"""Read-only target-host capacity remediation planner.

This tool deliberately never deletes, truncates, moves, chmods, or rewrites
files.  It produces a bounded JSON plan that an operator can review before
granting separate cleanup authorization.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from odoo_accounting_cli_v3.capacity_plan import (
    DEFAULT_REQUIRED_FREE_BYTES,
    PLAN_KIND,
    CapacityPlanError,
    build_plan,
    collect_candidates,
    filesystem_summary,
    validate_keep_releases,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan V3 target capacity remediation without deleting files")
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument(
        "--required-free-bytes",
        type=int,
        default=DEFAULT_REQUIRED_FREE_BYTES,
    )
    parser.add_argument("--keep-release", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        plan = build_plan(
            root=arguments.root,
            required_free_bytes=arguments.required_free_bytes,
            keep_releases=validate_keep_releases(arguments.keep_release),
        )
    except CapacityPlanError as exc:
        print(f"capacity plan rejected: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
