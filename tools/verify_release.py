"""Verify an extracted release against its embedded manifest."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from odoo_accounting_cli_v3.release import ReleaseError, verify_manifest


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: verify_release.py EXTRACTED_RELEASE_DIR EXPECTED_MANIFEST_SHA256",
            file=sys.stderr,
        )
        return 2
    root = Path(sys.argv[1]).resolve()
    manifest_path = root / "RELEASE-MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_manifest(
            root,
            manifest,
            expected_manifest_sha256=sys.argv[2],
        )
    except (OSError, ValueError, ReleaseError) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"verified {manifest['version']} {manifest['commit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
