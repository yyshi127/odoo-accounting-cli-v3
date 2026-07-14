# Dev8 deployment toolchain

This directory is the version-controlled source for the release-specific
deployment, staging, and evidence tools that target
`0.1.0.dev8-bd21ca07c168`.

The canonical runtime artifact remains the single release package named in
the scripts. These tools do not promote `/opt/odoo-accounting-cli-v3/current`,
change the Pi route, modify V2, or authorize production accounting writes.
They install and validate a side-by-side test candidate only.

`TOOLCHAIN-MANIFEST.json` binds the exact bytes of all 16 operational tools and
the read-only `SERVER-BASELINE.json` to toolchain version
`0.1.0.dev8-toolchain.1` and to the canonical application release.
`check_toolchain.py` verifies that binding in CI.

Upload the manifest and operational tools by their basenames into the
root-only upload directory. The frozen evidence bundle records the manifest,
the exact bytes, and the metadata of every tool.
