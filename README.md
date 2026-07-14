# Odoo Accounting CLI V3

Production-oriented accounting capability gateway for Odoo 19 and Pi Agent.

V3 is built and released independently from V2. Its authoritative source is
this repository; the trusted server release root is
`/opt/odoo-accounting-cli-v3/releases/`.
V2 remains installed and runnable during side-by-side verification.

## Source boundary

This directory is the only local source root for V3. The V2 Odoo module,
historical remote snapshots, and deployment staging directories are external
inputs and must not contain V3 source files.

Four reads are staged execution candidates for the dedicated test environment:
the ACL-filtered capability registry, trial balance, and historical AR and AP
open items. Staging is separate from enablement: no capability is yet marked
enabled or routed through Pi. No write capability is staged or enabled;
sandbox and production remain closed until their approval, idempotency,
verification, recovery, and evidence gates pass.

## CLI boundary

The wheel-installed `odoo-accounting-cli-v3` command provides development and
packaging smoke coverage. A deployed accounting read uses the exact,
manifest-covered `<release>/bin/odoo-accounting-cli-v3` launcher and a runtime
configuration bound to the retained canonical tar. This keeps wheel contents,
working directories, and copied Pi code outside the production business-code
trust path. The standard write-operation lifecycle commands are present but
fail closed. They never return a simulated Odoo success.

```text
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry list
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry get --capability-id acct.gl.trial_balance.v1
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 release identity
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 read --runtime-config /absolute/root-managed/runtime.json --request-json '{...}'
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 operation prepare --request-json '{...}'
```

The bare wheel command is limited to development smoke such as `--version` and
registry-contract inspection; it is not a production accounting entry point.

All machine-facing output is JSON. Real accounting success additionally
requires an Odoo-bound signed receipt. CLI-Anything v0.4.0 supplies the CLI and
test-harness conventions only; Odoo 19 remains the backend and accounting
source of truth. See `docs/CLI_ANYTHING_V040_ADOPTION.md`.

## Development

```powershell
python -m pip install -e ".[test]"
python -m pytest
python tools/check_source_boundary.py
```

The acceptance gates and current evidence limits are in `tests/TEST.md` and
`docs/BASELINE.md`. Deployment, upgrade, promotion, and rollback are defined in
`docs/DEPLOYMENT.md`.
