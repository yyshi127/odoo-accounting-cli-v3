# Odoo Accounting CLI V3

Production-oriented accounting capability gateway for Odoo 19 and Pi Agent.

V3 is built and released independently from V2. Its authoritative source is
this repository; the intended server release root is
`/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v3/releases/`.
V2 remains installed and runnable during side-by-side verification.

## Source boundary

This directory is the only local source root for V3. The V2 Odoo module,
historical remote snapshots, and deployment staging directories are external
inputs and must not contain V3 source files.

The initial baseline is intentionally non-operational: no write capability is
enabled until it has passed the required sandbox, approval, idempotency,
verification, and recovery gates.

## CLI boundary

The installable `odoo-accounting-cli-v3` command currently provides validated
registry inspection. The standard operation lifecycle commands are present but
fail closed until the durable authenticated gateway is configured. They never
return a simulated Odoo success.

```text
odoo-accounting-cli-v3 registry list
odoo-accounting-cli-v3 registry get --capability-id acct.gl.trial_balance.v1
odoo-accounting-cli-v3 release identity
odoo-accounting-cli-v3 operation prepare --request-json '{...}'
```

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
`docs/BASELINE.md`.
