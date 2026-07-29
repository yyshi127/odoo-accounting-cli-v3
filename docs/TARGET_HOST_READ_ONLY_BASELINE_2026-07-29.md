# Target host read-only baseline — 2026-07-29

This is a read-only observation of `43.165.173.80`. It is not a deployment
receipt, Odoo business receipt, Pi end-to-end receipt, or production-promotion
evidence. No Odoo method was invoked, no service was changed, and no runtime
secret or configuration value was read.

## Observed V3 route

- `/opt/odoo-accounting-cli-v3/current` is a symbolic link to
  `/opt/odoo-accounting-cli-v3/releases/0.1.0.dev250-8414e9922f03`.
- The routed `VERSION` is `0.1.0.dev250`.
- The routed release manifest commit is
  `8414e9922f03441ec0346ddbbae42093a5c10c58`.
- No installed systemd service unit whose name begins with
  `odoo-accounting-cli-v3` was listed.

Consequently, the local `0.1.0.dev253` candidate at commit
`af85e2d8b8e74274621ac4e18db06a4ce6af6423` was not the target host's active
route at observation time. Local release-integrity mechanisms do not prove that
the target host runs that candidate.

## Observed Pi route

`sudo-pi-agent-bridge.service` was enabled and active. Its fixed command was:

```text
/usr/bin/node /mnt/odoo/odoo19/custom/services/pi-agent-bridge/server.mjs
```

The service was therefore not launched from the routed immutable V3 release
tree. This observation does not prove the bridge source content or its runtime
configuration; those require a separately authorized identity and health
evidence capture.

## V2 preservation baseline

The following non-secret V2 scope was hashed without modifying it:

```text
/root/project/odoo_accounting_agent_cli_v2/src
/root/project/odoo_accounting_agent_cli_v2/docs
/root/project/odoo_accounting_agent_cli_v2/tests
/root/project/odoo_accounting_agent_cli_v2/pyproject.toml
/root/project/odoo_accounting_agent_cli_v2/README.md
/root/project/odoo_accounting_agent_cli_v2/Makefile
```

Interpreter caches (`__pycache__`, `.pytest_cache`, `*.pyc`, `*.pyo`) and log
files were excluded. The deterministic aggregate SHA-256 over the remaining
sorted per-file SHA-256 records was:

```text
b6587ea3b832d0d807d420a6b1f52b7eb61ba61d27c095b930cd7a7de009760b
```

This hash is only a scoped preservation baseline. A later migration or route
change must reproduce the same algorithm and scope before and after the change;
it must not treat this document alone as proof that V2 remained unchanged.

## Disposition

- Keep V2 running and unchanged.
- Keep all V3 write capabilities disabled.
- Do not describe Dev253 or a later local candidate as deployed until the
  installed release, current route, Odoo add-on, broker and Pi health evidence
  independently reproduce one exact version, commit, package, manifest and
  registry identity.
- Do not describe any accounting operation as successful without its separately
  verified Odoo receipt.
