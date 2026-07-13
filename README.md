# Odoo Accounting CLI V3

Production-oriented accounting capability gateway for Odoo 19 and Pi Agent.

## Source boundary

This directory is the only local source root for V3. The V2 Odoo module,
historical remote snapshots, and deployment staging directories are external
inputs and must not contain V3 source files.

The initial baseline is intentionally non-operational: no write capability is
enabled until it has passed the required sandbox, approval, idempotency,
verification, and recovery gates.

## Development

```powershell
python -m pytest
```
