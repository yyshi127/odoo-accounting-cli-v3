# Dev29 read oracle contract

`read_plan.json` freezes the target, Odoo runtime, five positive reads, seven
negative requests, historical goldens, PostgreSQL relation identities, and
privacy-limited witness projections. It is test-only and does not authorize a
production write or promotion.

Run the oracle only with the exact Odoo virtual-environment Python recorded in
the plan. `-I` is required; `-S` must not be used because psycopg2 2.9.9 is
installed in that virtual environment rather than the system Python.

```text
/opt/odoo/odoo19/odoo19-venv/bin/python -I read_oracles.py witness \
  --plan read_plan.json

/opt/odoo/odoo19/odoo19-venv/bin/python -I read_oracles.py verify \
  --plan read_plan.json --case trial_balance \
  --request request.json --response response.json
```

Success is exit `0`, empty stderr, and one canonical JSON object plus LF on
stdout. A valid financial/golden mismatch or a fixture gap is exit `1`.
Malformed input, runtime drift, database/schema/ACL identity drift, or a failed
transaction boundary is exit `2`. Failure stdout remains canonical JSON;
stderr contains only the stable category `oracle_mismatch` or
`oracle_input_error`.

Every database run uses the fixed local Unix socket, clears libpq selector
environment variables, starts `REPEATABLE READ READ ONLY`, sets
`search_path=pg_catalog`, qualifies Odoo relations as `public.*`, rolls back,
and requires final libpq `IDLE`. The witness publishes only relation/schema
identity, canonical projected-row stream SHA-256, and count. It never publishes
raw rows, credentials, authentication secrets, or unrestricted user/config
columns. A suite must compare complete pre/post witness objects exactly.
