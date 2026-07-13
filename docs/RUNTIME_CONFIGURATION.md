# V3 read runtime configuration

The `read` command accepts one absolute path to a root-managed JSON file. The
file is an allowlist: callers cannot replace the Odoo executable, database,
release, state stores, or signing keys through request parameters.

```json
{
  "instance_id": "odoo19@43.165.173.80",
  "environment": "test",
  "capability_channel": "staged",
  "database_name": "odoo_test",
  "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
  "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
  "odoo_python_sha256": "<sha256-of-resolved-runtime-file>",
  "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
  "odoo_bin_sha256": "<sha256-of-runtime-file>",
  "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
  "odoo_config_sha256": "<sha256-of-runtime-file>",
  "release_root": "/opt/odoo-accounting-cli-v3/releases/<release>",
  "auth_state_path": "/var/lib/odoo-accounting-cli-v3/test/auth.sqlite3",
  "receipt_state_path": "/var/lib/odoo-accounting-cli-v3/test/receipt.sqlite3",
  "auth_key_id": "test-auth-2026-07",
  "receipt_key_id": "test-receipt-2026-07",
  "auth_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/auth.hmac",
  "receipt_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/receipt.hmac"
}
```

The object must contain exactly these fields. The configuration and its parent
directory must be canonical, root-owned, and not group/world writable. Each
secret must be a distinct root-owned regular file of at least 32 bytes; group
read is allowed for the dedicated service group, but world access and
group/world write are rejected. The distinct Key IDs are part of the signed
wire protocol and are checked against this configuration. Secrets and business
parameters are carried to the Odoo shell through a sealed inherited file
descriptor; standard input contains only a fixed bootstrap, and argv and the
fixed child environment contain neither secrets nor request data.

The two state paths are private SQLite/WAL databases. Their parent directories
must not be group/world writable; a service-owned mode `0700` directory and
mode `0600` database files are the expected deployment. Authentication tokens
and read receipts are consumed atomically and survive process restart. A
verified read is appended to the receipt database's tamper-evident audit chain
before the CLI may report success.

The CLI process must itself come from `release_root`. Before starting Odoo it
verifies the release manifest against the external deployment anchor and
rejects a version, source root, package, registry, or runtime identity mismatch.
The `/opt` release hierarchy is used because every ancestor is root-managed;
the earlier `/mnt/.../odoo_accounting_agent_cli_v3` candidates remain retained
deployment evidence and are not a runtime source.

This configuration enables only capabilities whose registry entry contains the
same environment in the selected `capability_channel`. The `staged` channel is
allowed only for root-configured test/sandbox evidence runs; normal Pi-facing
execution uses `enabled`. It does not authorize production writes; all V3 write
commands remain fail-closed until their sandbox lifecycle and specialized
transactional state persistence are complete.

The current HMAC arrangement is an isolated test-candidate boundary, not the
final production trust split: the parent and Odoo child still share symmetric
key material. Production promotion additionally requires independent service
identities and role-separated verification/signing keys (preferably
asymmetric), durable failure auditing, and an externally anchored audit head.
