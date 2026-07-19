# Target host effect-finalizer runtime audit (2026-07-19)

## Scope and safety

This is a read-only audit of target host `43.165.173.80` performed while the
repository was at Dev26 commit
`bc27354855480ceb8148365d6a68c1e22a4c2c3f`. No package, account, database,
configuration, service, or filesystem state was changed. No Odoo ORM write was
executed. The observations below are host facts, not authorization to install
Dev27 or to enable any write capability.

## Observed runtime boundary

- `/usr/bin/python3 -I` is Python 3.12.3. It could not import `odoo`,
  `psycopg2`, or `psycopg` at audit time.
- The Odoo virtual environment could import `psycopg2` 2.9.9 in isolated mode,
  but could not import the Odoo source tree without an injected module path.
- The Odoo virtual environment, its `psycopg2` files, and the Odoo source tree
  are under paths writable by the `odoo` owner. The environment also contains
  startup `.pth` processing. A finalizer launched from that environment would
  therefore execute bytes controllable by the Odoo service identity while
  holding the finalizer HMAC and PostgreSQL credential. That trust boundary is
  rejected.
- The reviewed Odoo configuration omits `db_host` and `db_name` and sets
  `db_port = 5432`. Odoo 19 `connection_info_for()` consequently does not
  produce the explicit socket host required by the Dev26 finalizer adapter.
  Importing Odoo would not have made that adapter start successfully.
- The Odoo configuration is `root:odoo` mode `0640`, but its ancestor path
  includes `/mnt/odoo/odoo19/custom/addons`, owned by `odoo`. The Dev26
  root-managed ancestor policy correctly rejects that path, and the dedicated
  finalizer identity has no reason to read the Odoo configuration.
- The finalizer service and socket were not installed: both were absent and
  inactive. Production writes remained disabled.

## PostgreSQL-only option

The finalization transaction uses a direct PostgreSQL LOGIN and the guarded SQL
contract. It does not need the Odoo ORM. The runtime already pins the database
name and local socket, database UUID and OID, guard installation UUID, direct
LOGIN, statement timeout, one-row pgpass binding, and the database guard state.
Dev27 therefore removes Odoo imports and Odoo-config access from the finalizer
instead of weakening isolated mode or reusing the Odoo virtual environment.

At audit time the Ubuntu repository exposed
`python3-psycopg2 2.9.9-1build1`; the reviewed downloaded `.deb` package
archive SHA-256 was
`b3210c34c3938ec4200b6bdf64c9502246d6d9e801d1f79b2d2d02686853293c`.
Installed `libpq5` reported version 16.14. These observations do not prove an
installed or retained runtime closure: `/usr/bin/python3 -I` still could not
import the driver.

## Required evidence before service start

The following remain separately authorized deployment work:

1. Install and version-lock a root-owned PostgreSQL driver for
   `/usr/bin/python3 -I`.
2. Collect and externally retain the observed eager-import interpreter, Python
   module, `sys.path`, `.pth`, native-extension, and libpq paths, owners, modes,
   versions, and SHA-256 values; re-verify the same manifest at service start.
3. Install the exact canonical Dev27-or-later release, schema-v2 finalizer
   runtime, dedicated Linux identity, HMAC, one-row pgpass, and hardened systemd
   units without exposing the Odoo writable tree.
4. Create the direct PostgreSQL finalizer LOGIN and only the reviewed guard
   grants, then pass startup/preflight without enabling an accounting write.
5. Obtain separate authorization and an isolated sandbox before any real
   finalization, replay, Odoo write, recovery, or rollback test.

Until all applicable gates pass, the effect-finalizer and every production
write capability must remain disabled.
