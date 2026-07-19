# Dev23 isolated effect finalizer

This composition adds the database-effect finalizer beside the existing V3
broker and beside V2. It does not stop, replace, edit, or reuse either V2 copy,
and installing or starting its socket does not enable a write capability.
Production writes remain disabled unless each capability has separate explicit
authorization and retained production-safety evidence.

## Identity and secret boundary

Create the static, non-root `odoo-v3-effect-finalizer` user and same-named
primary group. Do not reuse `odoo`, `odoo-v3-broker`, the Pi identity, or a
database owner. Let the host allocate the numeric UID/GID, then record them and
place those exact numbers in the root-managed finalizer runtime document. The
finalizer may additionally belong to `odoo-v3-runtime` only so it can traverse
the shared mode-`0750` runtime directory. It must not belong to the broker,
Odoo-control, Pi, PostgreSQL, or privileged administrative groups.

The socket manager creates
`/run/odoo-accounting-cli-v3/effect-finalizer.sock` as
`root:odoo-v3-broker` mode `0660`. Only the dedicated broker identity belongs
to that client group. The finalizer authenticates the connecting Linux peer as
the exact broker systemd main PID and configured UID; group access alone is
not authorization.

Install `/etc/odoo-accounting-cli-v3/effect-finalizer-runtime.json` as a
canonical `root:odoo-v3-effect-finalizer` regular file, mode `0440`, beneath
root-owned non-writable ancestors. It contains paths and pinned identities,
never secret values. Create `/etc/odoo-accounting-cli-v3/effect-finalizer` as
a canonical root-owned directory, group `odoo-v3-effect-finalizer`, mode
`0750`, then install the finalizer HMAC
credential and exact one-entry pgpass as distinct
`odoo-v3-effect-finalizer:odoo-v3-effect-finalizer` regular files, each mode
`0400`, beneath a root-owned, non-writable ancestor chain. The pgpass is read
once by the finalizer and its password is passed directly to libpq; no
`passfile` path is passed onward. The service also clears inherited Python,
dynamic-loader, and PostgreSQL environment selectors.

Neither the broker unit nor a write child receives the finalizer runtime
document, HMAC credential, pgpass, database LOGIN, or their paths. Do not add
an `EnvironmentFile` containing any of them. The broker receives only its
permission to connect to the root-owned socket. The Odoo child must not inherit
that connected descriptor.

The finalizer database LOGIN must be a distinct direct PostgreSQL LOGIN with
only the reviewed guard functions/relations granted by the module-guard SQL.
`SET ROLE`, owner/superuser membership, a shared Odoo password, TCP database
transport, wildcard pgpass entries, and multiple pgpass rows are forbidden.
The current adapter accepts only the trusted local PostgreSQL socket directory
`/run/postgresql` or `/var/run/postgresql`; `PrivateNetwork=yes` and
`RestrictAddressFamilies=AF_UNIX` enforce the same deployment boundary.

## State and runtime configuration

Set `journal_path` below
`/var/lib/odoo-accounting-cli-v3-effect-finalizer`, the service-owned
mode-`0700` `StateDirectory`. Preserve that append-only attempt journal across
restart, upgrade, rollback, and incident analysis. Never place it in the
broker state directory or give the broker write access.

Populate every field in the deliberately non-deployable template documented
in `docs/RUNTIME_CONFIGURATION.md` from host evidence. In particular:

- `service_uid`/`service_gid` equal the finalizer process identity;
- `socket_owner_uid` is root (`0`), while `socket_group_gid` is the actual
  numeric GID of `odoo-v3-broker`;
- `broker_service_uid` is the actual broker UID and the broker/finalizer unit
  names match these examples;
- the Odoo configuration digest, database UUID/OID, guard installation UUID,
  finalizer Key ID, and all paths are independently pinned; and
- `database_connect_timeout_seconds * 1000 + statement_timeout_ms + 1000` is
  strictly less than `request_io_timeout_seconds * 1000`. Equality is invalid.

The launcher currently uses the root-managed `/usr/bin/python3` isolated
runtime, matching the other canonical release launchers. Before starting the
service, prove that this exact interpreter can import the required Odoo and
PostgreSQL driver dependencies without `PYTHONPATH`, record their canonical
paths, owners, modes, versions, and SHA-256 values, and retain that evidence.
If this cannot be proved, leave the finalizer and all production writes
disabled; do not weaken isolated mode or inject a user-controlled module path.

## Side-by-side installation

1. Side-load and verify the immutable release using `docs/DEPLOYMENT.md`. The
   canonical archive must contain the CLI, broker, and effect-finalizer
   launchers from the same manifest and version. Do not copy a launcher from a
   checkout or install a second source tree.
2. Create the identities, configuration, credential files, journal parent, and
   PostgreSQL grants above. Verify numeric IDs and modes; do not use example
   numbers as production values.
3. Render the service only from the selected externally anchored release:

   ```sh
   python3 -I \
     /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev9/render-systemd-service.py \
     --release-root /opt/odoo-accounting-cli-v3/releases/<release> \
     --component effect-finalizer
   ```

   Install stdout as
   `/etc/systemd/system/odoo-accounting-cli-v3-effect-finalizer.service`,
   root-owned mode `0644`. Never install the raw `@V3_RELEASE@` template.
   Install the sibling socket unit with the same owner/mode. Install the Dev9
   tmpfiles rule first so the shared runtime parent has its documented owner
   and mode.
4. Run `systemd-analyze verify` on the rendered service and socket, then
   `systemctl daemon-reload`. Enable/start the socket only; socket activation
   starts the service:

   ```sh
   systemctl enable --now odoo-accounting-cli-v3-effect-finalizer.socket
   ```

5. With the V3 production write route still disabled, prove fail-closed startup,
   exact process UID/GID, socket owner/group/mode, direct database LOGIN,
   pinned database/guard identity, deadline rejection, peer rejection,
   pgpass/environment injection rejection, response-loss replay, and journal
   restart recovery. Real write/finalization tests remain sandbox-only without
   separate production-write authorization.

## Upgrade and rollback

An upgrade is a new immutable release and a newly reviewed runtime document;
never patch the installed release or reuse an unverified launcher. First stop
new V3 write routing and drain the broker. Stop the finalizer socket/service,
retain the journal and database ledger, render the new anchored service, run
all gates, and start its socket without enabling production writes. Only a
passing sandbox replay/recovery gate may allow later canary consideration.
V2 remains running and unchanged throughout.

Rollback likewise removes V3 write routing first. Stop the finalizer socket
and service, then restore only a previously anchored release plus its matching
runtime identity and a journal/database schema it can verify. Never delete,
truncate, edit, or replace the finalizer journal or database effect ledger, and
never create a fresh operation ID to hide an ambiguous attempt. If compatibility
or reconciliation cannot be proved, leave V3 writes disabled and preserve all
evidence. A binary rollback is not an accounting reversal; accounting effects
use the recorded recovery or compensating capability only.
