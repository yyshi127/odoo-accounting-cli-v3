# Dev11 Pi Bridge V3 sidecar

This is a new, non-routed sidecar. It must not replace, stop, edit, or reuse
`sudo-pi-agent-bridge.service`, its `odoo` identity, port `18787`, mutable
checkout, or `node_modules`. The rendered V3 service uses the dedicated
`odoo-v3-pi-broker` identity and loopback port `18788`.
Bootstrap fixes hardened V3-only mode: the sidecar never offers any of the five
legacy V2 tools and never passes `ODOO_TOOL_*` credentials/selectors to Pi.
The independent V2 service remains the only legacy path.
The sidecar also rejects the legacy `/session/delete` route: a conversation ID
does not establish ownership, so deletion remains unavailable until a separate
authenticated owner binding exists.
Caller messages are wrapped in a fixed literal prefix before Pi is spawned;
leading `@file`, `--tools`, or `--extension` input cannot become Pi CLI syntax.

Before staging, create the static system user and same-named primary group
`odoo-v3-pi-broker`, create `odoo-v3-runtime` if absent, and add only that Pi
identity (plus the separately documented broker identities) to the runtime
group. Resolve and record the numeric UID/GIDs. The Pi identity must be the
member authorized by the existing Dev9 `odoo-v3-pi-broker.socket` group; do not
substitute the `odoo` user or reuse an unrelated same-number group.

## Build the one anchored runtime

Start only after the canonical release package, `RELEASE-MANIFEST.json`, and
external `<release>.json` anchor are installed below
`/opt/odoo-accounting-cli-v3` as root-owned, non-symlink, non-group/world
writable objects. Use the exact canonical release name in every path below.

1. Create a new sibling staging directory below
   `/opt/odoo-accounting-cli-v3/pi-runtime/<release>/pi_bridge`. Copy the exact
   release versions of the Bridge runtime members into it. Do not copy the V2
   Bridge or its dependencies.
2. In that staging `pi_bridge` directory, run the root-managed npm paired with
   `/usr/bin/node` as a trusted installer:

   ```sh
   env -i HOME=/root PATH=/usr/bin:/bin \
     /usr/bin/npm ci --ignore-scripts --omit=dev --omit=optional --no-audit \
       --registry=https://registry.npmjs.org/
   env -i HOME=/root PATH=/usr/bin:/bin \
     /usr/bin/npm audit --omit=dev --omit=optional --audit-level=info \
       --registry=https://registry.npmjs.org/
   ```

   The lock is authoritative, and the audit must report zero vulnerabilities;
   scripts, network updates, and manual dependency edits are forbidden after
   this step. Recursively use no-dereference chown
   (`chown -hR`) to set every file and symlink owner/group to
   `root:root` and remove group/world write permission.
3. From the same canonical release, create the external binding once:

   ```sh
   env -i HOME=/root PATH=/usr/bin:/bin \
     /usr/bin/node \
     /opt/odoo-accounting-cli-v3/releases/<release>/pi_bridge/create-runtime-binding.mjs \
     /opt/odoo-accounting-cli-v3/pi-runtime/<release>/pi_bridge
   ```

   The installer uses `O_EXCL`, hashes the exact `/usr/bin/node` bytes and
   every regular file and symlink in `node_modules`, binds the release and
   package-lock digests, writes `PI-RUNTIME-MANIFEST.json`, then writes the
   independent root-owned
   `/opt/odoo-accounting-cli-v3/trusted-artifacts/<release>.pi-runtime.json`
   anchor. Both files and their parent-directory changes are fsynced. It never
   overwrites an existing binding.

If the machine loses power before the external anchor is durable, the runtime
manifest is inert and bootstrap refuses V3. Confirm that no V3 service used the
candidate, preserve both paths for diagnosis, remove only the orphan manifest
under an explicit root maintenance change, fsync its parent, and rerun the
trusted installer. Never manufacture or edit a digest to recover.

After binding, freeze runtime directories/files against the service identity.
Bootstrap rehashes the canonical release, package, tracked Bridge copy, exact
Node executable, and complete dependency tree on every start. A stale copy,
extra/missing dependency, byte change, unsafe owner/mode, symlink escape,
different Node path, or different runtime anchor fails before V3 tools exist.

## Render but do not route

Create `/etc/odoo-accounting-cli-v3/pi-bridge-v3.env` as `root:root` mode
`0600`. It may contain only model/provider credentials and
`PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256`, computed from the exact
release-bound resolver copy. It must not contain `HOME`, loader variables,
host, port, runtime/release paths, broker socket, resolver path, or identity
digests. The canonical bootstrap overwrites all of those fixed boundary values
from its root-owned ExecStart argument; hostile values in the environment file
cannot select them.

Render the unit from the canonical release:

```sh
python3 -I \
  /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev11/render-pi-bridge-service.py \
  --release-root /opt/odoo-accounting-cli-v3/releases/<release> \
  --runtime-root /opt/odoo-accounting-cli-v3/pi-runtime/<release>/pi_bridge
```

Install stdout as
`/etc/systemd/system/odoo-accounting-cli-v3-pi-bridge.service`, root-owned mode
`0644`, and install the sibling
`odoo-accounting-cli-v3-pi-bridge.socket` with the same ownership/mode. The
root systemd socket manager reserves `127.0.0.1:18788` and passes the one named
descriptor; bootstrap requires it, and the Pi child never inherits it. This
prevents a same-UID process from replacing the gateway listener while the
service restarts. The renderer verifies the release/package anchors, runtime anchor,
package-lock digest, exact `/usr/bin/node` SHA-256, and fixed canonical
ExecStart. Verify both units with `systemd-analyze verify`, then start the
socket without routing production traffic; do not enable the service directly.
Require a verified `/health` identity and all
negative/tamper gates before any canary routing. Rollback is stopping this new
sidecar only; the V2 unit remains untouched.

The chat request budget is fixed at 5 seconds of Broker preflight, at most 120
seconds for the Pi child, and 10 seconds for parent-only result delivery. The
150-second stop window exceeds that 135-second request budget so an in-flight
request can fail closed before systemd escalates termination.
