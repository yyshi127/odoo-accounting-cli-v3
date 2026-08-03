# Dev9 trusted broker service

These units are a V3-only production composition. They do not replace, stop,
rename, or reuse any V2 service, directory, socket, state database, or user.
Do not install them until the Dev9 package, root configuration, identities,
groups, sandbox gates, and rollback package have all been independently
verified.

## Identity and path contract

- `odoo-v3-broker:odoo-v3-broker` is a dedicated non-root service identity.
  Its numeric UID/GID must exactly match `broker_service_uid` and
  `broker_service_gid` in `/etc/odoo-accounting-cli-v3/broker-runtime.json`.
- `odoo-v3-pi-broker` contains the Pi Bridge identity only. It controls access
  to `/run/odoo-accounting-cli-v3/pi-broker.sock`.
- `odoo-v3-odoo-control` contains the Odoo service identity only. It controls
  access to the mint and approval sockets. Pi must not be in this group.
- `odoo-v3-runtime` grants traversal of the V3 runtime directory only. The
  broker, Pi Bridge and Odoo service identities are its only members; it must
  own no files outside this V3 runtime boundary.
- Grant the broker identity read/traverse ACLs only on the exact pinned Odoo
  Python, source tree, add-ons and configuration that its immutable runtime
  names. Do not add it to the Odoo service's primary group: that group may
  carry unrelated write authority. Validate both Unix-socket and configured
  TCP PostgreSQL connectivity while running as `odoo-v3-broker` before the
  service is enabled.
- `/run/odoo-accounting-cli-v3` is created by the supplied tmpfiles rule as
  `root:odoo-v3-runtime`, mode `0750`. Each socket remains root-owned, mode
  `0660`, and protected by its distinct client group.
- systemd creates the non-overlapping
  `/var/lib/odoo-accounting-cli-v3-broker` directory for the broker as mode
  `0700`, owns it as the broker service UID, and sets the broker's `HOME` to
  that exact path. It must never use `/var/lib/odoo-accounting-cli-v3` as a
  `StateDirectory`: systemd would recursively change the ownership of retained
  candidate state and historical evidence below that existing root. The unit's
  explicit `ReadWritePaths=/var/lib/odoo-accounting-cli-v3` mount exception
  does not change discretionary ownership or modes. That historical root must
  already be a canonical, non-symlink directory with safe root-managed
  metadata, while every exact read, write, session, and audit store parent
  named by the root-managed runtime configurations remains service-owned mode
  `0700`. The example root composition uses the explicit
  `/var/lib/odoo-accounting-cli-v3/broker-state` parent; it is not a managed
  `StateDirectory`. `ProtectHome=yes` hides every ordinary home directory.
  Before any Odoo process is spawned, the runner requires the fixed broker
  `HOME` to be an absolute, existing, canonical non-symlink directory owned by
  its effective UID with exact mode `0700`; any drift fails closed.
- The broker must start through
  `/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3-broker`,
  inside the same root-owned, immutable, non-symlink release tree selected by
  the current runtime route. Never use a second broker copy, mutable checkout,
  stable alias, or `current` symlink.

The broker composition file is secret-free but root-controlled. Its referenced
release manifests, runtime configurations, authority files, secret files, and
SQLite parents must retain the owners and modes required by their individual
loaders. Broker state directories must be writable only by the dedicated
broker identity. Numeric socket UIDs/GIDs and all three socket paths in the
composition must match these units exactly.

`broker-runtime.example.json` is the complete schema and deadline/capacity
baseline, not a deployable configuration. Replace every example UID, GID,
release/registry digest, file digest, and release path from verified host and
immutable-package evidence. Keep JSON `socket_mode` at decimal `432` (octal
`0660`). The production loader rejects missing or extra fields, unsafe aliases,
untrusted ownership, digest drift, identity overlap, deadline inversion, and
capacity values outside their bounds. Its three SQLite paths remain explicit
configuration values below the operator-created, broker-owned mode-`0700`
`broker-state` directory; systemd does not infer or create those stores from
the broker HOME.

The root composition and every retained authority runtime must use the same
SQLite busy timeout, capped at `1000` ms. The loader also reserves the declared
SQLite phases and shutdown margin inside each Pi, mint, and approval transport
deadline; adding a retained release can therefore require lowering the Odoo
approver timeout before the new route is accepted.

At runtime, broker and session-mint handlers install their absolute monotonic
deadline before durable work. Approval broker workers receive the same context
through an explicit thread-context copy. Nested work may shorten but never
extend that deadline, and every SQLite connection and `busy_timeout` PRAGMA is
rebounded to the then-current remaining time; an expired budget is rejected
before `sqlite3.connect`.

## Installation gate

### Target Linux mount-isolation gate

Never bind-mount a fake `/var/lib`, `/etc`, `/run`, release root, or state root
directly in the target host's mount namespace. A mount namespace is not safe
merely because `unshare --mount` was requested: its propagation must be private
before the first mount. A shared bind can propagate back to PID 1, hide live
PostgreSQL state, and crash the database checkpointer.

Any target-Linux test that creates a mount must run its complete command through
`run-private-mount-gate.sh`:

```sh
deployment/dev9/run-private-mount-gate.sh bash -ceu '
  # Test-only mounts and the test command belong here.
'
```

The wrapper creates a distinct mount namespace with
`--propagation private`, kills the child if the wrapper exits, verifies that the
new namespace differs from PID 1, rejects shared/master propagation on `/`, and
compares the outer `/var/lib` mount record before and after the command. It also
refuses a pre-existing temporary, deleted, or fake `/var/lib` mount. Do not
bypass the wrapper, invoke its private inside token, or let the child daemonize.
The outer before/after check is required even when the inner test succeeds.

1. Install the verified V3 release and configuration without changing V2.
   Freeze directories at mode `0555`, ordinary files at `0444`, both
   `bin/odoo-accounting-cli-v3`, `bin/odoo-accounting-cli-v3-broker`, and
   `bin/odoo-accounting-cli-v3-effect-finalizer`, and
   `deployment/dev9/run-private-mount-gate.sh` at `0555`. Run the extracted
   broker launcher with `--help` and require exit
   zero, empty stderr, and its exact usage line before publishing the release.
   Create the dedicated broker identity and all named V3 groups, add only the
   identities documented above, and verify their numeric IDs.
2. From that exact release root, run
   `python3 -I deployment/dev9/render-systemd-service.py --release-root ABSOLUTE_RELEASE_ROOT`,
   capture stdout to a
   new root-only temporary file, and install it as
   `/etc/systemd/system/odoo-accounting-cli-v3-broker.service` mode `0644`.
   Rendering verifies the release manifest and external deployment anchor and
   rejects any canonical launcher unless it is a regular non-symlink file
   with exact mode `0555`. It replaces the single `@V3_RELEASE@` token; never
   install the unrendered template. Copy the three socket units beside the
   rendered service, all root-owned and not group/world writable. Install
   `odoo-accounting-cli-v3-tmpfiles.conf` under `/etc/tmpfiles.d/`, then run
   `systemd-tmpfiles --create /etc/tmpfiles.d/odoo-accounting-cli-v3-tmpfiles.conf`
   and verify the runtime directory owner and mode.
3. Before starting the service, verify that
   `/var/lib/odoo-accounting-cli-v3` already exists with its established safe
   root metadata and that only the exact runtime-configured store parents are
   broker-owned mode `0700`. Verify that the sibling broker `StateDirectory`
   cannot overlap or contain that historical root. Run `systemd-analyze
   verify` on all four installed units. Then run
   `systemctl daemon-reload`. The release CI additionally executes the real
   Odoo child-process boundary from outside `/home` in a transient service
   with `ProtectHome=yes`, `ProtectSystem=strict`, and the same managed
   `StateDirectory`; a static unit verification alone is not sufficient.
4. Enable and start all three socket units in one transaction:

   ```sh
   systemctl enable --now \
     odoo-accounting-cli-v3-pi-broker.socket \
     odoo-accounting-cli-v3-session-mint.socket \
     odoo-accounting-cli-v3-trusted-approval.socket
   ```

   Do not enable the service directly: it requires the exact three named
   descriptors and fails closed on missing, extra, duplicated, renamed, or
   untrusted sockets.
5. Before routing Pi traffic, verify the service runs as the dedicated UID,
   all socket owners/groups/modes, the composition fingerprint, integrity
   preflight, read-only calls, rejection gates, and sandbox write/recovery
   evidence. Production write capabilities remain disabled until their own
   safety gates pass.

The service performs full root-config loading, release/topology verification,
and durable-store integrity checks before reading the systemd activation
environment or accepting traffic. All three transports are started together.
SIGTERM/SIGINT closes the group; an unexpected exit from any transport closes
the other two and makes systemd restart the service. Journal errors are fixed
messages and never contain request bodies, handles, paths, secrets, or nested
exceptions. The 135-second stop window exceeds the outer 115-second broker
deadline, allowing in-flight handlers and their bounded Odoo child processes
to finish before systemd escalates termination.

The separate Pi chat boundary reserves 5 seconds for Broker preflight, at most
120 seconds for the Pi child, and 10 seconds for parent-only result delivery.
Its 135-second total is enclosed by Odoo's 150-second HTTP deadline. Both the
ordinary model-facing session and the independent single-use result-delivery
session must have an issued lifetime of at least 170 seconds and enough
remaining lifetime to cover the outer deadline; the deployed 180-second mint
TTL satisfies that gate.

## Rollback

First remove V3 routing from Pi. Stop and disable the three V3 socket units,
then stop the V3 broker service and confirm no V3 socket remains. Restore the
previous immutable V3 broker package/config only if its matching state schema
and release routes are retained; otherwise leave V3 offline for forensic
recovery. Do not change V2 during this rollback, and never delete V3 SQLite or
audit files.
