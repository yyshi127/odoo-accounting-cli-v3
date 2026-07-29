# Target host Dev258 immutable side-load

This record covers the side-by-side installation of Dev258 on
`43.165.173.80` on 2026-07-30. It is an immutable release-installation
receipt, not an Odoo business receipt, Pi end-to-end evidence, write-capability
evidence, or production-promotion approval.

No Odoo business method was invoked. The active V3 route, Odoo service, Pi
Bridge service, V2 files, runtime configuration, secrets, and systemd units
were not changed.

## Canonical identity

- release: `0.1.0.dev258-6a8e1eb06a57`
- commit: `6a8e1eb06a5782c1c4bd52450f2ad27f8767d8ab`
- package SHA-256:
  `7e938434fe385606d426c0d96b738096b8cf70c616e800295fb287fedb476150`
- semantic manifest SHA-256:
  `cd62b2346ca5c78e5c806dc79ab2f92e7fb9924217d1a84142d0930d51e01338`
- rendered manifest file SHA-256:
  `46d8c7384d7975e07130ed2935142f205300e51264cba3557733b0f5e5e945c0`
- trusted-artifact SHA-256:
  `2a336d543fc3fbd8bfedc19a1ec4c044f19e70ea1255c68dba25a1be6092c33f`
- capability registry digest:
  `53e908e0eeb62c07bf7627a687750323edc6ca1a6759c5548580cd3a5b96b601`
- exact installer SHA-256:
  `ce9a3cb58bb9fc679046a798f2575265568bb57154d8b26716ee572a89982808`

Two clean local builds produced byte-identical package, manifest, and
trusted-artifact hashes. The final package was independently extracted and all
396 manifest-listed source files plus `RELEASE-MANIFEST.json` were verified
before transfer.

## Pre-install observation

- `/opt/odoo-accounting-cli-v3/current` resolved to
  `/opt/odoo-accounting-cli-v3/releases/0.1.0.dev250-8414e9922f03`.
- Dev258 was not installed and had no incoming upload directory.
- ordinary available space on the root filesystem was `7003066368` bytes.
  This exceeds the installer's 2 GiB retained-space floor but remains below
  the separate 8 GiB sandbox-write floor.
- `odoo19.service` was active with PID `3516490`, started
  `2026-07-29 10:23:30 CST`.
- `sudo-pi-agent-bridge.service` was active with PID `3296254`, started
  `2026-07-29 06:01:25 CST`, and still launched
  `/mnt/odoo/odoo19/custom/services/pi-agent-bridge/server.mjs`.

## Transfer and installation

The archive, trusted-artifact sidecar, and exact installer were transferred
only to:

```text
/opt/odoo-accounting-cli-v3/upload-sources/incoming/0.1.0.dev258-6a8e1eb06a57/
```

The directory was root-owned mode `0700`. Each input was a root-owned,
single-link regular file mode `0444`. Server-side SHA-256 values matched the
canonical identity above before Python was invoked.

The release-owned side-load installer returned:

```json
{
  "already_installed": false,
  "commit": "6a8e1eb06a5782c1c4bd52450f2ad27f8767d8ab",
  "manifest_sha256": "cd62b2346ca5c78e5c806dc79ab2f92e7fb9924217d1a84142d0930d51e01338",
  "package_sha256": "7e938434fe385606d426c0d96b738096b8cf70c616e800295fb287fedb476150",
  "release": "0.1.0.dev258-6a8e1eb06a57",
  "version": "0.1.0.dev258"
}
```

It published the immutable release, canonical package, and external
trusted-artifact anchor. It did not create or replace `current`.

## Post-install verification

- the installed file set was exactly the 396 manifest-listed source files plus
  `RELEASE-MANIFEST.json`;
- sampled data and manifest files were root-owned mode `0444`;
- the canonical CLI launcher was root-owned mode `0555`;
- the installed package and external anchor reproduced their canonical hashes;
- the exact release launcher returned `verified:true` with the canonical
  version, commit, package, manifest, and registry identity;
- the registry audit returned 30 strict-schema capabilities: 10 reads and 20
  writes;
- all 20 writes remained `evidence.level:declared`, with no staged or enabled
  write environment;
- no capability was enabled in test, sandbox, or production;
- production promotion remained false.

The release verifier was independently rerun as the unprivileged `nobody`
identity with the same empty environment and release-owned `PYTHONPATH` used
by the installer. It returned:

```text
verified 0.1.0.dev258 6a8e1eb06a5782c1c4bd52450f2ad27f8767d8ab
```

A second invocation of the exact installer returned
`"already_installed":true` with the same complete identity, proving the
side-load publication is idempotent.

## Unchanged active state

After both installation invocations:

- `current` still pointed to `0.1.0.dev250-8414e9922f03`;
- `odoo19.service` retained the same PID and start time;
- `sudo-pi-agent-bridge.service` retained the same PID, start time, and legacy
  launch path;
- Dev258 remained an unrouted candidate.

## Promotion blockers

Dev258 must not be routed or described as production ready because:

- the pinned Pi dependency closure still reports one high and one moderate
  denial-of-service vulnerability;
- the target does not have retained live Pi 38-scenario/95%-selection evidence
  for this exact release;
- no registered write capability has real Odoo creation, replay, failure,
  verification, and recovery evidence;
- important write families remain unimplemented;
- the target remains below the configured 8 GiB sandbox-write capacity floor;
  and
- Odoo, CLI, and Pi Bridge do not yet run one routed release identity.
