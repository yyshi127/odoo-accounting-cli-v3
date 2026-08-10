# Target-host Dev263 side-load evidence - 2026-08-10

This record documents a side-load-only Dev263 delivery to the target host. It
does not authorize a production route, enable a capability, or prove any Odoo
accounting write. V2 and the routed V3 release were left unchanged.

## Release identity

- Version: `0.1.0.dev263`
- Commit: `37f547287e20e7d80473b4a24ad40fa74b781f3a`
- Commit tree: `ef2ee736626bddf7603814d0e04c7a8003fa866d`
- Release: `0.1.0.dev263-37f547287e20`
- Package SHA-256:
  `677d8093b6697ca4f2e91766cecfdba4196686a36f52901fffc80bede9dc3974`
- Trusted-artifact SHA-256:
  `9a5467ed8b90226a14027d65761ed7810f58192597e6fdef1d454f44cbb439a2`
- Embedded manifest identity SHA-256:
  `d6222c52f05c96dfd0c945a7940d53f5b26ec51e8108e9edd357c1e0f2c57353`
- Embedded manifest file SHA-256:
  `3cda2547d241ecd42e79fee5d6023a2fd15eebfbfcf91d6dcfa3aab1d712a6bb`

Two clean-tree builds produced byte-identical packages and trusted-artifact
documents. The GitHub branch `codex/dev9-write-control` and the local branch
both resolved to the full commit above after a non-force push.

## Pre-delivery gates

- Full local `pytest` suite: exit `0` in 513.6 seconds.
- Release-archive tests: `26/26` passed.
- Release archive plus strict CLI v3 dispatch tests: `43/43` passed.
- Compileall, YAML parsing, staged-diff checks, and sensitive-path/key scans
  passed.
- A pre-install target Linux/root run collected exactly `145` tests:
  `67` admission, `61` v3, `1` real Linux integration, and `16` SSHSIG.
  All `145` passed with zero skips, failures, or errors. Its JUnit SHA-256 was
  `c99e81372e1fb2d5851b8f84baf5a8095263e9849634814077e921562c635076`.

The Linux integration used real `ssh-keygen`, root-managed fixed paths, a real
SQLite publication ledger, and cleanup assertions. It remained synthetic with
respect to the raw Odoo, accounting-oracle, Pi, and security source bodies, so
it did not change the Dev263 Goal blocker.

## Side-load result

The exact release installer from the package installed these immutable
objects:

```text
/opt/odoo-accounting-cli-v3/releases/0.1.0.dev263-37f547287e20
/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev263-37f547287e20.tar.gz
/opt/odoo-accounting-cli-v3/trusted-artifacts/0.1.0.dev263-37f547287e20.json
```

The first installer response reported `already_installed:false`. Repeating the
same exact request reported `already_installed:true`; the package, release
manifest, external anchor, and running installer identity were reverified.
The installed main CLI `--help` entry point also executed successfully.

The installed immutable release then ran the same four Linux/root test modules
with bytecode disabled, pytest plugin auto-loading disabled, and `PYTHONPATH`
pinned to the installed release. The exact result was again `145/145`, with
zero skips, failures, or errors. The retained JUnit SHA-256 was
`ab413c8b0fce83d3534eb3dde4bf92d3876da93873b64ff7805e905650b3e1a2`.

## Unchanged production boundary

After installation and every verification step:

- `/opt/odoo-accounting-cli-v3/current` still resolved to
  `/opt/odoo-accounting-cli-v3/releases/0.1.0.dev250-8414e9922f03`;
- the routed version remained `0.1.0.dev250`;
- `odoo19.service` was active and its Odoo process remained present;
- the V3 broker and effect-finalizer services remained inactive;
- no production Odoo accounting request or write was executed;
- no capability was staged or enabled;
- no `/var/lib/odoo-accounting-cli-v3/read-evidence-v3` test ledger remained;
- no integration release, `.install-*` object, or upload staging directory
  remained; and
- uploads and generated test artifacts were kept under the dedicated V3
  temporary hierarchy, never under `/root`.

Dev263 is therefore installed and reproducible but deliberately not routed.
Its raw evidence is still normalized-contract-only, self-contained sealed
final evidence is not implemented, and all production promotion flags must
remain false.
