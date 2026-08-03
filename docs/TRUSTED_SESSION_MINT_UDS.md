# Trusted Session Mint UDS

`trusted_session_mint_uds` is a local credential lifecycle boundary. It exposes
`POST /v1/trusted-session/mint`, the parent-only
`POST /v1/trusted-session/result-delivery/mint`, and
`POST /v1/trusted-session/revoke` on a Linux filesystem Unix socket. It does
not create a TCP listener. Revoke accepts exactly `{ "handle": "..." }`,
applies the fixed audit reason
`odoo_request_completed`, and never echoes the handle.

The root-owned launcher fixes the Odoo issuer UID, Pi Bridge UID, socket group,
session TTL, maximum resolution count, and the broker's current release and
registry digests. Those route digests are injected into the mint configuration
from the already validated top-level broker route; they are not duplicated in
the `session_mint_uds` JSON object. The HTTP request cannot select or override
TTL, use count, session ID, or handle. The socket admits only the configured
Odoo issuer UID using Linux `SO_PEERCRED`.

The durable store defaults to one resolution as a fail-safe primitive, but that
value is not a valid production mint budget. Broker authentication plus
Authority authorization consumes at least two resolutions for a normal read or
write, `operation.preview` consumes three, and one `/chat` plan can call
prepare, preview, status, and result in sequence. The mint configuration
therefore enforces a minimum of 16 uses and defaults to 32 (maximum 64). This
budget applies only to the ordinary model-facing session. The independent
result-delivery route always issues exactly one use and the Pi child never
receives that handle. The composition root must still choose TTL and budget for
its complete call graph; it must never inherit a small test fixture value.

## Same-UID threat

`SO_PEERCRED` proves a Unix UID. It cannot distinguish a legitimate Odoo worker
from another process running under that same UID. Any code execution under the
Odoo issuer UID therefore has credential-minting authority and can submit a
different user or company binding.

Production requirements:

- Pi Bridge must run under a different Unix UID from the Odoo issuer. The
  configuration rejects equal UIDs.
- Pi Bridge must not be able to `sudo`, `setuid`, inject into, or write code or
  configuration executed by the Odoo issuer UID.
- Pi Bridge should not belong to the mint socket group. Filesystem permissions
  are defense in depth; `SO_PEERCRED` remains mandatory.
- The Odoo issuer account should be dedicated and unprivileged. Other services
  must not share it.
- The opaque handle returned on success is a bearer credential. It must not be
  logged, persisted in Odoo chatter, returned to a browser, or included in an
  exception. Pass it directly to the trusted broker and discard it.

## Odoo-side identity source

No generic web payload may be forwarded to the mint route. The V3 Control Addon
implements a private `models.AbstractModel` client method; it is deliberately
named with a leading underscore and has no HTTP controller or ACL row. It builds
the request inside trusted server-side model code:

- `database_name` from `env.cr.dbname`;
- `user_id` and principal from `env.user`;
- `company_id` from `env.company`;
- `allowed_company_ids` from `env.companies`;
- database UUID, Odoo instance ID, and environment from trusted database/server
  configuration, not request context supplied by a browser or Pi.
- release-manifest and capability-registry digests from an independent check of
  the exact add-on files executing under `__file__`, not an environment value,
  add-on version string, browser field, or Pi header.

Before contacting the mint socket, the client requires the canonical source
path
`<release>/odoo_addons/odoo_accounting_cli_v3_control/models/session_client.py`.
The release must be under the fixed `releases/<version>-<commit12>` layout. On
Linux, the release, add-on files, manifest, registry, external anchor, and their
relevant ancestors must be canonical non-symlink objects, root-owned, and not
writable by the Odoo identity; immutable release members are required to have
no write bit and exactly one hard link. The verifier opens files with
`O_NOFOLLOW`, compares path and descriptor identity before and after a bounded
read, and rejects runtime bytecode, missing files, or any extra add-on member.

It then verifies the exact four-field external anchor, the canonical unsigned
`RELEASE-MANIFEST.json` digest, release directory name, commit, every manifest
entry for the control add-on, and the manifest-bound registry bytes. The
registry digest uses the same canonical ordered `capabilities` array algorithm
as `registry.registry_digest`. A failure prevents both mint and Pi calls.

The client accepts exactly `{ "message": "..." }` as its business input. It
rejects identity, company, database, environment, TTL, use-budget, header, and
session-handle fields present in RPC/controller/web/Pi payloads. Instance ID,
environment, mint socket path, and Pi Bridge port come from the root-injected
Odoo process environment: `ODOO_V3_INSTANCE_ID`, `ODOO_V3_ENVIRONMENT`,
`ODOO_V3_SESSION_MINT_SOCKET`, `ODOO_V3_PI_BRIDGE_PORT`, and the mandatory
positive `ODOO_V3_BROKER_UID`. The broker UID must identify the dedicated
non-root systemd-activated broker service and must differ from the current Odoo
process UID. Browser and Pi payloads cannot override it. The client verifies the
socket is in a non-writable root-owned directory, is a root-owned Unix socket,
and reports exactly the configured broker service UID through `SO_PEERCRED`
after connection. Socket ownership authenticates the systemd-created endpoint;
peer credentials authenticate the non-root worker serving it.

For chat, Odoo mints an ordinary session and a distinct, single-use final-result
session from the same server-established identity. It sends them only in
`X-Odoo-V3-Broker-Session` and
`X-Odoo-V3-Result-Delivery-Session` to literal loopback `127.0.0.1` on
`/chat`. Pi receives only the ordinary handle on FD3; the parent retains the
second handle for `result.deliver`. The client attempts to revoke every acquired
handle after both success and failure, even when an earlier revoke fails. Any
missing or rejected revoke makes the Odoo call fail closed. Neither transport
logs or returns either handle.

The fixed timing budget is 5 seconds for Broker preflight, at most 120 seconds
for the Pi child, and 10 seconds for parent-only result delivery (135 seconds
total). Odoo uses a 150-second outer HTTP deadline and accepts chat sessions only
when their issued lifetime is at least 170 seconds and their remaining lifetime
covers that outer deadline. The deployed 180-second root TTL meets this bound;
shorter or expired credentials fail before `/chat`.

## Request and response

The strict JSON request contains exactly these fields:

```json
{
  "allowed_company_ids": [7, 9],
  "company_id": 7,
  "database_name": "accounting",
  "database_uuid": "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81",
  "environment": "sandbox",
  "odoo_instance_id": "odoo-prod-01",
  "principal": "odoo:user:42",
  "registry_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "release_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "user_id": 42
}
```

Mint compares both request digests with its root-composed current route before
calling the durable store, so a different but valid retained add-on release
cannot create a session or security event. The digests are immutable columns in
trusted-session store schema v2 and are covered by the binding digest and
hash-chained issue/resolve events. Broker authentication rechecks them against
the current route after every handle resolution, before parsing or executing
read, prepare, preview, approve-execute, status, result, recovery, or any of the
three independent approval calls.

Schema v1 sessions have no release identity. They are intentionally not
migrated: opening a v1 store rejects startup without modifying the database.
Because sessions are short-lived bearer credentials, the upgrade procedure is
to stop the broker, retain the v1 file as audit evidence, initialize a new v2
session store at the configured private path, and require callers to mint new
sessions. Never add default route digests to old rows.

Successful responses return the server-generated opaque handle, session ID,
issue/expiry timestamps, and server-selected use count: the root-configured
budget for ordinary mint and exactly one for result delivery. Errors are fixed
safe envelopes and never echo request values or exception details.
