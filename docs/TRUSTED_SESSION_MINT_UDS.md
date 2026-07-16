# Trusted Session Mint UDS

`trusted_session_mint_uds` is a local credential lifecycle boundary. It exposes
only `POST /v1/trusted-session/mint` and `POST /v1/trusted-session/revoke` on a
Linux filesystem Unix socket. It does not create a TCP listener. Revoke accepts
exactly `{ "handle": "..." }`, applies the fixed audit reason
`odoo_request_completed`, and never echoes the handle.

The root-owned launcher fixes the Odoo issuer UID, Pi Bridge UID, socket group,
session TTL, and maximum resolution count. The HTTP request cannot select or
override TTL, use count, session ID, or handle. The socket admits only the
configured Odoo issuer UID using Linux `SO_PEERCRED`.

The durable store defaults to one resolution as a fail-safe primitive, but that
value is not a valid production mint budget. Broker authentication plus
Authority authorization consumes at least two resolutions for a normal read or
write, `operation.preview` consumes three, and one `/chat` plan can call
prepare, preview, status, and result in sequence. The mint configuration
therefore enforces a minimum of 16 uses and defaults to 32 (maximum 64). The
composition root must still choose TTL and budget for its complete call graph;
it must never inherit the durable store's single-use default or a small test
fixture value.

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

After minting, it sends the handle only in
`X-Odoo-V3-Broker-Session` to literal loopback `127.0.0.1` on `/chat`.
The client invokes `/v1/trusted-session/revoke` after both success and failure.
A missing or rejected revoke makes the Odoo call fail closed. Neither transport
logs the handle.

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
  "user_id": 42
}
```

Successful responses return the server-generated opaque handle, session ID,
issue/expiry timestamps, and root-configured use count. Errors are fixed safe
envelopes and never echo request values or exception details.
