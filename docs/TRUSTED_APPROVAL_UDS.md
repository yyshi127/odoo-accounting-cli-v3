# Trusted Odoo approval boundary

The Dev9 approval service exposes exactly three local Unix-socket routes:

- `POST /v1/approval/request` creates or reuses the immutable challenge for a
  previewed operation and must run as the original requester;
- `POST /v1/approval/inspect` accepts exactly `session_handle` and
  `challenge_id`, then returns the approver-authenticated authoritative
  operation parameters and durable precheck evidence without approving it;
- `POST /v1/approval/decide` records `approve` or `deny` as a different Odoo
  user in the same company, after a fresh Odoo ACL check.

The socket is root-created, mode `0660`, and admits only the configured Odoo
Unix UID through Linux `SO_PEERCRED`. Pi Bridge has a different UID and group
and cannot connect. The broker runs as a third dedicated non-root UID. The
wire body carries an opaque short-lived session handle plus only the exact
operation/challenge business fields. It cannot select a user, company,
database, release, registry, signing key, approval signature, TTL, or route.
The inspect body cannot supply a deadline or peer identity. Its success body is
exactly `{ "ok": true, "inspection": ... }`; the inspection is independently
rebuilt and checked against its operation, challenge, precheck evidence, and
both canonical digests before it is returned. Full financial preview and
dependency evidence remains under
`inspection.precheck.evidence.handler_details`. The same response-size,
absolute-timeout, concurrency, and shutdown-drain bounds apply to all three
routes. Request bodies remain bounded to 8 KiB by default. Responses default
to 1 MiB, matching the Odoo approval client, so complete 200-line bank
statement and 250-line adjustment previews are not truncated; operators may
configure a smaller bound for constrained deployments or raise it only as far
as the fixed 4 MiB hard ceiling. An oversized response fails closed with the
fixed `approval_response_rejected` error and is never partially reported as a
successful inspection.

The Odoo control addon keeps request, inspect, and decision transport methods
private (their names start with `_`). It does not expose bare
`request_v3_approval` or `decide_v3_approval` model-RPC methods and has no
anonymous/custom HTTP controller. The only approver-facing entry is the
`odoo.accounting.cli.v3.approval.wizard` transient form. Its public `create`
method accepts exactly one `challenge_id`; user, company, parameters, digests,
and authority data cannot be supplied by RPC. The wizard rejects superuser
environments, requires the approver group, binds every record to `create_uid`
and the active allowed company, and rejects self-approval.

Creation immediately calls the private `_odoo_v3_inspect_approval` transport
and stores a complete canonical snapshot. The form shows the full parameters
JSON, precheck JSON, and authoritative snapshot JSON read-only so amounts,
dates, suppliers/partners, currencies, and line details remain auditable. Only
a strict denial reason can be edited. Before either decision, the wizard
inspects again and compares the complete snapshot; after the decision it
inspects once more and requires the same challenge binding and the exact
authoritative version transition. Expired, non-pending, cross-company,
self-approved, changed, or malformed previews fail closed. A failure never
returns an Odoo success action; the saved wizard remains available for an
explicit refresh and review.

An approver-only ACL grants read/write/create but no unlink. A matching record
rule requires both `create_uid = user.id` and `company_id in company_ids`.
The action, menu, and all object buttons are also restricted to the approver
group. No approval path uses `sudo` or caller-provided context authority.

Every call revokes its minted handle in a `finally` path. A malformed mint
response that contains a syntactically valid candidate handle is also revoked,
even when its HTTP status is wrong. A revoke failure, response mismatch,
timeout, broker error, or audit failure is reported only as a fixed safe Odoo
error. It never returns or logs the handle or a backend exception.

The durable broker audit records the authenticated Odoo session identity,
company, operation/challenge route, outcome, and the observed Unix UID/GID/PID.
The approval service never returns a signed approval to Odoo or Pi; only the
trusted authority may consume the durable approved challenge when the original
requester later invokes `operation.approve_execute`.
