# Odoo Accounting CLI V3 Pi Bridge

This directory is the release-owned Pi Agent gateway for V3. It keeps the V2
tools available while exposing capability discovery and a business-only V3
tool surface. The model never receives fields for user/database context,
authentication signatures, approval signatures, approver identity, or signing
keys.

The service obtains the release and registry digests from the fixed V3 CLI's
verified `release identity` response. It passes those digests to the Pi process,
and the V3 runner rejects every call when either digest is missing or when a
registry, read receipt, release identity, or write audit receipt does not match.
Production service configuration must set `PI_BRIDGE_REQUIRE_V3_IDENTITY=1`.

Authenticated V3 reads and writes never spawn the CLI from the Pi extension.
They cross the root-configured Unix-domain socket in
`ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET`. Each fixed action path receives the
model's business JSON as its unchanged request body. The local broker derives
the signed user, company, database, principal, request, and operation identity
from an opaque authenticated-session handle. The handle is delivered to the Pi
child over inherited file descriptor 3; it is not an argument, environment
variable, tool parameter, result, or log field.

The HTTP service deliberately has no built-in SSO assumption. A root-owned ESM
module path must be configured in
`PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE`; the module exports
`resolveAuthenticatedSession(requestMetadata)` and returns exactly
`{ brokerSessionHandle }` only after authenticating the inbound HTTP request.
Production also sets
`PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256` to the lowercase SHA-256 of
that exact module. The resolver is a dependency-free, single-file ESM module
with exactly one `resolveAuthenticatedSession` or default export. V3 opens it
with `O_NOFOLLOW`, binds the opened inode and exact bytes to the configured
digest, verifies every ancestor is root-owned and not group/world writable,
and imports the verified bytes rather than reopening the configured path.
Without that injected resolver, without a valid resolved session, or without
the broker socket, V3 read/write tools are omitted from the Pi invocation and
the broker client also rejects direct calls before any CLI can run. The
caller-supplied `session_id` remains conversation-memory naming only and is
never an identity source.

Approval is a separate authenticated product channel, not a Pi tool and not a
route in this bridge. `odoo_v3_operation_approve_execute` exposes only
`operation_id`; the broker must load a valid, unexpired, content-bound approval
already recorded by that independent channel. It must never mint an approval
for the model. Broker responses require
`X-Odoo-V3-Broker-Authority: verified-v1`; terminal results are still rejected
unless their signed receipt structure, release digest, registry digest, and
fresh verification evidence match. Pi intentionally holds no receipt signing
key and therefore does not perform the cryptographic verification itself. The
broker may emit the authority header only for a response bound to an
authenticated session and fixed route. Before emitting a successful execution
response it must also cryptographically verify context, approval, result, and
receipt signatures. A trusted error such as "approval missing" may carry the
header only after the broker has authenticated the session and validated that
error without dispatching an unauthorized write.

Production remains disabled until the authenticated-session resolver, broker
socket ownership/permissions, broker session mapping, independent approval
endpoint, and retained-release routing have been implemented and exercised in
the dedicated sandbox. Every configured resolver module and its ancestor path
must satisfy the immutable Linux checks above; production also sets
`PI_BRIDGE_REQUIRE_V3_IDENTITY=1`. Deployment must likewise verify the broker
socket and every
parent directory against replacement, restrict the socket to the service
identity, validate peer credentials where supported, and keep the fixed
protocol/action allowlist. Until those gates are evidenced, the authority
header is not a production trust proof and V3 read/write tools must stay
unavailable.

The request release/registry headers always identify the current verified Pi
package. Every successful broker response separately supplies
`X-Odoo-V3-Executed-Release-Digest` and
`X-Odoo-V3-Executed-Registry-Digest`. For a new prepare or read they must equal
the current identity. For an existing operation they may identify a retained
historical release selected only from the durable operation record by the
broker. Pi validates a terminal receipt against that broker-selected executed
identity and rejects every model attempt to supply a release, registry,
runtime-config, binary, or broker-socket selector. Trusted error envelopes may
omit the executed identity when execution did not yield a trustworthy route
response; `odoo_effect: unknown` remains mandatory when dispatch outcome is
uncertain.

Run the bridge contract tests with:

```text
npm ci --ignore-scripts
npm test
```
