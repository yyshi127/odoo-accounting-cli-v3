# Odoo Accounting CLI V3 Pi Bridge

This directory is the release-owned Pi Agent gateway for V3. Legacy direct
startup can retain the five V2 tools for the separately running V2 service,
but the canonical/bootstrap sidecar is strictly V3-only. Without a valid
broker session it exposes no tools; with a session it exposes only the ten
release-bound V3 tools. It never passes legacy `ODOO_TOOL_*`
credentials or selectors to that hardened Pi child. The model never receives fields for user/database context,
authentication signatures, approval signatures, approver identity, or signing
keys.
The legacy unauthenticated `/session/delete` maintenance route is not exposed
by the hardened sidecar because conversation IDs are not ownership credentials.
Every caller message is passed as one fixed-prefix literal argument, so leading
`@file` and `--option` text cannot activate Pi file or CLI argument syntax.

Production starts the canonical release's `pi_bridge/bootstrap.mjs`, never a
copied `server.mjs`. Before importing any Bridge runtime code, that built-ins-
only bootstrap verifies its root-managed Node interpreter, the external release
anchor, canonical manifest digest, complete immutable release file set, every
release file hash, and canonical package hash. It then verifies the separate
external Pi runtime anchor, exact Node bytes/version/platform/architecture and
the complete `node_modules` file/symlink inventory. Only then may it invoke the
already verified CLI's `release identity`; that response must exactly match the
anchor rather than becoming a new trust root.

The bootstrap next compares every executing Bridge runtime member (server,
extension, runner, session boundary, release verifier, package declaration,
and lockfile) with its manifest size and SHA-256 before dynamically importing
the server. The bootstrap attestation is held in the canonical bootstrap
module's private closure, not a public global; runtime server code can only read
it from that exact module instance. The server repeats the canonical release,
Node, dependency and Bridge checks before selecting tools; the Pi
extension repeats it before registering them. A direct server start, stale or
partially copied Bridge, changed file, symlink, hard link, or writable runtime
therefore fails closed; when optional V2-only startup is allowed, it exposes
only the retained V2 tools. On Linux the interpreter, manifest, package,
release, runtime files, and ancestors must be canonical, root-owned, and not
group/world writable. The bootstrap-derived manifest path is passed to the Pi
child as `ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST`; it is not a caller setting.

After this self-binding succeeds, the service passes the release and registry
digests to the Pi process. The V3 runner rejects every call when either digest
is missing or when a registry, read receipt, release identity, or write audit
receipt does not match. Production service configuration must set
`PI_BRIDGE_REQUIRE_V3_IDENTITY=1`; this now requires both the externally
anchored CLI identity and the executing Bridge self-binding.

Pi is invoked with `--no-extensions` plus the one explicit manifest-bound
extension, so project/global extension discovery cannot pre-register an
allowlisted V3 tool name. `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT`, and Jiti/ts-node loader settings are rejected or
removed before the child starts.

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
Without the release self-binding, every V3 tool is omitted. Without the
injected resolver, a valid resolved session, or the broker socket, V3
read/write tools are omitted from the Pi invocation and the broker client also
rejects direct calls before any CLI can run. The caller-supplied `session_id`
is not accepted by the hardened `/chat` request and is never an identity source.

`odoo_v3_capability_list` performs `acct.registry.list.v1` through that same
authenticated broker. Its model-facing request is exactly empty; only after
session authentication does the broker bind the trusted company ID, sign the
read context, execute Odoo ACL and company filtering, and return the complete
signed read envelope. `odoo_v3_capability_get` performs a fresh authenticated
registry read and selects one item locally. That selected item is explicitly
unsigned and always retains the unmodified complete signed source, receipt ID,
and result digest. A local static registry is never authorization evidence.

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

For terminal writes, `ok:true` means only that the broker/CLI returned a
well-formed tool envelope. Pi must still treat `business_succeeded:false` as an
unverified business outcome. The bridge adds
`bridge_guidance.must_not_report_business_success:true` with the next
`operation.status`/operator-review action for such responses; the model must
not convert them into accounting success, create a replacement operation, or
hide the missing verification/audit receipt from the user.

The hardened `/chat` path has a second, dedicated evidence channel on child
file descriptor 4. The release-bound extension emits one small canonical event
only after the Broker client has verified a successful read, preview,
diagnostic, or write result. At Pi `session_shutdown` it writes a terminal
event-count/stream-digest commit and closes the descriptor. The parent accepts
the child only after clean evidence EOF and exit zero, then requires Pi stdout
to be exactly one bounded canonical seven-field JSON object with an exact
action/capability match to one committed terminal event. Missing, truncated,
duplicated, reordered, oversized, or digest-mismatched evidence fails closed.
A clarification or refusal may have only the authenticated registry-list read
as supporting evidence; that receipt can never satisfy business success. A
diagnostic answer is explicitly `business_succeeded:false`: its receipt proves
the query, not success of the inspected operation. This
terminal-answer control does not by itself prove the full 38-scenario
natural-language gate or financial correctness; those require the separately
retained evidence described in `docs/PI_SCENARIO_ACCEPTANCE.md`.
The seven-field answer is currently an evidence locator, not the user-facing
accounting payload. Before production use, the parent must obtain the exact
verified result body from the trusted Broker/receipt store, recheck its digest,
and render a bounded business result plus audit receipt without asking Pi to
restate numbers. That result-delivery path is not yet implemented.

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

For `operation.approve_execute`, a connected broker response loss is reported
as `bridge_v3_broker_outcome_unknown`. An ambiguous local-state action is
reported as `bridge_v3_broker_reconciliation_required`. Both errors set
`retryable: false`: Pi must not repeat the request or create a replacement
operation. An operator must first query the operation and reconcile the trusted
broker/authority state, then follow the returned recovery guidance.

Run the bridge contract tests with:

```text
npm ci --ignore-scripts
npm test
npm audit --omit=dev
```

`npm audit` must be clean (or an explicitly reviewed, release-bound exception
must exist) before production promotion. At the time of this development
snapshot the pinned Pi dependency tree still produces a nonzero audit result;
root-level `overrides` do not repair the package's published shrinkwrap
reproducibly and therefore are not treated as a fix.
