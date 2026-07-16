# Historical write-release routing

`odoo_accounting_cli_v3.historical_router.HistoricalReleaseRouter` is the
fail-closed broker component for continuing a durable write operation with the
exact V3 release that created it. It is intentionally separate from the Pi
command surface. Pi supplies only one of the six exact write requests; it
cannot supply a release digest, executable, runtime configuration, state path,
or command argument.

## Root-managed manifest

The service owns one absolute, canonical, non-symlink manifest path. On POSIX,
the production loader requires the manifest, every route target, and every path
ancestor to be root-owned and not group/world writable. Every target is opened
with `O_NOFOLLOW`, checked for replacement while open, hashed, and checked again
after dispatch. The manifest schema is:

```json
{
  "schema_version": 1,
  "current_release_digest": "<release-manifest-sha256>",
  "routes": [
    {
      "release_digest": "<release-manifest-sha256>",
      "registry_digest": "<capability-registry-sha256>",
      "executable_path": "/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3",
      "executable_sha256": "<launcher-sha256>",
      "runtime_config_path": "/etc/odoo-accounting-cli-v3/releases/<release>/write-runtime.json",
      "runtime_config_sha256": "<write-runtime-config-sha256>"
    }
  ]
}
```

Release entries, paths, and file inodes must be unique. The selected executable
is invoked without a shell as the fixed argv
`[executable, "operation", <fixed-action>]`. The complete exact request is sent
as canonical JSON on standard input. The child receives a minimal fixed
environment containing the route's trusted configuration path and digest plus
the expected release and registry digests. Request, response, stderr, and
elapsed-time limits are enforced; timeout and output-limit failures terminate
the child process group.

## Durable selection rules

- Before routing `operation.prepare`, the trusted broker resolves its stable
  Odoo-instance, database-UUID, environment, company, capability, and
  idempotency identity from the one shared durable operation store. An exact
  retry uses the release and registry recorded by the existing operation and
  reuses its original operation and request IDs. A first request uses
  `current_release_digest`. Changed business content, tenant bindings, or an
  unavailable retained release fail closed. A successful child response is
  rejected unless the selected release also persisted that exact operation.
- Preview, status, result, and approve-execute first load the operation from the
  durable operation store. Its immutable release and registry bindings select
  the route. Caller-supplied context must match the stored principal, database,
  environment, user, and company before dispatch.
- Recover first loads the trusted origin operation. A retry with an existing
  recovery operation must also have a matching durable recovery-operation
  binding; an orphan recovery operation is rejected. A first recovery prepare
  uses the origin release and is not returned unless the child persists the new
  recovery operation and its trusted origin binding.
- Every successful child response must contain the selected release and
  registry identity in the action's immutable operation, precheck, or audit
  receipt. The router then reloads durable state and re-hashes both route files
  before returning the response.

## Broker integration and retained-route gate

The router is now integrated into the trusted broker composition root,
`build_trusted_broker_runtime`; it is deliberately not composed by `cli.py`.
Before accepting traffic, that root pins the root-managed routing manifest,
requires its release/registry route set to match the authority route set,
verifies every immutable release and runtime configuration, and rejects a
retained runtime whose write state is not the one shared `SQLitePersistence`
store. The broker uses that same store for operation lookup and its
`SQLitePrepareIdempotencyResolver`, builds a release-specific authority and
receipt verifier for every admitted route, and delegates write dispatch to the
router. Pi still cannot select or invoke a release child directly.

Composition is not retained-release admission evidence. A historical write
release may be retained only when target-Linux evidence explicitly proves that
the exact release's Odoo runner and supervisor are compatible with the router's
outer process-group boundary. Timeout, output-limit, broker shutdown, and
forced-termination tests must prove that the CLI child, its Odoo supervisor,
the Odoo shell, and every descendant are terminated and reaped, including a
descendant that creates another session or process group. A current runner's
behavior must not be assumed for older release bytes.

Absent that exact-release supervisor/process-tree evidence, the route must be
omitted from both the root broker route set and the historical manifest. The
currently unsupported historical write routes therefore remain prohibited;
an operation bound to an unavailable route fails closed instead of falling
back to current code. The manifest may retain the current release as its sole
route, but neither composition tests nor router unit tests enable a historical
write release.
