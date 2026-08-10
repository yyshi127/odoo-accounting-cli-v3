# Read-evidence index: Dev265 inventory, Dev264 contracts, and Dev263 active admission

Dev263 adds a Linux-only, public-key-verifiable `read-evidence-index.v3`
active-admission path beside the legacy v2 structural checker. The public v3
verifier is active-only: callers provide the index path, while the executing
release identity, trust roots, clock, root-owner policy, active pointer, and
publication ledger are derived internally. There is no caller-selected
`mode`, `now`, trust path, key, owner override, or sealed-verification API.

This is a cryptographic closure and publication boundary, not yet complete
Goal evidence. The retained v3 raw bodies currently contain normalized
contract summaries rather than the original Odoo requests/results/receipts,
PostgreSQL oracle rows, Pi event traces, and negative-control request/response
objects. Consequently a successfully signed closure reports:

```text
cryptographic_closure_verified: true
semantic_evidence_level: normalized_contract_only
external_read_evidence_verified: false
goal_evidence_admissible: false
production_promotion_allowed: false
```

Every capability remains `verified:false` until the real raw semantic adapters
independently recompute those facts. Signatures prove key possession and exact
bytes; they do not prove that a summarized accounting claim is true.

The current Dev265 Registry has 13 read capabilities. The newly added
`acct.refund.post_reconcile_eligibility.v1` is mapped to the reviewed refund
eligibility handler and to the full-raw contract inventory, is
`contract_tested`, and is staged only for `test`. It has an empty receipt list,
is not enabled, and has no retained target-release Odoo or accounting-oracle
evidence. Its local contract binds the exact pristine refund/origin graphs,
term-line/account pair, full or partial expected reconciliation outcome,
partner-rank preconditions, and the parameters for the disabled
`acct.refund.post_reconcile_origin.v1` write; this is not evidence that those
facts were observed on real Odoo.

## Dev264 offline contract boundaries

Dev264 adds two library-only validators; it does not change the public v3
index verifier or CLI dispatch.

`read_evidence_raw_v3.validate_full_raw_evidence` revalidates the supplied
complete `Capability` tuple, requires its full Registry digest to match the
supplied release identity, derives every read capability and contract, binds
the exact canonical v3 scope plus trailing-LF digest, and supports four distinct
offline contracts. `live_odoo` and `accounting_oracle` validate successful
requests/results/receipts against Registry schemas and bind the explicitly
declared request, result, and oracle company fields;
`release_identity` validates release and scope bindings; `security_negative`
validates the request, exact error, authentication witness, zero-side-effect
witness, and absence of a receipt. It rejects `pi_e2e` and directs that full raw
exchange to the existing `PiEvidenceVerifier`; duplicating its broker
request/response, timing, operation-snapshot, and special-route contract would
create a second incompatible trust boundary. The release identity, Registry,
and scope are still authenticated inputs from a future trusted collector
context; this function does not create that trust. It does not verify
read-receipt signatures or independently attest an SQL oracle's implementation,
query semantics, company-scoped database execution, or read-only transaction.
A disclosed technical rate-source company is type-checked without treating it
as a requested business company.
Its only positive claim is
`full_raw_contract_validated:true`; trusted source, external evidence, Goal,
and production claims remain false.

`read_evidence_publication.validate_publication_receipt_contract` accepts only
bounded canonical JSON bytes with one LF and validates the exact future receipt
schema, fixed admission paths, digests, counts, sizes, half-open authorization
times, and deterministic receipt ID. It accepts no ledger object, filesystem
path, key, trust root, clock, closure binding, or signature material. A
structurally valid receipt therefore reports all of these as false:

```text
ledger_provenance_verified: false
source_closure_verified: false
retained_closure_verified: false
publisher_signature_verified: false
external_read_evidence_verified: false
goal_evidence_admissible: false
production_promotion_allowed: false
```

Neither Dev264 validator is a signing API, a sealed verifier, an active-index
adapter, or a promotion hook. Their schemas are foundations for later trusted
producer and final-bundle work, not evidence that such work already exists.

## Active v3 locations

For executing release `<release>` and run `<run-id>`, the verifier accepts only
the canonical active tree:

```text
/var/lib/odoo-accounting-cli-v3/read-evidence-v3/<release>/
  active.json
  runs/<run-id>/
    index.json
    index.json.sshsig
    active-admission.json
    active-admission.json.sshsig
    ...exact signed closure members...

/var/lib/odoo-accounting-cli-v3/read-evidence-v3/admissions.sqlite3
```

The index must be canonical JSON with one trailing LF. The run directory must
contain exactly the declared regular, single-link files and directories; links,
hard links, special files, extras, path traversal, digest/size drift, and
read-time replacement are rejected. File-count, tree-depth, JSON-complexity,
per-file, and total-byte limits apply.

`active.json` binds the exact release, run, index digest, admission digest,
admission payload digest, and monotonic sequence. Active verification also
requires the same exact payload binding to be in `PUBLISHED` state in the existing
publication ledger. A missing, stale, expired, changed, replayed, or merely
consumed admission fails closed.

## Fixed release trust

The verifier first proves the executing immutable release through its deployment
anchor and `RELEASE-MANIFEST.json`. It then derives, rather than accepts from a
caller, these v3 trust inputs:

```text
/opt/odoo-accounting-cli-v3/trusted-artifacts/<release>.read-evidence-v3.json
/etc/odoo-accounting-cli-v3/trust/read-evidence-v3/<release>/revocations
/etc/odoo-accounting-cli-v3/trust/read-evidence-v3/<release>/roles/<role>.allowed-signers
/usr/bin/ssh-keygen
```

Role filenames replace each role-name dot with `__`; for example,
`verifier.live_odoo` uses `verifier__live_odoo.allowed-signers`.

The trust anchor pins the exact release identity, `ssh-keygen`, revocations,
each allowed-signers file, and nine unique Ed25519 public-key fingerprints.
Every path component is root-owned and not group/world writable. Files are
opened with `O_NOFOLLOW`, held by descriptor, digest-checked, and passed to
`ssh-keygen -Y verify` through `/proc/self/fd` with a fixed principal and
namespace. Unsupported platforms fail before evidence or trust input is used.

The nine non-interchangeable roles are:

- `scope`
- `authorization`
- `collector`
- `admission`
- `verifier.accounting_oracle`
- `verifier.live_odoo`
- `verifier.pi_e2e`
- `verifier.release_identity`
- `verifier.security_negative`

The authorization binds the release, run, scope, collector role, unique
authorization ID, nonce digest, and half-open approval interval
`not_before <= time < expires_at`. `admitted_at` must be inside that interval;
active verification uses the system UTC clock and rejects the closure at or
after expiry. Callers cannot extend or replace the approval interval.

## Rollback-journal publication ledger

The admission store is a private SQLite database using `DELETE` rollback
journaling, not WAL. Its parent is mode `0700`; the writer requires database
mode `0600`, while the existing-only verifier accepts the private read-only
mode `0400` as well as `0600`. Unsafe owners, ancestors, links, extra hard
links, legacy WAL/SHM sidecars, or a hot rollback journal are rejected.
Read-only verification opens an existing database only, enables query-only
access, and never creates or recovers state. A hot journal requires the
authorized writer recovery path before verification can continue.
The writer may resume an interrupted first bootstrap only when the same private
single-link inode is exactly zero-length or a strictly empty SQLite database.
For a valid hot rollback journal it first completes SQLite recovery, closes the
connection, confirms the same inode and no remaining sidecar, fsyncs the
database and parent, and only then initializes the schema. Unknown objects,
metadata, residual pages, or sidecars that do not recover cleanly are rejected.

Publication is one-way and replay-safe. A unique authorization/nonce/run/index
reservation may move only `PENDING -> CONSUMED -> PUBLISHED`. The first
transition fixes the payload binding; the second adds the exact
admission-signature path, digest, size, and publication time. Triggers forbid
deletion, changes to schema metadata or identity/binding columns, any other
transition, and every change after terminal `PUBLISHED`. Repeating the same
committed request recovers the existing decision; a conflicting idempotency or
binding reuse is rejected. If commit durability is uncertain, the publisher
must stop signing, inspect the durable row through the recovery lookup, and
either resume the exact transition or leave the request rejected. It must never
invent a new sequence or payload to hide an uncertain outcome.

## Strict CLI dispatch

Run only the launcher inside the exact immutable release:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<release>
INDEX=/var/lib/odoo-accounting-cli-v3/read-evidence-v3/<release>/runs/<run-id>/index.json

"$RELEASE_DIR/bin/odoo-accounting-cli-v3" \
  evidence read-evidence-index-check \
  --evidence-index "$INDEX"

"$RELEASE_DIR/bin/odoo-accounting-cli-v3" \
  evidence read-capabilities-readiness \
  --read-evidence-index "$INDEX"
```

The CLI loads the executing release identity before reading the supplied index,
takes a bounded root-managed canonical schema snapshot, and dispatches exact v3
only to the active v3 verifier. Exact v2 goes only to the legacy checker.
Unknown, duplicated, non-finite, noncanonical, missing, unreadable, or swapped
schemas are rejected without fallback. A v3-to-v2 or v2-to-v3 replacement after
classification cannot select the other verifier.

## Legacy v2 remains diagnostic only

`read-evidence-index.v2` retains its strict source-bundle, receipt, HMAC, and
internal semantic checks for regression diagnosis. The same process can read
its HMAC signing material, so v2 does not establish independent public-key
custody. Regardless of structural success, the CLI forcibly reports v2 as:

```text
evidence_protocol: hmac-v2
external_read_evidence_verified: false
goal_evidence_admissible: false
production_promotion_allowed: false
```

A v2 bundle cannot be grandfathered, relabelled, or merely re-signed as v3.

### Legacy v2 trust inputs

The caller selects only the evidence index. It cannot select an attestation key,
runtime configuration, database, company, user, principal, environment, or
capability channel. For release `<release>`, the verifier derives and reopens:

```text
/opt/odoo-accounting-cli-v3/trusted-artifacts/<release>.read-evidence.json
/var/lib/odoo-accounting-cli-v3/evidence-sources/<release>/
/etc/odoo-accounting-cli-v3/trust/read-evidence/<release>/attestation-keys.json
```

The anchor binds the exact release identity, read runtime configuration, five
purpose-specific verifier identities and source-code digests, and one exact
instance/database/company/user/principal/environment/channel scope. The HMAC
file is a root-owned, canonical, single-link regular file with mode `0400` or
`0600`; every ancestor is root-managed and not group/world writable. Its five
keys, authority IDs, verifier IDs, source digests, and secrets are unique and
ordered by evidence purpose.

Those restrictions stop a caller redirecting verification to a parallel key
set, but they do not establish external verification. The checker process reads
all signing and receipt secrets, while collector/verifier IDs and source hashes
remain bound labels. Internal scope agreement does not itself prove which live
Odoo database, user, principal, or authorization token produced a case.

### Legacy v2 retained bundles and semantics

Each source bundle is a direct child of the release source parent and has one
canonical `BUNDLE-MANIFEST.json` plus an exact recursively enumerated file set.
The manifest binds release, scope, collector, collection time, and every member
path, size, and SHA-256. Links, hard links, special or extra files, unsafe
directories, digest/size drift, and read-time replacement are rejected. Bounds
apply to files, bytes, directories, JSON depth, nodes, and strings.

For every capability and evidence kind, the artifact reopens and exactly equals
this canonical source member; a hash or signed `passed:true` alone is rejected:

```text
artifacts/<capability-id>/<evidence-kind>.json
```

The exact sorted 12-by-5 v2 checks are:

- `live_odoo`: complete requests, results, and `read_receipt_v2` receipts, with
  recomputed counts/digests/HMAC and exact scope/release binding.
- `accounting_oracle`: the same verified result plus an equal oracle result and
  a database/company, repeatable-read, read-only, rollback, zero-write,
  unchanged-state, query/row-stream witness.
- `pi_e2e`: natural language, selected capability, identical collected/CLI
  parameters, fixed event order, verified Odoo receipt, business result, and
  audit-receipt bindings.
- `security_negative`: exact ACL, cross-company, expired, replay, and
  parameter-tamper rejections, with the fixed error/exit and no receipt or write.
- `release_identity`: exact executing version, commit, manifest, package,
  registry, release root, and complete capability-contract digest.

The legacy verifier derives counts, read/write facts, and pass state from those
bodies rather than trusting attestation claims. Attestations bind the source
manifest, derived summary, scope, release, capability contract, collection time,
and anchor-pinned verifier; receipt IDs cannot be reused across the set. These
checks remain valuable malformed-bundle and regression controls, but do not cure
the shared-HMAC authority or labelled-role limitations.

## Remaining blockers

Dev264 does not implement sealed verification or copy the complete v3 closure
into a self-contained final-evidence bundle. The existing final-manifest path
must therefore remain non-ready; its external source reopening is not archival
proof. A later change must atomically retain the exact closure, verify that copy
without the active pointer or live ledger, bind its tree digest/count/bytes into
a new final-manifest schema, and prove the checker never reopens an external
path.

After that, trusted raw Odoo, accounting-oracle, Pi E2E, release-identity, and
security-negative producers/attestors must collect and independently validate
all 13 current read capabilities. The Dev264 offline contracts do not verify
receipt signatures, oracle execution, collector identity, publisher
signatures, the live ledger, or either source/retained file tree. Until those
blockers close with target-host receipts, read Goal readiness remains false, no read
capability is production-enabled, and no business success may be reported from
this foundation alone.
