# Read-evidence index: legacy v2 status

Dev262 implements a strict parser and semantic checker for the legacy
`read-evidence-index.v2` format. It is a structural-audit boundary only. It is
not externally admissible read evidence and cannot make a registered read or
the Goal ready. A v2 check must report
`external_read_evidence_verified:false` and
`goal_evidence_admissible:false`, even when all of its internal checks pass.
It does not collect evidence, enable a capability, execute an Odoo write, or
authorize production.

## Legacy v2 trust inputs

The caller selects only the evidence index. It cannot select an attestation key,
runtime configuration, database, company, user, principal, environment, or
capability channel.

For release `<release>`, the verifier derives and reopens this root-managed
anchor:

```text
/opt/odoo-accounting-cli-v3/trusted-artifacts/<release>.read-evidence.json
```

The canonical v1 anchor binds the exact release identity, read runtime config
path and SHA-256, release-specific attestation key path and SHA-256, five
purpose-specific verifier identities and source-code digests, one complete
execution scope, and this source parent:

```text
/var/lib/odoo-accounting-cli-v3/evidence-sources/<release>/
```

The execution scope contains the Odoo instance, database name and UUID, active
and allowed companies, Odoo user, Pi principal, environment, capability
channel, receipt key ID, release digest, and registry digest. The runtime config
must independently agree with the instance/database/environment/channel,
release package, and receipt key. Every capability, artifact, source bundle,
read receipt, and attestation must match that one trusted scope.

The HMAC key file is not a caller input. Its exact path is:

```text
/etc/odoo-accounting-cli-v3/trust/read-evidence/<release>/attestation-keys.json
```

It must be a root-owned, canonical, single-link regular file with mode `0400`
or `0600`; every ancestor must be root-managed and non-writable by group or
world. Its raw SHA-256 and every authority/key/verifier identity are pinned by
the release anchor. The five keys, authority IDs, verifier IDs, verifier source
digests, and HMAC secrets must be unique and ordered by evidence purpose.

Those restrictions prevent a caller from redirecting the checker to an
arbitrary parallel key set, but they do not create an external verifier. The
same checker process reads all five HMAC signing secrets and the read-receipt
verification secret, so it has the material needed to create values it later
accepts. `collector_id`, `verifier_id`, and their source hashes are bound labels;
string or hash inequality does not prove separate key custody or that a
particular process executed. The anchor/runtime agreement also does not by
itself prove the live Odoo database, company, user, principal, or authorization
token that produced a case.

## SSHSIG foundation

Dev262 adds a separate Linux-only verification foundation for detached SSHSIG
signatures. It requires root-owned paths with no group/world write access and
Linux `O_NOFOLLOW` plus `/proc/self/fd`. It digest-pins and keeps open the
`ssh-keygen` executable, canonical single-Ed25519 allowed-signers file,
revocation file, and signature, then gives the child only those inherited file
descriptors. The subprocess uses `shell=False`, an exact principal and
namespace, raw message bytes on stdin, a timeout, and a minimal environment.
Unsupported hosts fail closed, and its API accepts and reports no private key
or secret.

This foundation is not wired into `read-evidence-index.v2` and is not evidence
admission. There is not yet a v3 active-admission document, a public-key role
chain for the collector and five verifiers, an externally signed live-scope and
authorization-token decision, or an adapter from the retained raw Odoo, SQL
oracle and Pi traces into that chain. Passing the SSHSIG module tests therefore
does not change either v2 readiness flag.

## Retained source bundles

Each source bundle is a direct child of the release source parent. It has one
canonical `BUNDLE-MANIFEST.json` and an exact recursively enumerated file set.
The manifest binds the release, trusted scope, collector identity and source
digest, collection time, and every member path, size, and SHA-256. Paths are
relative and canonical; links, hard links, special files, extra files, unsafe
directories, digest drift, size drift, and read-time replacement are rejected.
Per-file, total-size, file-count, JSON depth, node-count, and string-size limits
apply.

For every capability and evidence kind, the strict artifact points to the one
canonical source member:

```text
artifacts/<capability-id>/<evidence-kind>.json
```

The verifier reopens that member and requires its canonical JSON body to equal
the artifact payload. An artifact hash or signed `passed:true` is not enough.

## Evidence semantics

The index contains all current read capabilities and all five evidence kinds in
sorted exact order. Each capability directory contains exactly ten files:

```text
<evidence-kind>.artifact.json
<evidence-kind>.attestation.json
```

The legacy v2 kinds and derived structural checks are:

- `live_odoo`: one or more complete requests, result bodies, and
  `read_receipt_v2` receipts. The verifier derives `page.total_count`, recomputes
  request/result digests and HMAC, and binds instance, database, company, user,
  principal, environment, channel, registry, release, key, and collection time.
- `accounting_oracle`: the same verified Odoo receipt plus a canonical oracle
  result that must exactly equal the signed Odoo result. Its PostgreSQL witness
  must bind database/company, repeatable-read, read-only, rollback, zero write
  statements, unchanged pre/post state, query/row-stream digests, and the
  recomputed oracle-result digest.
- `pi_e2e`: a non-empty natural-language request, selected capability, identical
  collected/CLI parameters, the fixed nine-event lifecycle, a newly verified
  Odoo receipt, and recomputed final business-result and audit-receipt digests.
- `security_negative`: the exact ACL denial, cross-company denial, expired
  authorization, replay, and post-signature parameter-tamper cases. Each must
  return its fixed error code and exit 6 with no receipt, Odoo effect, Odoo
  write, or PostgreSQL write.
- `release_identity`: the executing release, version, commit, manifest identity,
  package, registry, release root, and complete capability-contract digest must
  match values independently verified by the installed CLI.

The generic verifier derives the case counts, receipt counts, read/write facts,
and pass state from these bodies. Those facts are not accepted from attestation
claims. Attestations bind the artifact, source-manifest digest, derived summary,
trusted-scope digest, exact release and capability contract, collection time,
and anchor-pinned verifier. Collector and verifier identities/source hashes must
differ. Receipt IDs cannot be reused across the 12-by-5 evidence set.

These checks reject many malformed or internally inconsistent bundles. They do
not cure the shared-HMAC authority, labelled-role, self-asserted collection-time
or missing external scope/authentication-admission limitations described above.

## Verification commands

Run only the installed immutable release launcher:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<release>
INDEX=/var/lib/odoo-accounting-cli-v3/evidence/<run-id>/read-evidence-index.json

"$RELEASE_DIR/bin/odoo-accounting-cli-v3" \
  evidence read-evidence-index-check \
  --evidence-index "$INDEX"

"$RELEASE_DIR/bin/odoo-accounting-cli-v3" \
  evidence read-capabilities-readiness \
  --read-evidence-index "$INDEX"
```

The same index may be passed to `evidence goal-readiness` only to obtain the
explicit blocker and remediation output. The final-manifest checker may reopen
it for structural diagnostics, but must not convert it into externally verified
or Goal-admissible evidence. It ignores any key or anchor path copied into a
retained readiness report, so a caller cannot redirect the recheck to a
parallel trust set.

A structurally successful legacy check still returns
`external_read_evidence_verified:false`,
`goal_evidence_admissible:false`, `production_promotion_allowed:false`, and
`real_odoo_write_performed:false`. Production routing remains subject to the
separate Pi, write, sandbox, capacity, route, enablement, and final-manifest
gates, plus the unfinished v3 public-key admission chain.

## Current evidence status

Dev262 provides the legacy structural checker, source-bundle reopening,
receipt/evidence semantic checks, CLI wiring, negative controls, and the
standalone SSHSIG public-verification foundation. It does not yet provide the
v3 active admission or role-signature chain, raw-evidence adapters, or an exact
target-host source bundle produced and signed by independent roles for all 12
reads. Fresh real Odoo, PostgreSQL-oracle and Pi evidence must be collected
after that v3 chain exists; a v2 bundle cannot be grandfathered or merely
re-signed. Read Goal readiness remains false and no read capability is enabled.
