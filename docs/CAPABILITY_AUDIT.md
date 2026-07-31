# Capability registry audit

This document records how to prove the V3 capability registry is complete,
strictly shaped, and closed for production until environment-specific evidence
exists. It is a registry and control-plane audit only. It is not a real Odoo
business receipt, sandbox-write receipt, or production-write authorization.

## Historical retained target-host audit example

The retained target-host audit that introduced this command was run against:

| Field | Value |
| --- | --- |
| Version | `0.1.0.dev218` |
| Release | `0.1.0.dev218-c68fd23c7ef8` |
| Commit | `c68fd23c7ef8d71f4c258adce176934596762496` |
| Manifest SHA-256 | `6d2fb03112ca414ee98f4270e221e041ac8b71d08d60ee8c5bf89a022579ada0` |
| Package SHA-256 | `2c19c8bad0dff694d2e459cea306c918ad2c139d294934deee990df369be1db2` |
| Registry digest | `07e40781c647fa1434b6dca088fca491e17d3cc6319994b97be754a55aea29a2` |

The target route was verified with:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/0.1.0.dev218-c68fd23c7ef8
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" release current-route \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --expected-release 0.1.0.dev218-c68fd23c7ef8 \
  --expected-commit c68fd23c7ef8d71f4c258adce176934596762496 \
  --expected-manifest-sha256 6d2fb03112ca414ee98f4270e221e041ac8b71d08d60ee8c5bf89a022579ada0 \
  --expected-package-sha256 2c19c8bad0dff694d2e459cea306c918ad2c139d294934deee990df369be1db2
```

The route returned `current_route_ready:true`, an empty blocker list, and the
registry digest shown above.

This is deliberately a historical Dev218 evidence record. Its 24 total and
14 write capabilities are not the current development registry. Never copy
these counts into a current readiness claim; run the machine audit from the
exact routed release and retain that output. The current development registry
has subsequently grown, but a dirty checkout is not a release or target-host
receipt.

## Current development inventory

The current development registry contains 35 capabilities: 12 reads and 23
writes. All 35 have strict input/output schemas. The 12 reads are
`contract_tested` and staged only for `test`; the 23 writes remain `declared`,
with empty staged and enabled environment lists. No capability is enabled in
any environment.

Dev259 adds these contracts to the preceding 30-capability inventory:

- `acct.move.document_post_eligibility.v1` (read);
- `acct.refund.draft_cancel_eligibility.v1` (read);
- `acct.invoice.customer_post.v1` (write);
- `acct.bill.vendor_post.v1` (write); and
- `acct.refund.draft_cancel.v1` (write).

The two reads only prove local contract and test-channel integration. They have
zero retained real-Odoo read receipts. The three writes have source handlers
and control-plane contracts, but no retained real-Odoo write lifecycle
receipts. Across the complete development inventory, source/contract
implementation is 23/23 writes; 21 reach capability-specific ORM prechecks,
while payment registration and deferred creation fail closed before ORM
access. Real-Odoo write evidence remains 0/23.
These facts must not be restated as sandbox verification, production
readiness, or Goal completion.

The current posting implementation also has a deliberately narrow partner-rank
boundary. It accepts a customer-invoice/vendor-bill target only when the
relevant `customer_rank`/`supplier_rank` is exactly `0` before `action_post` and
requires an exact value of `1` afterward. That closes the observed Odoo 19
postcommit delta for this development slice; it is not general production
coverage for existing-ranked partners or unreviewed module extensions.

The eligibility oracle and document-post handler additionally admit only a
complete company-currency, product-line, taxless, undiscounted financial graph
with one receivable/payable maturity line. Eligibility binds that exact
Odoo-created line ID and account ID into the write parameters; precheck and
post-action verification reject an alternate account even when it has the same
receivable/payable type. Foreign-currency, taxed, non-product-line, discounted, and
complex payment-term documents fail closed until their exact Odoo 19 semantics
are proved. This is a safe development boundary, not full accounting document
coverage.

Within that boundary, a full refund must reproduce an exact linewise reversal,
including immutable line references. A partial refund must stay within the
origin total and map every business line by one unique reference to an origin
line with the same account, partner, currency, product and tax identity; its
quantity, subtotal and total may not exceed the origin line.

Dev260 retains `odoo_cli_v3_document_binding` as the immutable V1 digest of the
exact approved source parameters and adds
`odoo_cli_v3_document_binding_v2` as a separate versioned canonical graph
digest. New customer invoices, vendor bills, and refunds write V1, V2, and the
business binding together. V2 normalizes decimal trailing zeros, tax-ID order,
and line order by unique `line_reference`; it rejects duplicate tax IDs and
line references. It does not change the meaning of an existing V1 digest.

The posting eligibility read validates the stored V1 digest shape, then
reconstructs the Odoo graph and requires its V2 and business bindings to match.
Refund-cancellation applies the same rule to both refund and origin. For the
already-posted origin, exactly one V2 candidate must match: creation recorded
`posting_mode:"post"`, or creation recorded `posting_mode:"draft"` and the
current document is now posted. The second candidate proves only the
creation-time binding; it does not identify the later caller or prove that the
controlled posting capability performed the transition.

Existing V1-only records are not automatically backfilled. A missing V2 value
returns an explicit provenance-migration failure and remains ineligible. The
current release contains no migration capability, so operators must not write
or infer V2 directly from the current Odoo graph. A future migration must prove
the original signed operation parameters and historical receipt/release before
performing a separately approved, auditable update.

An installed-module graph proves module name/version-set stability only. It
does not semantically enumerate or approve overrides of `action_post`,
`account.move.write`, or postcommit behavior. No Dev259 write may be enabled
without a real Odoo 19 sandbox lifecycle and an explicit target-module override
review; retained graph equality alone is insufficient.

These are development-tree observations, not an exact-release audit. Replace
them with retained `registry audit` and Odoo receipts from the packaged release
before making any routed-release claim.

## Machine audit command

Run the exact release member, not a developer checkout:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" registry audit
```

The command is read-only. It loads the packaged `capabilities.json`, reuses the
same validation path as `registry list` and `registry get`, and emits a compact
machine-checkable summary. It does not open Odoo, query PostgreSQL, write state,
enable a capability, or make a production-promotion decision.

An acceptable registry audit must satisfy all of the following:

- `ok:true`
- `command:"registry.audit"`
- `registry_audit_ready:true`
- `blockers:[]`
- `strict_schema.input_strict_count == total_count`
- `strict_schema.output_strict_count == total_count`
- `policy_counts.write_approval_required == write_count`
- `policy_counts.write_idempotency_required == write_count`
- `enabled_environment_counts.production == 0` until production evidence exists
- `production_promotion_allowed:false`
- `real_odoo_write_performed:false`

For that historical audited release, the target host returned:

| Metric | Value |
| --- | ---: |
| Total registered capabilities | 24 |
| Read capabilities | 10 |
| Write capabilities | 14 |
| Strict input schemas | 24 |
| Strict output schemas | 24 |
| Write capabilities requiring approval | 14 |
| Write capabilities requiring idempotency | 14 |
| Capabilities enabled in production | 0 |
| Capabilities staged in sandbox | 0 |
| Capabilities staged in test | 6 |

Risk distribution:

| Risk level | Count |
| --- | ---: |
| Low | 6 |
| Medium | 4 |
| High | 9 |
| Critical | 5 |

Evidence distribution:

| Evidence level | Count |
| --- | ---: |
| `contract_tested` | 6 |
| `declared` | 18 |
| `odoo_verified` | 0 |
| `sandbox_verified` | 0 |
| `production_verified` | 0 |

The six test-staged read capabilities were:

- `acct.registry.list.v1`
- `acct.gl.trial_balance.v1`
- `acct.ar.open_items.v1`
- `acct.ap.open_items.v1`
- `acct.multicurrency.balance_read.v1`
- `acct.move.draft_cancel_eligibility.v1`

No write capability is staged or enabled by this audit.

## What this proves

The audit proves that every registered capability has the mandatory registry
shape enforced by the release:

- unique capability ID;
- business description;
- strict input and output JSON object schemas;
- read/write access declaration;
- risk level;
- Odoo permissions;
- company-scope policy;
- approval policy;
- idempotency policy;
- verification method;
- recovery method;
- evidence level; and
- explicit staged/enabled environment lists.

For write capabilities, it additionally proves that the registry requires both
approval and idempotency before execution can ever be considered. This supports
the Pi Agent gateway contract: Pi can query and choose capabilities from one
registry but cannot bypass the write lifecycle or enablement gates.

## What this does not prove

This audit does not prove that any capability has executed successfully in Odoo.
It does not replace:

- signed Odoo read receipts;
- sandbox provisioning authorization;
- sandbox database isolation evidence;
- sandbox write preflight;
- create/readback/duplicate/failure/recovery drills;
- write lifecycle receipts;
- Pi natural-language end-to-end acceptance; or
- production promotion approval.

If `registry_audit_ready:true` is present but the release has no matching Odoo
receipt for a business request, the CLI and Pi Bridge must still refuse to
report business success.

## Current remaining target-host gates

On the same audited release, `evidence sandbox-onboarding-readiness` returned
`sandbox_onboarding_ready:false` with these blockers:

- `sandbox database was not observed in the PostgreSQL catalog`
- `sandbox provision authorization file was not supplied`
- `sandbox write capacity gate is not ready`

The capacity gate reported approximately 2.69 GB available against an 8 GiB
floor, with a shortfall of approximately 5.90 GB. Therefore sandbox-write drills
and production promotion remain closed.
