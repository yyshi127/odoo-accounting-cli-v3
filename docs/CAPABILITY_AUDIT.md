# Capability registry audit

This document records how to prove the V3 capability registry is complete,
strictly shaped, and closed for production until environment-specific evidence
exists. It is a registry and control-plane audit only. It is not a real Odoo
business receipt, sandbox-write receipt, or production-write authorization.

## Retained target-host audit example

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

For that audited release, the target host returned:

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
