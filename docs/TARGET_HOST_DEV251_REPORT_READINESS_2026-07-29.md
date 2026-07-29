# Target host Dev251 report-read readiness disposition

This record covers the read-only Dev251 native-report evidence attempt on
`43.165.173.80`. It is a failure disposition, not a passing evidence receipt
and not production-promotion evidence.

## Immutable candidate identity

- release: `0.1.0.dev251-f6f54e86edfa`
- commit: `f6f54e86edfa7a9dfac85f4b3773ac6fcd5e9dd8`
- package SHA-256:
  `27cf01b9b777548a527ec8e4aa970e96c37e2d6227bad6756246295c6c00bfb4`
- manifest SHA-256:
  `56a0baf91f41727c6a3895031a06e4efca8b9557c32bf26ec841599a28d4649b`
- registry semantic digest:
  `0cf8e66de1ace7e8c2dcbbbb63cbef99e7f2ccd4ba5b86a093f7a0399036d27c`

The package was uploaded below the dedicated
`/opt/odoo-accounting-cli-v3/upload-sources/incoming/0.1.0.dev251-f6f54e86edfa/`
directory, hash-verified, and side-loaded. The installed release tree passed
its embedded manifest verifier. The active `current` route remained
`0.1.0.dev250-8414e9922f03`; no service or Pi route was changed.

## Observed readiness result

The exact installed CLI reported:

- 10 registered and required read capabilities;
- 8 statically admissible read capabilities;
- exactly 2 declared-only gaps:
  `acct.diagnostics.operation_read.v1` and
  `acct.multicompany.consolidated_read.v1`;
- both `acct.tax.report_read.v1` and
  `acct.report.financial_read.v1` were `contract_tested`, staged only for
  `test`, not enabled, backed by the trusted Odoo handler, and passed all nine
  static checks;
- read Goal readiness, external-evidence readiness, and production promotion
  all remained false.

That state is the intended current registry state. The Dev251 collector
incorrectly required the global `read_static_readiness_ready` value to be true,
which would require the two explicitly retained gaps to be implemented.

## Fail-closed boundary

Collection name:
`dev251-report-read-20260729T050933Z`.

The collector returned:
`dev251_report_read_collection_failed: read readiness probe has unsafe semantics`.

The retained diagnostic directory contained only:

- `report-read-plan.json`;
- `release-identity.json`.

It contained no read-boundary result, PostgreSQL witness, signed request,
report response, or validation report. No final directory was published below
`/var/lib/odoo-accounting-cli-v3/evidence`. Therefore no Odoo report query and
no Odoo business write was executed by this attempt, and the attempt cannot be
reported as business success.

## Disposition

Dev251 remains an immutable, non-promotable historical candidate. It must not
be patched in place, rebuilt under the same version, routed, or used as
evidence. Dev252 corrects the collector and independent verifier to require the
exact 10/8/2 inventory and per-capability safety semantics before any Odoo
query. All existing accounting-oracle, definition-baseline, Dev29 closure,
Pi end-to-end, security-negative, and production-enablement gates remain
closed.
