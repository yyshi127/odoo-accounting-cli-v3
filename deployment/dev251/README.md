# Dev251 native-report read evidence protocol

This directory adds a supplemental exact-release evidence gate for four
test-staged native Odoo reports:

- generic tax report;
- balance sheet with one previous-period comparison;
- profit and loss with one previous-year comparison;
- cash flow without a comparison.

`dev251` is the immutable protocol namespace and trusted release-member path,
not a requirement that the executing software version also be dev251. The
original `0.1.0.dev251-f6f54e86edfa` candidate exposed a fail-closed readiness
contract defect before any report query: it required all ten registered reads
to be statically admissible even though operation diagnostics and multi-company
consolidation are explicitly retained as the only two declared gaps. That
candidate must not be promoted or rebuilt. Version dev252 and later may execute
this protocol only when the exact 10-registered/8-admissible/2-declared-gap
targeted readiness contract passes.

It does not replace the Dev29 dependency-closure gate or its PostgreSQL
witness. It does not provide an independent accounting standard answer, enable
either report capability, authorize a production route, or perform an Odoo
business write.

## Paths and authority

Run the collector and verifier only from the immutable installed release as
root with the fixed system Python. The collector demotes Odoo reads to `odoo`
and independent PostgreSQL witnesses to `postgres`.

Transient collection is restricted to:

```text
/run/odoo-accounting-cli-v3-dev251/<evidence-name>
```

Frozen evidence is published only to:

```text
/var/lib/odoo-accounting-cli-v3/evidence/<evidence-name>
```

Do not stage uploads, generated evidence, or temporary files in `/root`.

## Collect

Obtain every expected identity value from the independently verified release
package, trusted-artifact sidecar, installed manifest, and registry. Do not
copy expected values from a candidate evidence bundle.

```sh
VERSION='<independently-verified-version>'
RELEASE="$VERSION-<commit12>"
ROOT="/opt/odoo-accounting-cli-v3/releases/$RELEASE"
RUNTIME="/etc/odoo-accounting-cli-v3/candidates/runtime-test-$RELEASE.json"
EVIDENCE_NAME="dev251-report-read-<unique-id>"

sudo /usr/bin/python3.12 -I -S \
  "$ROOT/deployment/dev251/collect_report_read_evidence.py" \
  --evidence-name "$EVIDENCE_NAME" \
  --runtime-config "$RUNTIME" \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

The collector writes the fixed plan, exact release identity, static readiness
probe, rollback-only read-boundary result, pre/post PostgreSQL witnesses, four
signed requests and responses, and a validation report. It freezes a pending
copy, invokes the independent verifier, removes pre-commit staging, and then
publishes with a no-replace rename plus parent-directory `fsync`.

Any execution, validation, witness, or pre-commit cleanup failure returns no
success and leaves no final evidence directory. A retained `/run` directory
after an earlier collection failure is diagnostic state, not reusable evidence;
choose a new evidence name after review.

If the no-replace rename succeeds but the evidence-parent `fsync` fails, the
collector returns exit code `3` with
`status=publication_outcome_unknown`, `reconcile_required=true`, and
`safe_to_rerun=false`. The frozen final directory is retained. Do not repeat
the Odoo reads or reuse the collection command.

Reconcile that exact evidence name without calling Odoo:

```sh
sudo /usr/bin/python3.12 -I -S \
  "$ROOT/deployment/dev251/collect_report_read_evidence.py" \
  --reconcile \
  --evidence-name "$EVIDENCE_NAME" \
  --runtime-config "$RUNTIME" \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

Reconciliation independently verifies the frozen bundle and retries only the
parent-directory durability confirmation. It is idempotent and never executes
the report requests again.

## Verify a published bundle

```sh
EVIDENCE="/var/lib/odoo-accounting-cli-v3/evidence/$EVIDENCE_NAME"

sudo /usr/bin/python3.12 -I -S \
  "$ROOT/deployment/dev251/verify_report_read_evidence.py" \
  --evidence-dir "$EVIDENCE" \
  --runtime-config "$RUNTIME" \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit '<40-lowercase-hex>' \
  --expected-manifest-sha256 '<64-lowercase-hex>' \
  --expected-package-sha256 '<64-lowercase-hex>' \
  --expected-registry-digest '<64-lowercase-hex>'
```

The verifier is standard-library-only and does not import the collector, Odoo,
or the Dev29 verifier. It independently checks the exact file set and metadata,
release/runtime/registry bindings, request and receipt signatures and digests,
complete pagination and report structure, the rollback boundary, equal
PostgreSQL witnesses, and absence of runtime secrets from the bundle.

A passing report always states:

```text
accounting_correctness_verified=false
accounting_oracle_available=false
production_promotion_allowed=false
```

Production remains closed until approved report-definition baselines,
independent tax and accounting oracles, Pi natural-language end-to-end evidence,
and the remaining Goal security gates pass.
