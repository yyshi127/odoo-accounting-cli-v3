# Pi Agent scenario acceptance

This document defines the evidence required before V3 can claim that
“小兢会计” correctly turns natural-language accounting requests into safe,
auditable Odoo CLI actions. It distinguishes a frozen test corpus from captured
Pi execution traces so a command, fixture, or model-free unit test is not
mistaken for end-to-end business success.

## Offline gate and corpus

The offline scorer is:

```bash
python tools/pi_scenario_gate.py \
  --corpus tests/fixtures/pi_scenarios.v1.json \
  --registry registry/capabilities.json \
  --traces <NORMALIZED_PI_TRACE_CAPTURE_JSON> \
  --attestation-keys <TRUSTED_TRACE_ATTESTATION_KEYS_JSON> \
  --expected-release-sha256 <CANONICAL_PACKAGE_SHA256> \
  --output <REPORT_JSON>
```

The scorer never invokes Pi, an LLM, Odoo, PostgreSQL, or the network. It only
scores already captured and HMAC-attested Pi traces against the frozen corpus
and the exact capability registry.

The current corpus is `tests/fixtures/pi_scenarios.v1.json`:

| Property | Value |
| --- | ---: |
| Scenario count | 28 |
| Registered capability count covered | 24 |
| Write capability count covered | 14 |
| Required categories | ordinary, ambiguous, adversarial, multi_company, multi_currency, recovery |

The corpus is validated by `tests/test_pi_scenario_gate.py`. Corpus validation
proves that expected capabilities, clarification fields, and material
parameters are well-formed; it does not prove that Pi selected them correctly in
a live conversation.

## Required gates

The report schema is `odoo-accounting-cli-v3.pi-gate-report.v1`. Acceptance
requires all gates below:

| Gate | Requirement | Threshold |
| --- | --- | ---: |
| F01 | Capability selection matches the expected capability ID | 95% |
| F02 | Clarification outcome and required fields match the scenario | 100% |
| F03 | Material parameters transit byte-for-byte through every required stage | 100% |
| F05 | Terminal answer is business-verified and has an audit receipt | 100% |

F03 is intentionally stricter for write capabilities. For writes, the scorer
checks that the finalized material parameters are retained through
`cli_input`, `prepare`, `preview`, `approval_binding`, `odoo_execution`,
`odoo_result`, and `audit_receipt`. A missing date, company, partner, currency,
tax, idempotency key, document binding, or recovery binding fails the scenario.

F05 prevents a dangerous false positive: a terminal response with
`business_succeeded:false`, missing audit receipt, or bridge guidance explaining
that success is unverified is not a successful business result, even if a CLI
command exited successfully.

## Trace requirements

A scoreable trace document must contain:

- schema `odoo-accounting-cli-v3.pi-traces.v1`;
- one trace for every frozen scenario ID;
- no duplicate scenario IDs;
- the current release/package identity expected by the scorer;
- normalized event sequence from `user_input` through `audit_receipt`;
- material parameters at every required event; and
- an HMAC attestation over the canonical trace payload.

The attestation key file is host-local trusted evidence. It must not be
generated from the same business message being scored, and it must not be
committed to the repository.
Before scoring, validate the retained trace capture against the routed release:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" evidence pi-trace-capture-check \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --trace-file <NORMALIZED_PI_TRACE_CAPTURE_JSON> \
  --attestation-keys <TRUSTED_TRACE_ATTESTATION_KEYS_JSON> \
  --expected-release <ROUTED_RELEASE> \
  --expected-commit <FULL_GIT_COMMIT> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --expected-package-sha256 <PACKAGE_SHA256> \
  --expected-registry-digest <REGISTRY_DIGEST>
```

The trace check is read-only and offline. It uses the exact release's scenario
gate validator to reject malformed traces, untrusted or invalid HMAC
attestations, corpus/registry mismatches, missing scenarios, placeholder hashes,
and captures whose `capture.v3_release_sha256` is not the routed package
SHA-256.

## Current status

The current repository has the scorer, corpus, and validation tests. It does not
yet contain retained live Pi trace evidence for the target release. Therefore:

- the corpus is ready for scoring;
- the local gate implementation is test-covered;
- the 95% natural-language selection requirement is not yet proven; and
- no Pi end-to-end scenario may be reported as business-successful without a
  matching Odoo result and audit receipt in the captured trace.

Run this regression whenever the corpus, capability registry, Pi Bridge
transport, or CLI command shapes change:

```bash
python -m pytest tests/test_pi_scenario_gate.py tests/test_pi_bridge_source.py -q
cd pi_bridge
npm test -- --test-reporter=spec tests/odoo-v3-cli.test.mjs
```

The Node test verifies fixed-argv routing, byte-for-byte material parameter
transit, release/registry binding, and fail-closed terminal write handling. It
does not replace the captured Pi trace report.

## Promotion rule

A release can pass the Pi scenario gate only when its retained report has:

- `capture.v3_release_sha256` equal to the current release package SHA-256;
- `trace_coverage.passed:true`;
- `gates.F01.passed:true` with at least `95.00`;
- `gates.F02.passed:true`;
- `gates.F03.passed:true`;
- `gates.F05.passed:true`; and
- `acceptance_passed:true`.

If any scenario is missing, any trace is unsigned, any material parameter
differs, or any terminal response lacks verified business success, the release
must remain unaccepted for Pi end-to-end operation.

After the Pi report is retained, bind it into the final aggregate check:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" evidence pi-scenario-report-check \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --pi-scenario-report <REPORT_JSON> \
  --expected-release <ROUTED_RELEASE> \
  --expected-commit <FULL_GIT_COMMIT> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --expected-package-sha256 <PACKAGE_SHA256> \
  --expected-registry-digest <REGISTRY_DIGEST>
```

This standalone check performs no Odoo, PostgreSQL, Pi, LLM, or network call. It
verifies the routed release identity and rejects any retained report whose
`capture.v3_release_sha256` is not the current package SHA-256. Only a passing
standalone check should be supplied to the final aggregate gate.

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" evidence goal-readiness \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --pi-scenario-report <REPORT_JSON> \
  --sandbox-onboarding-receipt <SANDBOX_ONBOARDING_READINESS_JSON> \
  --sandbox-provision-authorization-file <SANDBOX_PROVISION_AUTHORIZATION_JSON> \
  --write-pipeline-report <WRITE_PIPELINE_READINESS_JSON> \
  --expected-sandbox-database-name <SANDBOX_DATABASE_NAME> \
  --expected-source-database-name <AUTHORIZED_SOURCE_DATABASE> \
  --expected-company <AUTHORIZED_COMPANY> \
  --observed-database-name <OBSERVED_DATABASE> \
  --capacity-path / \
  --required-free-bytes 8589934592
```

If the report is absent or fails any gate, `goal-readiness` keeps the release
unaccepted for the full V3 objective.
