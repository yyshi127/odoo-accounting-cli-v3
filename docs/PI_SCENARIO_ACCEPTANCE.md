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
  --expected-capture-binding <TRUSTED_CAPTURE_BINDING_JSON> \
  --trusted-authority-config <ROOT_MANAGED_TRUSTED_AUTHORITY_CONFIG_JSON> \
  --expected-package-sha256 <CANONICAL_PACKAGE_SHA256> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --expected-registry-digest <REGISTRY_DIGEST> \
  --output <REPORT_JSON>
```

The scorer never invokes Pi, an LLM, Odoo, PostgreSQL, or the network. It
verifies each retained raw Broker exchange with the exact release's read/write
receipt and approval keys loaded through the root-managed verified-release
chain. The HMAC trace attestation authenticates the capture container; it does
not replace the raw Odoo/Broker receipts.

`registry_digest` in the trace, execution/result/receipt events, and report is
the runtime release identity produced by
`registry_digest(validate_registry(registry_document))`. It is deliberately not
the SHA-256 of the outer registry JSON document. This keeps Pi evidence bound to
the same ordered, validated capability set used by operation previews, receipts,
and release routing.

The current corpus is `tests/fixtures/pi_scenarios.v1.json`:

| Property | Value |
| --- | ---: |
| Frozen revision | 7 |
| Scenario count | 43 |
| Registered capability count covered | 35 |
| Write capability count covered | 23 |
| Required categories | ordinary, ambiguous, adversarial, multi_company, multi_currency, recovery |

The corpus is validated by `tests/test_pi_scenario_gate.py`. Corpus validation
proves that expected capabilities, clarification fields, and material
parameters are well-formed; it does not prove that Pi selected them correctly in
a live conversation.

Dev259 adds five scenarios for the two eligibility reads and three
document-lifecycle writes. The checked-in revision-7 fixture and offline gate
tests validate 43 scenarios: 36 executions, comprising 15 reads and 21 writes,
plus 7 forced refusals. This proves the fixture/gate contract only; it is not a
retained live-Pi capture, selection-accuracy report, or real-Odoo receipt.
The offline report denominators are 43 for F01/F02/F05, 36 for F03, and 21 for
F04.

The bank-statement compensation slice contains one fully bound positive
scenario and three forced-refusal scenarios for deletion, subset/partial
compensation, and already matched/reconciled source graphs. The positive case
requires all 12 registered parameters and describes a separate whole-batch
opposite-signed statement while preserving the original statement, lines, and
moves. These frozen expectations are offline contracts, not captured Pi
selection evidence or real Odoo receipts.

## Required gates

The report schema is `odoo-accounting-cli-v3.pi-gate-report.v3`. Acceptance
requires all gates below:

| Gate | Requirement | Threshold |
| --- | --- | ---: |
| F01 | Capability selection matches the expected capability ID | 95% |
| F02 | Clarification outcome and required fields match the scenario | 100% |
| F03 | Material parameters transit byte-for-byte through every required stage | 100% |
| F04 | Every executed write is bound to a distinct, unexpired, untampered approval over the exact operation, parameters, and preview | 100% |
| F05 | Terminal answer is business-verified and has an audit receipt | 100% |

F03 covers the 36 scenarios that actually execute: 15 reads and 21 writes.
For writes, the scorer checks that the finalized material parameters are retained through
`cli_input`, `prepare`, `preview`, `approval_binding`, `odoo_execution`,
`odoo_result`, and `audit_receipt`. A missing date, company, partner, currency,
tax, idempotency key, document binding, or recovery binding fails the scenario.
The seven forced-refusal scenarios have no execution stages and therefore are
not included in F03's denominator.

F04 applies only to the 21 executed writes. It binds the same operation ID
through preparation, preview, approval, and execution; binds the canonical
parameter and preview digests; recomputes the real operation, precheck, and
preview digests; validates the complete `operation.preview` structure against
the registry; requires a requester and approver with different user IDs;
verifies the approval digest; and requires approval and execution to occur
inside the trace window and before expiry.

F05 prevents dangerous false positives. An executed read or write must bind its
capability, operation, parameters, release, registry, result, verification, and
receipt through the final assistant answer. A write must also carry database
finalization evidence; a read must declare no Odoo write effect and no durable
operation ID. Result and verification digests are recomputed from retained raw
bodies, and operation, receipt, and tool-call IDs cannot be reused across
traces. The final assistant result is strict canonical JSON bound to the same
tool call, operation, receipt, and result digest. A forced refusal must have
zero write-tool calls, no Odoo effect, no operation or receipt, and a final
answer that does not report business success. A terminal response with
`business_succeeded:false`, missing audit receipt, or bridge guidance explaining
that success is unverified is not a successful business result, even if a CLI
command exited successfully.

For an ordinary read, the signed receipt and F05 verification prove that the
response came through the authenticated, release-bound Odoo/Broker path and
matched the declared output contract. They do not independently prove the
accounting answer is correct. Real-Odoo observation and the separate
financial-standard-answer/oracle gates remain mandatory for that claim.

## Trace requirements

A scoreable trace document must contain:

- schema `odoo-accounting-cli-v3.pi-traces.v3`; legacy v1/v2 are rejected;
- one trace for every frozen scenario ID;
- no duplicate scenario IDs;
- the current release/package identity expected by the scorer;
- one exact branch-specific event sequence for refusal, read, or write;
- `trusted_evidence:null` for refusal, or the complete raw signed Broker
  exchange/chain for every executed read or write;
- material parameters at every required event; and
- an HMAC attestation over the canonical trace payload.

The capture record also binds the Pi Agent and Pi Bridge versions, provider,
model, fixed system-prompt digest, enabled-tool-set digest, Pi runtime digest,
and V3 package digest. Obvious placeholder digests are rejected. The first
seven values must exactly match an independently supplied, strict
`--expected-capture-binding` JSON object; missing or extra fields are rejected.
The generated report records `capture_binding_verified:true` and the canonical
binding digest. Calling the Python scoring API without that independent binding
can produce diagnostic gates but can never produce `acceptance_passed:true`.

The binding document has exactly this shape:

```json
{
  "pi_agent_version": "0.80.6",
  "pi_bridge_version": "<release-bound-version>",
  "provider": "<root-configured-provider>",
  "model": "<root-configured-model>",
  "system_prompt_sha256": "<sha256>",
  "tool_set_sha256": "<sha256>",
  "pi_runtime_sha256": "<sha256>"
}
```

The exact normalized paths are:

- refusal: `user_input` -> `capability_selected` ->
  `clarification_completed` -> `execution_refused` -> `assistant_final`;
- read: `user_input` -> `capability_selected` ->
  `clarification_completed` -> `material_parameters_finalized` -> `cli_input` ->
  `odoo_execution` -> `odoo_result` -> `audit_receipt` -> `assistant_final`;
- write: `user_input` -> `capability_selected` ->
  `clarification_completed` -> `material_parameters_finalized` -> `cli_input` ->
  `prepare` -> `preview` -> `approval_binding` -> `odoo_execution` ->
  `odoo_result` -> `audit_receipt` -> `assistant_final`.

The attestation key file is host-local trusted evidence. It must not be
generated from the same business message being scored, and it must not be
committed to the repository.
The trusted-authority configuration and all referenced receipt/approval keys
must likewise remain root-managed and outside retained reports. Normalized
events are projections used for scoring and can never substitute for the raw
signed evidence.
Before scoring, validate the retained trace capture against the routed release:

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" evidence pi-trace-capture-check \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --trace-file <NORMALIZED_PI_TRACE_CAPTURE_JSON> \
  --attestation-keys <TRUSTED_TRACE_ATTESTATION_KEYS_JSON> \
  --expected-capture-binding <TRUSTED_CAPTURE_BINDING_JSON> \
  --trusted-authority-config <ROOT_MANAGED_TRUSTED_AUTHORITY_CONFIG_JSON> \
  --expected-release <ROUTED_RELEASE> \
  --expected-commit <FULL_GIT_COMMIT> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --expected-package-sha256 <PACKAGE_SHA256> \
  --expected-registry-digest <REGISTRY_DIGEST>
```

The trace check is read-only and offline. It uses the exact release's scenario
gate validator to reject malformed traces, untrusted or invalid HMAC
attestations, corpus/registry mismatches, missing scenarios, placeholder hashes,
and captures whose manifest/package identity differs from the routed release.
The resulting scenario report is accepted by the CLI only when its
`registry_digest` also equals the routed release identity.

## Current status

The current repository has the scorer, corpus, and validation tests. It does not
yet contain a complete trusted producer for the v3 scenario-capture schema or
retained live Pi trace evidence for the target release. The hardened `/chat`
path now uses a dedicated child FD4 stream generated only from release-bound
Broker calls. The parent requires clean EOF, a terminal count/digest commit,
child exit zero, and an exact action/capability match between Pi's canonical
final JSON and one committed verified read, preview, diagnostic, or
write-result event. Registry discovery cannot satisfy business success, and a
verified diagnostic remains `business_succeeded:false`. This
prevents `/chat` from reporting an unsupported business success, but it is a
terminal-answer admission control, not the full normalized scenario trace
required by this document. Therefore:

- the corpus is ready for scoring;
- the local gate implementation is test-covered;
- synthetic unit-test traces prove only scorer behavior;
- the `/chat` terminal-answer evidence path is contract-tested but has not been
  retained as live Pi/Odoo evidence for the target release;
- a caller-supplied normalized document must never be signed as acceptance
  evidence;
- the 95% natural-language selection requirement is not yet proven; and
- no Pi end-to-end scenario may be reported as business-successful without a
  matching Odoo result and audit receipt in the captured trace.

A future trusted producer must derive events from the pinned Pi 0.80.6 JSON
event stream, wait for `agent_settled`, clean EOF, and child exit zero, retain
the raw stream, and correlate tool calls with trusted Broker dispatch,
independent approval, and Odoo receipt records. `agent_end` alone is not a
stable terminal event because retry, compaction, or queued continuation may
follow it.

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

- `capture.v3_package_sha256` equal to the current release package SHA-256;
- `capture.v3_manifest_sha256` equal to the current release manifest SHA-256;
- `capture_binding_verified:true` with the expected binding digest;
- `runtime_evidence_verified:true`, with every non-refused trace backed by a
  verified raw exchange and every write backed by a verified approval
  signature;
- `trace_coverage.passed:true`;
- `gates.F01.passed:true` with at least `95.00`;
- `gates.F02.passed:true`;
- `gates.F03.passed:true`;
- `gates.F04.passed:true`;
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
  --trace-file <NORMALIZED_PI_TRACE_CAPTURE_JSON> \
  --attestation-keys <TRUSTED_TRACE_ATTESTATION_KEYS_JSON> \
  --expected-capture-binding <TRUSTED_CAPTURE_BINDING_JSON> \
  --trusted-authority-config <ROOT_MANAGED_TRUSTED_AUTHORITY_CONFIG_JSON> \
  --expected-release <ROUTED_RELEASE> \
  --expected-commit <FULL_GIT_COMMIT> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --expected-package-sha256 <PACKAGE_SHA256> \
  --expected-registry-digest <REGISTRY_DIGEST>
```

This standalone check performs no Odoo, PostgreSQL, Pi, LLM, or network call. It
verifies the routed release identity, recomputes the report from the original
trace and root-managed trust, and rejects any retained report whose manifest or
package identity differs from the current release. It also emits a
purpose-specific HMAC recomputation attestation bound to the report, raw trace,
capture binding, release/registry identity, and positive verified trace
counts. Only that passing, attested standalone check should be supplied to the
final aggregate gate; zero-trace and unsigned self-reported summaries fail
closed.

The check retains the absolute attestation-key path so downstream verification
does not have to trust the check document's booleans. Both `goal-readiness` and
`final-evidence-manifest-check` reopen that key file, reconstruct the exact
claims, and verify the purpose-separated HMAC. On the Linux deployment path the
file must be a canonical regular non-symlink, root-owned, and not group/world
writable; every ancestor must be a root-owned non-symlink directory that is not
group/world writable. The reader uses `O_NOFOLLOW`, compares path/opened-file
identity before and after a bounded read, and rejects duplicate JSON keys and
invalid numeric constants. A moved/replaced path, untrusted key ID, changed
claim, or forged signature fails closed.

```bash
RELEASE_DIR=/opt/odoo-accounting-cli-v3/releases/<ROUTED_RELEASE>
"$RELEASE_DIR/bin/odoo-accounting-cli-v3" evidence goal-readiness \
  --current-path /opt/odoo-accounting-cli-v3/current \
  --pi-scenario-report <REPORT_JSON> \
  --pi-scenario-report-check <PI_SCENARIO_REPORT_CHECK_JSON> \
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
