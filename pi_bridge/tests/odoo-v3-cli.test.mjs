import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";

import {
	V3_OPERATION_COMMANDS,
	V3_TOOL_NAMES,
	addUnknownEffectGuidance,
	createV3BrokerClient,
	createV3CliRunner,
	deriveCapabilityGetFromRegistryRead,
	preflightV3BrokerSession,
} from "../extensions/odoo-v3-cli.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_RELEASE_DIGEST = "7".repeat(64);
const EXPECTED_REGISTRY_DIGEST = "a".repeat(64);
const TEST_BROKER_SESSION_HANDLE = "test-broker-session-0123456789abcdef";
let fixtureDir;
let successFixture;
let trustedFixture;
let unknownFixture;

before(async () => {
	fixtureDir = await mkdtemp(path.join(os.tmpdir(), "pi-v3-cli-test-"));
	successFixture = path.join(fixtureDir, "success-cli.mjs");
	trustedFixture = path.join(fixtureDir, "trusted-cli.mjs");
	unknownFixture = path.join(fixtureDir, "unknown-cli.mjs");
	await writeFile(successFixture, `
const args = process.argv.slice(2);
let stdin = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) stdin += chunk;
const command = args[1] === "approve-execute"
  ? "operation.approve_execute"
  : \`operation.\${args[1]}\`;
const payload = {
  command,
  data: { argv: args, parsed_request: JSON.parse(stdin), raw_stdin: stdin },
  ok: true,
};
if (["operation.approve_execute", "operation.result"].includes(command)) {
  payload.business_succeeded = true;
}
process.stdout.write(JSON.stringify(payload));
`, "utf8");
	await writeFile(trustedFixture, `
const args = process.argv.slice(2);
const mutation = args[0]?.startsWith("__test_") ? args.shift() : "";
let stdin = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) stdin += chunk;
const request = JSON.parse(stdin);
const command = args[0] === "registry"
  ? "registry.list"
  : args[0] === "read"
    ? "read"
    : args[1] === "approve-execute"
      ? "operation.approve_execute"
      : \`operation.\${args[1]}\`;
const evidence = {
  operation_id: request.operation_id ?? "op-1",
  operation_state: "completed",
  verification: {
    method: "fresh_odoo_readback",
    passed: true,
    checks: ["record_fingerprint_matches"],
    evidence_digest: "1".repeat(64),
    verified_at: "2026-07-15T08:01:00Z",
  },
  database_finalization: {
    attestation_digest: "a".repeat(64),
    attestation_id: "22222222-2222-5222-8222-222222222222",
    attestation_key_id: "effect-finalizer-v1",
    database_oid: 16384,
    database_uuid: request.context?.database_uuid ?? "11111111-1111-4111-8111-111111111111",
    finalized_at: "2026-07-15T08:01:00Z",
    finalized_txid: "9123",
    guard_epoch: 0,
    guard_installation_id: "33333333-3333-4333-8333-333333333333",
    intent_digest: "b".repeat(64),
    operation_id: request.operation_id ?? "op-1",
    proof_expires_at: "2026-07-15T08:05:00Z",
    proof_verified_at: "2026-07-15T08:00:00Z",
    protocol_version: 1,
    receipt_digest: "c".repeat(64),
    remaining_unresolved_count: 0,
    request_digest: "d".repeat(64),
    resolution_kind: "verified",
    resolution_operation_id: request.operation_id ?? "op-1",
    resolved_anchor_count: 1,
  },
  audit_receipt: {
    receipt_id: "receipt-1",
    request_id: "req-1",
    operation_id: request.operation_id ?? "op-1",
    capability_id: "acct.bill.vendor_create.v1",
    principal: request.context?.principal ?? "pi:user-42",
    odoo_instance_id: request.context?.odoo_instance_id ?? "odoo19@sandbox",
    database_name: request.context?.database_name ?? "odoo_v3_sandbox",
    database_uuid: request.context?.database_uuid ?? "11111111-1111-4111-8111-111111111111",
    user_id: request.context?.user_id ?? 42,
    approver_user_id: 99,
    company_id: request.context?.company_id ?? 7,
    environment: request.context?.environment ?? "sandbox",
    capability_channel: "staged",
    request_digest: "2".repeat(64),
    operation_digest: "3".repeat(64),
    approval_digest: "4".repeat(64),
    result_digest: "5".repeat(64),
    verification_evidence_digest: "1".repeat(64),
    registry_digest: "a".repeat(64),
    release_digest: "7".repeat(64),
    audit_head: "8".repeat(64),
    issued_at: "2026-07-15T08:01:00Z",
    signature_version: 1,
    signature_purpose: "write_audit_receipt_v1",
    signing_key_id: "audit-key-1",
    signature: "9".repeat(64),
  },
  argv: args,
  parsed_request: request,
  raw_stdin: stdin,
};
let data = { argv: args, parsed_request: request, raw_stdin: stdin };
if (command === "registry.list") {
  data = {
    capabilities: [
      { id: "acct.gl.trial_balance.v1", _test_argv: args, _test_raw_stdin: stdin },
      { id: "acct.bill.vendor_create.v1", _test_argv: args, _test_raw_stdin: stdin },
    ],
    count: 2,
    registry_digest: "a".repeat(64),
  };
} else if (command === "read") {
  data = {
    capability_id: request.capability_id,
    release_identity: {
      verified: true,
      manifest_sha256: "7".repeat(64),
      registry_digest: "a".repeat(64),
    },
    result: {
      _test_argv: args,
      _test_parsed_request: request,
      _test_raw_stdin: stdin,
      receipt: {
        id: "read-receipt-1",
        odoo_instance_id: "odoo19@sandbox",
        database_name: "odoo_v3_sandbox",
        database_uuid: "11111111-1111-4111-8111-111111111111",
        company_id: request.parameters.company_id,
        environment: "sandbox",
        user_id: 42,
        capability_id: request.capability_id,
        capability_channel: "staged",
        request_digest: "a".repeat(64),
        result_digest: "b".repeat(64),
        registry_digest: "a".repeat(64),
        release_digest: "7".repeat(64),
        record_count: 0,
        observed_at: "2026-07-15T08:01:00Z",
        signature_version: 2,
        signature_purpose: "read_receipt_v2",
        signature_key_id: "read-key-1",
        signature: "e".repeat(64),
      },
    },
    runtime: {},
  };
} else if (command === "operation.diagnostics") {
  data = {
    operation: {
      operation_id: request.operation_id,
      capability_id: "acct.bill.vendor_create.v1",
      company_id: request.company_id,
      state: "prepared",
      revision: 0,
      terminal: false,
      business_succeeded: false,
      allowed_next_states: ["failed", "prechecked"],
    },
    audit: {
      chain_verified: true,
      event_count: 0,
      event_types: [],
      event_types_offset: 0,
      event_types_truncated: false,
      last_event_id: null,
      last_event_hash: null,
      global_head_hash: null,
    },
    verification: {
      trusted_terminal_result_verified: false,
      passed: null,
      method: null,
      evidence_digest: null,
    },
    failure: { present: false, stage: null, result_id: null, evidence_digest: null },
    recovery: {
      lifecycle_status: "not_started",
      available: false,
      plan_status: null,
      plan_digest: null,
      recovery_capability_id: null,
      requires_approval: null,
      attempt_count: 0,
      latest_attempt_plan_digest: null,
      bound_operation_ids: [],
      completion_evidence_digest: null,
      completion_receipt_body_digest: null,
      completion_receipt_id: null,
    },
    odoo_refs: [],
    receipts: {
      unique_final_receipt_verified: false,
      current_candidate_count: 0,
      durable_final_receipt_id: null,
      durable_final_receipt_body_digest: null,
      write_audit_receipt_id: null,
      write_audit_result_digest: null,
      write_audit_head: null,
      difference_digest: null,
      database_finalization_digest: null,
    },
    page: { count: 1, total_count: 1 },
    receipt: {
      id: "diagnostics-receipt-1",
      odoo_instance_id: "odoo19@sandbox",
      database_name: "odoo_v3_sandbox",
      database_uuid: "11111111-1111-4111-8111-111111111111",
      company_id: request.company_id,
      environment: "sandbox",
      user_id: 42,
      capability_id: "acct.diagnostics.operation_read.v1",
      capability_channel: "staged",
      request_digest: "a".repeat(64),
      result_digest: "b".repeat(64),
      registry_digest: "a".repeat(64),
      release_digest: "7".repeat(64),
      record_count: 1,
      observed_at: "2026-07-15T08:01:00Z",
      signature_version: 2,
      signature_purpose: "read_receipt_v2",
      signature_key_id: "read-key-1",
      signature: "e".repeat(64),
    },
  };
} else if (["operation.approve_execute", "operation.result"].includes(command)) {
  data = evidence;
}
if (mutation.startsWith("__test_diagnostics_recovered")) {
  data.operation.state = "recovered";
  data.operation.revision = 12;
  data.operation.terminal = true;
  data.operation.business_succeeded = false;
  data.operation.allowed_next_states = [];
  data.recovery.lifecycle_status = "recovered_verified";
  data.recovery.attempt_count = 1;
  data.recovery.latest_attempt_plan_digest = "c".repeat(64);
  data.recovery.bound_operation_ids = [
    "op-prior-failed-recovery",
    "op-successful-recovery",
  ];
  data.recovery.completion_evidence_digest = "d".repeat(64);
  data.recovery.completion_receipt_body_digest = "e".repeat(64);
  data.recovery.completion_receipt_id = "final-recovered-origin";
  data.receipts.current_candidate_count = 1;
}
if (mutation === "__test_diagnostics_recovered_missing_digest") {
  delete data.recovery.completion_evidence_digest;
}
if (mutation === "__test_diagnostics_recovered_tampered_receipt") {
  data.recovery.completion_receipt_body_digest = "not-a-digest";
}
if (mutation === "__test_bad_signature") delete data.audit_receipt.signature;
if (mutation === "__test_failed_verification") data.verification.passed = false;
if (mutation === "__test_non_terminal") data.operation_state = "executing";
if (mutation === "__test_missing_finalization") delete data.database_finalization;
if (mutation === "__test_wrong_finalization_operation") data.database_finalization.operation_id = "op-other";
if (mutation === "__test_invalid_remaining_count") data.database_finalization.remaining_unresolved_count = -1;
if (mutation === "__test_unverified_business_result") data.verification.passed = false;
if (mutation.startsWith("__test_recovered")) {
  // Current incident recovery is a distinct operation that completes while
  // its database receipt resolves the failed origin as "recovered".
  data.operation_state = "completed";
  data.database_finalization.operation_id = "op-failed-origin";
  data.database_finalization.resolution_kind = "recovered";
  data.database_finalization.resolution_operation_id = request.operation_id ?? "op-1";
  data.database_finalization.resolved_anchor_count = 2;
  data.database_finalization.remaining_unresolved_count = 0;
}
if (mutation === "__test_recovered_wrong_target") {
  data.database_finalization.operation_id = request.operation_id ?? "op-1";
}
if (mutation === "__test_recovered_wrong_resolution") {
  data.database_finalization.resolution_operation_id = "op-other-recovery";
}
if (mutation === "__test_recovered_wrong_anchor_count") {
  data.database_finalization.resolved_anchor_count = 1;
}
const payload = { command, data, ok: true };
if (["operation.approve_execute", "operation.result"].includes(command)) {
  payload.business_succeeded = mutation === "__test_unverified_business_result"
    ? false
    : true;
}
process.stdout.write(JSON.stringify(payload));
`, "utf8");
	await writeFile(unknownFixture, `
let stdin = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) stdin += chunk;
const request = JSON.parse(stdin);
process.stderr.write(JSON.stringify({
  command: "operation.approve_execute",
  error: {
    code: "odoo_write_outcome_unknown",
    message: "Execution acknowledgement was lost; query the durable operation.",
    odoo_effect: "unknown",
    operation_id: request.operation_id,
    retryable: true,
    state: "executing",
  },
  ok: false,
}));
process.exitCode = 6;
`, "utf8");
});

after(async () => {
	await rm(fixtureDir, { force: true, recursive: true });
});

function createBoundRunner(options = {}) {
	const expectedReleaseDigest = options.expectedReleaseDigest ?? EXPECTED_RELEASE_DIGEST;
	const expectedRegistryDigest = options.expectedRegistryDigest ?? EXPECTED_REGISTRY_DIGEST;
	const cli = createV3CliRunner({
		...options,
		expectedReleaseDigest,
		expectedRegistryDigest,
	});
	const transport = async (call) => await new Promise((resolve, reject) => {
		const actionArgs = call.action === "read"
			? ["read", "--runtime-config", options.runtimeConfigPath]
			: V3_OPERATION_COMMANDS[call.action];
		const child = spawn(options.cliPath, [
			...(options.prefixArgs ?? []),
			...actionArgs,
		], {
			cwd: path.dirname(options.cliPath),
			env: process.env,
			stdio: ["pipe", "pipe", "pipe"],
			windowsHide: true,
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
		child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
		child.on("error", reject);
		child.on("close", (code) => resolve({
			authorityVerified: true,
			body: code === 0 ? stdout.trim() : stderr.trim(),
			executedRegistryDigest: expectedRegistryDigest,
			executedReleaseDigest: expectedReleaseDigest,
			statusCode: 200,
		}));
		child.stdin.end(call.body, "utf8");
	});
	const broker = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest,
		expectedRegistryDigest,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport,
	});
	return async (action, request) => (
		action === "registry.list" || action === "registry.get"
			? cli(action, request)
			: broker(action, request)
	);
}

function createStaticBrokerRunner(response) {
	return createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport: async () => response,
	});
}

function registryDescriptor(id, capabilityChannel = "staged") {
	return {
		access: id.includes(".create.") ? "write" : "read",
		approval_required: id.includes(".create."),
		business_description: `Visible capability ${id}`,
		capability_channel: capabilityChannel,
		company_scope: "bound_company",
		contract_digest: "c".repeat(64),
		domain: "gateway",
		evidence_level: "contract_tested",
		id,
		idempotency_required: id.includes(".create."),
		input_schema_json: "{\"additionalProperties\":false,\"type\":\"object\"}",
		odoo_permissions: ["base.group_user"],
		output_schema_json: "{\"additionalProperties\":false,\"type\":\"object\"}",
		recovery_method: "not_applicable",
		risk_level: id.includes(".create.") ? "high" : "low",
		verification_method: "signed_read_receipt",
	};
}

function signedRegistryRead(ids = [
	"acct.bill.vendor_create.v1",
	"acct.gl.trial_balance.v1",
]) {
	const capabilities = [...ids].sort().map((id) => registryDescriptor(id));
	return {
		command: "read",
		data: {
			capability_id: "acct.registry.list.v1",
			release_identity: {
				manifest_sha256: EXPECTED_RELEASE_DIGEST,
				registry_digest: EXPECTED_REGISTRY_DIGEST,
				verified: true,
			},
			result: {
				capabilities,
				page: {
					count: capabilities.length,
					total_count: capabilities.length,
				},
				receipt: {
					capability_channel: "staged",
					capability_id: "acct.registry.list.v1",
					company_id: 7,
					database_name: "odoo_v3_sandbox",
					database_uuid: "11111111-1111-4111-8111-111111111111",
					environment: "sandbox",
					id: "registry-read-receipt-1",
					observed_at: "2026-07-29T08:01:00Z",
					odoo_instance_id: "odoo19@sandbox",
					record_count: capabilities.length,
					registry_digest: EXPECTED_REGISTRY_DIGEST,
					release_digest: EXPECTED_RELEASE_DIGEST,
					request_digest: "d".repeat(64),
					result_digest: "e".repeat(64),
					signature: "f".repeat(64),
					signature_key_id: "read-key-1",
					signature_purpose: "read_receipt_v2",
					signature_version: 2,
					user_id: 42,
				},
			},
			runtime: {},
		},
		ok: true,
	};
}

function signedRegistryBrokerResponse(envelope = signedRegistryRead()) {
	return {
		authorityVerified: true,
		body: JSON.stringify(envelope),
		executedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		executedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		statusCode: 200,
	};
}

function localBrokerSocketPath(name) {
	return process.platform === "win32"
		? `\\\\.\\pipe\\odoo-v3-${name}-${process.pid}-${Date.now()}`
		: path.join(fixtureDir, `${name}.sock`);
}

function writeParameterFixtures() {
	const invoiceLine = {
		line_reference: "line-001",
		name: "七月云服务费",
		product_id: null,
		account_id: 610001,
		quantity: "1.00",
		price_unit: "128.50",
		tax_ids: [17],
	};
	const balancedLines = [
		{
			line_reference: "debit-001",
			account_id: 660001,
			partner_id: null,
			currency_id: 12,
			name: "月末预提费用",
			side: "debit",
			amount: "125.00",
			amount_currency: "125.00",
			tax_ids: [],
		},
		{
			line_reference: "credit-001",
			account_id: 220201,
			partner_id: null,
			currency_id: 12,
			name: "月末预提负债",
			side: "credit",
			amount: "125.00",
			amount_currency: "-125.00",
			tax_ids: [],
		},
	];
	return {
		"acct.invoice.customer_create.v1": {
			company_id: 7,
			partner_id: 901,
			invoice_date: "2026-07-14",
			accounting_date: "2026-07-15",
			due_date: "2026-08-14",
			currency_id: 12,
			journal_id: 31,
			posting_mode: "draft",
			reference: "客户发票 CN/2026/0001",
			lines: [invoiceLine],
			idempotency_key: "customer-invoice-2026-0001",
		},
		"acct.bill.vendor_create.v1": {
			company_id: 7,
			partner_id: 902,
			invoice_date: "2026-07-14",
			accounting_date: "2026-07-15",
			due_date: "2026-08-14",
			currency_id: 12,
			journal_id: 32,
			posting_mode: "draft",
			vendor_reference: "供应商 A/INV-001",
			lines: [{ ...invoiceLine, line_reference: "vendor-line-001" }],
			idempotency_key: "vendor-bill-2026-0001",
		},
		"acct.refund.create.v1": {
			company_id: 7,
			origin_move_id: 1001,
			refund_type: "customer_credit_note",
			refund_mode: "partial",
			refund_date: "2026-07-15",
			journal_id: 31,
			currency_id: 12,
			expected_total_amount: "128.50",
			reason: "部分退回七月云服务费",
			posting_mode: "draft",
			lines: [{
				line_reference: "refund-line-001",
				name: "云服务退款",
				account_id: 610001,
				quantity: "1.00",
				price_unit: "128.50",
				tax_ids: [17],
			}],
			idempotency_key: "refund-2026-0001",
		},
		"acct.payment.register.v1": {
			company_id: 7,
			target_move_ids: [1001],
			partner_id: 901,
			partner_type: "customer",
			direction: "inbound",
			payment_date: "2026-07-15",
			currency_id: 12,
			amount: "128.50",
			journal_id: 41,
			payment_method_line_id: 51,
			memo: "客户回款 CN/2026/0001",
			idempotency_key: "payment-2026-0001",
		},
		"acct.payment.cancel.v1": {
			company_id: 7,
			payment_id: 7001,
			move_id: 7002,
			expected_payment_state: "in_process",
			expected_move_state: "posted",
			expected_payment_date: "2026-07-15",
			expected_partner_id: 901,
			expected_partner_type: "customer",
			expected_direction: "inbound",
			expected_amount: "128.50",
			expected_currency_id: 12,
			expected_journal_id: 41,
			expected_payment_method_line_id: 51,
			expected_is_sent: true,
			expected_line_ids: [7101, 7102],
			reason: "Cancel the reviewed, unreconciled payment entered in error",
			idempotency_key: "payment-cancel-7001",
		},
		"acct.bank.statement_import.v1": {
			company_id: 7,
			journal_id: 41,
			statement_date: "2026-07-15",
			currency_id: 12,
			external_reference: "银行流水 2026-07-15",
			source_digest: "a".repeat(64),
			source_filename: "bank-2026-07-15.csv",
			opening_balance: "1000.00",
			closing_balance: "1128.50",
			lines: [{
				external_transaction_id: "bank-txn-0001",
				transaction_date: "2026-07-15",
				value_date: "2026-07-15",
				direction: "credit",
				amount: "128.50",
				foreign_currency_id: null,
				foreign_amount: null,
				summary: "客户回款・小兢会计",
				partner_id: 901,
				source_line_digest: "b".repeat(64),
			}],
			idempotency_key: "bank-import-2026-0001",
		},
		"acct.bank.statement_compensate.v1": {
			company_id: 7,
			origin_operation_id: "op-bank-statement-import-0001",
			expected_origin_revision: 8,
			expected_origin_final_receipt_body_digest: "c".repeat(64),
			expected_recovery_plan_digest: "d".repeat(64),
			expected_statement_id: 8001,
			expected_journal_id: 41,
			expected_currency_id: 12,
			expected_source_digest: "a".repeat(64),
			compensation_date: "2026-07-16",
			reason: "Post the approved whole-batch compensating bank statement",
			idempotency_key: "bank-statement-compensate-op-0001",
		},
		"acct.reconciliation.apply.v1": {
			company_id: 7,
			line_ids: [2001, 2002],
			account_id: 112201,
			partner_id: 901,
			reconciliation_date: "2026-07-15",
			currency_id: 12,
			mode: "full",
			amount: "128.50",
			tolerance_amount: "0.00",
			writeoff_account_id: null,
			writeoff_journal_id: null,
			writeoff_label: null,
			idempotency_key: "reconcile-2026-0001",
		},
		"acct.asset.create.v1": {
			company_id: 7,
			source_move_line_id: 3001,
			asset_model_id: 71,
			asset_name: "生产服务器・东京二号",
			acquisition_date: "2026-07-15",
			currency_id: 12,
			acquisition_value: "12000.00",
			posting_mode: "confirm",
			idempotency_key: "asset-2026-0001",
		},
		"acct.depreciation.post.v1": {
			company_id: 7,
			asset_id: 4001,
			depreciation_move_id: 4002,
			period_start: "2026-07-01",
			period_end: "2026-07-31",
			posting_date: "2026-07-31",
			journal_id: 33,
			currency_id: 12,
			amount: "1000.00",
			idempotency_key: "depreciation-2026-07-4002",
		},
		"acct.accrual.create.v1": {
			company_id: 7,
			journal_id: 33,
			posting_date: "2026-07-31",
			reversal_date: "2026-08-01",
			currency_id: 12,
			reference: "2026-07 月末云服务预提",
			posting_mode: "post",
			lines: balancedLines,
			idempotency_key: "accrual-2026-07-cloud",
		},
		"acct.deferred.create.v1": {
			company_id: 7,
			source_move_line_id: 5001,
			deferred_type: "expense",
			schedule_start_date: "2026-07-15",
			schedule_end_date: "2027-06-30",
			expected_generation_method: "on_validation",
			amount_computation_method: "month",
			expected_deferred_account_id: 180101,
			expected_deferred_journal_id: 33,
			currency_id: 12,
			total_amount: "12000.00",
			posting_mode: "post",
			idempotency_key: "deferred-2026-0001",
		},
		"acct.period.adjustment_create.v1": {
			company_id: 7,
			journal_id: 33,
			posting_date: "2026-07-31",
			period_end_date: "2026-07-31",
			currency_id: 12,
			reference: "2026-07 月末调整",
			reason: "按财务复核结果调整",
			posting_mode: "draft",
			lines: balancedLines.map((line, index) => ({
				...line,
				line_reference: `adjustment-${index + 1}`,
			})),
			idempotency_key: "adjustment-2026-07-0001",
		},
		"acct.journal.entry_create.v1": {
			company_id: 7,
			journal_id: 33,
			posting_date: "2026-07-31",
			currency_id: 12,
			reference: "MANUAL/2026/0001",
			reason: "Create a reviewed manual reclassification entry in draft",
			posting_mode: "draft",
			lines: balancedLines.map((line, index) => ({
				...line,
				line_reference: `manual-entry-${index + 1}`,
			})),
			idempotency_key: "manual-entry-2026-0001",
		},
		"acct.move.post.v1": {
			company_id: 7,
			move_id: 6003,
			expected_move_type: "entry",
			expected_document_binding: "81e39a4b5c787a0ab48a0cd6512482f12349903d9856cc34e508adc2db1b9d7f",
			expected_business_binding: "e5271e4b7fb376c421537305be33a73237f387fde9d076cccd9fb9dbb815dcb0",
			expected_journal_id: 33,
			expected_currency_id: 12,
			expected_posting_date: "2026-07-31",
			expected_reference: "MANUAL/2026/0002",
			expected_total_debit: "125.00",
			expected_total_credit: "125.00",
			expected_line_count: 2,
			reason: "Post the separately approved V3 manual entry",
			idempotency_key: "manual-entry-post-6003",
		},
		"acct.move.draft_cancel.v2": {
			company_id: 7,
			move_id: 6004,
			expected_move_type: "entry",
			expected_document_binding: "9bef9ff60ca971676105c4def52b6d5de1e71f97ba88db2e6fd44f120bbcdf8b",
			expected_business_binding: "67819435e13b74e033805f70ecf1aee39a3afeb56ff04bf2d4a7fc95c06b1c5d",
			expected_line_ids: [6101, 6102],
			reason: "Cancel the explicitly bound pristine V3 manual entry draft",
			idempotency_key: "manual-entry-draft-cancel-6004",
		},
		"acct.move.reverse.v1": {
			company_id: 7,
			move_id: 6001,
			reversal_date: "2026-08-01",
			journal_id: 33,
			currency_id: 12,
			expected_total_amount: "125.00",
			reason: "冲销经复核确认的错误分录",
			posting_mode: "post",
			idempotency_key: "reverse-6001-2026-08-01",
		},
		"acct.move.draft_cancel.v1": {
			company_id: 7,
			move_id: 6002,
			expected_move_type: "out_invoice",
			expected_document_binding: "d".repeat(64),
			expected_business_binding: "e".repeat(64),
			reason: "Cancel the explicitly bound pristine draft invoice",
			idempotency_key: "draft-cancel-6002",
		},
		"acct.recovery.execute.v1": {
			company_id: 7,
			origin_operation_id: "op-origin-0001",
			expected_recovery_plan_digest: "c".repeat(64),
			recovery_date: "2026-08-01",
			reason: "执行已验证原操作的注册恢复计划",
			idempotency_key: "recovery-op-origin-0001",
		},
		"acct.reconciliation.undo.v1": {
			company_id: 7,
			origin_operation_id: "op-reconciliation-apply-0001",
			expected_origin_revision: 6,
			expected_origin_final_receipt_body_digest: "d".repeat(64),
			expected_recovery_plan_digest: "e".repeat(64),
			recovery_date: "2026-08-02",
			reason: "Undo the complete receipt-bound reconciliation graph",
			idempotency_key: "reconciliation-undo-op-origin-0001",
		},
	};
}

function assertSchemaValue(value, schema, location = "parameters") {
	if (schema.oneOf) {
		let matchCount = 0;
		for (const branch of schema.oneOf) {
			try {
				assertSchemaValue(value, branch, location);
				matchCount += 1;
			} catch {
				// A oneOf value must match exactly one branch.
			}
		}
		assert.equal(matchCount, 1, `${location} must match exactly one oneOf branch`);
		return;
	}
	const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
	if (value === null) {
		assert.ok(allowedTypes.includes("null"), `${location} does not allow null`);
		return;
	}
	if (schema.enum) {
		assert.ok(schema.enum.includes(value), `${location} is not in its enum`);
	}
	if (allowedTypes.includes("object")) {
		assert.equal(typeof value, "object", `${location} must be an object`);
		assert.equal(Array.isArray(value), false, `${location} must not be an array`);
		for (const required of schema.required ?? []) {
			assert.ok(Object.hasOwn(value, required), `${location}.${required} is required`);
		}
		if (schema.additionalProperties === false) {
			assert.deepEqual(
				Object.keys(value).sort(),
				Object.keys(schema.properties ?? {}).filter((key) => Object.hasOwn(value, key)).sort(),
				`${location} contains a field outside the registry schema`,
			);
		}
		for (const [key, item] of Object.entries(value)) {
			assertSchemaValue(item, schema.properties[key], `${location}.${key}`);
		}
		return;
	}
	if (allowedTypes.includes("array")) {
		assert.ok(Array.isArray(value), `${location} must be an array`);
		assert.ok(value.length >= (schema.minItems ?? 0), `${location} is shorter than minItems`);
		assert.ok(value.length <= (schema.maxItems ?? Number.MAX_SAFE_INTEGER), `${location} exceeds maxItems`);
		if (schema.uniqueItems) {
			assert.equal(new Set(value.map((item) => JSON.stringify(item))).size, value.length, `${location} must be unique`);
		}
		value.forEach((item, index) => assertSchemaValue(item, schema.items, `${location}[${index}]`));
		return;
	}
	if (allowedTypes.includes("integer")) {
		assert.ok(Number.isSafeInteger(value), `${location} must be an integer`);
		assert.ok(value >= (schema.minimum ?? Number.MIN_SAFE_INTEGER), `${location} is below minimum`);
		return;
	}
	if (allowedTypes.includes("string")) {
		assert.equal(typeof value, "string", `${location} must be a string`);
		assert.ok(value.length >= (schema.minLength ?? 0), `${location} is shorter than minLength`);
		assert.ok(value.length <= (schema.maxLength ?? Number.MAX_SAFE_INTEGER), `${location} exceeds maxLength`);
		if (schema.pattern) {
			assert.match(value, new RegExp(schema.pattern), `${location} does not match its pattern`);
		}
		return;
	}
	if (allowedTypes.includes("boolean")) {
		assert.equal(typeof value, "boolean", `${location} must be boolean`);
		return;
	}
	assert.fail(`${location} uses an unsupported test schema type`);
}

function requests() {
	return {
		"operation.prepare": {
			capability_id: "acct.bill.vendor_create.v1",
			parameters: {
				accounting_date: "2026-07-15",
				company_id: 7,
				currency_id: 12,
				idempotency_key: "bill-1",
				partner_id: 901,
			},
		},
		"operation.preview": { operation_id: "op-1" },
		"operation.approve_execute": { operation_id: "op-1" },
		"operation.status": { operation_id: "op-1" },
		"operation.result": { operation_id: "op-1" },
		"operation.diagnostics": { company_id: 7, operation_id: "op-1" },
		"operation.recover": {
			origin_operation_id: "op-origin",
			recovery_date: "2026-07-16",
			reason: "Reverse the verified origin operation",
			idempotency_key: "recover-origin-1",
		},
	};
}

test("the runner fails closed when its release identity is not configured", async () => {
	const run = createV3CliRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		timeoutMs: 5000,
	});

	const result = await run("registry.list", {});

	assert.deepEqual(result, {
		command: "registry.list",
		error: {
			code: "bridge_v3_identity_not_configured",
			message: "The verified V3 release and registry identities are not configured.",
			odoo_effect: "none",
			retryable: false,
		},
		ok: false,
	});
});

test("registry, read, and write responses must match the configured release identity", async (t) => {
	await t.test("registry digest mismatch", async () => {
		const run = createBoundRunner({
			cliPath: process.execPath,
			expectedRegistryDigest: "f".repeat(64),
			prefixArgs: [trustedFixture],
			timeoutMs: 5000,
		});
		const result = await run("registry.list", {});
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_cli_response");
	});

	await t.test("read release digest mismatch", async () => {
		const run = createBoundRunner({
			cliPath: process.execPath,
			expectedReleaseDigest: "f".repeat(64),
			prefixArgs: [trustedFixture],
			runtimeConfigPath: path.join(fixtureDir, "runtime.json"),
			timeoutMs: 5000,
		});
		const result = await run("read", {
			capability_id: "acct.gl.trial_balance.v1",
			parameters: {
				company_id: 7,
				date_from: "2026-01-01",
				date_to: "2026-07-15",
			},
		});
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
	});

	await t.test("write registry digest mismatch", async () => {
		const run = createBoundRunner({
			cliPath: process.execPath,
			expectedRegistryDigest: "f".repeat(64),
			prefixArgs: [trustedFixture],
			timeoutMs: 5000,
		});
		const result = await run(
			"operation.result",
			requests()["operation.result"],
		);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
	});
});

test("the explicit test broker transport preserves all six business requests and downstream fixed argv", async (t) => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		timeoutMs: 5000,
	});
	for (const [action, commandArgs] of Object.entries(V3_OPERATION_COMMANDS)) {
		await t.test(action, async () => {
			const request = requests()[action];
			const result = await run(action, request);
			assert.equal(result.ok, true);
			if (action === "operation.diagnostics") {
				assert.deepEqual(commandArgs, ["operation", "diagnostics"]);
				assert.equal(result.data.operation.operation_id, request.operation_id);
				assert.equal(result.data.operation.company_id, request.company_id);
				assert.equal(result.data.receipt.company_id, request.company_id);
			} else {
				assert.deepEqual(result.data.argv, commandArgs);
				assert.deepEqual(result.data.parsed_request, request);
				assert.equal(result.data.raw_stdin, JSON.stringify(request));
				assert.equal(result.data.argv.includes("--request-json"), false);
			}
		});
	}
});

test("capability queries and the explicit test broker read retain fixed argv and UTF-8 JSON", async () => {
	const runtimeConfigPath = path.join(fixtureDir, "runtime.json");
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		runtimeConfigPath,
		timeoutMs: 5000,
	});

	const listed = await run("registry.list", {});
	assert.equal(listed.ok, true);
	assert.deepEqual(listed.data.capabilities[0]._test_argv, ["registry", "list"]);
	assert.equal(listed.data.capabilities[0]._test_raw_stdin, "{}");

	const getRequest = { capability_id: "acct.bill.vendor_create.v1" };
	const capability = await run("registry.get", getRequest);
	assert.equal(capability.ok, true);
	assert.equal(capability.command, "registry.get");
	assert.equal(capability.data.capability.id, getRequest.capability_id);
	assert.deepEqual(capability.data.capability._test_argv, ["registry", "list"]);
	assert.equal(capability.data.capability._test_raw_stdin, JSON.stringify(getRequest));

	const readRequest = {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: {
			company_id: 7,
			date_from: "2026-01-01",
			date_to: "2026-07-15",
			note: "小兢会计・真实读取",
		},
	};
	const read = await run("read", readRequest);
	assert.equal(read.ok, true);
	assert.deepEqual(read.data.result._test_argv, ["read", "--runtime-config", runtimeConfigPath]);
	assert.equal(read.data.result._test_raw_stdin, JSON.stringify(readRequest));
	assert.deepEqual(read.data.result._test_parsed_request, readRequest);
});

test("authenticated capability discovery sends no caller-selected company", async () => {
	const envelope = signedRegistryRead();
	const calls = [];
	const run = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport: async (call) => {
			calls.push(call);
			return {
				authorityVerified: true,
				body: JSON.stringify(envelope),
				executedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
				executedReleaseDigest: EXPECTED_RELEASE_DIGEST,
				statusCode: 200,
			};
		},
	});

	const result = await run("read", {
		capability_id: "acct.registry.list.v1",
		parameters: {},
	});

	assert.deepEqual(result, envelope);
	assert.equal(calls.length, 1);
	assert.equal(
		calls[0].body,
		'{"capability_id":"acct.registry.list.v1","parameters":{}}',
	);
	assert.equal(calls[0].body.includes("company_id"), false);
	assert.equal(
		result.data.result.receipt.company_id,
		7,
	);
});

test("broker session preflight binds one exact handle to a fixed company-free registry read", async () => {
	const calls = [];
	let spawnCount = 0;
	const accepted = await preflightV3BrokerSession({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandle: TEST_BROKER_SESSION_HANDLE,
		transport: async (call) => {
			calls.push(call);
			return signedRegistryBrokerResponse();
		},
	});
	if (accepted) spawnCount += 1;

	assert.equal(accepted, true);
	assert.equal(spawnCount, 1);
	assert.equal(calls.length, 1);
	assert.equal(calls[0].action, "read");
	assert.equal(calls[0].path, "/v1/read");
	assert.equal(calls[0].sessionHandle, TEST_BROKER_SESSION_HANDLE);
	assert.equal(
		calls[0].body,
		'{"capability_id":"acct.registry.list.v1","parameters":{}}',
	);
	assert.equal(calls[0].body.includes("company_id"), false);
});

test("broker session preflight fails closed before spawn", async (t) => {
	const otherSessionHandle = "other-broker-session-0123456789abcdef";
	const cases = [
		{
			name: "invalid handle",
			sessionHandle: "short",
			transport: async () => {
				throw new Error("invalid handles must not reach transport");
			},
		},
		{
			name: "unknown session",
			sessionHandle: otherSessionHandle,
			transport: async () => ({
				authorityVerified: false,
				body: "",
				statusCode: 404,
			}),
		},
		{
			name: "broker rejection",
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => ({
				authorityVerified: false,
				body: "",
				statusCode: 403,
			}),
		},
		{
			name: "wrong executed release identity",
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => ({
				...signedRegistryBrokerResponse(),
				executedReleaseDigest: "8".repeat(64),
			}),
		},
		{
			name: "wrong signed receipt identity",
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => {
				const envelope = signedRegistryRead();
				envelope.data.result.receipt.registry_digest = "8".repeat(64);
				return signedRegistryBrokerResponse(envelope);
			},
		},
		{
			name: "missing receipt signature",
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => {
				const envelope = signedRegistryRead();
				delete envelope.data.result.receipt.signature;
				return signedRegistryBrokerResponse(envelope);
			},
		},
		{
			name: "wrong registry route",
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => {
				const envelope = signedRegistryRead();
				envelope.data.capability_id = "acct.gl.trial_balance.v1";
				return signedRegistryBrokerResponse(envelope);
			},
		},
	];
	for (const scenario of cases) {
		await t.test(scenario.name, async () => {
			let spawnCount = 0;
			const accepted = await preflightV3BrokerSession({
				brokerSocketPath:
					"/run/odoo-accounting-cli-v3/test-broker.sock",
				expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
				expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
				sessionHandle: scenario.sessionHandle,
				transport: scenario.transport,
			});
			if (accepted) spawnCount += 1;

			assert.equal(accepted, false);
			assert.equal(spawnCount, 0);
		});
	}

	await t.test("caller-selected company option", async () => {
		let transportCount = 0;
		let spawnCount = 0;
		const accepted = await preflightV3BrokerSession({
			brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
			company_id: 7,
			expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
			expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
			sessionHandle: TEST_BROKER_SESSION_HANDLE,
			transport: async () => {
				transportCount += 1;
				return signedRegistryBrokerResponse();
			},
		});
		if (accepted) spawnCount += 1;

		assert.equal(accepted, false);
		assert.equal(transportCount, 0);
		assert.equal(spawnCount, 0);
	});
});

test("concurrent broker preflights do not cross session handles", async () => {
	const sessionHandles = [
		"broker-session-alpha-0123456789abcdef",
		"broker-session-bravo-0123456789abcdef",
	];
	const calls = [];
	let releaseBoth;
	const bothArrived = new Promise((resolve) => {
		releaseBoth = resolve;
	});
	const transport = async (call) => {
		calls.push(call);
		if (calls.length === sessionHandles.length) releaseBoth();
		await bothArrived;
		return signedRegistryBrokerResponse();
	};
	const spawnedHandles = [];

	const accepted = await Promise.all(sessionHandles.map(async (sessionHandle) => {
		const allowed = await preflightV3BrokerSession({
			brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
			expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
			expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
			sessionHandle,
			transport,
		});
		if (allowed) spawnedHandles.push(sessionHandle);
		return allowed;
	}));

	assert.deepEqual(accepted, [true, true]);
	assert.equal(calls.length, 2);
	assert.deepEqual(
		calls.map((call) => call.sessionHandle).sort(),
		[...sessionHandles].sort(),
	);
	assert.ok(calls.every(
		(call) => call.body
			=== '{"capability_id":"acct.registry.list.v1","parameters":{}}',
	));
	assert.deepEqual(spawnedHandles.sort(), [...sessionHandles].sort());
});

test("authenticated capability discovery rejects caller parameters before transport", async (t) => {
	for (const parameters of [
		{ company_id: 7 },
		{ company_id: 8 },
		{ extra: "caller-controlled" },
	]) {
		await t.test(JSON.stringify(parameters), async () => {
			let calls = 0;
			const run = createV3BrokerClient({
				brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
				expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
				expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
				sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
				transport: async () => {
					calls += 1;
					throw new Error("must not be called");
				},
			});

			const result = await run("read", {
				capability_id: "acct.registry.list.v1",
				parameters,
			});

			assert.equal(result.ok, false);
			assert.equal(result.error.code, "bridge_invalid_request_json");
			assert.equal(calls, 0);
		});
	}
});

test("capability get is an unsigned selection retaining the complete signed source", () => {
	const source = signedRegistryRead();
	const requestedId = "acct.gl.trial_balance.v1";
	const selected = deriveCapabilityGetFromRegistryRead(source, requestedId);

	assert.equal(selected.ok, true);
	assert.equal(selected.command, "capability.get");
	assert.equal(selected.data.selection.visible, true);
	assert.equal(selected.data.selection.signed, false);
	assert.equal(selected.data.selection.requested_capability_id, requestedId);
	assert.equal(selected.data.selection.source_index, 1);
	assert.equal(
		selected.data.selection.source_receipt_id,
		source.data.result.receipt.id,
	);
	assert.equal(
		selected.data.selection.source_result_digest,
		source.data.result.receipt.result_digest,
	);
	assert.strictEqual(selected.data.signed_registry_read, source);
	assert.strictEqual(
		selected.data.capability,
		source.data.result.capabilities[1],
	);

	const hidden = deriveCapabilityGetFromRegistryRead(
		source,
		"acct.tax.unavailable_write.v1",
	);
	assert.equal(hidden.ok, true);
	assert.deepEqual(hidden.data.capability, null);
	assert.deepEqual(
		hidden.data.selection,
		{
			requested_capability_id: "acct.tax.unavailable_write.v1",
			signed: false,
			source_index: null,
			source_receipt_id: source.data.result.receipt.id,
			source_result_digest: source.data.result.receipt.result_digest,
			visible: false,
		},
	);
	assert.strictEqual(hidden.data.signed_registry_read, source);
});

test("capability discovery rejects malformed signed registry result structures", async (t) => {
	const mutations = [
		["unsorted descriptors", (source) => {
			source.data.result.capabilities.reverse();
		}],
		["duplicate descriptor", (source) => {
			source.data.result.capabilities[1] = structuredClone(
				source.data.result.capabilities[0],
			);
		}],
		["page count drift", (source) => {
			source.data.result.page.total_count += 1;
		}],
		["receipt count drift", (source) => {
			source.data.result.receipt.record_count += 1;
		}],
		["channel drift", (source) => {
			source.data.result.capabilities[0].capability_channel = "enabled";
		}],
		["invalid contract schema", (source) => {
			source.data.result.capabilities[0].input_schema_json = "[]";
		}],
	];
	for (const [name, mutate] of mutations) {
		await t.test(name, async () => {
			const envelope = signedRegistryRead();
			mutate(envelope);
			const run = createStaticBrokerRunner({
				authorityVerified: true,
				body: JSON.stringify(envelope),
				executedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
				executedReleaseDigest: EXPECTED_RELEASE_DIGEST,
				statusCode: 200,
			});

			const result = await run("read", {
				capability_id: "acct.registry.list.v1",
				parameters: {},
			});

			assert.equal(result.ok, false);
			assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
		});
	}
});

test("multicurrency read retains the complete company, cutoff, currency set, policy, and page", async () => {
	const runtimeConfigPath = path.join(fixtureDir, "runtime.json");
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		runtimeConfigPath,
		timeoutMs: 5000,
	});
	const request = {
		capability_id: "acct.multicurrency.balance_read.v1",
		parameters: {
			company_id: 7,
			as_of_date: "2026-06-30",
			currency_ids: [6, 1, 2],
			balance_basis: "posted_ledger_cumulative",
			off_balance_policy: "exclude",
			limit: 100,
			offset: 0,
		},
	};
	const before = structuredClone(request);

	const result = await run("read", request);

	assert.equal(result.ok, true);
	assert.equal(result.data.result._test_raw_stdin, JSON.stringify(before));
	assert.deepEqual(result.data.result._test_parsed_request, before);
	assert.deepEqual(request, before);
});

test("tax and financial report reads retain every report request, period, filter, currency, and page parameter", async (t) => {
	const registryPath = path.resolve(root, "..", "registry", "capabilities.json");
	const registry = JSON.parse(await readFile(registryPath, "utf8"));
	const reportSchemas = new Map(
		registry.capabilities
			.filter((item) => ["acct.tax.report_read.v1", "acct.report.financial_read.v1"].includes(item.id))
			.map((item) => [item.id, item.input_schema]),
	);
	const runtimeConfigPath = path.join(fixtureDir, "runtime.json");
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		runtimeConfigPath,
		timeoutMs: 5000,
	});
	const cases = [
		{
			case_name: "tax",
			capability_id: "acct.tax.report_read.v1",
			parameters: {
				company_id: 7,
				date_from: "2026-04-01",
				date_to: "2026-06-30",
				move_state: "posted",
				journal_scope: "all_report_eligible",
				tax_unit_id: null,
				unreconciled_only: false,
				hide_zero_lines: false,
				line_expansion_request: "none",
				currency_id: 12,
				limit: 100,
				offset: 0,
			},
		},
		{
			case_name: "balance-sheet-previous-period",
			capability_id: "acct.report.financial_read.v1",
			parameters: {
				company_id: 7,
				report_request: {
					kind: "balance_sheet",
					comparison: {
						mode: "previous_period",
						periods: 1,
					},
				},
				date_from: "2026-04-01",
				date_to: "2026-06-30",
				move_state: "posted",
				journal_scope: "all_report_eligible",
				tax_unit_id: null,
				unreconciled_only: false,
				hide_zero_lines: false,
				line_expansion_request: "none",
				currency_id: 12,
				limit: 100,
				offset: 0,
			},
		},
		{
			case_name: "profit-and-loss-previous-year",
			capability_id: "acct.report.financial_read.v1",
			parameters: {
				company_id: 7,
				report_request: {
					kind: "profit_and_loss",
					comparison: {
						mode: "previous_year",
						periods: 1,
					},
				},
				date_from: "2026-04-01",
				date_to: "2026-06-30",
				move_state: "posted",
				journal_scope: "all_report_eligible",
				tax_unit_id: null,
				unreconciled_only: false,
				hide_zero_lines: false,
				line_expansion_request: "none",
				currency_id: 12,
				limit: 100,
				offset: 0,
			},
		},
		{
			case_name: "cash-flow-without-comparison",
			capability_id: "acct.report.financial_read.v1",
			parameters: {
				company_id: 7,
				report_request: {
					kind: "cash_flow",
					comparison: null,
				},
				date_from: "2026-04-01",
				date_to: "2026-06-30",
				move_state: "posted",
				journal_scope: "all_report_eligible",
				tax_unit_id: null,
				unreconciled_only: false,
				hide_zero_lines: false,
				line_expansion_request: "none",
				currency_id: 12,
				limit: 100,
				offset: 0,
			},
		},
	];

	for (const testCase of cases) {
		const { case_name: caseName, ...request } = testCase;
		await t.test(caseName, async () => {
			const inputSchema = reportSchemas.get(request.capability_id);
			assert.ok(inputSchema, `${request.capability_id} must exist in the current registry`);
			assertSchemaValue(request.parameters, inputSchema, `${caseName}.parameters`);
			const before = structuredClone(request);
			const result = await run("read", request);

			assert.equal(result.ok, true);
			assert.equal(result.data.result._test_raw_stdin, JSON.stringify(before));
			assert.deepEqual(result.data.result._test_parsed_request, before);
			assert.deepEqual(request, before);
		});
	}
});

test("approve-execute and result reject evidence-free fake CLI success", async () => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [successFixture],
		timeoutMs: 5000,
	});
	for (const action of ["operation.approve_execute", "operation.result"]) {
		const result = await run(action, requests()[action]);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
	}
});

test("write success fails closed on unsigned, unverified, or non-terminal evidence", async (t) => {
	for (const mutation of [
		"__test_bad_signature",
		"__test_failed_verification",
		"__test_non_terminal",
		"__test_missing_finalization",
		"__test_wrong_finalization_operation",
		"__test_invalid_remaining_count",
	]) {
		await t.test(mutation, async () => {
			const run = createBoundRunner({
				cliPath: process.execPath,
				prefixArgs: [trustedFixture, mutation],
				timeoutMs: 5000,
			});
			for (const action of ["operation.approve_execute", "operation.result"]) {
				const result = await run(action, requests()[action]);
				assert.equal(result.ok, false);
				assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
			}
		});
	}
});

test("recovered write success requires the exact two-anchor database binding", async (t) => {
	const validRun = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture, "__test_recovered"],
		timeoutMs: 5000,
	});
	for (const action of ["operation.approve_execute", "operation.result"]) {
		const result = await validRun(action, requests()[action]);
		assert.equal(result.ok, true);
		assert.equal(result.business_succeeded, true);
		assert.equal(result.data.operation_state, "completed");
		assert.deepEqual({
			operation_id: result.data.database_finalization.operation_id,
			resolution_operation_id: result.data.database_finalization.resolution_operation_id,
			resolved_anchor_count: result.data.database_finalization.resolved_anchor_count,
			remaining_unresolved_count: result.data.database_finalization.remaining_unresolved_count,
		}, {
			operation_id: "op-failed-origin",
			resolution_operation_id: requests()[action].operation_id,
			resolved_anchor_count: 2,
			remaining_unresolved_count: 0,
		});
	}

	for (const mutation of [
		"__test_recovered_wrong_target",
		"__test_recovered_wrong_resolution",
		"__test_recovered_wrong_anchor_count",
	]) {
		await t.test(mutation, async () => {
			const run = createBoundRunner({
				cliPath: process.execPath,
				prefixArgs: [trustedFixture, mutation],
				timeoutMs: 5000,
			});
			for (const action of ["operation.approve_execute", "operation.result"]) {
				const result = await run(action, requests()[action]);
				assert.equal(result.ok, false);
				assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
			}
		});
	}
});

test("recovered diagnostics requires exact completion evidence and receipt identifiers", async (t) => {
	const validRun = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture, "__test_diagnostics_recovered"],
		timeoutMs: 5000,
	});
	const request = requests()["operation.diagnostics"];
	const result = await validRun("operation.diagnostics", request);
	assert.equal(result.ok, true);
	assert.equal(result.data.operation.state, "recovered");
	assert.equal(result.data.operation.business_succeeded, false);
	assert.equal(result.data.recovery.lifecycle_status, "recovered_verified");
	assert.deepEqual(result.data.recovery.bound_operation_ids, [
		"op-prior-failed-recovery",
		"op-successful-recovery",
	]);
	assert.equal(
		result.data.recovery.completion_evidence_digest,
		"d".repeat(64),
	);
	assert.equal(
		result.data.recovery.completion_receipt_body_digest,
		"e".repeat(64),
	);
	assert.equal(
		result.data.recovery.completion_receipt_id,
		"final-recovered-origin",
	);

	for (const mutation of [
		"__test_diagnostics_recovered_missing_digest",
		"__test_diagnostics_recovered_tampered_receipt",
	]) {
		await t.test(mutation, async () => {
			const run = createBoundRunner({
				cliPath: process.execPath,
				prefixArgs: [trustedFixture, mutation],
				timeoutMs: 5000,
			});
			const rejected = await run("operation.diagnostics", request);
			assert.equal(rejected.ok, false);
			assert.equal(
				rejected.error.code,
				"bridge_invalid_v3_broker_response",
			);
		});
	}
});

test("unverified terminal write response carries explicit no-success guidance", async () => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture, "__test_unverified_business_result"],
		timeoutMs: 5000,
	});
	for (const action of ["operation.approve_execute", "operation.result"]) {
		const result = await run(action, requests()[action]);
		assert.equal(result.ok, true);
		assert.equal(result.business_succeeded, false);
		assert.deepEqual(result.bridge_guidance, {
			must_not_report_business_success: true,
			next_action: "operation.status",
			operation_id: requests()[action].operation_id,
			reason: "terminal_write_result_is_not_business_verified",
		});
	}
});

test("complex financial parameters are retained byte-for-byte through the test broker transport", async () => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [successFixture],
		timeoutMs: 5000,
	});
	const request = requests()["operation.prepare"];
	request.parameters = {
		accounting_date: "2026-07-15",
		company_id: 7,
		currency_id: 12,
		currency_code: "SGD",
		invoice_date: "2026-07-14",
		due_date: "2026-08-14",
		idempotency_key: "供应商账单:SG/2026/0001",
		partner_id: 901,
		supplier_reference: "供应商-A/INV-001",
		lines: [
			{
				account_id: 610001,
				analytic_distribution: { "部门/新加坡": "100.00" },
				description: "云服务费 – 七月",
				price_unit: "8888.80",
				quantity: "1.00",
				tax_ids: [17, 19],
			},
		],
		metadata: { source: "小兢会计", tags: ["应付", "多币种", "审计"] },
	};
	const before = structuredClone(request);

	const result = await run("operation.prepare", request);

	assert.equal(result.ok, true);
	assert.equal(result.data.raw_stdin, JSON.stringify(before));
	assert.deepEqual(result.data.parsed_request, before);
	assert.deepEqual(request, before);
	assert.deepEqual(result.data.argv, ["operation", "prepare"]);
});

test("all 20 registered write schemas have valid complete fixtures and transit byte-for-byte", async (t) => {
	const registryPath = path.resolve(root, "..", "registry", "capabilities.json");
	const registry = JSON.parse(await readFile(registryPath, "utf8"));
	const writeCapabilities = registry.capabilities.filter((item) => item.access === "write");
	const fixtures = writeParameterFixtures();
	assert.equal(writeCapabilities.length, 20);
	assert.deepEqual(Object.keys(fixtures).sort(), writeCapabilities.map((item) => item.id).sort());

	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		timeoutMs: 5000,
	});
	for (const [index, capability] of writeCapabilities.entries()) {
		await t.test(capability.id, async () => {
			const parameters = fixtures[capability.id];
			assertSchemaValue(parameters, capability.input_schema);
			assert.deepEqual(Object.keys(parameters).sort(), [...capability.input_schema.required].sort());
			const request = {
				capability_id: capability.id,
				parameters,
			};
			const before = structuredClone(request);

			const result = await run("operation.prepare", request);

			assert.equal(result.ok, true);
			assert.deepEqual(result.data.argv, ["operation", "prepare"]);
			assert.equal(result.data.raw_stdin, JSON.stringify(before));
			assert.deepEqual(result.data.parsed_request, before);
			assert.deepEqual(request, before);
		});
	}
});

test("reconciliation undo preserves every trusted origin binding and no free-form graph", async () => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [trustedFixture],
		timeoutMs: 5000,
	});
	const parameters = writeParameterFixtures()["acct.reconciliation.undo.v1"];
	const request = {
		capability_id: "acct.reconciliation.undo.v1",
		parameters,
	};
	const before = structuredClone(request);

	const result = await run("operation.prepare", request);

	assert.equal(result.ok, true);
	assert.deepEqual(result.data.parsed_request, before);
	assert.equal(result.data.raw_stdin, JSON.stringify(before));
	assert.equal(result.data.parsed_request.parameters.expected_origin_revision, 6);
	assert.equal(
		result.data.parsed_request.parameters.expected_origin_final_receipt_body_digest,
		"d".repeat(64),
	);
	assert.equal(
		result.data.parsed_request.parameters.expected_recovery_plan_digest,
		"e".repeat(64),
	);
	assert.equal(Object.hasOwn(result.data.parsed_request.parameters, "line_ids"), false);
	assert.equal(Object.hasOwn(result.data.parsed_request.parameters, "payment_id"), false);
	assert.deepEqual(request, before);
});

test("unknown Odoo effect preserves the complete CLI error and forbids blind replacement", async () => {
	const run = createBoundRunner({
		cliPath: process.execPath,
		prefixArgs: [unknownFixture],
		timeoutMs: 5000,
	});
	const request = requests()["operation.approve_execute"];

	const result = await run("operation.approve_execute", request);

	assert.deepEqual(result, {
		command: "operation.approve_execute",
		error: {
			code: "odoo_write_outcome_unknown",
			message: "Execution acknowledgement was lost; query the durable operation.",
			odoo_effect: "unknown",
			operation_id: "op-1",
			retryable: true,
			state: "executing",
		},
		ok: false,
	});
	const guided = addUnknownEffectGuidance(result);
	assert.deepEqual(guided.error, result.error);
	assert.deepEqual(guided.bridge_guidance, {
		must_not_create_new_operation: true,
		next_action: "operation.status",
		operation_id: "op-1",
	});
});

test("authenticated broker reconciliation errors enforce the optional boolean contract", async (t) => {
	const action = "operation.status";
	const request = requests()[action];
	const runError = async (error) => {
		const envelope = { command: action, error, ok: false };
		const run = createStaticBrokerRunner({
			authorityVerified: true,
			body: JSON.stringify(envelope),
			statusCode: 200,
		});
		return { envelope, result: await run(action, request) };
	};
	const baseError = {
		code: "broker_session_rejected",
		message: "The trusted V3 broker rejected the request.",
		odoo_effect: "none",
		retryable: false,
	};

	for (const [name, error] of [
		["absent", { ...baseError }],
		["false", {
			...baseError,
			odoo_effect: "unknown",
			reconciliation_required: false,
			retryable: true,
		}],
		["true with safe denial", {
			...baseError,
			reconciliation_required: true,
		}],
		["true with authority reconciliation", {
			...baseError,
			code: "broker_authority_reconciliation_required",
			reconciliation_required: true,
		}],
	]) {
		await t.test(`accepts ${name}`, async () => {
			const { envelope, result } = await runError(error);
			assert.deepEqual(result, envelope);
			assert.equal(Object.hasOwn(result, "business_succeeded"), false);
			assert.equal(Object.hasOwn(result, "data"), false);
		});
	}

	for (const [name, error] of [
		["wrong type", { ...baseError, reconciliation_required: "true" }],
		["true and retryable", {
			...baseError,
			reconciliation_required: true,
			retryable: true,
		}],
		["true and unknown effect", {
			...baseError,
			odoo_effect: "unknown",
			reconciliation_required: true,
		}],
		["an extra error field", {
			...baseError,
			reconciliation_required: true,
			unexpected: true,
		}],
	]) {
		await t.test(`rejects ${name}`, async () => {
			const { result } = await runError(error);
			assert.equal(result.ok, false);
			assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
			assert.equal(Object.hasOwn(result.error, "reconciliation_required"), false);
		});
	}
});

test("recover broker errors bind only a correctly named origin operation id", async (t) => {
	const action = "operation.recover";
	const request = requests()[action];
	const baseError = {
		code: "broker_recovery_rejected",
		message: "The trusted V3 broker rejected the request.",
		odoo_effect: "none",
		retryable: false,
	};
	const acceptedEnvelope = {
		command: action,
		error: {
			...baseError,
			origin_operation_id: request.origin_operation_id,
		},
		ok: false,
	};
	const accepted = await createStaticBrokerRunner({
		authorityVerified: true,
		body: JSON.stringify(acceptedEnvelope),
		statusCode: 200,
	})(action, request);
	assert.deepEqual(accepted, acceptedEnvelope);
	const brokerOmittedOrigin = await createStaticBrokerRunner({
		authorityVerified: true,
		body: JSON.stringify({
			command: action,
			error: baseError,
			ok: false,
		}),
		statusCode: 200,
	})(action, request);
	assert.deepEqual(brokerOmittedOrigin, acceptedEnvelope);

	for (const [name, error] of [
		["wrong origin", {
			...baseError,
			origin_operation_id: "op-different-origin",
		}],
		["origin mislabeled as recovery operation", {
			...baseError,
			operation_id: request.origin_operation_id,
		}],
	]) {
		await t.test(`rejects ${name}`, async () => {
			const result = await createStaticBrokerRunner({
				authorityVerified: true,
				body: JSON.stringify({ command: action, error, ok: false }),
				statusCode: 200,
			})(action, request);
			assert.equal(result.ok, false);
			assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
			assert.equal(
				result.error.origin_operation_id,
				request.origin_operation_id,
			);
			assert.equal(Object.hasOwn(result.error, "operation_id"), false);
		});
	}

	await t.test("rejects origin identifiers on non-recover errors", async () => {
		const statusAction = "operation.status";
		const statusRequest = requests()[statusAction];
		const result = await createStaticBrokerRunner({
			authorityVerified: true,
			body: JSON.stringify({
				command: statusAction,
				error: {
					...baseError,
					origin_operation_id: request.origin_operation_id,
				},
				ok: false,
			}),
			statusCode: 200,
		})(statusAction, statusRequest);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
		assert.equal(result.error.operation_id, statusRequest.operation_id);
		assert.equal(Object.hasOwn(result.error, "origin_operation_id"), false);
	});
});

test("the exact pre-auth broker reconciliation denial is returned unchanged", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const envelope = {
		command: action,
		error: {
			code: "broker_session_reconciliation_required",
			message: "The trusted V3 broker rejected the request.",
			odoo_effect: "none",
			reconciliation_required: true,
			retryable: false,
		},
		ok: false,
	};
	const run = createStaticBrokerRunner({
		authorityVerified: false,
		body: JSON.stringify(envelope),
		statusCode: 503,
	});

	const result = await run(action, request);

	assert.deepEqual(result, envelope);
	assert.deepEqual(Object.keys(result).sort(), ["command", "error", "ok"]);
	assert.equal(Object.hasOwn(result, "business_succeeded"), false);
	assert.equal(Object.hasOwn(result, "data"), false);
	assert.equal(Object.hasOwn(result, "executedReleaseDigest"), false);
	assert.equal(Object.hasOwn(result, "executedRegistryDigest"), false);
});

test("a pre-auth recover reconciliation denial is bound to its origin", async () => {
	const action = "operation.recover";
	const request = requests()[action];
	const envelope = {
		command: action,
		error: {
			code: "broker_session_reconciliation_required",
			message: "The trusted V3 broker rejected the request.",
			odoo_effect: "none",
			reconciliation_required: true,
			retryable: false,
		},
		ok: false,
	};
	const run = createStaticBrokerRunner({
		authorityVerified: false,
		body: JSON.stringify(envelope),
		statusCode: 503,
	});

	const result = await run(action, request);

	assert.deepEqual(result, {
		...envelope,
		error: {
			...envelope.error,
			origin_operation_id: request.origin_operation_id,
		},
	});
	assert.deepEqual(addUnknownEffectGuidance(result).bridge_guidance, {
		must_not_create_new_operation: true,
		next_action: "operation.diagnostics",
		origin_operation_id: request.origin_operation_id,
		reason: "recovery_prepare_delivery_must_be_reconciled",
	});
});

test("a possibly delivered approve-execute transport failure forbids replay", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const run = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport: async () => {
			throw new Error("private socket acknowledgement loss");
		},
	});

	const result = await run(action, request);

	assert.deepEqual(result, {
		command: action,
		error: {
			code: "bridge_v3_broker_outcome_unknown",
			message: "The trusted V3 broker request may have been accepted; reconcile it before retrying.",
			odoo_effect: "unknown",
			operation_id: request.operation_id,
			retryable: false,
		},
		ok: false,
	});
	assert.deepEqual(addUnknownEffectGuidance(result).bridge_guidance, {
		must_not_create_new_operation: true,
		next_action: "operation.status",
		operation_id: request.operation_id,
	});
	assert.equal(JSON.stringify(result).includes("private socket"), false);
});

test("a definite pre-connect broker refusal remains safely retryable", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const missingSocket = path.join(
		os.tmpdir(),
		`odoo-v3-missing-${process.pid}-${Date.now()}.sock`,
	);
	const run = createV3BrokerClient({
		brokerSocketPath: missingSocket,
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		timeoutMs: 1000,
	});

	const result = await run(action, request);

	assert.deepEqual(result, {
		command: action,
		error: {
			code: "bridge_v3_broker_unavailable",
			message: "The fixed local V3 trusted broker is unavailable.",
			odoo_effect: "none",
			operation_id: request.operation_id,
			retryable: true,
		},
		ok: false,
	});
});

test("a broker that drops a partial response produces outcome unknown", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const socketPath = localBrokerSocketPath("partial-response");
	let receivedBody = "";
	let markReceived;
	const received = new Promise((resolve) => { markReceived = resolve; });
	let markPartialSent;
	const partialSent = new Promise((resolve) => { markPartialSent = resolve; });
	const server = http.createServer((incoming, outgoing) => {
		incoming.setEncoding("utf8");
		incoming.on("data", (chunk) => { receivedBody += chunk; });
		incoming.on("end", () => {
			markReceived();
			outgoing.writeHead(200, {
				"Connection": "close",
				"Content-Length": "1024",
				"Content-Type": "application/json; charset=utf-8",
				"X-Odoo-V3-Broker-Authority": "verified-v1",
			});
			outgoing.end('{"ok":', "utf8", markPartialSent);
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});
	let settleTimer;
	const run = createV3BrokerClient({
		brokerSocketPath: socketPath,
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		timeoutMs: 5000,
	});
	try {
		const pendingResult = run(action, request);
		await received;
		await partialSent;
		const didNotSettle = Symbol("did-not-settle");
		const result = await Promise.race([
			pendingResult,
			new Promise((resolve) => {
				settleTimer = setTimeout(() => resolve(didNotSettle), 1000);
			}),
		]);
		assert.notEqual(result, didNotSettle, "partial broker response did not settle");
		assert.equal(receivedBody, JSON.stringify(request));
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_v3_broker_outcome_unknown");
		assert.equal(result.error.odoo_effect, "unknown");
		assert.equal(result.error.retryable, false);
		assert.equal(Object.hasOwn(result.error, "reconciliation_required"), false);
	} finally {
		clearTimeout(settleTimer);
		await new Promise((resolve) => server.close(resolve));
	}
});

test("a broker response-phase timeout produces outcome unknown", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const socketPath = localBrokerSocketPath("response-timeout");
	const server = http.createServer((incoming, outgoing) => {
		incoming.resume();
		incoming.on("end", () => {
			outgoing.writeHead(200, {
				"Content-Type": "application/json; charset=utf-8",
				"X-Odoo-V3-Broker-Authority": "verified-v1",
			});
			outgoing.write('{"ok":');
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});
	const run = createV3BrokerClient({
		brokerSocketPath: socketPath,
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		timeoutMs: 500,
	});
	try {
		const result = await run(action, request);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_v3_broker_outcome_unknown");
		assert.equal(result.error.odoo_effect, "unknown");
		assert.equal(result.error.retryable, false);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});

test("an oversized broker response produces outcome unknown", async () => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const socketPath = localBrokerSocketPath("oversized-response");
	const server = http.createServer((incoming, outgoing) => {
		incoming.resume();
		incoming.on("end", () => {
			outgoing.writeHead(200, {
				"Content-Type": "application/json; charset=utf-8",
				"X-Odoo-V3-Broker-Authority": "verified-v1",
			});
			outgoing.end("x".repeat(128));
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});
	const run = createV3BrokerClient({
		brokerSocketPath: socketPath,
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		maxOutputBytes: 16,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		timeoutMs: 5000,
	});
	try {
		const result = await run(action, request);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_v3_broker_outcome_unknown");
		assert.equal(result.error.odoo_effect, "unknown");
		assert.equal(result.error.retryable, false);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});

test("a possibly delivered local-state action requires broker reconciliation", async () => {
	const action = "operation.preview";
	const request = requests()[action];
	const run = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport: async () => {
			throw new Error("private response loss");
		},
	});

	const result = await run(action, request);

	assert.deepEqual(result, {
		command: action,
		error: {
			code: "bridge_v3_broker_reconciliation_required",
			message: "The trusted V3 broker request may have been accepted; reconcile it before retrying.",
			odoo_effect: "none",
			operation_id: request.operation_id,
			reconciliation_required: true,
			retryable: false,
		},
		ok: false,
	});
});

test("a possibly delivered recover binds the origin and forbids replacement", async () => {
	const action = "operation.recover";
	const request = requests()[action];
	const run = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/test-broker.sock",
		expectedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		expectedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		sessionHandleProvider: () => TEST_BROKER_SESSION_HANDLE,
		transport: async () => {
			throw new Error("recovery acknowledgement loss");
		},
	});

	const result = await run(action, request);

	assert.deepEqual(result, {
		command: action,
		error: {
			code: "bridge_v3_broker_reconciliation_required",
			message: "The trusted V3 broker request may have been accepted; reconcile it before retrying.",
			odoo_effect: "none",
			origin_operation_id: request.origin_operation_id,
			reconciliation_required: true,
			retryable: false,
		},
		ok: false,
	});
	assert.equal(Object.hasOwn(result.error, "operation_id"), false);
	assert.deepEqual(addUnknownEffectGuidance(result).bridge_guidance, {
		must_not_create_new_operation: true,
		next_action: "operation.diagnostics",
		origin_operation_id: request.origin_operation_id,
		reason: "recovery_prepare_delivery_must_be_reconciled",
	});
});

test("all other unauthenticated or non-200 broker responses stay untrusted", async (t) => {
	const action = "operation.approve_execute";
	const request = requests()[action];
	const error = {
		code: "broker_session_reconciliation_required",
		message: "The trusted V3 broker rejected the request.",
		odoo_effect: "none",
		reconciliation_required: true,
		retryable: false,
	};
	const envelope = { command: action, error, ok: false };
	const response = {
		authorityVerified: false,
		body: JSON.stringify(envelope),
		statusCode: 503,
	};
	const bodyWith = (overrides) => JSON.stringify({
		...envelope,
		...overrides,
	});
	const errorBodyWith = (overrides) => bodyWith({
		error: { ...error, ...overrides },
	});

	for (const [name, unsafeResponse] of [
		["wrong status", { ...response, statusCode: 500 }],
		["authenticated 503", { ...response, authorityVerified: true }],
		["unauthenticated 200", { ...response, statusCode: 200 }],
		["executed release identity", {
			...response,
			executedReleaseDigest: EXPECTED_RELEASE_DIGEST,
		}],
		["executed registry identity", {
			...response,
			executedRegistryDigest: EXPECTED_REGISTRY_DIGEST,
		}],
		["wrong command", {
			...response,
			body: bodyWith({ command: "operation.status" }),
		}],
		["wrong code", {
			...response,
			body: errorBodyWith({ code: "broker_session_rejected" }),
		}],
		["wrong flag", {
			...response,
			body: errorBodyWith({ reconciliation_required: false }),
		}],
		["retryable", {
			...response,
			body: errorBodyWith({ retryable: true }),
		}],
		["unknown effect", {
			...response,
			body: errorBodyWith({ odoo_effect: "unknown" }),
		}],
		["private message", {
			...response,
			body: errorBodyWith({ message: "private session-store failure" }),
		}],
		["extra error field", {
			...response,
			body: errorBodyWith({ unexpected: true }),
		}],
		["extra envelope field", {
			...response,
			body: bodyWith({ unexpected: true }),
		}],
		["session handle echo", {
			...response,
			body: errorBodyWith({
				message: `Rejected ${TEST_BROKER_SESSION_HANDLE}`,
			}),
		}],
	]) {
		await t.test(name, async () => {
			const run = createStaticBrokerRunner(unsafeResponse);
			const result = await run(action, request);
			assert.deepEqual(result, {
				command: action,
				error: {
					code: "bridge_invalid_v3_broker_response",
					message: "The V3 broker did not return its authenticated response contract.",
					odoo_effect: "unknown",
					operation_id: request.operation_id,
					retryable: false,
				},
				ok: false,
			});
		});
	}
});

test("the extension retains legacy registration while hardened policy grants only V3", async () => {
	assert.deepEqual(Object.values(V3_TOOL_NAMES), [
		"odoo_v3_capability_list",
		"odoo_v3_capability_get",
		"odoo_v3_read",
		"odoo_v3_operation_prepare",
		"odoo_v3_operation_preview",
		"odoo_v3_operation_approve_execute",
		"odoo_v3_operation_status",
		"odoo_v3_operation_result",
		"odoo_v3_operation_diagnostics",
		"odoo_v3_operation_recover",
	]);
	const extension = await readFile(path.join(root, "extensions", "odoo-tools.ts"), "utf8");
	const server = await readFile(path.join(root, "server.mjs"), "utf8");
	const policy = await readFile(path.join(root, "tool-policy.mjs"), "utf8");
	for (const v2Tool of [
		"odoo_get_context",
		"odoo_list_skills",
		"odoo_execute_skill",
		"odoo_list_reports",
		"odoo_export_report",
	]) {
		assert.match(extension, new RegExp(`name: "${v2Tool}"`));
		assert.match(policy, new RegExp(`"${v2Tool}"`));
	}
	assert.match(server, /enabledPiToolNames/);
	assert.match(server, /PI_BRIDGE_HARDENED_V3_ONLY/);
	assert.match(extension, /if \(!hardenedV3Only\)/);
	assert.match(extension, /PI_BRIDGE_HARDENED_V3_ONLY/);
	for (const registration of [
		"v3CapabilityListTool",
		"v3CapabilityGetTool",
		"v3ReadTool",
		"v3PrepareTool",
		"v3PreviewTool",
		"v3ApproveExecuteTool",
		"v3StatusTool",
		"v3ResultTool",
		"v3DiagnosticsTool",
		"v3RecoverTool",
	]) {
		assert.match(extension, new RegExp(`pi\\.registerTool\\(${registration}\\)`));
	}
});
