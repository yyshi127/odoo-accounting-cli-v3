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
} else if (["operation.approve_execute", "operation.result"].includes(command)) {
  data = evidence;
}
if (mutation === "__test_bad_signature") delete data.audit_receipt.signature;
if (mutation === "__test_failed_verification") data.verification.passed = false;
if (mutation === "__test_non_terminal") data.operation_state = "executing";
const payload = { command, data, ok: true };
if (["operation.approve_execute", "operation.result"].includes(command)) {
  payload.business_succeeded = true;
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
		"acct.recovery.execute.v1": {
			company_id: 7,
			origin_operation_id: "op-origin-0001",
			expected_recovery_plan_digest: "c".repeat(64),
			recovery_date: "2026-08-01",
			reason: "执行已验证原操作的注册恢复计划",
			idempotency_key: "recovery-op-origin-0001",
		},
	};
}

function assertSchemaValue(value, schema, location = "parameters") {
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
			assert.deepEqual(result.data.argv, commandArgs);
			assert.deepEqual(result.data.parsed_request, request);
			assert.equal(result.data.raw_stdin, JSON.stringify(request));
			assert.equal(result.data.argv.includes("--request-json"), false);
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

test("all 13 registered write schemas have valid complete fixtures and transit byte-for-byte", async (t) => {
	const registryPath = path.resolve(root, "..", "registry", "capabilities.json");
	const registry = JSON.parse(await readFile(registryPath, "utf8"));
	const writeCapabilities = registry.capabilities.filter((item) => item.access === "write");
	const fixtures = writeParameterFixtures();
	assert.equal(writeCapabilities.length, 13);
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
		"v3RecoverTool",
	]) {
		assert.match(extension, new RegExp(`pi\\.registerTool\\(${registration}\\)`));
	}
});
