import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
	FinalResultDeliveryError,
	MAX_DELIVERED_AUDIT_RECEIPT_BYTES,
	MAX_DELIVERED_BUSINESS_RESULT_BYTES,
	MAX_DELIVERED_FINAL_ANSWER_BYTES,
	createFinalResultDeliverer,
	serializeFinalDeliveredAnswer,
} from "../final-result-delivery.mjs";

const RELEASE = "7".repeat(64);
const REGISTRY = "a".repeat(64);
const READ_CAPABILITY = "acct.gl.trial_balance.v1";
const WRITE_CAPABILITY = "acct.invoice.customer_create.v1";
const SESSION_HANDLE = "authenticated-session-0123456789abcdef";
const RESULT_DELIVERY_SESSION_HANDLE =
	"result-delivery-session-0123456789abcdef";

function canonicalJson(value) {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
			throw new TypeError("non-canonical number");
		}
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	const keys = Object.keys(value).sort();
	return `{${keys.map(
		(key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
	).join(",")}}`;
}

function digest(value) {
	return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function readFixture() {
	const businessResult = {
		label: "现金",
		page: { count: 1, total_count: 1 },
		rows: [{ account_code: "1000", debit: "10.00", credit: "0.00" }],
	};
	const resultDigest = digest(businessResult);
	const receipt = {
		capability_channel: "staged",
		capability_id: READ_CAPABILITY,
		company_id: 7,
		database_name: "odoo_v3_sandbox",
		database_uuid: "11111111-1111-4111-8111-111111111111",
		environment: "sandbox",
		id: "read-receipt-1",
		observed_at: "2026-07-31T08:00:00Z",
		odoo_instance_id: "odoo19@sandbox",
		record_count: 1,
		registry_digest: REGISTRY,
		release_digest: RELEASE,
		request_digest: "b".repeat(64),
		result_digest: resultDigest,
		signature: "c".repeat(64),
		signature_key_id: "read-key-1",
		signature_purpose: "read_receipt_v2",
		signature_version: 2,
		user_id: 42,
	};
	const locator = {
		action: "read",
		business_succeeded: true,
		capability_id: READ_CAPABILITY,
		operation_id: null,
		receipt_id: receipt.id,
		result_digest: resultDigest,
		status: "verified_success",
	};
	return {
		businessResult,
		locator,
		response: {
			business_succeeded: true,
			command: "result.deliver",
			data: {
				audit_receipt: receipt,
				business_result: businessResult,
				current_identity: {
					registry_digest: REGISTRY,
					release_digest: RELEASE,
				},
				executed_identity: {
					registry_digest: REGISTRY,
					release_digest: RELEASE,
				},
				locator,
				session_binding: {
					company_id: 7,
					database_name: "odoo_v3_sandbox",
					database_uuid: "11111111-1111-4111-8111-111111111111",
					environment: "sandbox",
					odoo_instance_id: "odoo19@sandbox",
					principal: "pi:user-42",
					user_id: 42,
				},
			},
			ok: true,
		},
	};
}

function writeFixture() {
	const businessResult = {
		database_finalization: {
			attestation_digest: "d".repeat(64),
			operation_id: "operation-1",
		},
		operation_id: "operation-1",
		operation_state: "completed",
		verification: {
			checks: ["record_fingerprint_matches"],
			evidence_digest: "e".repeat(64),
			method: "fresh_odoo_readback",
			passed: true,
			verified_at: "2026-07-31T08:00:00Z",
		},
	};
	const resultDigest = digest(businessResult);
	const receipt = {
		approval_digest: "1".repeat(64),
		approver_user_id: 99,
		audit_head: "2".repeat(64),
		capability_channel: "staged",
		capability_id: WRITE_CAPABILITY,
		company_id: 7,
		database_name: "odoo_v3_sandbox",
		database_uuid: "11111111-1111-4111-8111-111111111111",
		environment: "sandbox",
		issued_at: "2026-07-31T08:00:00Z",
		odoo_instance_id: "odoo19@sandbox",
		operation_digest: "3".repeat(64),
		operation_id: "operation-1",
		principal: "pi:user-42",
		receipt_id: "write-receipt-1",
		registry_digest: REGISTRY,
		release_digest: RELEASE,
		request_digest: "4".repeat(64),
		request_id: "request-1",
		result_digest: resultDigest,
		signature: "5".repeat(64),
		signature_purpose: "write_audit_receipt_v1",
		signature_version: 1,
		signing_key_id: "write-key-1",
		user_id: 42,
		verification_evidence_digest: "e".repeat(64),
	};
	const locator = {
		action: "operation.result",
		business_succeeded: true,
		capability_id: WRITE_CAPABILITY,
		operation_id: "operation-1",
		receipt_id: receipt.receipt_id,
		result_digest: resultDigest,
		status: "verified_success",
	};
	return {
		businessResult,
		locator,
		response: {
			business_succeeded: true,
			command: "result.deliver",
			data: {
				audit_receipt: receipt,
				business_result: businessResult,
				current_identity: {
					registry_digest: REGISTRY,
					release_digest: RELEASE,
				},
				executed_identity: {
					registry_digest: REGISTRY,
					release_digest: RELEASE,
				},
				locator,
				session_binding: {
					company_id: 7,
					database_name: "odoo_v3_sandbox",
					database_uuid: "11111111-1111-4111-8111-111111111111",
					environment: "sandbox",
					odoo_instance_id: "odoo19@sandbox",
					principal: "pi:user-42",
					user_id: 42,
				},
			},
			ok: true,
		},
	};
}

function harness(responseFactory) {
	const calls = [];
	const deliver = createFinalResultDeliverer({
		brokerClient: async (action, request) => {
			calls.push({ action, request });
			return responseFactory(action, request);
		},
		expectedRegistryDigest: REGISTRY,
		expectedReleaseDigest: RELEASE,
		sessionHandle: SESSION_HANDLE,
	});
	return { calls, deliver };
}

test("verified read is delivered only from the trusted broker body and receipt", async () => {
	const fixture = readFixture();
	const { calls, deliver } = harness(() => fixture.response);

	const delivered = await deliver(fixture.locator);

	assert.deepEqual(calls, [{
		action: "result.deliver",
		request: fixture.locator,
	}]);
	assert.deepEqual(delivered, {
		action: "read",
		audit_receipt: fixture.response.data.audit_receipt,
		business_result: fixture.businessResult,
		business_succeeded: true,
		capability_id: READ_CAPABILITY,
		operation_id: null,
		receipt_id: "read-receipt-1",
		result_digest: fixture.locator.result_digest,
		status: "verified_success",
	});
	assert.equal(JSON.stringify(delivered).includes(SESSION_HANDLE), false);
});

test("verified terminal write is delivered from durable trusted state", async () => {
	const fixture = writeFixture();
	const { calls, deliver } = harness(() => fixture.response);

	const delivered = await deliver(fixture.locator);

	assert.equal(calls.length, 1);
	assert.equal(delivered.business_succeeded, true);
	assert.deepEqual(delivered.business_result, fixture.businessResult);
	assert.deepEqual(delivered.audit_receipt, fixture.response.data.audit_receipt);
});

test("clarification, refusal, and awaiting approval remain explicit non-success", async () => {
	for (const locator of [
		{
			action: null,
			business_succeeded: false,
			capability_id: null,
			operation_id: null,
			receipt_id: null,
			result_digest: null,
			status: "clarification_required",
		},
		{
			action: null,
			business_succeeded: false,
			capability_id: null,
			operation_id: null,
			receipt_id: null,
			result_digest: null,
			status: "refused",
		},
		{
			action: "operation.preview",
			business_succeeded: false,
			capability_id: WRITE_CAPABILITY,
			operation_id: "operation-1",
			receipt_id: null,
			result_digest: null,
			status: "awaiting_approval",
		},
	]) {
		const { calls, deliver } = harness(() => {
			throw new Error("broker must not be called");
		});
		const delivered = await deliver(locator);
		assert.equal(delivered.status, locator.status);
		assert.equal(delivered.business_succeeded, false);
		assert.equal(delivered.business_result, null);
		assert.equal(delivered.audit_receipt, null);
		assert.equal(calls.length, 0);
	}
});

test("diagnostic locator and malformed or forged terminal locators fail closed", async () => {
	const diagnostic = {
		action: "operation.diagnostics",
		business_succeeded: false,
		capability_id: "acct.diagnostics.operation_read.v1",
		operation_id: "operation-1",
		receipt_id: "diagnostic-receipt-1",
		result_digest: "f".repeat(64),
		status: "verified_diagnostic",
	};
	const fixture = readFixture();
	const { calls, deliver } = harness(() => fixture.response);
	await assert.rejects(
		deliver(diagnostic),
		(error) => error instanceof FinalResultDeliveryError
			&& error.code === "final_result_delivery_unsupported",
	);
	await assert.rejects(
		deliver({ ...fixture.locator, extra: true }),
		(error) => error.code === "final_result_locator_rejected",
	);
	await assert.rejects(
		deliver({ ...fixture.locator, business_succeeded: false }),
		(error) => error.code === "final_result_locator_rejected",
	);
	assert.equal(calls.length, 0);
});

test("parent rejects broker locator, identity, company, receipt, and digest mismatches", async () => {
	const mutations = [
		(response) => {
			response.data.locator.receipt_id = "other";
		},
		(response) => {
			response.data.current_identity.release_digest = "0".repeat(64);
		},
		(response) => {
			response.data.executed_identity.registry_digest = "0".repeat(64);
		},
		(response) => {
			response.data.session_binding.company_id = 8;
		},
		(response) => {
			response.data.audit_receipt.company_id = 8;
		},
		(response) => {
			response.data.audit_receipt.result_digest = "0".repeat(64);
		},
		(response) => {
			response.data.business_result.rows[0].debit = "999.00";
		},
		(response) => {
			response.data.session_binding.session_handle = SESSION_HANDLE;
		},
		(response) => {
			response.data.business_result.auth_token = "sensitive";
		},
	];
	for (const mutate of mutations) {
		const fixture = readFixture();
		mutate(fixture.response);
		const { deliver } = harness(() => fixture.response);
		await assert.rejects(
			deliver(fixture.locator),
			(error) => error instanceof FinalResultDeliveryError,
		);
	}
});

test("broker failures and output never expose the authenticated session handle", async () => {
	const fixture = readFixture();
	const { deliver } = harness(() => ({
		command: "result.deliver",
		error: {
			code: `unsafe-${SESSION_HANDLE}`,
			message: SESSION_HANDLE,
			odoo_effect: "none",
			retryable: false,
		},
		ok: false,
	}));
	await assert.rejects(
		deliver(fixture.locator),
		(error) => (
			error instanceof FinalResultDeliveryError
			&& !String(error.code).includes(SESSION_HANDLE)
			&& !String(error.message).includes(SESSION_HANDLE)
		),
	);
});

test("business result and audit receipt byte limits fail closed", async () => {
	for (const [field, maximum] of [
		["business_result", MAX_DELIVERED_BUSINESS_RESULT_BYTES],
		["audit_receipt", MAX_DELIVERED_AUDIT_RECEIPT_BYTES],
	]) {
		const fixture = readFixture();
		fixture.response.data[field] = {
			payload: "x".repeat(maximum + 1),
		};
		const { deliver } = harness(() => fixture.response);
		await assert.rejects(
			deliver(fixture.locator),
			(error) => error.code === "final_result_delivery_too_large",
		);
	}
});

test("an exact 256 KiB canonical business result remains deliverable", async () => {
	const fixture = readFixture();
	const emptyBytes = Buffer.byteLength(canonicalJson({ payload: "" }), "utf8");
	const businessResult = {
		payload: "x".repeat(
			MAX_DELIVERED_BUSINESS_RESULT_BYTES - emptyBytes,
		),
	};
	assert.equal(
		Buffer.byteLength(canonicalJson(businessResult), "utf8"),
		MAX_DELIVERED_BUSINESS_RESULT_BYTES,
	);
	const resultDigest = digest(businessResult);
	fixture.locator.result_digest = resultDigest;
	fixture.response.data.business_result = businessResult;
	fixture.response.data.audit_receipt.result_digest = resultDigest;
	const { deliver } = harness(() => fixture.response);

	const delivered = await deliver(fixture.locator);

	assert.equal(delivered.result_digest, resultDigest);
	assert.deepEqual(delivered.business_result, businessResult);
});

test("canonical digest is stable for Chinese nested data and property order", async () => {
	const fixture = readFixture();
	const businessResult = {
		合计: { 贷方: "0.00", 借方: "10.00" },
		行: [{ 序号: 1, 科目: "现金" }],
	};
	const reorderedResult = {
		行: [{ 科目: "现金", 序号: 1 }],
		合计: { 借方: "10.00", 贷方: "0.00" },
	};
	const resultDigest = digest(businessResult);
	assert.equal(digest(reorderedResult), resultDigest);
	fixture.locator.result_digest = resultDigest;
	fixture.response.data.business_result = reorderedResult;
	fixture.response.data.audit_receipt.result_digest = resultDigest;
	const { deliver } = harness(() => fixture.response);

	const delivered = await deliver(fixture.locator);

	assert.equal(delivered.result_digest, resultDigest);
	assert.deepEqual(delivered.business_result, reorderedResult);
});

test("non-integer JSON numbers fail closed before result delivery", async () => {
	const fixture = readFixture();
	fixture.response.data.business_result = { amount: 1.25 };
	const { deliver } = harness(() => fixture.response);

	await assert.rejects(
		deliver(fixture.locator),
		(error) => error instanceof FinalResultDeliveryError
			&& error.code === "final_result_delivery_json_rejected",
	);
});

test("parent uses an authenticated broker client with bounded output", async () => {
	const fixture = readFixture();
	const factoryCalls = [];
	const deliver = createFinalResultDeliverer({
		brokerClientFactory: (options) => {
			factoryCalls.push(options);
			return async () => fixture.response;
		},
		brokerSocketPath: "/run/odoo-accounting-cli-v3/pi-broker.sock",
		expectedRegistryDigest: REGISTRY,
		expectedReleaseDigest: RELEASE,
		sessionHandle: SESSION_HANDLE,
	});

	await deliver(fixture.locator);

	assert.equal(factoryCalls.length, 1);
	assert.equal(factoryCalls[0].sessionHandleProvider(), SESSION_HANDLE);
	assert.ok(factoryCalls[0].maxOutputBytes > 0);
	assert.equal(
		JSON.stringify(factoryCalls[0]).includes(SESSION_HANDLE),
		false,
	);
});

test("an exhausted ordinary handle cannot affect the independent one-use delivery handle", async () => {
	const fixture = readFixture();
	let ordinaryHandleExhausted = true;
	const factoryCalls = [];
	const deliver = createFinalResultDeliverer({
		brokerClientFactory: (options) => {
			factoryCalls.push(options);
			return async () => {
				assert.equal(ordinaryHandleExhausted, true);
				assert.equal(
					options.sessionHandleProvider(),
					RESULT_DELIVERY_SESSION_HANDLE,
				);
				return fixture.response;
			};
		},
		brokerSocketPath: "/run/odoo-accounting-cli-v3/pi-broker.sock",
		expectedRegistryDigest: REGISTRY,
		expectedReleaseDigest: RELEASE,
		sessionHandle: RESULT_DELIVERY_SESSION_HANDLE,
	});

	const delivered = await deliver(fixture.locator);
	ordinaryHandleExhausted = false;

	assert.equal(delivered.business_succeeded, true);
	assert.equal(factoryCalls.length, 1);
});

test("final answers are bounded canonical JSON strings and hide both handles", async () => {
	const fixture = readFixture();
	const { deliver } = harness(() => fixture.response);
	const delivered = await deliver(fixture.locator);

	const answer = serializeFinalDeliveredAnswer(delivered, [
		SESSION_HANDLE,
		RESULT_DELIVERY_SESSION_HANDLE,
	]);

	assert.equal(typeof answer, "string");
	assert.equal(answer, canonicalJson(delivered));
	assert.ok(Buffer.byteLength(answer, "utf8") <= MAX_DELIVERED_FINAL_ANSWER_BYTES);
	assert.equal(answer.includes(SESSION_HANDLE), false);
	assert.equal(answer.includes(RESULT_DELIVERY_SESSION_HANDLE), false);

	const nonSuccess = await deliver({
		action: null,
		business_succeeded: false,
		capability_id: null,
		operation_id: null,
		receipt_id: null,
		result_digest: null,
		status: "refused",
	});
	assert.equal(
		serializeFinalDeliveredAnswer(nonSuccess, [
			SESSION_HANDLE,
			RESULT_DELIVERY_SESSION_HANDLE,
		]),
		canonicalJson(nonSuccess),
	);
});

test("final serialization rejects missing, equal, malformed, or leaked handles", async () => {
	const fixture = readFixture();
	const { deliver } = harness(() => fixture.response);
	const delivered = await deliver(fixture.locator);
	for (const handles of [
		[SESSION_HANDLE],
		[SESSION_HANDLE, SESSION_HANDLE],
		[SESSION_HANDLE, "short"],
	]) {
		assert.throws(
			() => serializeFinalDeliveredAnswer(delivered, handles),
			(error) => error instanceof FinalResultDeliveryError
				&& error.code === "final_result_serialization_configuration_rejected",
		);
	}
	assert.throws(
		() => serializeFinalDeliveredAnswer({
			...delivered,
			business_result: { leaked: RESULT_DELIVERY_SESSION_HANDLE },
		}, [SESSION_HANDLE, RESULT_DELIVERY_SESSION_HANDLE]),
		(error) => error instanceof FinalResultDeliveryError
			&& error.code === "final_result_sensitive_data_rejected",
	);
	assert.throws(
		() => serializeFinalDeliveredAnswer({
			...delivered,
			business_result: { result_delivery_session_handle: "redacted" },
		}, [SESSION_HANDLE, RESULT_DELIVERY_SESSION_HANDLE]),
		(error) => error instanceof FinalResultDeliveryError
			&& error.code === "final_result_serialization_rejected",
	);
	assert.throws(
		() => serializeFinalDeliveredAnswer({
			...delivered,
			business_result: { invalid_utf16: "\ud800" },
		}, [SESSION_HANDLE, RESULT_DELIVERY_SESSION_HANDLE]),
		(error) => error instanceof FinalResultDeliveryError
			&& error.code === "final_result_delivery_json_rejected",
	);
});
