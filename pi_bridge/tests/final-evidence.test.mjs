import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
	FINAL_EVIDENCE_COMMIT_TYPE,
	FINAL_EVIDENCE_EVENT_TYPE,
	MAX_FINAL_ANSWER_BYTES,
	MAX_FINAL_EVIDENCE_BYTES,
	MAX_FINAL_EVIDENCE_EVENTS,
	MAX_PI_PRINT_STDOUT_BYTES,
	FinalEvidenceError,
	collectFinalEvidenceStream,
	createFinalEvidenceBrokerClient,
	decodeFinalEvidenceStream,
	decodePiPrintFinalAnswer,
	registerFinalEvidenceSessionShutdown,
	validateFinalAnswer,
} from "../final-evidence.mjs";

const RELEASE_DIGEST = "7".repeat(64);
const REGISTRY_DIGEST = "a".repeat(64);
const RESULT_DIGEST = "b".repeat(64);
const SESSION_HANDLE = "fd4-broker-session-0123456789abcdef";
const BROKER_SOCKET = "/run/odoo-accounting-cli-v3/test-broker.sock";

function readReceipt(capabilityId = "acct.gl.trial_balance.v1") {
	return {
		capability_channel: "enabled",
		capability_id: capabilityId,
		company_id: 7,
		database_name: "odoo_v3_sandbox",
		database_uuid: "11111111-1111-4111-8111-111111111111",
		environment: "sandbox",
		id: "read-receipt-1",
		observed_at: "2026-07-30T01:00:00Z",
		odoo_instance_id: "odoo19@sandbox",
		record_count: 3,
		registry_digest: REGISTRY_DIGEST,
		release_digest: RELEASE_DIGEST,
		request_digest: "c".repeat(64),
		result_digest: RESULT_DIGEST,
		signature: "d".repeat(64),
		signature_key_id: "read-key-1",
		signature_purpose: "read_receipt_v2",
		signature_version: 2,
		user_id: 42,
	};
}

function writeReceipt(operationId = "op-write-1") {
	return {
		approval_digest: "1".repeat(64),
		approver_user_id: 99,
		audit_head: "2".repeat(64),
		capability_channel: "enabled",
		capability_id: "acct.bill.vendor_create.v1",
		company_id: 7,
		database_name: "odoo_v3_sandbox",
		database_uuid: "11111111-1111-4111-8111-111111111111",
		environment: "sandbox",
		issued_at: "2026-07-30T01:00:00Z",
		odoo_instance_id: "odoo19@sandbox",
		operation_digest: "3".repeat(64),
		operation_id: operationId,
		principal: "pi:user-42",
		receipt_id: "write-receipt-1",
		registry_digest: REGISTRY_DIGEST,
		release_digest: RELEASE_DIGEST,
		request_digest: "4".repeat(64),
		request_id: "request-1",
		result_digest: RESULT_DIGEST,
		signature: "5".repeat(64),
		signature_purpose: "write_audit_receipt_v1",
		signature_version: 1,
		signing_key_id: "write-key-1",
		user_id: 42,
		verification_evidence_digest: "6".repeat(64),
	};
}

function databaseFinalization(operationId = "op-write-1") {
	return {
		attestation_digest: "a".repeat(64),
		attestation_id: "22222222-2222-5222-8222-222222222222",
		attestation_key_id: "effect-finalizer-v1",
		database_oid: 16384,
		database_uuid: "11111111-1111-4111-8111-111111111111",
		finalized_at: "2026-07-30T01:01:00Z",
		finalized_txid: "9123",
		guard_epoch: 0,
		guard_installation_id: "33333333-3333-4333-8333-333333333333",
		intent_digest: "b".repeat(64),
		operation_id: operationId,
		proof_expires_at: "2026-07-30T01:05:00Z",
		proof_verified_at: "2026-07-30T01:00:00Z",
		protocol_version: 1,
		receipt_digest: "c".repeat(64),
		remaining_unresolved_count: 0,
		request_digest: "d".repeat(64),
		resolution_kind: "verified",
		resolution_operation_id: operationId,
		resolved_anchor_count: 1,
	};
}

function diagnosticsData(operationId = "op-write-1", companyId = 7) {
	return {
		audit: {
			chain_verified: true,
			event_count: 2,
			event_types: ["prepared", "failed"],
			event_types_offset: 0,
			event_types_truncated: false,
			global_head_hash: "1".repeat(64),
			last_event_hash: "2".repeat(64),
			last_event_id: 2,
		},
		failure: {
			evidence_digest: "3".repeat(64),
			present: true,
			result_id: "failure-result-1",
			stage: "odoo_execute",
		},
		odoo_refs: [],
		operation: {
			allowed_next_states: ["recovery_pending"],
			business_succeeded: false,
			capability_id: "acct.bill.vendor_create.v1",
			company_id: companyId,
			operation_id: operationId,
			revision: 3,
			state: "failed",
			terminal: true,
		},
		page: {
			count: 1,
			total_count: 1,
		},
		receipt: {
			...readReceipt("acct.diagnostics.operation_read.v1"),
			company_id: companyId,
			id: "diagnostics-receipt-1",
			record_count: 1,
		},
		receipts: {
			current_candidate_count: 0,
			database_finalization_digest: null,
			difference_digest: null,
			durable_final_receipt_body_digest: null,
			durable_final_receipt_id: null,
			unique_final_receipt_verified: false,
			write_audit_head: null,
			write_audit_receipt_id: null,
			write_audit_result_digest: null,
		},
		recovery: {
			attempt_count: 0,
			available: true,
			bound_operation_ids: [],
			completion_evidence_digest: null,
			completion_receipt_body_digest: null,
			completion_receipt_id: null,
			latest_attempt_plan_digest: null,
			lifecycle_status: "available",
			plan_digest: null,
			plan_status: null,
			recovery_capability_id: "acct.recovery.execute.v1",
			requires_approval: true,
		},
		verification: {
			evidence_digest: "4".repeat(64),
			method: "diagnostic_projection",
			passed: true,
			trusted_terminal_result_verified: false,
		},
	};
}

function responseFor(action, request) {
	if (action === "read") {
		return {
			command: "read",
			data: {
				capability_id: request.capability_id,
				release_identity: {
					manifest_sha256: RELEASE_DIGEST,
					registry_digest: REGISTRY_DIGEST,
					verified: true,
				},
				result: {
					lines: [],
					receipt: readReceipt(request.capability_id),
				},
				runtime: {},
			},
			ok: true,
		};
	}
	if (["operation.approve_execute", "operation.result"].includes(action)) {
		return {
			business_succeeded: true,
			command: action,
			data: {
				audit_receipt: writeReceipt(request.operation_id),
				database_finalization: databaseFinalization(request.operation_id),
				operation_id: request.operation_id,
				operation_state: "completed",
				verification: {
					checks: ["record_fingerprint_matches"],
					evidence_digest: "6".repeat(64),
					method: "fresh_odoo_readback",
					passed: true,
					verified_at: "2026-07-30T01:01:00Z",
				},
			},
			ok: true,
		};
	}
	if (action === "operation.preview") {
		return {
			command: action,
			data: {
				approval_challenge: {
					capability_id: "acct.bill.vendor_create.v1",
					operation_id: request.operation_id,
				},
				capability_id: "acct.bill.vendor_create.v1",
				operation_id: request.operation_id,
				operation_state: "awaiting_approval",
				precheck_identity: {
					operation_id: request.operation_id,
				},
			},
			ok: true,
		};
	}
	if (action === "operation.diagnostics") {
		return {
			command: action,
			data: diagnosticsData(
				request.operation_id,
				request.company_id,
			),
			ok: true,
		};
	}
	return {
		command: action,
		data: { accepted: true },
		ok: true,
	};
}

function createHarness({
	beforeResponse = async () => {},
	executedRegistryDigest = REGISTRY_DIGEST,
	executedReleaseDigest = RELEASE_DIGEST,
	responseFactory = responseFor,
	writeFrame,
} = {}) {
	const frames = [];
	const client = createFinalEvidenceBrokerClient({
		brokerSocketPath: BROKER_SOCKET,
		expectedRegistryDigest: REGISTRY_DIGEST,
		expectedReleaseDigest: RELEASE_DIGEST,
		sessionHandleProvider: () => SESSION_HANDLE,
		transport: async (call) => {
			await beforeResponse(call);
			const request = JSON.parse(call.body);
			return {
				authorityVerified: true,
				body: JSON.stringify(responseFactory(call.action, request)),
				executedRegistryDigest,
				executedReleaseDigest,
				statusCode: 200,
			};
		},
		writeFrame: writeFrame ?? (async (frame) => {
			frames.push(Buffer.from(frame));
		}),
	});
	return {
		finalize: client.finalize,
		frames,
		run: client.run,
		stream: () => Buffer.concat(frames),
	};
}

function verifiedAnswer(event) {
	return JSON.stringify({
		action: event.action,
		business_succeeded: true,
		capability_id: event.capability_id,
		operation_id: event.operation_id,
		receipt_id: event.receipt_id,
		result_digest: event.result_digest,
		status: "verified_success",
	});
}

const REFUSED_ANSWER = JSON.stringify({
	action: null,
	business_succeeded: false,
	capability_id: null,
	operation_id: null,
	receipt_id: null,
	result_digest: null,
	status: "refused",
});

const CLARIFICATION_ANSWER = JSON.stringify({
	action: null,
	business_succeeded: false,
	capability_id: null,
	operation_id: null,
	receipt_id: null,
	result_digest: null,
	status: "clarification_required",
});

function awaitingApprovalAnswer(operationId = "op-write-1") {
	return JSON.stringify({
		action: "operation.preview",
		business_succeeded: false,
		capability_id: "acct.bill.vendor_create.v1",
		operation_id: operationId,
		receipt_id: null,
		result_digest: null,
		status: "awaiting_approval",
	});
}

function verifiedDiagnosticAnswer(event) {
	return JSON.stringify({
		action: "operation.diagnostics",
		business_succeeded: false,
		capability_id: "acct.diagnostics.operation_read.v1",
		operation_id: event.operation_id,
		receipt_id: event.receipt_id,
		result_digest: event.result_digest,
		status: "verified_diagnostic",
	});
}

function expectCode(action, code) {
	assert.throws(
		action,
		(error) => error instanceof FinalEvidenceError && error.code === code,
	);
}

async function expectCodeAsync(action, code) {
	await assert.rejects(
		action,
		(error) => error instanceof FinalEvidenceError && error.code === code,
	);
}

function canonicalFrame(value) {
	return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function streamFromEvents(events, commitOverrides = {}) {
	const eventFrames = events.map(canonicalFrame);
	const commit = {
		event_count: events.length,
		event_type: FINAL_EVIDENCE_COMMIT_TYPE,
		stream_digest: createHash("sha256")
			.update(Buffer.concat(eventFrames))
			.digest("hex"),
		...commitOverrides,
	};
	return Buffer.concat([...eventFrames, canonicalFrame(commit)]);
}

test("read evidence is emitted only after the broker client validates it", async () => {
	const harness = createHarness();
	const request = {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	};
	const response = await harness.run("read", request);
	assert.equal(response.ok, true);
	assert.equal(harness.frames.length, 1);

	const summary = await harness.finalize();
	assert.equal(harness.frames.length, 2);
	const evidence = decodeFinalEvidenceStream(harness.stream());
	assert.deepEqual(evidence.events, [{
		action: "read",
		business_succeeded: true,
		capability_id: request.capability_id,
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: null,
		receipt_id: "read-receipt-1",
		result_digest: RESULT_DIGEST,
	}]);
	assert.deepEqual(summary, {
		event_count: 1,
		stream_digest: createHash("sha256")
			.update(harness.frames[0])
			.digest("hex"),
	});
	assert.deepEqual(evidence.commit, {
		event_count: 1,
		event_type: FINAL_EVIDENCE_COMMIT_TYPE,
		stream_digest: summary.stream_digest,
	});
	assert.ok(harness.frames.every((frame) => frame.at(-1) === 0x0a));
});

test("write evidence accepts only broker-validated operation.result success", async () => {
	const harness = createHarness();
	const response = await harness.run(
		"operation.result",
		{ operation_id: "op-write-1" },
	);
	assert.equal(response.ok, true);
	await harness.finalize();
	const evidence = decodeFinalEvidenceStream(harness.stream());
	assert.deepEqual(evidence.events, [{
		action: "operation.result",
		business_succeeded: true,
		capability_id: "acct.bill.vendor_create.v1",
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: "op-write-1",
		receipt_id: "write-receipt-1",
		result_digest: RESULT_DIGEST,
	}]);

	const approve = createHarness();
	assert.equal(
		(await approve.run(
			"operation.approve_execute",
			{ operation_id: "op-write-1" },
		)).ok,
		true,
	);
	await approve.finalize();
	assert.deepEqual(
		decodeFinalEvidenceStream(approve.stream()).events,
		[],
	);
});

test("preview evidence is bound to a broker-validated awaiting-approval operation", async () => {
	const harness = createHarness();
	const response = await harness.run(
		"operation.preview",
		{ operation_id: "op-write-1" },
	);
	assert.equal(response.ok, true);
	await harness.finalize();
	assert.deepEqual(
		decodeFinalEvidenceStream(harness.stream()).events,
		[{
			action: "operation.preview",
			business_succeeded: false,
			capability_id: "acct.bill.vendor_create.v1",
			event_type: FINAL_EVIDENCE_EVENT_TYPE,
			operation_id: "op-write-1",
			receipt_id: null,
			result_digest: null,
		}],
	);

	for (const mutate of [
		(responsePayload) => {
			responsePayload.data.operation_id = "op-other";
		},
		(responsePayload) => {
			responsePayload.data.operation_state = "prepared";
		},
		(responsePayload) => {
			responsePayload.data.approval_challenge.operation_id = "op-other";
		},
	]) {
		const rejected = createHarness({
			responseFactory: (action, request) => {
				const responsePayload = responseFor(action, request);
				mutate(responsePayload);
				return responsePayload;
			},
		});
		await expectCodeAsync(
			() => rejected.run(
				"operation.preview",
				{ operation_id: "op-write-1" },
			),
			"final_evidence_verified_result_rejected",
		);
		assert.equal(rejected.frames.length, 0);
	}
});

test("diagnostics emits a receipt bound to its requested operation and company", async () => {
	const harness = createHarness();
	const response = await harness.run(
		"operation.diagnostics",
		{ company_id: 7, operation_id: "op-write-1" },
	);
	assert.equal(response.ok, true);
	await harness.finalize();
	const evidence = decodeFinalEvidenceStream(harness.stream());
	assert.deepEqual(evidence.events, [{
		action: "operation.diagnostics",
		business_succeeded: false,
		capability_id: "acct.diagnostics.operation_read.v1",
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: "op-write-1",
		receipt_id: "diagnostics-receipt-1",
		result_digest: RESULT_DIGEST,
	}]);
	const answer = verifiedDiagnosticAnswer(evidence.events[0]);
	assert.deepEqual(
		validateFinalAnswer(answer, evidence),
		JSON.parse(answer),
	);
	expectCode(
		() => validateFinalAnswer(
			JSON.stringify({
				...JSON.parse(answer),
				business_succeeded: true,
				status: "verified_success",
			}),
			evidence,
		),
		"final_answer_rejected",
	);

	const mismatched = createHarness({
		responseFactory: (action, request) => {
			const payload = responseFor(action, request);
			payload.data.receipt.company_id = 8;
			return payload;
		},
	});
	const rejected = await mismatched.run(
		"operation.diagnostics",
		{ company_id: 7, operation_id: "op-write-1" },
	);
	assert.equal(rejected.ok, false);
	assert.equal(rejected.error.code, "bridge_invalid_v3_broker_response");
	assert.equal(mismatched.frames.length, 0);
});

test("forged or incomplete broker responses cannot emit evidence", async () => {
	const incompleteWrite = createHarness({
		responseFactory: (action, request) => ({
			business_succeeded: true,
			command: action,
			data: {
				audit_receipt: writeReceipt(request.operation_id),
				database_finalization: { remaining_unresolved_count: 0 },
				operation_id: request.operation_id,
				operation_state: "completed",
				verification: {
					evidence_digest: "6".repeat(64),
					passed: true,
				},
			},
			ok: true,
		}),
	});
	const result = await incompleteWrite.run(
		"operation.result",
		{ operation_id: "op-write-1" },
	);
	assert.equal(result.ok, false);
	assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
	assert.equal(incompleteWrite.frames.length, 0);
	await incompleteWrite.finalize();
	assert.deepEqual(
		decodeFinalEvidenceStream(incompleteWrite.stream()).events,
		[],
	);

	const wrongIdentity = createHarness({
		executedReleaseDigest: "8".repeat(64),
	});
	assert.equal(
		(await wrongIdentity.run("read", {
			capability_id: "acct.gl.trial_balance.v1",
			parameters: { company_id: 7 },
		})).ok,
		false,
	);
	assert.equal(wrongIdentity.frames.length, 0);
});

test("emitter rejects duplicate receipts and conflicting write terminal events", async () => {
	const duplicateRead = createHarness();
	const request = {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	};
	await duplicateRead.run("read", request);
	await expectCodeAsync(
		() => duplicateRead.run("read", request),
		"final_evidence_duplicate_receipt",
	);

	let callCount = 0;
	const conflictingWrite = createHarness({
		responseFactory: (action, operationRequest) => {
			const response = responseFor(action, operationRequest);
			callCount += 1;
			if (callCount === 2) {
				response.data.audit_receipt.receipt_id = "write-receipt-2";
				response.data.audit_receipt.result_digest = "e".repeat(64);
			}
			return response;
		},
	});
	await conflictingWrite.run(
		"operation.result",
		{ operation_id: "op-write-1" },
	);
	await expectCodeAsync(
		() => conflictingWrite.run(
			"operation.result",
			{ operation_id: "op-write-1" },
		),
		"final_evidence_duplicate_operation",
	);

	const duplicatePreview = createHarness();
	await duplicatePreview.run(
		"operation.preview",
		{ operation_id: "op-write-1" },
	);
	await expectCodeAsync(
		() => duplicatePreview.run(
			"operation.preview",
			{ operation_id: "op-write-1" },
		),
		"final_evidence_duplicate_preview",
	);
});

test("terminal commit cannot race an in-flight broker operation", async () => {
	let markEntered;
	let releaseResponse;
	const entered = new Promise((resolve) => { markEntered = resolve; });
	const released = new Promise((resolve) => { releaseResponse = resolve; });
	const harness = createHarness({
		beforeResponse: async () => {
			markEntered();
			await released;
		},
	});
	const pending = harness.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await entered;
	await expectCodeAsync(
		() => harness.finalize(),
		"final_evidence_operations_in_flight",
	);
	releaseResponse();
	assert.equal((await pending).ok, true);
	await harness.finalize();
	assert.equal(
		decodeFinalEvidenceStream(harness.stream()).events.length,
		1,
	);
});

test("awaited session_shutdown commits before closing the evidence channel", async () => {
	const harness = createHarness();
	await harness.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	const handlers = new Map();
	let closed = false;
	const pi = {
		on(eventName, handler) {
			handlers.set(eventName, handler);
		},
	};
	registerFinalEvidenceSessionShutdown(pi, {
		close: async () => {
			assert.equal(harness.frames.length, 2);
			closed = true;
		},
		finalize: harness.finalize,
	});
	const shutdown = handlers.get("session_shutdown");
	assert.equal(typeof shutdown, "function");
	const first = shutdown();
	const second = shutdown();
	assert.equal(first, second);
	await first;
	assert.equal(closed, true);
	assert.equal(
		decodeFinalEvidenceStream(harness.stream()).events.length,
		1,
	);
});

test("session_shutdown closes the evidence channel when commit fails", async () => {
	const handlers = new Map();
	let closeCount = 0;
	registerFinalEvidenceSessionShutdown({
		on(eventName, handler) {
			handlers.set(eventName, handler);
		},
	}, {
		close: async () => {
			closeCount += 1;
		},
		finalize: async () => {
			throw new Error("commit failed");
		},
	});
	await assert.rejects(
		handlers.get("session_shutdown")(),
		/commit failed/,
	);
	assert.equal(closeCount, 1);
});

test("parent evidence collection requires clean EOF and enforces its byte bound", async () => {
	const clean = new PassThrough();
	const cleanResult = collectFinalEvidenceStream(clean);
	clean.end(Buffer.from("committed\n"));
	assert.deepEqual(await cleanResult, Buffer.from("committed\n"));

	const truncated = new PassThrough();
	const truncatedResult = collectFinalEvidenceStream(truncated);
	truncated.write(Buffer.from("partial"));
	truncated.destroy();
	await expectCodeAsync(
		() => truncatedResult,
		"final_evidence_stream_truncated",
	);

	const oversized = new PassThrough();
	const oversizedResult = collectFinalEvidenceStream(oversized);
	oversized.end(Buffer.alloc(MAX_FINAL_EVIDENCE_BYTES + 1));
	await expectCodeAsync(
		() => oversizedResult,
		"final_evidence_stream_too_large",
	);
});

test("Pi print framing removes only its one host-owned LF", () => {
	const canonical = Buffer.from(`${CLARIFICATION_ANSWER}\n`, "utf8");
	assert.equal(
		decodePiPrintFinalAnswer(canonical),
		CLARIFICATION_ANSWER,
	);
	for (const [payload, code] of [
		[Buffer.from(CLARIFICATION_ANSWER), "final_answer_framing_rejected"],
		[Buffer.from(`${CLARIFICATION_ANSWER}\n\n`), "final_answer_framing_rejected"],
		[Buffer.from(`${CLARIFICATION_ANSWER}\r\n`), "final_answer_framing_rejected"],
		[Buffer.from([0xff, 0x0a]), "final_answer_utf8_rejected"],
		[Buffer.alloc(MAX_PI_PRINT_STDOUT_BYTES + 1), "final_answer_too_large"],
	]) {
		expectCode(
			() => decodePiPrintFinalAnswer(payload),
			code,
		);
	}
});

test("mandatory terminal commit detects missing, duplicate, tail, and prefix truncation", async () => {
	const harness = createHarness();
	await harness.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await harness.finalize();
	const [eventFrame, commitFrame] = harness.frames;

	expectCode(
		() => decodeFinalEvidenceStream(
			harness.stream().subarray(0, -1),
		),
		"final_evidence_stream_truncated",
	);
	expectCode(
		() => decodeFinalEvidenceStream(eventFrame),
		"final_evidence_commit_missing",
	);
	expectCode(
		() => decodeFinalEvidenceStream(commitFrame),
		"final_evidence_commit_count_mismatch",
	);
	expectCode(
		() => decodeFinalEvidenceStream(
			Buffer.concat([eventFrame, commitFrame, commitFrame]),
		),
		"final_evidence_commit_duplicate",
	);
	expectCode(
		() => decodeFinalEvidenceStream(
			Buffer.concat([eventFrame, commitFrame, eventFrame]),
		),
		"final_evidence_commit_not_terminal",
	);
});

test("decoder rejects noncanonical, extra, tampered, and conflicting frames", async () => {
	const harness = createHarness();
	await harness.run("operation.result", { operation_id: "op-write-1" });
	await harness.finalize();
	const valid = decodeFinalEvidenceStream(harness.stream());
	const event = valid.events[0];

	const reordered = {
		event_type: event.event_type,
		action: event.action,
		business_succeeded: event.business_succeeded,
		capability_id: event.capability_id,
		operation_id: event.operation_id,
		receipt_id: event.receipt_id,
		result_digest: event.result_digest,
	};
	expectCode(
		() => decodeFinalEvidenceStream(streamFromEvents([reordered])),
		"final_evidence_json_noncanonical",
	);
	const extraEvent = {
		action: event.action,
		business_succeeded: event.business_succeeded,
		capability_id: event.capability_id,
		event_type: event.event_type,
		extra: true,
		operation_id: event.operation_id,
		receipt_id: event.receipt_id,
		result_digest: event.result_digest,
	};
	expectCode(
		() => decodeFinalEvidenceStream(
			streamFromEvents([extraEvent]),
		),
		"final_evidence_event_rejected",
	);
	expectCode(
		() => decodeFinalEvidenceStream(
			streamFromEvents([event], { event_count: 2 }),
		),
		"final_evidence_commit_count_mismatch",
	);
	expectCode(
		() => decodeFinalEvidenceStream(
			streamFromEvents([event], { stream_digest: "f".repeat(64) }),
		),
		"final_evidence_commit_digest_mismatch",
	);

	const duplicateReceipt = {
		...event,
		operation_id: "op-write-2",
	};
	expectCode(
		() => decodeFinalEvidenceStream(
			streamFromEvents([event, duplicateReceipt]),
		),
		"final_evidence_duplicate_receipt",
	);
	const duplicateOperation = {
		...event,
		receipt_id: "write-receipt-2",
		result_digest: "e".repeat(64),
	};
	expectCode(
		() => decodeFinalEvidenceStream(
			streamFromEvents([event, duplicateOperation]),
		),
		"final_evidence_duplicate_operation",
	);
});

test("decoder enforces UTF-8, total bytes, count, and newline-inclusive frame size", async () => {
	expectCode(
		() => decodeFinalEvidenceStream(Buffer.from([0xff, 0x0a])),
		"final_evidence_utf8_rejected",
	);
	expectCode(
		() => decodeFinalEvidenceStream(
			Buffer.alloc(MAX_FINAL_EVIDENCE_BYTES + 1, 0x20),
		),
		"final_evidence_stream_too_large",
	);

	const readHarness = createHarness();
	await readHarness.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await readHarness.finalize();
	const baseEvent = decodeFinalEvidenceStream(
		readHarness.stream(),
	).events[0];
	const many = Array.from(
		{ length: MAX_FINAL_EVIDENCE_EVENTS + 1 },
		(_, index) => ({
			...baseEvent,
			receipt_id: `read-receipt-${index}`,
			result_digest: index.toString(16).padStart(64, "0"),
		}),
	);
	expectCode(
		() => decodeFinalEvidenceStream(streamFromEvents(many)),
		"final_evidence_event_count_exceeded",
	);

	let segmentLength = 1;
	let boundaryEvent;
	for (;;) {
		boundaryEvent = {
			...baseEvent,
			capability_id: `acct.${"a".repeat(segmentLength)}.read.v1`,
		};
		const lineBytes = Buffer.byteLength(JSON.stringify(boundaryEvent), "utf8");
		if (lineBytes >= 4096) {
			assert.equal(lineBytes, 4096);
			break;
		}
		segmentLength += 1;
	}
	expectCode(
		() => decodeFinalEvidenceStream(streamFromEvents([boundaryEvent])),
		"final_evidence_event_too_large",
	);
});

test("verified_success canonically matches exactly one committed FD4 event", async () => {
	for (const [action, request] of [
		["read", {
			capability_id: "acct.gl.trial_balance.v1",
			parameters: { company_id: 7 },
		}],
		["operation.result", { operation_id: "op-write-1" }],
	]) {
		const harness = createHarness();
		await harness.run(action, request);
		await harness.finalize();
		const evidence = decodeFinalEvidenceStream(harness.stream());
		const answer = verifiedAnswer(evidence.events[0]);
		assert.deepEqual(
			validateFinalAnswer(answer, evidence),
			JSON.parse(answer),
		);
		expectCode(
			() => validateFinalAnswer(
				answer.replace(RESULT_DIGEST, "e".repeat(64)),
				evidence,
			),
			"final_answer_evidence_mismatch",
		);

		const empty = createHarness();
		await empty.finalize();
		expectCode(
			() => validateFinalAnswer(
				answer,
				decodeFinalEvidenceStream(empty.stream()),
			),
			"final_answer_evidence_mismatch",
		);
		expectCode(
			() => validateFinalAnswer(answer, {
				commit: evidence.commit,
				events: evidence.events,
			}),
			"final_answer_evidence_untrusted",
		);
	}
});

test("registry discovery evidence cannot satisfy verified business success", () => {
	const evidence = decodeFinalEvidenceStream(streamFromEvents([{
		action: "read",
		business_succeeded: true,
		capability_id: "acct.registry.list.v1",
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: null,
		receipt_id: "registry-receipt-1",
		result_digest: "9".repeat(64),
	}]));
	expectCode(
		() => validateFinalAnswer(
			verifiedAnswer(evidence.events[0]),
			evidence,
		),
		"final_answer_rejected",
	);
});

test("awaiting_approval requires exactly one matching committed preview", async () => {
	const harness = createHarness();
	await harness.run(
		"operation.preview",
		{ operation_id: "op-write-1" },
	);
	await harness.finalize();
	const evidence = decodeFinalEvidenceStream(harness.stream());
	const answer = awaitingApprovalAnswer();
	assert.deepEqual(
		validateFinalAnswer(answer, evidence),
		JSON.parse(answer),
	);
	expectCode(
		() => validateFinalAnswer(
			awaitingApprovalAnswer("op-other"),
			evidence,
		),
		"final_answer_approval_evidence_mismatch",
	);

	const empty = createHarness();
	await empty.finalize();
	expectCode(
		() => validateFinalAnswer(
			answer,
			decodeFinalEvidenceStream(empty.stream()),
		),
		"final_answer_approval_evidence_mismatch",
	);

	const withResult = createHarness();
	await withResult.run(
		"operation.preview",
		{ operation_id: "op-write-1" },
	);
	await withResult.run(
		"operation.result",
		{ operation_id: "op-write-1" },
	);
	await withResult.finalize();
	expectCode(
		() => validateFinalAnswer(
			answer,
			decodeFinalEvidenceStream(withResult.stream()),
		),
		"final_answer_approval_evidence_mismatch",
	);
});

test("clarification_required is false/null-only and permits only registry support", async () => {
	const empty = createHarness();
	await empty.finalize();
	const evidence = decodeFinalEvidenceStream(empty.stream());
	assert.deepEqual(
		validateFinalAnswer(CLARIFICATION_ANSWER, evidence),
		JSON.parse(CLARIFICATION_ANSWER),
	);
	for (const changed of [
		{ action: "read" },
		{ business_succeeded: true },
		{ capability_id: "acct.gl.trial_balance.v1" },
		{ operation_id: "op-write-1" },
		{ receipt_id: "receipt-1" },
		{ result_digest: RESULT_DIGEST },
	]) {
		expectCode(
			() => validateFinalAnswer(
				JSON.stringify({
					...JSON.parse(CLARIFICATION_ANSWER),
					...changed,
				}),
				evidence,
			),
			"final_answer_rejected",
		);
	}

	const read = createHarness();
	await read.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await read.finalize();
	expectCode(
		() => validateFinalAnswer(
			CLARIFICATION_ANSWER,
			decodeFinalEvidenceStream(read.stream()),
		),
		"final_answer_clarification_conflicts_with_evidence",
	);

	const registryEvidence = decodeFinalEvidenceStream(streamFromEvents([{
		action: "read",
		business_succeeded: true,
		capability_id: "acct.registry.list.v1",
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: null,
		receipt_id: "registry-receipt-1",
		result_digest: "9".repeat(64),
	}]));
	assert.deepEqual(
		validateFinalAnswer(CLARIFICATION_ANSWER, registryEvidence),
		JSON.parse(CLARIFICATION_ANSWER),
	);
	assert.deepEqual(
		validateFinalAnswer(REFUSED_ANSWER, registryEvidence),
		JSON.parse(REFUSED_ANSWER),
	);
});

test("final stdout rejects noncanonical, extra, oversized, and unsupported forms", async () => {
	const harness = createHarness();
	await harness.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await harness.finalize();
	const evidence = decodeFinalEvidenceStream(harness.stream());
	const answer = JSON.parse(verifiedAnswer(evidence.events[0]));

	expectCode(
		() => validateFinalAnswer(` ${JSON.stringify(answer)}`, evidence),
		"final_answer_json_noncanonical",
	);
	expectCode(
		() => validateFinalAnswer(JSON.stringify({
			status: answer.status,
			action: answer.action,
			business_succeeded: answer.business_succeeded,
			capability_id: answer.capability_id,
			operation_id: answer.operation_id,
			receipt_id: answer.receipt_id,
			result_digest: answer.result_digest,
		}), evidence),
		"final_answer_json_noncanonical",
	);
	expectCode(
		() => validateFinalAnswer(
			JSON.stringify({ ...answer, extra: true }),
			evidence,
		),
		"final_answer_rejected",
	);
	expectCode(
		() => validateFinalAnswer(
			"x".repeat(MAX_FINAL_ANSWER_BYTES + 1),
			evidence,
		),
		"final_answer_too_large",
	);
	const unsupported = JSON.stringify({
		action: null,
		business_succeeded: false,
		capability_id: null,
		operation_id: null,
		receipt_id: null,
		result_digest: null,
		status: "needs_approval",
	});
	expectCode(
		() => validateFinalAnswer(unsupported, evidence),
		"final_answer_status_unsupported",
	);
});

test("refused accepts only false plus five nulls and a committed empty stream", async () => {
	const empty = createHarness();
	await empty.finalize();
	const emptyEvidence = decodeFinalEvidenceStream(empty.stream());
	assert.deepEqual(
		validateFinalAnswer(REFUSED_ANSWER, emptyEvidence),
		JSON.parse(REFUSED_ANSWER),
	);

	const successful = createHarness();
	await successful.run("read", {
		capability_id: "acct.gl.trial_balance.v1",
		parameters: { company_id: 7 },
	});
	await successful.finalize();
	expectCode(
		() => validateFinalAnswer(
			REFUSED_ANSWER,
			decodeFinalEvidenceStream(successful.stream()),
		),
		"final_answer_refusal_conflicts_with_evidence",
	);
	for (const changed of [
		{ action: "read" },
		{ business_succeeded: true },
		{ capability_id: "acct.gl.trial_balance.v1" },
		{ operation_id: "op-write-1" },
		{ receipt_id: "receipt-1" },
		{ result_digest: RESULT_DIGEST },
	]) {
		expectCode(
			() => validateFinalAnswer(
				JSON.stringify({ ...JSON.parse(REFUSED_ANSWER), ...changed }),
				emptyEvidence,
			),
			"final_answer_rejected",
		);
	}
});
