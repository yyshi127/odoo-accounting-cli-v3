import { createHash } from "node:crypto";

import { createV3BrokerClient } from "./extensions/odoo-v3-cli.mjs";

export const FINAL_EVIDENCE_EVENT_TYPE = "odoo_v3_final_evidence_v1";
export const FINAL_EVIDENCE_COMMIT_TYPE = "odoo_v3_final_evidence_commit_v1";
export const MAX_FINAL_EVIDENCE_BYTES = 64 * 1024;
export const MAX_FINAL_EVIDENCE_EVENTS = 32;
export const MAX_FINAL_ANSWER_BYTES = 2048;
export const MAX_PI_PRINT_STDOUT_BYTES = MAX_FINAL_ANSWER_BYTES + 1;

const MAX_FINAL_EVIDENCE_FRAME_BYTES = 4096;
const SHA256 = /^[0-9a-f]{64}$/;
const CAPABILITY_ID = /^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$/;
const DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1";
const REGISTRY_LIST_CAPABILITY_ID = "acct.registry.list.v1";
const BROKER_CLIENT_OPTION_KEYS = Object.freeze([
	"brokerSocketPath",
	"expectedRegistryDigest",
	"expectedReleaseDigest",
	"maxOutputBytes",
	"sessionHandleProvider",
	"timeoutMs",
	"transport",
	"writeFrame",
]);
const FINAL_EVENT_KEYS = Object.freeze([
	"action",
	"business_succeeded",
	"capability_id",
	"event_type",
	"operation_id",
	"receipt_id",
	"result_digest",
]);
const FINAL_COMMIT_KEYS = Object.freeze([
	"event_count",
	"event_type",
	"stream_digest",
]);
const FINAL_ANSWER_KEYS = Object.freeze([
	"action",
	"business_succeeded",
	"capability_id",
	"operation_id",
	"receipt_id",
	"result_digest",
	"status",
]);

const trustedEvidenceStreams = new WeakSet();

export class FinalEvidenceError extends Error {
	constructor(code, message = code) {
		super(message);
		this.name = "FinalEvidenceError";
		this.code = code;
	}
}

function reject(code) {
	throw new FinalEvidenceError(code);
}

function isObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
	if (!isObject(value)) return false;
	const ownKeys = Reflect.ownKeys(value);
	return ownKeys.every((key) => typeof key === "string")
		&& JSON.stringify([...ownKeys].sort()) === JSON.stringify(keys);
}

function hasOnlyKeys(value, keys) {
	return isObject(value)
		&& Reflect.ownKeys(value).every(
			(key) => typeof key === "string" && keys.includes(key),
		);
}

function nonEmptyString(value, maximum = 512) {
	return typeof value === "string"
		&& value.length > 0
		&& value.length <= maximum
		&& value === value.trim()
		&& !/[\u0000-\u001f\u007f]/.test(value);
}

function canonicalJson(value) {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value) || Object.is(value, -0)) {
			reject("final_evidence_json_rejected");
		}
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	if (!isObject(value)) reject("final_evidence_json_rejected");
	const keys = Reflect.ownKeys(value);
	if (keys.some((key) => typeof key !== "string")) {
		reject("final_evidence_json_rejected");
	}
	keys.sort();
	return `{${keys.map(
		(key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
	).join(",")}}`;
}

function validFinalEvent(event) {
	if (
		!exactKeys(event, FINAL_EVENT_KEYS)
		|| event.event_type !== FINAL_EVIDENCE_EVENT_TYPE
		|| !CAPABILITY_ID.test(event.capability_id)
	) {
		return false;
	}
	if (event.action === "operation.preview") {
		return event.business_succeeded === false
			&& nonEmptyString(event.operation_id, 256)
			&& event.receipt_id === null
			&& event.result_digest === null;
	}
	if (event.action === "operation.diagnostics") {
		return event.business_succeeded === false
			&& event.capability_id === DIAGNOSTICS_CAPABILITY_ID
			&& nonEmptyString(event.operation_id, 256)
			&& nonEmptyString(event.receipt_id, 256)
			&& SHA256.test(event.result_digest);
	}
	return event.business_succeeded === true
		&& nonEmptyString(event.receipt_id, 256)
		&& SHA256.test(event.result_digest)
		&& (
			(event.action === "read" && event.operation_id === null)
			|| (
				event.action === "operation.result"
				&& nonEmptyString(event.operation_id, 256)
			)
		);
}

function validFinalCommit(commit) {
	return exactKeys(commit, FINAL_COMMIT_KEYS)
		&& commit.event_type === FINAL_EVIDENCE_COMMIT_TYPE
		&& Number.isSafeInteger(commit.event_count)
		&& commit.event_count >= 0
		&& commit.event_count <= MAX_FINAL_EVIDENCE_EVENTS
		&& SHA256.test(commit.stream_digest);
}

function frameFor(value) {
	const frame = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
	if (frame.length > MAX_FINAL_EVIDENCE_FRAME_BYTES) {
		reject("final_evidence_event_too_large");
	}
	return frame;
}

function eventFromVerifiedBrokerResult(action, request, response) {
	if (action === "read" && response?.ok === true && response.command === "read") {
		const capabilityId = request?.capability_id;
		const receipt = response.data?.result?.receipt;
		if (
			!CAPABILITY_ID.test(capabilityId)
			|| response.data?.capability_id !== capabilityId
			|| receipt?.capability_id !== capabilityId
			|| !nonEmptyString(receipt?.id, 256)
			|| !SHA256.test(receipt?.result_digest)
		) {
			reject("final_evidence_verified_result_rejected");
		}
		return {
			action: "read",
			business_succeeded: true,
			capability_id: capabilityId,
			event_type: FINAL_EVIDENCE_EVENT_TYPE,
			operation_id: null,
			receipt_id: receipt.id,
			result_digest: receipt.result_digest,
		};
	}
	if (
		action === "operation.diagnostics"
		&& response?.ok === true
		&& response.command === "operation.diagnostics"
	) {
		const operationId = request?.operation_id;
		const receipt = response.data?.receipt;
		if (
			!nonEmptyString(operationId, 256)
			|| response.data?.operation?.operation_id !== operationId
			|| receipt?.capability_id !== DIAGNOSTICS_CAPABILITY_ID
			|| receipt?.company_id !== request?.company_id
			|| !nonEmptyString(receipt?.id, 256)
			|| !SHA256.test(receipt?.result_digest)
		) {
			reject("final_evidence_verified_result_rejected");
		}
		return {
			action: "operation.diagnostics",
			business_succeeded: false,
			capability_id: DIAGNOSTICS_CAPABILITY_ID,
			event_type: FINAL_EVIDENCE_EVENT_TYPE,
			operation_id: operationId,
			receipt_id: receipt.id,
			result_digest: receipt.result_digest,
		};
	}
	if (
		action === "operation.preview"
		&& response?.ok === true
		&& response.command === "operation.preview"
	) {
		const operationId = request?.operation_id;
		const capabilityId = response.data?.capability_id;
		const challenge = response.data?.approval_challenge;
		const precheckIdentity = response.data?.precheck_identity;
		if (
			!nonEmptyString(operationId, 256)
			|| response.data?.operation_id !== operationId
			|| response.data?.operation_state !== "awaiting_approval"
			|| !CAPABILITY_ID.test(capabilityId)
			|| precheckIdentity?.operation_id !== operationId
			|| challenge?.operation_id !== operationId
			|| challenge?.capability_id !== capabilityId
		) {
			reject("final_evidence_verified_result_rejected");
		}
		return {
			action: "operation.preview",
			business_succeeded: false,
			capability_id: capabilityId,
			event_type: FINAL_EVIDENCE_EVENT_TYPE,
			operation_id: operationId,
			receipt_id: null,
			result_digest: null,
		};
	}
	if (
		action === "operation.result"
		&& response?.ok === true
		&& response.command === "operation.result"
		&& response.business_succeeded === true
	) {
		const operationId = request?.operation_id;
		const receipt = response.data?.audit_receipt;
		if (
			!nonEmptyString(operationId, 256)
			|| response.data?.operation_id !== operationId
			|| receipt?.operation_id !== operationId
			|| !CAPABILITY_ID.test(receipt?.capability_id)
			|| !nonEmptyString(receipt?.receipt_id, 256)
			|| !SHA256.test(receipt?.result_digest)
		) {
			reject("final_evidence_verified_result_rejected");
		}
		return {
			action: "operation.result",
			business_succeeded: true,
			capability_id: receipt.capability_id,
			event_type: FINAL_EVIDENCE_EVENT_TYPE,
			operation_id: operationId,
			receipt_id: receipt.receipt_id,
			result_digest: receipt.result_digest,
		};
	}
	return null;
}

function asFinalEvidenceError(error) {
	return error instanceof FinalEvidenceError
		? error
		: new FinalEvidenceError("final_evidence_write_failed");
}

export function createFinalEvidenceBrokerClient(options = {}) {
	if (
		!hasOnlyKeys(options, BROKER_CLIENT_OPTION_KEYS)
		|| typeof options.writeFrame !== "function"
	) {
		reject("final_evidence_configuration_rejected");
	}
	const broker = createV3BrokerClient({
		brokerSocketPath: options.brokerSocketPath,
		expectedRegistryDigest: options.expectedRegistryDigest,
		expectedReleaseDigest: options.expectedReleaseDigest,
		maxOutputBytes: options.maxOutputBytes,
		sessionHandleProvider: options.sessionHandleProvider,
		timeoutMs: options.timeoutMs,
		transport: options.transport,
	});
	const receiptIds = new Set();
	const operationResultIds = new Set();
	const previewOperationIds = new Set();
	const streamHash = createHash("sha256");
	let eventCount = 0;
	let eventBytes = 0;
	let closing = false;
	let failure = null;
	let queue = Promise.resolve();
	let activeRuns = 0;

	const enqueue = (task) => {
		const scheduled = queue.then(async () => {
			if (failure) throw failure;
			try {
				return await task();
			} catch (error) {
				failure = asFinalEvidenceError(error);
				throw failure;
			}
		});
		queue = scheduled.catch(() => undefined);
		return scheduled;
	};

	const write = async (frame) => {
		try {
			await options.writeFrame(Buffer.from(frame));
		} catch {
			reject("final_evidence_write_failed");
		}
	};

	const emit = async (event) => {
		if (closing) reject("final_evidence_already_finalized");
		return await enqueue(async () => {
			if (
				event.receipt_id !== null
				&& receiptIds.has(event.receipt_id)
			) {
				reject("final_evidence_duplicate_receipt");
			}
			if (
				event.action === "operation.result"
				&& operationResultIds.has(event.operation_id)
			) {
				reject("final_evidence_duplicate_operation");
			}
			if (
				event.action === "operation.preview"
				&& previewOperationIds.has(event.operation_id)
			) {
				reject("final_evidence_duplicate_preview");
			}
			if (eventCount >= MAX_FINAL_EVIDENCE_EVENTS) {
				reject("final_evidence_event_count_exceeded");
			}
			const frame = frameFor(event);
			const nextCount = eventCount + 1;
			const reservedCommit = frameFor({
				event_count: nextCount,
				event_type: FINAL_EVIDENCE_COMMIT_TYPE,
				stream_digest: "0".repeat(64),
			});
			if (
				eventBytes + frame.length + reservedCommit.length
				> MAX_FINAL_EVIDENCE_BYTES
			) {
				reject("final_evidence_stream_too_large");
			}
			await write(frame);
			if (event.receipt_id !== null) {
				receiptIds.add(event.receipt_id);
			}
			if (event.action === "operation.result") {
				operationResultIds.add(event.operation_id);
			}
			if (event.action === "operation.preview") {
				previewOperationIds.add(event.operation_id);
			}
			streamHash.update(frame);
			eventBytes += frame.length;
			eventCount = nextCount;
		});
	};

	const run = async (action, request) => {
		if (closing) reject("final_evidence_already_finalized");
		if (failure) throw failure;
		activeRuns += 1;
		try {
			const response = await broker(action, request);
			const event = eventFromVerifiedBrokerResult(action, request, response);
			if (event) await emit(event);
			return response;
		} finally {
			activeRuns -= 1;
		}
	};

	const finalize = async () => {
		if (closing) reject("final_evidence_already_finalized");
		if (activeRuns !== 0) reject("final_evidence_operations_in_flight");
		closing = true;
		return await enqueue(async () => {
			const streamDigest = streamHash.digest("hex");
			const commit = {
				event_count: eventCount,
				event_type: FINAL_EVIDENCE_COMMIT_TYPE,
				stream_digest: streamDigest,
			};
			const frame = frameFor(commit);
			if (eventBytes + frame.length > MAX_FINAL_EVIDENCE_BYTES) {
				reject("final_evidence_stream_too_large");
			}
			await write(frame);
			return Object.freeze({
				event_count: eventCount,
				stream_digest: streamDigest,
			});
		});
	};

	return Object.freeze({ finalize, run });
}

export function registerFinalEvidenceSessionShutdown(
	pi,
	{ close, finalize },
) {
	if (
		!isObject(pi)
		|| typeof pi.on !== "function"
		|| typeof close !== "function"
		|| typeof finalize !== "function"
	) {
		reject("final_evidence_configuration_rejected");
	}
	let shutdownPromise = null;
	pi.on("session_shutdown", () => {
		if (shutdownPromise === null) {
			shutdownPromise = (async () => {
				try {
					await finalize();
				} finally {
					await close();
				}
			})();
		}
		return shutdownPromise;
	});
}

export function collectFinalEvidenceStream(stream) {
	if (
		stream === null
		|| typeof stream !== "object"
		|| typeof stream.on !== "function"
	) {
		reject("final_evidence_configuration_rejected");
	}
	return new Promise((resolve, rejectPromise) => {
		const chunks = [];
		let byteCount = 0;
		let ended = false;
		let settled = false;
		const fail = (code) => {
			if (settled) return;
			settled = true;
			rejectPromise(new FinalEvidenceError(code));
		};
		stream.on("data", (chunk) => {
			if (settled) return;
			const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			byteCount += bytes.length;
			if (byteCount > MAX_FINAL_EVIDENCE_BYTES) {
				fail("final_evidence_stream_too_large");
				stream.destroy?.();
				return;
			}
			chunks.push(Buffer.from(bytes));
		});
		stream.once("end", () => {
			ended = true;
			if (settled) return;
			settled = true;
			resolve(Buffer.concat(chunks, byteCount));
		});
		stream.once("error", () => {
			fail("final_evidence_stream_read_failed");
		});
		stream.once("aborted", () => {
			fail("final_evidence_stream_truncated");
		});
		stream.once("close", () => {
			if (!ended) fail("final_evidence_stream_truncated");
		});
	});
}

// Pi 0.80.6 print mode writes exactly one host-owned LF after each assistant
// text block. Removing only that framing byte preserves strict canonical JSON.
export function decodePiPrintFinalAnswer(buffer) {
	if (!Buffer.isBuffer(buffer)) reject("final_answer_rejected");
	if (buffer.length > MAX_PI_PRINT_STDOUT_BYTES) {
		reject("final_answer_too_large");
	}
	if (buffer.length < 2 || buffer.at(-1) !== 0x0a) {
		reject("final_answer_framing_rejected");
	}
	const answerBytes = buffer.subarray(0, -1);
	let answer;
	try {
		answer = new TextDecoder("utf-8", { fatal: true }).decode(answerBytes);
	} catch {
		reject("final_answer_utf8_rejected");
	}
	if (
		answer.length === 0
		|| answer.endsWith("\n")
		|| answer.endsWith("\r")
	) {
		reject("final_answer_framing_rejected");
	}
	return answer;
}

function parseCanonicalLine(line) {
	if (line.length === 0) reject("final_evidence_json_rejected");
	if (Buffer.byteLength(line, "utf8") + 1 > MAX_FINAL_EVIDENCE_FRAME_BYTES) {
		reject("final_evidence_event_too_large");
	}
	let value;
	try {
		value = JSON.parse(line);
	} catch {
		reject("final_evidence_json_rejected");
	}
	if (canonicalJson(value) !== line) {
		reject("final_evidence_json_noncanonical");
	}
	return value;
}

// Callers must pass bytes captured exclusively from the dedicated child FD4.
// The OS pipe and release/runtime-manifest-owned emitter are the trust boundary.
export function decodeFinalEvidenceStream(buffer) {
	if (!Buffer.isBuffer(buffer)) reject("final_evidence_stream_rejected");
	if (buffer.length > MAX_FINAL_EVIDENCE_BYTES) {
		reject("final_evidence_stream_too_large");
	}
	if (buffer.length === 0) reject("final_evidence_commit_missing");
	let text;
	try {
		text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
	} catch {
		reject("final_evidence_utf8_rejected");
	}
	if (!text.endsWith("\n")) reject("final_evidence_stream_truncated");
	const lines = text.slice(0, -1).split("\n");
	if (lines.length > MAX_FINAL_EVIDENCE_EVENTS + 1) {
		reject("final_evidence_event_count_exceeded");
	}
	const values = lines.map(parseCanonicalLine);
	const commitIndexes = [];
	for (let index = 0; index < values.length; index += 1) {
		if (values[index]?.event_type === FINAL_EVIDENCE_COMMIT_TYPE) {
			commitIndexes.push(index);
		}
	}
	if (commitIndexes.length === 0) reject("final_evidence_commit_missing");
	if (commitIndexes.length > 1) reject("final_evidence_commit_duplicate");
	if (commitIndexes[0] !== values.length - 1) {
		reject("final_evidence_commit_not_terminal");
	}
	const commit = values.at(-1);
	if (!validFinalCommit(commit)) reject("final_evidence_commit_rejected");
	const events = values.slice(0, -1);
	if (events.length !== commit.event_count) {
		reject("final_evidence_commit_count_mismatch");
	}
	const receiptIds = new Set();
	const operationResultIds = new Set();
	const previewOperationIds = new Set();
	for (const event of events) {
		if (!validFinalEvent(event)) reject("final_evidence_event_rejected");
		if (
			event.receipt_id !== null
			&& receiptIds.has(event.receipt_id)
		) {
			reject("final_evidence_duplicate_receipt");
		}
		if (event.receipt_id !== null) {
			receiptIds.add(event.receipt_id);
		}
		if (event.action === "operation.result") {
			if (operationResultIds.has(event.operation_id)) {
				reject("final_evidence_duplicate_operation");
			}
			operationResultIds.add(event.operation_id);
		}
		if (event.action === "operation.preview") {
			if (previewOperationIds.has(event.operation_id)) {
				reject("final_evidence_duplicate_preview");
			}
			previewOperationIds.add(event.operation_id);
		}
	}
	const eventFrames = lines
		.slice(0, -1)
		.map((line) => Buffer.from(`${line}\n`, "utf8"));
	const streamDigest = createHash("sha256")
		.update(Buffer.concat(eventFrames))
		.digest("hex");
	if (streamDigest !== commit.stream_digest) {
		reject("final_evidence_commit_digest_mismatch");
	}
	const frozenEvents = Object.freeze(
		events.map((event) => Object.freeze(event)),
	);
	const evidence = Object.freeze({
		commit: Object.freeze(commit),
		events: frozenEvents,
	});
	trustedEvidenceStreams.add(evidence);
	return evidence;
}

function parseFinalAnswer(stdout) {
	if (
		typeof stdout !== "string"
		|| Buffer.byteLength(stdout, "utf8") > MAX_FINAL_ANSWER_BYTES
	) {
		reject(
			typeof stdout === "string"
				? "final_answer_too_large"
				: "final_answer_rejected",
		);
	}
	let answer;
	try {
		answer = JSON.parse(stdout);
	} catch {
		reject("final_answer_json_rejected");
	}
	if (!exactKeys(answer, FINAL_ANSWER_KEYS)) {
		reject("final_answer_rejected");
	}
	if (canonicalJson(answer) !== stdout) {
		reject("final_answer_json_noncanonical");
	}
	if (![
		"awaiting_approval",
		"clarification_required",
		"refused",
		"verified_diagnostic",
		"verified_success",
	].includes(answer.status)) {
		reject("final_answer_status_unsupported");
	}
	return answer;
}

export function validateFinalAnswer(stdout, evidence) {
	const answer = parseFinalAnswer(stdout);
	if (!trustedEvidenceStreams.has(evidence)) {
		reject("final_answer_evidence_untrusted");
	}
	if (answer.status === "verified_success") {
		if (
			answer.business_succeeded !== true
			|| !["read", "operation.result"].includes(answer.action)
			|| !CAPABILITY_ID.test(answer.capability_id)
			|| answer.capability_id === REGISTRY_LIST_CAPABILITY_ID
			|| !(
				(answer.action === "read" && answer.operation_id === null)
				|| (
					answer.action === "operation.result"
					&& nonEmptyString(answer.operation_id, 256)
				)
			)
			|| !nonEmptyString(answer.receipt_id, 256)
			|| !SHA256.test(answer.result_digest)
		) {
			reject("final_answer_rejected");
		}
		const matches = evidence.events.filter(
			(event) => (
				event.action === answer.action
				&& event.business_succeeded === answer.business_succeeded
				&& event.capability_id === answer.capability_id
				&& event.operation_id === answer.operation_id
				&& event.receipt_id === answer.receipt_id
				&& event.result_digest === answer.result_digest
			),
		);
		if (matches.length !== 1) {
			reject("final_answer_evidence_mismatch");
		}
	} else if (answer.status === "verified_diagnostic") {
		if (
			answer.action !== "operation.diagnostics"
			|| answer.business_succeeded !== false
			|| answer.capability_id !== DIAGNOSTICS_CAPABILITY_ID
			|| !nonEmptyString(answer.operation_id, 256)
			|| !nonEmptyString(answer.receipt_id, 256)
			|| !SHA256.test(answer.result_digest)
		) {
			reject("final_answer_rejected");
		}
		const matches = evidence.events.filter(
			(event) => (
				event.action === answer.action
				&& event.business_succeeded === answer.business_succeeded
				&& event.capability_id === answer.capability_id
				&& event.operation_id === answer.operation_id
				&& event.receipt_id === answer.receipt_id
				&& event.result_digest === answer.result_digest
			),
		);
		if (matches.length !== 1) {
			reject("final_answer_diagnostic_evidence_mismatch");
		}
	} else if (answer.status === "awaiting_approval") {
		if (
			answer.action !== "operation.preview"
			|| answer.business_succeeded !== false
			|| !CAPABILITY_ID.test(answer.capability_id)
			|| !nonEmptyString(answer.operation_id, 256)
			|| answer.receipt_id !== null
			|| answer.result_digest !== null
		) {
			reject("final_answer_rejected");
		}
		const previews = evidence.events.filter(
			(event) => event.action === "operation.preview",
		);
		if (
			previews.length !== 1
			|| previews[0].capability_id !== answer.capability_id
			|| previews[0].operation_id !== answer.operation_id
			|| evidence.events.some(
				(event) => event.action === "operation.result",
			)
		) {
			reject("final_answer_approval_evidence_mismatch");
		}
	} else {
		if (
			answer.action !== null
			|| answer.business_succeeded !== false
			|| answer.capability_id !== null
			|| answer.operation_id !== null
			|| answer.receipt_id !== null
			|| answer.result_digest !== null
		) {
			reject("final_answer_rejected");
		}
		const hasNonSupportingEvidence = evidence.events.some(
			(event) => !(
				event.action === "read"
				&& event.capability_id === REGISTRY_LIST_CAPABILITY_ID
				&& event.operation_id === null
			),
		);
		if (hasNonSupportingEvidence) {
			reject(
				answer.status === "refused"
					? "final_answer_refusal_conflicts_with_evidence"
					: "final_answer_clarification_conflicts_with_evidence",
			);
		}
	}
	return Object.freeze(answer);
}

export function validateFinalEvidenceChildResult({
	evidenceBuffer,
	exitCode,
	stdoutBuffer,
}) {
	if (exitCode !== 0) reject("final_evidence_child_exit_rejected");
	const evidence = decodeFinalEvidenceStream(evidenceBuffer);
	const answer = decodePiPrintFinalAnswer(stdoutBuffer);
	validateFinalAnswer(answer, evidence);
	return answer;
}
