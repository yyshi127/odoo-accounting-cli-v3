import { createHash } from "node:crypto";

import { createV3BrokerClient } from "./extensions/odoo-v3-cli.mjs";
import { validBrokerSessionHandle } from "./trusted-session.mjs";

export const MAX_DELIVERED_BUSINESS_RESULT_BYTES = 256 * 1024;
export const MAX_DELIVERED_AUDIT_RECEIPT_BYTES = 64 * 1024;
export const MAX_DELIVERED_FINAL_ANSWER_BYTES = 384 * 1024;
const MAX_DELIVERED_BROKER_RESPONSE_BYTES = 512 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const CAPABILITY_ID = /^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$/;
const DATABASE_UUID =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UTC_TIMESTAMP =
	/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/;
const LOCATOR_KEYS = Object.freeze([
	"action",
	"business_succeeded",
	"capability_id",
	"operation_id",
	"receipt_id",
	"result_digest",
	"status",
]);
const FINAL_ANSWER_KEYS = Object.freeze([
	"action",
	"audit_receipt",
	"business_result",
	"business_succeeded",
	"capability_id",
	"operation_id",
	"receipt_id",
	"result_digest",
	"status",
]);
const DELIVERY_DATA_KEYS = Object.freeze([
	"audit_receipt",
	"business_result",
	"current_identity",
	"executed_identity",
	"locator",
	"session_binding",
]);
const IDENTITY_KEYS = Object.freeze(["registry_digest", "release_digest"]);
const SESSION_BINDING_KEYS = Object.freeze([
	"company_id",
	"database_name",
	"database_uuid",
	"environment",
	"odoo_instance_id",
	"principal",
	"user_id",
]);
const READ_RECEIPT_KEYS = Object.freeze([
	"capability_channel",
	"capability_id",
	"company_id",
	"database_name",
	"database_uuid",
	"environment",
	"id",
	"observed_at",
	"odoo_instance_id",
	"record_count",
	"registry_digest",
	"release_digest",
	"request_digest",
	"result_digest",
	"signature",
	"signature_key_id",
	"signature_purpose",
	"signature_version",
	"user_id",
]);
const WRITE_RECEIPT_KEYS = Object.freeze([
	"approval_digest",
	"approver_user_id",
	"audit_head",
	"capability_channel",
	"capability_id",
	"company_id",
	"database_name",
	"database_uuid",
	"environment",
	"issued_at",
	"odoo_instance_id",
	"operation_digest",
	"operation_id",
	"principal",
	"receipt_id",
	"registry_digest",
	"release_digest",
	"request_digest",
	"request_id",
	"result_digest",
	"signature",
	"signature_purpose",
	"signature_version",
	"signing_key_id",
	"user_id",
	"verification_evidence_digest",
]);
const SENSITIVE_AUTHORITY_FIELDS = new Set([
	"approval_nonce",
	"auth_token",
	"auth_token_id",
	"broker_session_handle",
	"private_key",
	"result_delivery_session_handle",
	"secret",
	"session_handle",
]);

export class FinalResultDeliveryError extends Error {
	constructor(code) {
		super(code);
		this.name = "FinalResultDeliveryError";
		this.code = code;
	}
}

function reject(code) {
	throw new FinalResultDeliveryError(code);
}

function isObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
	return isObject(value)
		&& Reflect.ownKeys(value).every((key) => typeof key === "string")
		&& JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
}

function boundedString(value, maximum = 512) {
	return typeof value === "string"
		&& value.length > 0
		&& value.length <= maximum
		&& value === value.trim()
		&& !/[\u0000-\u001f\u007f]/.test(value);
}

function positiveInteger(value) {
	return Number.isSafeInteger(value) && value > 0;
}

function canonicalJson(value, state = { nodes: 0, seen: new Set() }, depth = 0) {
	state.nodes += 1;
	if (state.nodes > 100000 || depth > 64) {
		reject("final_result_delivery_json_rejected");
	}
	if (value === null) return "null";
	if (typeof value === "string") {
		if (!value.isWellFormed()) {
			reject("final_result_delivery_json_rejected");
		}
		return JSON.stringify(value);
	}
	if (typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
			reject("final_result_delivery_json_rejected");
		}
		return JSON.stringify(value);
	}
	if (!Array.isArray(value) && !isObject(value)) {
		reject("final_result_delivery_json_rejected");
	}
	if (state.seen.has(value)) reject("final_result_delivery_json_rejected");
	const prototype = Object.getPrototypeOf(value);
	if (
		!Array.isArray(value)
		&& prototype !== Object.prototype
		&& prototype !== null
	) {
		reject("final_result_delivery_json_rejected");
	}
	const keys = Reflect.ownKeys(value);
	if (keys.some((key) => (
		typeof key !== "string" || !key.isWellFormed()
	))) {
		reject("final_result_delivery_json_rejected");
	}
	state.seen.add(value);
	let encoded;
	if (Array.isArray(value)) {
		encoded = `[${value.map(
			(item) => canonicalJson(item, state, depth + 1),
		).join(",")}]`;
	} else {
		keys.sort();
		encoded = `{${keys.map(
			(key) => (
				`${JSON.stringify(key)}:${canonicalJson(value[key], state, depth + 1)}`
			),
		).join(",")}}`;
	}
	state.seen.delete(value);
	return encoded;
}

function canonicalBytes(value) {
	return Buffer.from(canonicalJson(value), "utf8");
}

function digest(value) {
	return createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function sameJson(left, right) {
	try {
		return canonicalJson(left) === canonicalJson(right);
	} catch {
		return false;
	}
}

function containsSensitiveAuthorityField(value, depth = 0) {
	if (depth > 64) return true;
	if (Array.isArray(value)) {
		return value.some((item) => containsSensitiveAuthorityField(item, depth + 1));
	}
	if (!isObject(value)) return false;
	return Object.entries(value).some(
		([key, item]) => (
			SENSITIVE_AUTHORITY_FIELDS.has(
				key
					.replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`)
					.replace(/-/g, "_")
					.toLowerCase(),
			)
			|| containsSensitiveAuthorityField(item, depth + 1)
		),
	);
}

function validLocator(locator) {
	if (!exactKeys(locator, LOCATOR_KEYS)) return false;
	if (["clarification_required", "refused"].includes(locator.status)) {
		return locator.action === null
			&& locator.business_succeeded === false
			&& locator.capability_id === null
			&& locator.operation_id === null
			&& locator.receipt_id === null
			&& locator.result_digest === null;
	}
	if (locator.status === "awaiting_approval") {
		return locator.action === "operation.preview"
			&& locator.business_succeeded === false
			&& CAPABILITY_ID.test(locator.capability_id)
			&& boundedString(locator.operation_id, 256)
			&& locator.receipt_id === null
			&& locator.result_digest === null;
	}
	if (locator.status === "verified_diagnostic") {
		return locator.action === "operation.diagnostics"
			&& locator.business_succeeded === false
			&& locator.capability_id === "acct.diagnostics.operation_read.v1"
			&& boundedString(locator.operation_id, 256)
			&& boundedString(locator.receipt_id, 256)
			&& SHA256.test(locator.result_digest);
	}
	if (locator.status !== "verified_success") return false;
	return locator.business_succeeded === true
		&& CAPABILITY_ID.test(locator.capability_id)
		&& boundedString(locator.receipt_id, 256)
		&& SHA256.test(locator.result_digest)
		&& (
			(locator.action === "read" && locator.operation_id === null)
			|| (
				locator.action === "operation.result"
				&& boundedString(locator.operation_id, 256)
			)
		);
}

function validIdentity(identity) {
	return exactKeys(identity, IDENTITY_KEYS)
		&& SHA256.test(identity.release_digest)
		&& SHA256.test(identity.registry_digest);
}

function validSessionBinding(binding) {
	return exactKeys(binding, SESSION_BINDING_KEYS)
		&& positiveInteger(binding.company_id)
		&& positiveInteger(binding.user_id)
		&& boundedString(binding.principal)
		&& boundedString(binding.odoo_instance_id)
		&& boundedString(binding.database_name)
		&& DATABASE_UUID.test(binding.database_uuid)
		&& boundedString(binding.environment, 64);
}

function receiptMatchesSession(receipt, binding) {
	return receipt.company_id === binding.company_id
		&& receipt.user_id === binding.user_id
		&& receipt.database_name === binding.database_name
		&& receipt.database_uuid === binding.database_uuid
		&& receipt.environment === binding.environment
		&& receipt.odoo_instance_id === binding.odoo_instance_id
		&& (
			receipt.principal === undefined
			|| receipt.principal === binding.principal
		);
}

function validReadReceipt(receipt, locator, executedIdentity, binding) {
	return exactKeys(receipt, READ_RECEIPT_KEYS)
		&& receipt.id === locator.receipt_id
		&& receipt.capability_id === locator.capability_id
		&& receipt.result_digest === locator.result_digest
		&& receipt.release_digest === executedIdentity.release_digest
		&& receipt.registry_digest === executedIdentity.registry_digest
		&& receiptMatchesSession(receipt, binding)
		&& Number.isSafeInteger(receipt.record_count)
		&& receipt.record_count >= 0
		&& UTC_TIMESTAMP.test(receipt.observed_at)
		&& SHA256.test(receipt.request_digest)
		&& SHA256.test(receipt.signature)
		&& receipt.signature_version === 2
		&& receipt.signature_purpose === "read_receipt_v2"
		&& boundedString(receipt.signature_key_id, 256)
		&& ["staged", "enabled"].includes(receipt.capability_channel);
}

function validWriteReceipt(receipt, locator, executedIdentity, binding) {
	return exactKeys(receipt, WRITE_RECEIPT_KEYS)
		&& receipt.receipt_id === locator.receipt_id
		&& receipt.operation_id === locator.operation_id
		&& receipt.capability_id === locator.capability_id
		&& receipt.result_digest === locator.result_digest
		&& receipt.release_digest === executedIdentity.release_digest
		&& receipt.registry_digest === executedIdentity.registry_digest
		&& receiptMatchesSession(receipt, binding)
		&& positiveInteger(receipt.approver_user_id)
		&& UTC_TIMESTAMP.test(receipt.issued_at)
		&& [
			"approval_digest",
			"audit_head",
			"operation_digest",
			"request_digest",
			"signature",
			"verification_evidence_digest",
		].every((key) => SHA256.test(receipt[key]))
		&& receipt.signature_version === 1
		&& receipt.signature_purpose === "write_audit_receipt_v1"
		&& boundedString(receipt.signing_key_id, 256)
		&& boundedString(receipt.request_id, 256)
		&& ["staged", "enabled"].includes(receipt.capability_channel);
}

function nonSuccessDelivery(locator) {
	return Object.freeze({
		action: locator.action,
		audit_receipt: null,
		business_result: null,
		business_succeeded: false,
		capability_id: locator.capability_id,
		operation_id: locator.operation_id,
		receipt_id: locator.receipt_id,
		result_digest: locator.result_digest,
		status: locator.status,
	});
}

export function serializeFinalDeliveredAnswer(delivered, forbiddenHandles) {
	if (
		!Array.isArray(forbiddenHandles)
		|| forbiddenHandles.length !== 2
		|| !forbiddenHandles.every(validBrokerSessionHandle)
		|| forbiddenHandles[0] === forbiddenHandles[1]
	) {
		reject("final_result_serialization_configuration_rejected");
	}
	if (!exactKeys(delivered, FINAL_ANSWER_KEYS)) {
		reject("final_result_serialization_rejected");
	}
	const locator = {
		action: delivered.action,
		business_succeeded: delivered.business_succeeded,
		capability_id: delivered.capability_id,
		operation_id: delivered.operation_id,
		receipt_id: delivered.receipt_id,
		result_digest: delivered.result_digest,
		status: delivered.status,
	};
	if (
		!validLocator(locator)
		|| (
			delivered.business_succeeded === true
			&& (
				!isObject(delivered.business_result)
				|| !isObject(delivered.audit_receipt)
			)
		)
		|| (
			delivered.business_succeeded === false
			&& (
				delivered.business_result !== null
				|| delivered.audit_receipt !== null
			)
		)
		|| containsSensitiveAuthorityField(delivered)
	) {
		reject("final_result_serialization_rejected");
	}
	const encoded = canonicalJson(delivered);
	if (Buffer.byteLength(encoded, "utf8") > MAX_DELIVERED_FINAL_ANSWER_BYTES) {
		reject("final_result_delivery_too_large");
	}
	if (forbiddenHandles.some((handle) => encoded.includes(handle))) {
		reject("final_result_sensitive_data_rejected");
	}
	return encoded;
}

function validateDeliveryResponse(
	response,
	locator,
	expectedReleaseDigest,
	expectedRegistryDigest,
	sessionHandle,
) {
	if (
		!exactKeys(
			response,
			["business_succeeded", "command", "data", "ok"],
		)
		|| response.ok !== true
		|| response.command !== "result.deliver"
		|| response.business_succeeded !== true
		|| !exactKeys(response.data, DELIVERY_DATA_KEYS)
	) {
		reject("final_result_broker_response_rejected");
	}
	const {
		audit_receipt: auditReceipt,
		business_result: businessResult,
		current_identity: currentIdentity,
		executed_identity: executedIdentity,
		locator: returnedLocator,
		session_binding: sessionBinding,
	} = response.data;
	if (
		!sameJson(locator, returnedLocator)
		|| !validIdentity(currentIdentity)
		|| !validIdentity(executedIdentity)
		|| currentIdentity.release_digest !== expectedReleaseDigest
		|| currentIdentity.registry_digest !== expectedRegistryDigest
		|| (
			locator.action === "read"
			&& (
				executedIdentity.release_digest !== expectedReleaseDigest
				|| executedIdentity.registry_digest !== expectedRegistryDigest
			)
		)
		|| !validSessionBinding(sessionBinding)
		|| !isObject(businessResult)
		|| !isObject(auditReceipt)
	) {
		reject("final_result_binding_rejected");
	}
	const businessBytes = canonicalBytes(businessResult);
	const receiptBytes = canonicalBytes(auditReceipt);
	if (
		containsSensitiveAuthorityField(businessResult)
		|| containsSensitiveAuthorityField(auditReceipt)
		|| canonicalBytes(response.data).includes(Buffer.from(sessionHandle, "utf8"))
	) {
		reject("final_result_sensitive_data_rejected");
	}
	if (
		businessBytes.length > MAX_DELIVERED_BUSINESS_RESULT_BYTES
		|| receiptBytes.length > MAX_DELIVERED_AUDIT_RECEIPT_BYTES
	) {
		reject("final_result_delivery_too_large");
	}
	if (digest(businessResult) !== locator.result_digest) {
		reject("final_result_digest_mismatch");
	}
	const receiptValid = locator.action === "read"
		? validReadReceipt(
			auditReceipt,
			locator,
			executedIdentity,
			sessionBinding,
		)
		: validWriteReceipt(
			auditReceipt,
			locator,
			executedIdentity,
			sessionBinding,
		);
	if (!receiptValid) reject("final_result_receipt_rejected");
	const safeBusinessResult = JSON.parse(businessBytes.toString("utf8"));
	const safeAuditReceipt = JSON.parse(receiptBytes.toString("utf8"));
	return Object.freeze({
		action: locator.action,
		audit_receipt: safeAuditReceipt,
		business_result: safeBusinessResult,
		business_succeeded: true,
		capability_id: locator.capability_id,
		operation_id: locator.operation_id,
		receipt_id: locator.receipt_id,
		result_digest: locator.result_digest,
		status: locator.status,
	});
}

export function createFinalResultDeliverer(options = {}) {
	if (
		!isObject(options)
		|| !SHA256.test(options.expectedReleaseDigest)
		|| !SHA256.test(options.expectedRegistryDigest)
		|| !validBrokerSessionHandle(options.sessionHandle)
	) {
		throw new FinalResultDeliveryError("final_result_delivery_configuration_rejected");
	}
	let brokerClient = options.brokerClient;
	if (brokerClient === undefined) {
		const factory = options.brokerClientFactory ?? createV3BrokerClient;
		if (typeof factory !== "function") {
			throw new FinalResultDeliveryError(
				"final_result_delivery_configuration_rejected",
			);
		}
		brokerClient = factory({
			brokerSocketPath: options.brokerSocketPath,
			expectedRegistryDigest: options.expectedRegistryDigest,
			expectedReleaseDigest: options.expectedReleaseDigest,
			maxOutputBytes: MAX_DELIVERED_BROKER_RESPONSE_BYTES,
			sessionHandleProvider: () => options.sessionHandle,
			timeoutMs: options.timeoutMs,
			transport: options.transport,
		});
	}
	if (typeof brokerClient !== "function") {
		throw new FinalResultDeliveryError("final_result_delivery_configuration_rejected");
	}
	const expectedReleaseDigest = options.expectedReleaseDigest;
	const expectedRegistryDigest = options.expectedRegistryDigest;
	return async function deliverFinalResult(locator) {
		if (!validLocator(locator)) reject("final_result_locator_rejected");
		if (["clarification_required", "refused", "awaiting_approval"].includes(
			locator.status,
		)) {
			return nonSuccessDelivery(locator);
		}
		if (locator.status !== "verified_success") {
			reject("final_result_delivery_unsupported");
		}
		let response;
		try {
			response = await brokerClient("result.deliver", locator);
		} catch {
			reject("final_result_broker_unavailable");
		}
		if (response?.ok !== true) reject("final_result_broker_rejected");
		return validateDeliveryResponse(
			response,
			locator,
			expectedReleaseDigest,
			expectedRegistryDigest,
			options.sessionHandle,
		);
	};
}
