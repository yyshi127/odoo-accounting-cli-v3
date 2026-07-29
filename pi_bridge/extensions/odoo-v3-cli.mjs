import path from "node:path";
import fs from "node:fs";
import http from "node:http";
import { spawn } from "node:child_process";
import { validBrokerSessionHandle } from "../trusted-session.mjs";

export const V3_TOOL_NAMES = Object.freeze({
	capabilityList: "odoo_v3_capability_list",
	capabilityGet: "odoo_v3_capability_get",
	read: "odoo_v3_read",
	prepare: "odoo_v3_operation_prepare",
	preview: "odoo_v3_operation_preview",
	approveExecute: "odoo_v3_operation_approve_execute",
	status: "odoo_v3_operation_status",
	result: "odoo_v3_operation_result",
	diagnostics: "odoo_v3_operation_diagnostics",
	recover: "odoo_v3_operation_recover",
});

export const V3_OPERATION_COMMANDS = Object.freeze({
	"operation.prepare": Object.freeze(["operation", "prepare"]),
	"operation.preview": Object.freeze(["operation", "preview"]),
	"operation.approve_execute": Object.freeze(["operation", "approve-execute"]),
	"operation.status": Object.freeze(["operation", "status"]),
	"operation.result": Object.freeze(["operation", "result"]),
	"operation.diagnostics": Object.freeze(["operation", "diagnostics"]),
	"operation.recover": Object.freeze(["operation", "recover"]),
});

export const V3_BROKER_ACTION_PATHS = Object.freeze({
	read: "/v1/read",
	"operation.prepare": "/v1/operation/prepare",
	"operation.preview": "/v1/operation/preview",
	"operation.approve_execute": "/v1/operation/approve-execute",
	"operation.status": "/v1/operation/status",
	"operation.result": "/v1/operation/result",
	"operation.diagnostics": "/v1/operation/diagnostics",
	"operation.recover": "/v1/operation/recover",
});

export const V3_QUERY_COMMANDS = Object.freeze({
	"registry.list": Object.freeze(["registry", "list"]),
	// registry.get is intentionally resolved from one immutable registry.list
	// invocation so user input is never interpolated into argv.
	"registry.get": Object.freeze(["registry", "list"]),
});

const DEFAULT_TIMEOUT_MS = 120000;
const MAX_OUTPUT_BYTES = 1024 * 1024;

function isObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

const SHA256 = /^[0-9a-f]{64}$/;
const CAPABILITY_ID = /^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$/;
const UTC_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/;
const DATABASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1";
const REGISTRY_LIST_CAPABILITY_ID = "acct.registry.list.v1";
const V3_BROKER_PREFLIGHT_OPTION_KEYS = Object.freeze([
	"brokerSocketPath",
	"expectedRegistryDigest",
	"expectedReleaseDigest",
	"sessionHandle",
	"timeoutMs",
	"transport",
]);

const REGISTRY_DESCRIPTOR_KEYS = Object.freeze([
	"access",
	"approval_required",
	"business_description",
	"capability_channel",
	"company_scope",
	"contract_digest",
	"domain",
	"evidence_level",
	"id",
	"idempotency_required",
	"input_schema_json",
	"odoo_permissions",
	"output_schema_json",
	"recovery_method",
	"risk_level",
	"verification_method",
].sort());

const DATABASE_FINALIZATION_KEYS = Object.freeze([
	"attestation_digest",
	"attestation_id",
	"attestation_key_id",
	"database_oid",
	"database_uuid",
	"finalized_at",
	"finalized_txid",
	"guard_epoch",
	"guard_installation_id",
	"intent_digest",
	"operation_id",
	"proof_expires_at",
	"proof_verified_at",
	"protocol_version",
	"receipt_digest",
	"remaining_unresolved_count",
	"request_digest",
	"resolution_kind",
	"resolution_operation_id",
	"resolved_anchor_count",
].sort());

const DATABASE_FINALIZATION_DIGEST_KEYS = Object.freeze([
	"attestation_digest",
	"intent_digest",
	"receipt_digest",
	"request_digest",
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
].sort());

const WRITE_RECEIPT_DIGEST_KEYS = Object.freeze([
	"approval_digest",
	"audit_head",
	"operation_digest",
	"registry_digest",
	"release_digest",
	"request_digest",
	"result_digest",
	"signature",
	"verification_evidence_digest",
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
].sort());

function exactKeys(value, keys) {
	return isObject(value)
		&& JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function nonEmptyString(value) {
	return typeof value === "string" && value.trim().length > 0;
}

function positiveIntegerValue(value) {
	return Number.isSafeInteger(value) && value > 0;
}

function validRegistryList(data, expectedRegistryDigest) {
	return exactKeys(data, ["capabilities", "count", "registry_digest"])
		&& Array.isArray(data.capabilities)
		&& data.capabilities.every((item) => isObject(item) && CAPABILITY_ID.test(item.id))
		&& Number.isSafeInteger(data.count)
		&& data.count === data.capabilities.length
		&& SHA256.test(data.registry_digest)
		&& data.registry_digest === expectedRegistryDigest;
}

function validReadReceipt(receipt, request, expectedReleaseDigest, expectedRegistryDigest) {
	return exactKeys(receipt, READ_RECEIPT_KEYS)
		&& nonEmptyString(receipt.id)
		&& receipt.capability_id === request?.capability_id
		&& nonEmptyString(receipt.odoo_instance_id)
		&& nonEmptyString(receipt.database_name)
		&& typeof receipt.database_uuid === "string"
		&& DATABASE_UUID.test(receipt.database_uuid)
		&& positiveIntegerValue(receipt.company_id)
		&& positiveIntegerValue(receipt.user_id)
		&& nonEmptyString(receipt.environment)
		&& ["staged", "enabled"].includes(receipt.capability_channel)
		&& ["request_digest", "result_digest", "registry_digest", "release_digest", "signature"]
			.every((key) => typeof receipt[key] === "string" && SHA256.test(receipt[key]))
		&& receipt.release_digest === expectedReleaseDigest
		&& receipt.registry_digest === expectedRegistryDigest
		&& Number.isSafeInteger(receipt.record_count)
		&& receipt.record_count >= 0
		&& typeof receipt.observed_at === "string"
		&& UTC_TIMESTAMP.test(receipt.observed_at)
		&& receipt.signature_version === 2
		&& receipt.signature_purpose === "read_receipt_v2"
		&& nonEmptyString(receipt.signature_key_id);
}

function validJsonObjectText(value) {
	if (typeof value !== "string" || value.length < 2) {
		return false;
	}
	try {
		return isObject(JSON.parse(value));
	} catch {
		return false;
	}
}

function validRegistryDescriptor(value, capabilityChannel) {
	return exactKeys(value, REGISTRY_DESCRIPTOR_KEYS)
		&& CAPABILITY_ID.test(value.id)
		&& nonEmptyString(value.domain)
		&& nonEmptyString(value.business_description)
		&& ["read", "write"].includes(value.access)
		&& ["low", "medium", "high", "critical"].includes(value.risk_level)
		&& [
			"bound_company",
			"allowed_companies",
			"explicit_single_company",
		].includes(value.company_scope)
		&& Array.isArray(value.odoo_permissions)
		&& value.odoo_permissions.length > 0
		&& new Set(value.odoo_permissions).size === value.odoo_permissions.length
		&& value.odoo_permissions.every(
			(permission) => (
				typeof permission === "string"
				&& /^[a-z0-9_]+\.[a-z0-9_]+$/.test(permission)
			),
		)
		&& typeof value.approval_required === "boolean"
		&& typeof value.idempotency_required === "boolean"
		&& validJsonObjectText(value.input_schema_json)
		&& validJsonObjectText(value.output_schema_json)
		&& SHA256.test(value.contract_digest)
		&& [
			"declared",
			"contract_tested",
			"test_verified",
			"sandbox_verified",
			"production_verified",
		].includes(value.evidence_level)
		&& nonEmptyString(value.verification_method)
		&& nonEmptyString(value.recovery_method)
		&& value.capability_channel === capabilityChannel;
}

function validRegistryReadResult(result) {
	if (
		!exactKeys(result, ["capabilities", "page", "receipt"])
		|| !Array.isArray(result.capabilities)
		|| !isObject(result.page)
		|| !isObject(result.receipt)
		|| !exactKeys(result.page, ["count", "total_count"])
		|| !Number.isSafeInteger(result.page.count)
		|| !Number.isSafeInteger(result.page.total_count)
		|| result.page.count !== result.capabilities.length
		|| result.page.total_count !== result.capabilities.length
		|| result.receipt.record_count !== result.capabilities.length
	) {
		return false;
	}
	const identifiers = result.capabilities.map((item) => item?.id);
	return result.capabilities.every(
		(item) => validRegistryDescriptor(
			item,
			result.receipt.capability_channel,
		),
	)
		&& identifiers.every(
			(identifier, index) => (
				index === 0 || identifiers[index - 1] < identifier
			),
		);
}

function validReadData(data, request, expectedReleaseDigest, expectedRegistryDigest) {
	return exactKeys(data, ["capability_id", "release_identity", "result", "runtime"])
		&& data.capability_id === request?.capability_id
		&& isObject(data.release_identity)
		&& data.release_identity.verified === true
		&& data.release_identity.manifest_sha256 === expectedReleaseDigest
		&& data.release_identity.registry_digest === expectedRegistryDigest
		&& isObject(data.result)
		&& isObject(data.runtime)
		&& validReadReceipt(
			data.result.receipt,
			request,
			expectedReleaseDigest,
			expectedRegistryDigest,
		)
		&& (
			request?.capability_id !== REGISTRY_LIST_CAPABILITY_ID
			|| validRegistryReadResult(data.result)
		);
}

function validDiagnosticsData(data, request, expectedReleaseDigest, expectedRegistryDigest) {
	const operation = data?.operation;
	const audit = data?.audit;
	const verification = data?.verification;
	const failure = data?.failure;
	const recovery = data?.recovery;
	const receipts = data?.receipts;
	const page = data?.page;
	return exactKeys(data, [
		"audit",
		"failure",
		"odoo_refs",
		"operation",
		"page",
		"receipt",
		"receipts",
		"recovery",
		"verification",
	])
		&& exactKeys(operation, [
			"allowed_next_states",
			"business_succeeded",
			"capability_id",
			"company_id",
			"operation_id",
			"revision",
			"state",
			"terminal",
		])
		&& operation.operation_id === request?.operation_id
		&& operation.company_id === request?.company_id
		&& CAPABILITY_ID.test(operation.capability_id)
		&& Number.isSafeInteger(operation.revision)
		&& operation.revision >= 0
		&& typeof operation.terminal === "boolean"
		&& typeof operation.business_succeeded === "boolean"
		&& Array.isArray(operation.allowed_next_states)
		&& exactKeys(audit, [
			"chain_verified",
			"event_count",
			"event_types",
			"event_types_offset",
			"event_types_truncated",
			"global_head_hash",
			"last_event_hash",
			"last_event_id",
		])
		&& audit.chain_verified === true
		&& Number.isSafeInteger(audit.event_count)
		&& audit.event_count >= 0
		&& Array.isArray(audit.event_types)
		&& audit.event_types.length <= 1000
		&& exactKeys(verification, [
			"evidence_digest",
			"method",
			"passed",
			"trusted_terminal_result_verified",
		])
		&& typeof verification.trusted_terminal_result_verified === "boolean"
		&& exactKeys(failure, ["evidence_digest", "present", "result_id", "stage"])
		&& typeof failure.present === "boolean"
		&& exactKeys(recovery, [
			"attempt_count",
			"available",
			"bound_operation_ids",
			"completion_evidence_digest",
			"completion_receipt_body_digest",
			"completion_receipt_id",
			"latest_attempt_plan_digest",
			"lifecycle_status",
			"plan_digest",
			"plan_status",
			"recovery_capability_id",
			"requires_approval",
		])
		&& typeof recovery.available === "boolean"
		&& Number.isSafeInteger(recovery.attempt_count)
		&& recovery.attempt_count >= 0
		&& Array.isArray(recovery.bound_operation_ids)
		&& (
			operation.state === "recovered"
				? recovery.lifecycle_status === "recovered_verified"
					&& SHA256.test(recovery.completion_evidence_digest)
					&& SHA256.test(recovery.completion_receipt_body_digest)
					&& boundedString(recovery.completion_receipt_id, 128)
				: recovery.lifecycle_status !== "recovered_verified"
					&& recovery.completion_evidence_digest === null
					&& recovery.completion_receipt_body_digest === null
					&& recovery.completion_receipt_id === null
		)
		&& Array.isArray(data.odoo_refs)
		&& exactKeys(receipts, [
			"current_candidate_count",
			"database_finalization_digest",
			"difference_digest",
			"durable_final_receipt_body_digest",
			"durable_final_receipt_id",
			"unique_final_receipt_verified",
			"write_audit_head",
			"write_audit_receipt_id",
			"write_audit_result_digest",
		])
		&& typeof receipts.unique_final_receipt_verified === "boolean"
		&& Number.isSafeInteger(receipts.current_candidate_count)
		&& receipts.current_candidate_count >= 0
		&& exactKeys(page, ["count", "total_count"])
		&& page.count === 1
		&& page.total_count === 1
		&& validReadReceipt(
			data.receipt,
			{ capability_id: DIAGNOSTICS_CAPABILITY_ID },
			expectedReleaseDigest,
			expectedRegistryDigest,
		)
		&& data.receipt.company_id === request?.company_id
		&& data.receipt.record_count === 1;
}

function validWriteAuditReceipt(
	receipt,
	verification,
	data,
	request,
	expectedReleaseDigest,
	expectedRegistryDigest,
) {
	return exactKeys(receipt, WRITE_RECEIPT_KEYS)
		&& nonEmptyString(receipt.receipt_id)
		&& nonEmptyString(receipt.request_id)
		&& receipt.operation_id === data.operation_id
		&& CAPABILITY_ID.test(receipt.capability_id)
		&& nonEmptyString(receipt.principal)
		&& nonEmptyString(receipt.odoo_instance_id)
		&& nonEmptyString(receipt.database_name)
		&& typeof receipt.database_uuid === "string"
		&& DATABASE_UUID.test(receipt.database_uuid)
		&& positiveIntegerValue(receipt.user_id)
		&& positiveIntegerValue(receipt.approver_user_id)
		&& positiveIntegerValue(receipt.company_id)
		&& nonEmptyString(receipt.environment)
		&& ["staged", "enabled"].includes(receipt.capability_channel)
		&& WRITE_RECEIPT_DIGEST_KEYS.every(
			(key) => typeof receipt[key] === "string" && SHA256.test(receipt[key]),
		)
		&& receipt.release_digest === expectedReleaseDigest
		&& receipt.registry_digest === expectedRegistryDigest
		&& receipt.verification_evidence_digest === verification.evidence_digest
		&& typeof receipt.issued_at === "string"
		&& UTC_TIMESTAMP.test(receipt.issued_at)
		&& receipt.signature_version === 1
		&& receipt.signature_purpose === "write_audit_receipt_v1"
		&& nonEmptyString(receipt.signing_key_id);
}

function validDatabaseFinalization(value, data, receipt) {
	if (!exactKeys(value, DATABASE_FINALIZATION_KEYS)
		|| value.protocol_version !== 1
		|| !DATABASE_FINALIZATION_DIGEST_KEYS.every(
			(key) => typeof value[key] === "string" && SHA256.test(value[key]),
		)
		|| typeof value.attestation_id !== "string"
		|| !DATABASE_UUID.test(value.attestation_id)
		|| typeof value.guard_installation_id !== "string"
		|| !DATABASE_UUID.test(value.guard_installation_id)
		|| !nonEmptyString(value.attestation_key_id)
		|| !positiveIntegerValue(value.database_oid)
		|| typeof value.database_uuid !== "string"
		|| !DATABASE_UUID.test(value.database_uuid)
		|| value.database_uuid !== receipt?.database_uuid
		|| !nonEmptyString(value.operation_id)
		|| !nonEmptyString(value.resolution_operation_id)
		|| !["verified", "recovered"].includes(value.resolution_kind)
		|| !Number.isSafeInteger(value.resolved_anchor_count)
		|| !Number.isSafeInteger(value.remaining_unresolved_count)
		|| value.remaining_unresolved_count < 0
		|| !Number.isSafeInteger(value.guard_epoch)
		|| value.guard_epoch < 0
		|| typeof value.finalized_txid !== "string"
		|| !POSITIVE_DECIMAL.test(value.finalized_txid)) {
		return false;
	}
	for (const key of ["proof_verified_at", "proof_expires_at", "finalized_at"]) {
		if (typeof value[key] !== "string" || !UTC_TIMESTAMP.test(value[key])) {
			return false;
		}
	}
	const verifiedAt = Date.parse(value.proof_verified_at);
	const expiresAt = Date.parse(value.proof_expires_at);
	const finalizedAt = Date.parse(value.finalized_at);
	if (!Number.isFinite(verifiedAt)
		|| !Number.isFinite(expiresAt)
		|| !Number.isFinite(finalizedAt)
		|| expiresAt <= verifiedAt
		|| expiresAt - verifiedAt > 300000
		|| finalizedAt < verifiedAt - 60000
		|| finalizedAt > expiresAt) {
		return false;
	}
	if (value.resolution_kind === "verified") {
		return value.operation_id === data.operation_id
			&& value.resolution_operation_id === data.operation_id
			&& value.resolved_anchor_count === 1;
	}
	return value.operation_id !== value.resolution_operation_id
		&& value.resolution_operation_id === data.operation_id
		&& value.resolved_anchor_count === 2;
}

function validVerifiedWriteSuccess(
	payload,
	request,
	expectedReleaseDigest,
	expectedRegistryDigest,
) {
	const data = payload.data;
	const verification = data?.verification;
	return payload.business_succeeded === true
		&& isObject(data)
		&& nonEmptyString(data.operation_id)
		&& data.operation_id === request?.operation_id
		&& data.operation_state === "completed"
		&& isObject(verification)
		&& nonEmptyString(verification.method)
		&& verification.passed === true
		&& Array.isArray(verification.checks)
		&& verification.checks.length > 0
		&& verification.checks.every(nonEmptyString)
		&& typeof verification.evidence_digest === "string"
		&& SHA256.test(verification.evidence_digest)
		&& typeof verification.verified_at === "string"
		&& UTC_TIMESTAMP.test(verification.verified_at)
		&& validDatabaseFinalization(
			data.database_finalization,
			data,
			data.audit_receipt,
		)
		&& validWriteAuditReceipt(
			data.audit_receipt,
			verification,
			data,
			request,
			expectedReleaseDigest,
			expectedRegistryDigest,
		);
}

function assertJsonValue(value, seen = new Set()) {
	if (value === null || typeof value === "string" || typeof value === "boolean") {
		return;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) {
			throw new TypeError("V3 request contains a non-finite number");
		}
		return;
	}
	if (typeof value !== "object") {
		throw new TypeError("V3 request contains a non-JSON value");
	}
	if (seen.has(value)) {
		throw new TypeError("V3 request contains a cycle");
	}
	seen.add(value);
	if (Array.isArray(value)) {
		for (const item of value) {
			assertJsonValue(item, seen);
		}
	} else {
		const prototype = Object.getPrototypeOf(value);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new TypeError("V3 request must contain only JSON objects");
		}
		for (const item of Object.values(value)) {
			assertJsonValue(item, seen);
		}
	}
	seen.delete(value);
}

function serializeRequest(request) {
	if (!isObject(request)) {
		throw new TypeError("V3 request must be a JSON object");
	}
	assertJsonValue(request);
	return JSON.stringify(request);
}

const FORBIDDEN_AUTHORITY_FIELDS = new Set([
	"allowed_company_ids",
	"approval",
	"approver_user_id",
	"auth_expires_at",
	"auth_issued_at",
	"auth_key_id",
	"auth_request_digest",
	"auth_signature",
	"auth_signature_purpose",
	"auth_signature_version",
	"auth_token_id",
	"binary_path",
	"broker_socket",
	"capability_channel",
	"cli_path",
	"config_path",
	"context",
	"database_name",
	"database_uuid",
	"environment",
	"key_id",
	"odoo_instance_id",
	"principal",
	"registry_digest",
	"release_digest",
	"release_version",
	"request_id",
	"runtime_config",
	"runtime_config_path",
	"signature",
	"signature_key_id",
	"signing_key_id",
	"user_id",
]);

function containsForbiddenAuthorityField(value) {
	if (Array.isArray(value)) {
		return value.some(containsForbiddenAuthorityField);
	}
	if (!isObject(value)) {
		return false;
	}
	for (const [key, item] of Object.entries(value)) {
		if (FORBIDDEN_AUTHORITY_FIELDS.has(key) || key.startsWith("auth_")) {
			return true;
		}
		if (containsForbiddenAuthorityField(item)) {
			return true;
		}
	}
	return false;
}

function boundedString(value, maximum = 512) {
	return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function validBrokerBusinessRequest(action, request) {
	if (!isObject(request) || containsForbiddenAuthorityField(request)) {
		return false;
	}
	if (["read", "operation.prepare"].includes(action)) {
		return exactKeys(request, ["capability_id", "parameters"])
			&& CAPABILITY_ID.test(request.capability_id)
			&& isObject(request.parameters)
			&& (
				action !== "read"
				|| request.capability_id !== REGISTRY_LIST_CAPABILITY_ID
				|| exactKeys(request.parameters, [])
			);
	}
	if ([
		"operation.preview",
		"operation.approve_execute",
		"operation.status",
		"operation.result",
	].includes(action)) {
		return exactKeys(request, ["operation_id"])
			&& boundedString(request.operation_id, 128);
	}
	if (action === "operation.diagnostics") {
		return exactKeys(request, ["company_id", "operation_id"])
			&& positiveIntegerValue(request.company_id)
			&& boundedString(request.operation_id, 128);
	}
	if (action === "operation.recover") {
		return exactKeys(request, [
			"idempotency_key",
			"origin_operation_id",
			"reason",
			"recovery_date",
		])
			&& boundedString(request.origin_operation_id, 128)
			&& /^\d{4}-\d{2}-\d{2}$/.test(request.recovery_date)
			&& boundedString(request.reason, 512)
			&& boundedString(request.idempotency_key, 200);
	}
	return false;
}

function requestedOperationId(action, request) {
	if (action === "operation.recover") return undefined;
	return boundedString(request?.operation_id, 128)
		? request.operation_id
		: undefined;
}

function requestedOriginOperationId(action, request) {
	return action === "operation.recover"
		&& boundedString(request?.origin_operation_id, 128)
		? request.origin_operation_id
		: undefined;
}

function bindRequestedOriginOperationId(payload, action, request) {
	const originOperationId = requestedOriginOperationId(action, request);
	if (payload?.ok !== false || !isObject(payload?.error) || !originOperationId) {
		return payload;
	}
	return {
		...payload,
		error: {
			...payload.error,
			origin_operation_id: originOperationId,
		},
	};
}

function bridgeFailure(
	action,
	request,
	{ code, message, odooEffect, reconciliationRequired = false, retryable },
) {
	const error = {
		code,
		message,
		odoo_effect: odooEffect,
		retryable,
	};
	if (reconciliationRequired) {
		error.reconciliation_required = true;
	}
	const operationId = requestedOperationId(action, request);
	if (operationId) {
		error.operation_id = operationId;
	}
	const originOperationId = requestedOriginOperationId(action, request);
	if (originOperationId) {
		error.origin_operation_id = originOperationId;
	}
	return { command: action, error, ok: false };
}

function addUnverifiedBusinessGuidance(payload, action, request) {
	if (
		!["operation.approve_execute", "operation.result"].includes(action)
		|| payload?.ok !== true
		|| payload.business_succeeded !== false
	) {
		return payload;
	}
	const operationId = requestedOperationId(action, request) ?? null;
	return {
		...payload,
		bridge_guidance: {
			must_not_report_business_success: true,
			next_action: operationId ? "operation.status" : "operator_review",
			operation_id: operationId,
			reason: "terminal_write_result_is_not_business_verified",
		},
	};
}

function parseSafePreauthReconciliationEnvelope(raw, cliCommand) {
	let payload;
	try {
		payload = JSON.parse(raw);
	} catch {
		return null;
	}
	const error = payload?.error;
	if (
		!exactKeys(payload, ["command", "error", "ok"])
		|| payload.command !== cliCommand
		|| payload.ok !== false
		|| !exactKeys(error, [
			"code",
			"message",
			"odoo_effect",
			"reconciliation_required",
			"retryable",
		])
		|| error.code !== "broker_session_reconciliation_required"
		|| error.message !== "The trusted V3 broker rejected the request."
		|| error.odoo_effect !== "none"
		|| error.reconciliation_required !== true
		|| error.retryable !== false
	) {
		return null;
	}
	return payload;
}

function parseCliEnvelope(
	raw,
	cliCommand,
	expectedOk,
	request,
	expectedReleaseDigest,
	expectedRegistryDigest,
) {
	let payload;
	try {
		payload = JSON.parse(raw);
	} catch {
		return null;
	}
	if (!isObject(payload) || payload.command !== cliCommand || payload.ok !== expectedOk) {
		return null;
	}
	if (expectedOk) {
		const reportsBusinessResult = ["operation.approve_execute", "operation.result"].includes(cliCommand);
		const expectedKeys = reportsBusinessResult
			? ["business_succeeded", "command", "data", "ok"]
			: ["command", "data", "ok"];
		if (
			JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(expectedKeys)
			|| !isObject(payload.data)
			|| (reportsBusinessResult && typeof payload.business_succeeded !== "boolean")
		) {
			return null;
		}
		if (
			reportsBusinessResult
			&& payload.business_succeeded === true
			&& !validVerifiedWriteSuccess(
				payload,
				request,
				expectedReleaseDigest,
				expectedRegistryDigest,
			)
		) {
			return null;
		}
		if (
			cliCommand === "read"
			&& !validReadData(
				payload.data,
				request,
				expectedReleaseDigest,
				expectedRegistryDigest,
			)
		) {
			return null;
		}
		if (
			cliCommand === "operation.diagnostics"
			&& !validDiagnosticsData(
				payload.data,
				request,
				expectedReleaseDigest,
				expectedRegistryDigest,
			)
		) {
			return null;
		}
		if (
			cliCommand === "registry.list"
			&& !validRegistryList(payload.data, expectedRegistryDigest)
		) {
			return null;
		}
		return addUnverifiedBusinessGuidance(payload, cliCommand, request);
	}
	const error = payload.error;
	const errorKeys = Object.keys(error ?? {});
	const originOperationId = requestedOriginOperationId(cliCommand, request);
	if (
		JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(["command", "error", "ok"])
		|| !isObject(error)
		|| typeof error.code !== "string"
		|| !error.code
		|| typeof error.message !== "string"
		|| !error.message
		|| !["none", "unknown"].includes(error.odoo_effect)
		|| typeof error.retryable !== "boolean"
		|| (error.operation_id !== undefined && typeof error.operation_id !== "string")
		|| (
			error.origin_operation_id !== undefined
			&& (
				cliCommand !== "operation.recover"
				|| error.origin_operation_id !== originOperationId
			)
		)
		|| (
			cliCommand === "operation.recover"
			&& error.operation_id !== undefined
		)
		|| (
			error.reconciliation_required !== undefined
			&& typeof error.reconciliation_required !== "boolean"
		)
		|| (
			error.reconciliation_required === true
			&& (error.retryable !== false || error.odoo_effect !== "none")
		)
		|| (error.state !== undefined && typeof error.state !== "string")
		|| errorKeys.some((key) => ![
			"code",
			"message",
			"odoo_effect",
			"operation_id",
			"origin_operation_id",
			"reconciliation_required",
			"retryable",
			"state",
		].includes(key))
	) {
		return null;
	}
	return payload;
}

function positiveInteger(value, fallback) {
	return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

export function createV3CliRunner(options = {}) {
	const cliPath = options.cliPath ?? process.env.ODOO_ACCOUNTING_CLI_V3_BIN ?? "";
	const prefixArgs = options.prefixArgs ?? [];
	const expectedReleaseDigest = options.expectedReleaseDigest
		?? process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST
		?? "";
	const expectedRegistryDigest = options.expectedRegistryDigest
		?? process.env.ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST
		?? "";
	const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
	const maxOutputBytes = positiveInteger(options.maxOutputBytes, MAX_OUTPUT_BYTES);
	if (!Array.isArray(prefixArgs) || prefixArgs.some((item) => typeof item !== "string")) {
		throw new TypeError("V3 CLI prefix arguments are invalid");
	}
	const fixedPrefixArgs = Object.freeze([...prefixArgs]);

	return async function runV3Operation(action, request) {
		if (action === "read" || Object.hasOwn(V3_OPERATION_COMMANDS, action)) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_broker_required",
				message: "Authenticated V3 read and write actions require the local trusted broker.",
				odooEffect: "none",
				retryable: false,
			});
		}
		const configuredArgs = V3_QUERY_COMMANDS[action];
		if (!configuredArgs) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_action",
				message: "The Pi Bridge does not recognize this V3 operation action.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (typeof cliPath !== "string" || !path.isAbsolute(cliPath) || cliPath.includes("\0")) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_cli_not_configured",
				message: "The fixed immutable V3 CLI launcher is not configured.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (!SHA256.test(expectedReleaseDigest) || !SHA256.test(expectedRegistryDigest)) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_identity_not_configured",
				message: "The verified V3 release and registry identities are not configured.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (
			action === "registry.get"
			&& (
				!exactKeys(request, ["capability_id"])
				|| typeof request.capability_id !== "string"
				|| !CAPABILITY_ID.test(request.capability_id)
			)
		) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The capability query must contain one exact capability_id.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (action === "registry.list" && !exactKeys(request, [])) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The capability list request must be an empty JSON object.",
				odooEffect: "none",
				retryable: false,
			});
		}

		const cliCommand = action === "registry.get" ? "registry.list" : action;
		const commandArgs = [...configuredArgs];

		let stdin;
		try {
			stdin = serializeRequest(request);
		} catch {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The V3 request is not a strict JSON object.",
				odooEffect: "none",
				retryable: false,
			});
		}

		return await new Promise((resolve) => {
			let child;
			let spawned = false;
			let settled = false;
			let stdout = "";
			let stderr = "";
			let timer;
			const uncertainEffect = () => (
				action === "operation.approve_execute" && spawned ? "unknown" : "none"
			);
			const finish = (result) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve(result);
			};

			try {
				child = spawn(cliPath, [...fixedPrefixArgs, ...commandArgs], {
					cwd: path.dirname(cliPath),
					env: process.env,
					stdio: ["pipe", "pipe", "pipe"],
					windowsHide: true,
				});
			} catch {
				resolve(bridgeFailure(action, request, {
					code: "bridge_v3_cli_unavailable",
					message: "The fixed V3 CLI launcher could not be started.",
					odooEffect: "none",
					retryable: true,
				}));
				return;
			}

			timer = setTimeout(() => {
				child.kill("SIGTERM");
				finish(bridgeFailure(action, request, {
					code: "bridge_v3_cli_timeout",
					message: "The V3 CLI did not return before the fixed bridge timeout.",
					odooEffect: uncertainEffect(),
					retryable: true,
				}));
			}, timeoutMs);

			child.on("spawn", () => {
				spawned = true;
			});
			child.stdout.on("data", (chunk) => {
				stdout += chunk.toString("utf8");
				if (Buffer.byteLength(stdout) > maxOutputBytes) {
					child.kill("SIGTERM");
					finish(bridgeFailure(action, request, {
						code: "bridge_v3_cli_output_limit",
						message: "The V3 CLI stdout exceeded the bridge limit.",
						odooEffect: uncertainEffect(),
						retryable: false,
					}));
				}
			});
			child.stderr.on("data", (chunk) => {
				stderr += chunk.toString("utf8");
				if (Buffer.byteLength(stderr) > maxOutputBytes) {
					child.kill("SIGTERM");
					finish(bridgeFailure(action, request, {
						code: "bridge_v3_cli_output_limit",
						message: "The V3 CLI stderr exceeded the bridge limit.",
						odooEffect: uncertainEffect(),
						retryable: false,
					}));
				}
			});
			child.on("error", () => {
				finish(bridgeFailure(action, request, {
					code: "bridge_v3_cli_unavailable",
					message: "The fixed V3 CLI launcher could not be started.",
					odooEffect: uncertainEffect(),
					retryable: true,
				}));
			});
			child.on("close", (code, signal) => {
				if (settled) {
					return;
				}
				const cleanStdout = stdout.trim();
				const cleanStderr = stderr.trim();
				if (code === 0 && signal === null && cleanStderr === "") {
					const payload = parseCliEnvelope(
						cleanStdout,
						cliCommand,
						true,
						request,
						expectedReleaseDigest,
						expectedRegistryDigest,
					);
					if (payload) {
						if (action === "registry.get") {
							const capability = payload.data.capabilities.find(
								(item) => item.id === request.capability_id,
							);
							if (!capability) {
								finish(bridgeFailure(action, request, {
									code: "capability_not_found",
									message: "The requested capability is not registered.",
									odooEffect: "none",
									retryable: false,
								}));
								return;
							}
							finish({
								command: action,
								data: {
									capability,
									registry_digest: payload.data.registry_digest,
								},
								ok: true,
							});
							return;
						}
						finish(payload);
						return;
					}
				} else if (code !== 0 && cleanStdout === "") {
					const payload = parseCliEnvelope(
						cleanStderr,
						cliCommand,
						false,
						request,
						expectedReleaseDigest,
						expectedRegistryDigest,
					);
					if (payload) {
						finish(action === cliCommand ? payload : { ...payload, command: action });
						return;
					}
				}
				finish(bridgeFailure(action, request, {
					code: "bridge_invalid_v3_cli_response",
					message: "The V3 CLI did not return its strict JSON response contract.",
					odooEffect: uncertainEffect(),
					retryable: false,
				}));
			});
			child.stdin.on("error", () => {
				// The close event determines whether the CLI produced a trusted envelope.
			});
			child.stdin.end(stdin, "utf8");
		});
	};
}

let inheritedSessionRead = false;
let inheritedSessionHandle = "";

class BrokerTransportError extends Error {
	constructor({ notDelivered }) {
		super("trusted broker transport failed");
		this.notDelivered = notDelivered === true;
	}
}

function inheritedBrokerSessionHandle() {
	if (!inheritedSessionRead) {
		inheritedSessionRead = true;
		try {
			inheritedSessionHandle = fs.readFileSync(3, "utf8").trim();
		} catch {
			inheritedSessionHandle = "";
		}
	}
	return inheritedSessionHandle;
}

function defaultBrokerTransport({
	action,
	body,
	maxOutputBytes,
	path: requestPath,
	registryDigest,
	releaseDigest,
	sessionHandle,
	socketPath,
	timeoutMs,
}) {
	return new Promise((resolve, reject) => {
		let connected = false;
		let deadline;
		let request;
		let response;
		let settled = false;
		let responseBody = "";
		const finish = (callback, value) => {
			if (settled) {
				return;
			}
			settled = true;
			clearTimeout(deadline);
			callback(value);
		};
		const fail = () => finish(
			reject,
			new BrokerTransportError({ notDelivered: !connected }),
		);
		const terminate = () => {
			if (settled) {
				return;
			}
			fail();
			response?.destroy();
			request?.destroy();
		};
		request = http.request({
			headers: {
				"Content-Length": Buffer.byteLength(body),
				"Content-Type": "application/json; charset=utf-8",
				"X-Odoo-V3-Broker-Action": action,
				"X-Odoo-V3-Broker-Protocol": "pi-broker-v1",
				"X-Odoo-V3-Broker-Session": sessionHandle,
				"X-Odoo-V3-Registry-Digest": registryDigest,
				"X-Odoo-V3-Release-Digest": releaseDigest,
			},
			method: "POST",
			path: requestPath,
			socketPath,
			timeout: timeoutMs,
		}, (incomingResponse) => {
			connected = true;
			response = incomingResponse;
			response.setEncoding("utf8");
			response.on("data", (chunk) => {
				if (
					Buffer.byteLength(responseBody)
					+ Buffer.byteLength(chunk) > maxOutputBytes
				) {
					terminate();
					return;
				}
				responseBody += chunk;
			});
			response.on("end", () => finish(resolve, {
				authorityVerified:
					response.headers["x-odoo-v3-broker-authority"] === "verified-v1",
				body: responseBody,
				executedRegistryDigest:
					response.headers["x-odoo-v3-executed-registry-digest"],
				executedReleaseDigest:
					response.headers["x-odoo-v3-executed-release-digest"],
				statusCode: response.statusCode ?? 0,
			}));
			response.on("aborted", terminate);
			response.on("error", terminate);
			response.on("close", terminate);
		});
		request.on("socket", (socket) => {
			if (socket.connecting) {
				socket.once("connect", () => { connected = true; });
			} else {
				connected = true;
			}
		});
		request.on("timeout", terminate);
		request.on("error", terminate);
		deadline = setTimeout(terminate, timeoutMs);
		try {
			request.end(body, "utf8");
		} catch {
			terminate();
		}
	});
}

export function createV3BrokerClient(options = {}) {
	const brokerSocketPath = options.brokerSocketPath
		?? process.env.ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET
		?? "";
	const expectedReleaseDigest = options.expectedReleaseDigest
		?? process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST
		?? "";
	const expectedRegistryDigest = options.expectedRegistryDigest
		?? process.env.ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST
		?? "";
	const sessionHandleProvider = options.sessionHandleProvider
		?? inheritedBrokerSessionHandle;
	const transport = options.transport ?? defaultBrokerTransport;
	const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
	const maxOutputBytes = positiveInteger(options.maxOutputBytes, MAX_OUTPUT_BYTES);

	return async function runV3BrokerOperation(action, request) {
		const requestPath = V3_BROKER_ACTION_PATHS[action];
		if (!requestPath) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_action",
				message: "The Pi Bridge does not recognize this V3 broker action.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (
			typeof brokerSocketPath !== "string"
			|| !path.isAbsolute(brokerSocketPath)
			|| brokerSocketPath.includes("\0")
		) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_broker_not_configured",
				message: "The fixed local V3 trusted-broker socket is not configured.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (!SHA256.test(expectedReleaseDigest) || !SHA256.test(expectedRegistryDigest)) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_identity_not_configured",
				message: "The verified V3 release and registry identities are not configured.",
				odooEffect: "none",
				retryable: false,
			});
		}
		let sessionHandle;
		try {
			sessionHandle = sessionHandleProvider();
		} catch {
			sessionHandle = "";
		}
		if (!validBrokerSessionHandle(sessionHandle)) {
			return bridgeFailure(action, request, {
				code: "bridge_v3_session_not_authenticated",
				message: "No independently authenticated broker session is available.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (!isObject(request)) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The V3 broker request must be a strict JSON object.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (containsForbiddenAuthorityField(request)) {
			return bridgeFailure(action, request, {
				code: "bridge_untrusted_authority_field",
				message: "Identity, authentication, approval, and signing fields are broker-owned.",
				odooEffect: "none",
				retryable: false,
			});
		}
		if (!validBrokerBusinessRequest(action, request)) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The V3 broker request does not match its business-only action schema.",
				odooEffect: "none",
				retryable: false,
			});
		}
		let body;
		try {
			body = serializeRequest(request);
		} catch {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_request_json",
				message: "The V3 broker request is not strict JSON.",
				odooEffect: "none",
				retryable: false,
			});
		}

		let response;
		try {
			response = await transport({
				action,
				body,
				maxOutputBytes,
				path: requestPath,
				registryDigest: expectedRegistryDigest,
				releaseDigest: expectedReleaseDigest,
				sessionHandle,
				socketPath: brokerSocketPath,
				timeoutMs,
			});
		} catch (error) {
			if (
				["read", "operation.diagnostics"].includes(action)
				|| (error instanceof BrokerTransportError && error.notDelivered)
			) {
				return bridgeFailure(action, request, {
					code: "bridge_v3_broker_unavailable",
					message: "The fixed local V3 trusted broker is unavailable.",
					odooEffect: "none",
					retryable: true,
				});
			}
			if (action !== "operation.approve_execute") {
				return bridgeFailure(action, request, {
					code: "bridge_v3_broker_reconciliation_required",
					message: "The trusted V3 broker request may have been accepted; reconcile it before retrying.",
					odooEffect: "none",
					reconciliationRequired: true,
					retryable: false,
				});
			}
			return bridgeFailure(action, request, {
				code: "bridge_v3_broker_outcome_unknown",
				message: "The trusted V3 broker request may have been accepted; reconcile it before retrying.",
				odooEffect: "unknown",
				retryable: false,
			});
		}
		const responseBodyIsSafeToInspect =
			isObject(response)
			&& typeof response.body === "string"
			&& Buffer.byteLength(response.body) <= maxOutputBytes
			&& !response.body.includes(sessionHandle);
		if (
			responseBodyIsSafeToInspect
			&& response.statusCode === 503
			&& response.authorityVerified === false
			&& response.executedReleaseDigest === undefined
			&& response.executedRegistryDigest === undefined
		) {
			const preauthReconciliation = parseSafePreauthReconciliationEnvelope(
				response.body,
				action,
			);
			if (preauthReconciliation) {
				return bindRequestedOriginOperationId(
					preauthReconciliation,
					action,
					request,
				);
			}
		}
		if (
			!isObject(response)
			|| response.statusCode !== 200
			|| response.authorityVerified !== true
			|| typeof response.body !== "string"
			|| Buffer.byteLength(response.body) > maxOutputBytes
			|| response.body.includes(sessionHandle)
		) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_v3_broker_response",
				message: "The V3 broker did not return its authenticated response contract.",
				odooEffect: action === "operation.approve_execute" ? "unknown" : "none",
				retryable: false,
			});
		}
		const cleanBody = response.body.trim();
		let envelopeClaimsSuccess = false;
		try {
			envelopeClaimsSuccess = JSON.parse(cleanBody)?.ok === true;
		} catch {
			// Strict envelope parsing below returns the public failure.
		}
		const executedIdentityValid =
			typeof response.executedReleaseDigest === "string"
			&& SHA256.test(response.executedReleaseDigest)
			&& typeof response.executedRegistryDigest === "string"
			&& SHA256.test(response.executedRegistryDigest);
		if (
			envelopeClaimsSuccess
			&& (
				!executedIdentityValid
				|| (
					["read", "operation.prepare", "operation.diagnostics"].includes(action)
					&& (
						response.executedReleaseDigest !== expectedReleaseDigest
						|| response.executedRegistryDigest !== expectedRegistryDigest
					)
				)
			)
		) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_v3_broker_response",
				message: "The V3 broker success response has no trusted executed-release identity.",
				odooEffect: action === "operation.approve_execute" ? "unknown" : "none",
				retryable: false,
			});
		}
		if (
			!envelopeClaimsSuccess
			&& (
				response.executedReleaseDigest !== undefined
				|| response.executedRegistryDigest !== undefined
			)
			&& !executedIdentityValid
		) {
			return bridgeFailure(action, request, {
				code: "bridge_invalid_v3_broker_response",
				message: "The V3 broker error response contains an invalid executed-release identity.",
				odooEffect: action === "operation.approve_execute" ? "unknown" : "none",
				retryable: false,
			});
		}
		const success = parseCliEnvelope(
			cleanBody,
			action,
			true,
			request,
			response.executedReleaseDigest,
			response.executedRegistryDigest,
		);
		if (success) {
			return success;
		}
		const failure = parseCliEnvelope(
			cleanBody,
			action,
			false,
			request,
			expectedReleaseDigest,
			expectedRegistryDigest,
		);
		if (failure) {
			return bindRequestedOriginOperationId(failure, action, request);
		}
		return bridgeFailure(action, request, {
			code: "bridge_invalid_v3_broker_response",
			message: "The V3 broker response failed signed-receipt structure and release binding validation.",
			odooEffect: action === "operation.approve_execute" ? "unknown" : "none",
			retryable: false,
		});
	};
}

export async function preflightV3BrokerSession(options = {}) {
	if (
		!isObject(options)
		|| Object.keys(options).some(
			(key) => !V3_BROKER_PREFLIGHT_OPTION_KEYS.includes(key),
		)
	) {
		return false;
	}
	const sessionHandle = options.sessionHandle;
	try {
		const run = createV3BrokerClient({
			brokerSocketPath: options.brokerSocketPath,
			expectedRegistryDigest: options.expectedRegistryDigest,
			expectedReleaseDigest: options.expectedReleaseDigest,
			sessionHandleProvider: () => sessionHandle,
			timeoutMs: options.timeoutMs,
			transport: options.transport,
		});
		const result = await run("read", {
			capability_id: REGISTRY_LIST_CAPABILITY_ID,
			parameters: {},
		});
		return result?.ok === true
			&& result.command === "read"
			&& result.data?.capability_id === REGISTRY_LIST_CAPABILITY_ID
			&& result.data?.result?.receipt?.capability_id
				=== REGISTRY_LIST_CAPABILITY_ID;
	} catch {
		return false;
	}
}

export function deriveCapabilityGetFromRegistryRead(
	signedRegistryRead,
	requestedCapabilityId,
) {
	if (
		typeof requestedCapabilityId !== "string"
		|| !CAPABILITY_ID.test(requestedCapabilityId)
	) {
		return bridgeFailure("capability.get", {}, {
			code: "bridge_invalid_request_json",
			message: "The capability query must contain one exact capability_id.",
			odooEffect: "none",
			retryable: false,
		});
	}
	if (signedRegistryRead?.ok === false) {
		return signedRegistryRead;
	}
	const releaseDigest =
		signedRegistryRead?.data?.release_identity?.manifest_sha256;
	const registryDigest =
		signedRegistryRead?.data?.release_identity?.registry_digest;
	const sourceRequest = {
		capability_id: REGISTRY_LIST_CAPABILITY_ID,
		parameters: {},
	};
	if (
		!exactKeys(signedRegistryRead, ["command", "data", "ok"])
		|| signedRegistryRead.command !== "read"
		|| signedRegistryRead.ok !== true
		|| !SHA256.test(releaseDigest)
		|| !SHA256.test(registryDigest)
		|| !validReadData(
			signedRegistryRead.data,
			sourceRequest,
			releaseDigest,
			registryDigest,
		)
	) {
		return bridgeFailure("capability.get", {}, {
			code: "bridge_invalid_v3_broker_response",
			message: "The authenticated capability registry response is invalid.",
			odooEffect: "none",
			retryable: false,
		});
	}
	const capabilities = signedRegistryRead.data.result.capabilities;
	const sourceIndex = capabilities.findIndex(
		(item) => item.id === requestedCapabilityId,
	);
	const visible = sourceIndex >= 0;
	const receipt = signedRegistryRead.data.result.receipt;
	return {
		command: "capability.get",
		data: {
			capability: visible ? capabilities[sourceIndex] : null,
			selection: {
				requested_capability_id: requestedCapabilityId,
				signed: false,
				source_index: visible ? sourceIndex : null,
				source_receipt_id: receipt.id,
				source_result_digest: receipt.result_digest,
				visible,
			},
			signed_registry_read: signedRegistryRead,
		},
		ok: true,
	};
}

export function addUnknownEffectGuidance(payload) {
	if (
		payload?.ok === false
		&& payload?.command === "operation.recover"
		&& payload?.error?.odoo_effect === "none"
		&& payload?.error?.reconciliation_required === true
		&& payload?.error?.retryable === false
		&& typeof payload?.error?.origin_operation_id === "string"
	) {
		return {
			...payload,
			bridge_guidance: {
				must_not_create_new_operation: true,
				next_action: "operation.diagnostics",
				origin_operation_id: payload.error.origin_operation_id,
				reason: "recovery_prepare_delivery_must_be_reconciled",
			},
		};
	}
	if (
		payload?.ok !== false
		|| payload?.error?.odoo_effect !== "unknown"
	) {
		return payload;
	}
	const operationId = typeof payload.error.operation_id === "string"
		? payload.error.operation_id
		: null;
	return {
		...payload,
		bridge_guidance: {
			must_not_create_new_operation: true,
			next_action: operationId ? "operation.status" : "operator_review",
			operation_id: operationId,
		},
	};
}

export const runV3Query = createV3CliRunner();
export const runV3BrokerOperation = createV3BrokerClient();
