import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
	V3_BROKER_ACTION_PATHS,
	createV3BrokerClient,
	createV3CliRunner,
} from "../extensions/odoo-v3-cli.mjs";
import {
	loadAuthenticatedSessionResolver,
	resolveAuthenticatedBrokerSession,
} from "../trusted-session.mjs";

const RELEASE_DIGEST = "7".repeat(64);
const REGISTRY_DIGEST = "a".repeat(64);
const SESSION_HANDLE = "opaque-broker-session-0123456789abcdef";

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function signedWriteReceipt(operationId = "op-1") {
	return {
		receipt_id: "receipt-1",
		request_id: "request-from-broker",
		operation_id: operationId,
		capability_id: "acct.bill.vendor_create.v1",
		principal: "pi:user-42",
		odoo_instance_id: "odoo19@sandbox",
		database_name: "odoo_v3_sandbox",
		database_uuid: "11111111-1111-4111-8111-111111111111",
		user_id: 42,
		approver_user_id: 99,
		company_id: 7,
		environment: "sandbox",
		capability_channel: "staged",
		request_digest: "2".repeat(64),
		operation_digest: "3".repeat(64),
		approval_digest: "4".repeat(64),
		result_digest: "5".repeat(64),
		verification_evidence_digest: "1".repeat(64),
		registry_digest: REGISTRY_DIGEST,
		release_digest: RELEASE_DIGEST,
		audit_head: "8".repeat(64),
		issued_at: "2026-07-15T08:01:00Z",
		signature_version: 1,
		signature_purpose: "write_audit_receipt_v1",
		signing_key_id: "audit-key-1",
		signature: "9".repeat(64),
	};
}

function databaseFinalization(operationId = "op-1") {
	return {
		attestation_digest: "a".repeat(64),
		attestation_id: "22222222-2222-5222-8222-222222222222",
		attestation_key_id: "effect-finalizer-v1",
		database_oid: 16384,
		database_uuid: "11111111-1111-4111-8111-111111111111",
		finalized_at: "2026-07-15T08:01:00Z",
		finalized_txid: "9123",
		guard_epoch: 0,
		guard_installation_id: "33333333-3333-4333-8333-333333333333",
		intent_digest: "b".repeat(64),
		operation_id: operationId,
		proof_expires_at: "2026-07-15T08:05:00Z",
		proof_verified_at: "2026-07-15T08:00:00Z",
		protocol_version: 1,
		receipt_digest: "c".repeat(64),
		remaining_unresolved_count: 0,
		request_digest: "d".repeat(64),
		resolution_kind: "verified",
		resolution_operation_id: operationId,
		resolved_anchor_count: 1,
	};
}

function diagnosticsResponse(request) {
	return {
		command: "operation.diagnostics",
		data: {
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
			failure: {
				present: false,
				stage: null,
				result_id: null,
				evidence_digest: null,
			},
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
				odoo_instance_id: "odoo19@test",
				database_name: "odoo_v3_test",
				database_uuid: "11111111-1111-4111-8111-111111111111",
				company_id: request.company_id,
				user_id: 42,
				capability_id: "acct.diagnostics.operation_read.v1",
				environment: "test",
				capability_channel: "staged",
				request_digest: "a".repeat(64),
				result_digest: "b".repeat(64),
				registry_digest: REGISTRY_DIGEST,
				release_digest: RELEASE_DIGEST,
				record_count: 1,
				observed_at: "2026-07-15T08:01:00Z",
				signature_version: 2,
				signature_purpose: "read_receipt_v2",
				signature_key_id: "read-key-1",
				signature: "e".repeat(64),
			},
		},
		ok: true,
	};
}

function responseFor(action, request) {
	if (action === "read") {
		return {
			command: "read",
			data: {
				capability_id: request.capability_id,
				release_identity: {
					verified: true,
					manifest_sha256: RELEASE_DIGEST,
					registry_digest: REGISTRY_DIGEST,
				},
				result: {
					receipt: {
						id: "read-receipt-1",
						odoo_instance_id: "odoo19@sandbox",
						database_name: "odoo_v3_sandbox",
						database_uuid: "11111111-1111-4111-8111-111111111111",
						company_id: 7,
						environment: "sandbox",
						user_id: 42,
						capability_id: request.capability_id,
						capability_channel: "staged",
						request_digest: "a".repeat(64),
						result_digest: "b".repeat(64),
						registry_digest: REGISTRY_DIGEST,
						release_digest: RELEASE_DIGEST,
						record_count: 0,
						observed_at: "2026-07-15T08:01:00Z",
						signature_version: 2,
						signature_purpose: "read_receipt_v2",
						signature_key_id: "read-key-1",
						signature: "e".repeat(64),
					},
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
				operation_id: request.operation_id,
				operation_state: "completed",
				verification: {
					method: "fresh_odoo_readback",
					passed: true,
					checks: ["record_fingerprint_matches"],
					evidence_digest: "1".repeat(64),
					verified_at: "2026-07-15T08:01:00Z",
				},
				database_finalization: databaseFinalization(request.operation_id),
				audit_receipt: signedWriteReceipt(request.operation_id),
			},
			ok: true,
		};
	}
	if (action === "operation.diagnostics") {
		return diagnosticsResponse(request);
	}
	return {
		command: action,
		data: { accepted_business_request: request },
		ok: true,
	};
}

function brokerHarness(responseFactory = responseFor, executedIdentity = {}) {
	const calls = [];
	const client = createV3BrokerClient({
		brokerSocketPath: "/run/odoo-accounting-cli-v3/pi-broker.sock",
		expectedRegistryDigest: REGISTRY_DIGEST,
		expectedReleaseDigest: RELEASE_DIGEST,
		sessionHandleProvider: () => SESSION_HANDLE,
		transport: async (call) => {
			calls.push(structuredClone(call));
			const request = JSON.parse(call.body);
			return {
				authorityVerified: true,
				body: JSON.stringify(responseFactory(call.action, request)),
				executedRegistryDigest:
					executedIdentity.registryDigest ?? REGISTRY_DIGEST,
				executedReleaseDigest:
					executedIdentity.releaseDigest ?? RELEASE_DIGEST,
				statusCode: 200,
			};
		},
	});
	return { calls, client };
}

test("model-facing business requests cross the fixed broker socket byte-for-byte", async (t) => {
	const requests = {
		read: {
			capability_id: "acct.gl.trial_balance.v1",
			parameters: { company_id: 7, date_from: "2026-01-01", date_to: "2026-07-15" },
		},
		"operation.prepare": {
			capability_id: "acct.bill.vendor_create.v1",
			parameters: { company_id: 7, partner_id: 901, currency_id: 12, idempotency_key: "bill-1" },
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

	for (const [action, request] of Object.entries(requests)) {
		await t.test(action, async () => {
			const { calls, client } = brokerHarness();
			const before = structuredClone(request);
			const result = await client(action, request);
			assert.equal(result.ok, true);
			assert.deepEqual(request, before);
			assert.equal(calls.length, 1);
			assert.equal(calls[0].body, JSON.stringify(before));
			assert.equal(calls[0].path, V3_BROKER_ACTION_PATHS[action]);
			assert.equal(calls[0].socketPath, "/run/odoo-accounting-cli-v3/pi-broker.sock");
			assert.equal(calls[0].sessionHandle, SESSION_HANDLE);
			assert.equal(calls[0].body.includes(SESSION_HANDLE), false);
			for (const forbidden of ["context", "approval", "approver_user_id", "auth_signature"])
				assert.equal(Object.hasOwn(request, forbidden), false);
		});
	}
});

test("operation diagnostics accepts one release-bound receipt and rejects tampering", async (t) => {
	const request = { company_id: 7, operation_id: "op-1" };
	const { client } = brokerHarness();
	const accepted = await client("operation.diagnostics", request);
	assert.equal(accepted.ok, true);
	assert.equal(accepted.data.operation.operation_id, request.operation_id);
	assert.equal(accepted.data.receipt.company_id, request.company_id);
	assert.equal(
		accepted.data.receipt.capability_id,
		"acct.diagnostics.operation_read.v1",
	);

	for (const [name, mutate] of [
		["operation id", (response) => {
			response.data.operation.operation_id = "op-tampered";
		}],
		["operation company", (response) => {
			response.data.operation.company_id = 8;
		}],
		["receipt company", (response) => {
			response.data.receipt.company_id = 8;
		}],
		["receipt release", (response) => {
			response.data.receipt.release_digest = "f".repeat(64);
		}],
		["receipt registry", (response) => {
			response.data.receipt.registry_digest = "f".repeat(64);
		}],
		["receipt count", (response) => {
			response.data.receipt.record_count = 0;
		}],
		["receipt signature", (response) => {
			delete response.data.receipt.signature;
		}],
	]) {
		await t.test(name, async () => {
			const harness = brokerHarness((_action, requested) => {
				const response = diagnosticsResponse(requested);
				mutate(response);
				return response;
			});
			const rejected = await harness.client(
				"operation.diagnostics",
				request,
			);
			assert.equal(rejected.ok, false);
			assert.equal(
				rejected.error.code,
				"bridge_invalid_v3_broker_response",
			);
		});
	}
});

test("operation diagnostics cannot switch to a broker-selected historical release", async () => {
	const historicalRelease = "c".repeat(64);
	const historicalRegistry = "d".repeat(64);
	const { client } = brokerHarness((_action, request) => {
		const response = diagnosticsResponse(request);
		response.data.receipt.release_digest = historicalRelease;
		response.data.receipt.registry_digest = historicalRegistry;
		return response;
	}, {
		registryDigest: historicalRegistry,
		releaseDigest: historicalRelease,
	});

	const rejected = await client(
		"operation.diagnostics",
		{ company_id: 7, operation_id: "op-1" },
	);
	assert.equal(rejected.ok, false);
	assert.equal(
		rejected.error.code,
		"bridge_invalid_v3_broker_response",
	);
});

test("operation diagnostics keeps company authority fields strict before broker transport", async () => {
	const { calls, client } = brokerHarness();
	for (const [request, expectedCode] of [
		[{ operation_id: "op-1" }, "bridge_invalid_request_json"],
		[{ company_id: 0, operation_id: "op-1" }, "bridge_invalid_request_json"],
		[
			{ company_id: 7, operation_id: "op-1", user_id: 1 },
			"bridge_untrusted_authority_field",
		],
		[
			{
				company_id: 7,
				context: { allowed_company_ids: [7, 8], user_id: 1 },
				operation_id: "op-1",
			},
			"bridge_untrusted_authority_field",
		],
	]) {
		const result = await client("operation.diagnostics", request);
		assert.equal(result.ok, false);
		assert.equal(result.error.code, expectedCode);
	}
	assert.equal(calls.length, 0);
});

test("approval execution exposes only operation_id and cannot mint an approval", async () => {
	const { calls, client } = brokerHarness();
	const result = await client("operation.approve_execute", { operation_id: "op-1" });
	assert.equal(result.ok, true);
	assert.deepEqual(JSON.parse(calls[0].body), { operation_id: "op-1" });

	for (const injected of [
		{ operation_id: "op-1", approval: { signature: "attacker" } },
		{ operation_id: "op-1", approver_user_id: 1 },
		{ operation_id: "op-1", context: { user_id: 1, company_id: 1 } },
	]) {
		const before = calls.length;
		const rejected = await client("operation.approve_execute", injected);
		assert.equal(rejected.ok, false);
		assert.equal(rejected.error.code, "bridge_untrusted_authority_field");
		assert.equal(calls.length, before);
	}
});

test("prompt-injected identity, authentication, approval, and signing fields never reach the broker", async () => {
	const { calls, client } = brokerHarness();
	for (const parameters of [
		{ company_id: 7, context: { user_id: 1 } },
		{ company_id: 7, approval: { approver_user_id: 1 } },
		{ company_id: 7, auth_signature: "attacker" },
		{ company_id: 7, signing_key_id: "attacker" },
		{ company_id: 7, metadata: { principal: "root" } },
		{
			company_id: 7,
			metadata: {
				broker_socket: "/tmp/attacker.sock",
				release_digest: "f".repeat(64),
				runtime_config_path: "/tmp/attacker.json",
			},
		},
	]) {
		const result = await client("operation.prepare", {
			capability_id: "acct.bill.vendor_create.v1",
			parameters,
		});
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_untrusted_authority_field");
	}
	assert.equal(calls.length, 0);
});

test("missing broker, authenticated session, or release identity rejects before transport or CLI", async () => {
	let transports = 0;
	const base = {
		expectedRegistryDigest: REGISTRY_DIGEST,
		expectedReleaseDigest: RELEASE_DIGEST,
		transport: async () => {
			transports += 1;
			throw new Error("must not run");
		},
	};
	const request = { operation_id: "op-1" };
	let result = await createV3BrokerClient({
		...base,
		sessionHandleProvider: () => SESSION_HANDLE,
	})("operation.status", request);
	assert.equal(result.error.code, "bridge_v3_broker_not_configured");

	result = await createV3BrokerClient({
		...base,
		brokerSocketPath: "/run/odoo-accounting-cli-v3/pi-broker.sock",
		sessionHandleProvider: () => "",
	})("operation.status", request);
	assert.equal(result.error.code, "bridge_v3_session_not_authenticated");

	result = await createV3BrokerClient({
		...base,
		brokerSocketPath: "/run/odoo-accounting-cli-v3/pi-broker.sock",
		expectedRegistryDigest: "",
		sessionHandleProvider: () => SESSION_HANDLE,
	})("operation.status", request);
	assert.equal(result.error.code, "bridge_v3_identity_not_configured");
	assert.equal(transports, 0);

	const direct = createV3CliRunner({
		cliPath: process.execPath,
		expectedRegistryDigest: REGISTRY_DIGEST,
		expectedReleaseDigest: RELEASE_DIGEST,
	});
	result = await direct("operation.status", request);
	assert.equal(result.error.code, "bridge_v3_broker_required");
});

test("terminal results remain bound to signed release and registry receipts", async () => {
	for (const mutate of [
		(receipt) => { delete receipt.signature; },
		(receipt) => { receipt.release_digest = "f".repeat(64); },
		(receipt) => { receipt.registry_digest = "f".repeat(64); },
	]) {
		const { client } = brokerHarness((action, request) => {
			const response = responseFor(action, request);
			mutate(response.data.audit_receipt);
			return response;
		});
		const result = await client("operation.result", { operation_id: "op-1" });
		assert.equal(result.ok, false);
		assert.equal(result.error.code, "bridge_invalid_v3_broker_response");
	}
});

test("historical operation receipts bind broker-selected executed identity, never caller routing fields", async () => {
	const historicalRelease = "c".repeat(64);
	const historicalRegistry = "d".repeat(64);
	const { client } = brokerHarness((action, request) => {
		const response = responseFor(action, request);
		response.data.audit_receipt.release_digest = historicalRelease;
		response.data.audit_receipt.registry_digest = historicalRegistry;
		return response;
	}, {
		registryDigest: historicalRegistry,
		releaseDigest: historicalRelease,
	});
	const result = await client("operation.result", { operation_id: "op-historical" });
	assert.equal(result.ok, true);
	assert.equal(result.data.audit_receipt.release_digest, historicalRelease);

	const rejected = await client("operation.result", {
		operation_id: "op-historical",
		release_digest: historicalRelease,
	});
	assert.equal(rejected.ok, false);
	assert.equal(rejected.error.code, "bridge_untrusted_authority_field");
});

test("broker errors and results never echo the authenticated session handle", async () => {
	const { client } = brokerHarness(() => ({
		command: "operation.status",
		error: {
			code: "operation_not_found",
			message: "No operation exists for the authenticated session.",
			odoo_effect: "none",
			retryable: false,
		},
		ok: false,
	}));
	const result = await client("operation.status", { operation_id: "op-1" });
	assert.equal(JSON.stringify(result).includes(SESSION_HANDLE), false);
});

test("the server accepts only an injected authenticated-session resolver", async () => {
	assert.equal(await loadAuthenticatedSessionResolver(""), null);
	const temp = await mkdtemp(path.join(os.tmpdir(), "pi-v3-session-resolver-"));
	try {
		const modulePath = path.join(temp, "resolver.mjs");
		await writeFile(modulePath, `
export async function resolveAuthenticatedSession(request) {
  if (request.headers.authorization !== "Bearer upstream-verified") return null;
  return { brokerSessionHandle: "${SESSION_HANDLE}" };
}
`, "utf8");
		const resolver = await loadAuthenticatedSessionResolver(modulePath);
		const resolved = await resolveAuthenticatedBrokerSession(resolver, {
			headers: { authorization: "Bearer upstream-verified" },
			method: "POST",
			remoteAddress: "127.0.0.1",
			url: "/chat",
		});
		assert.deepEqual(resolved, { brokerSessionHandle: SESSION_HANDLE });
		assert.equal(await resolveAuthenticatedBrokerSession(null, {}), null);
		assert.equal(await resolveAuthenticatedBrokerSession(resolver, {
			headers: { authorization: "Bearer attacker" },
		}), null);
	} finally {
		await rm(temp, { force: true, recursive: true });
	}
});

test("the shipped Odoo header resolver accepts only the exact loopback chat boundary", async () => {
	const modulePath = path.resolve(
		path.dirname(fileURLToPath(import.meta.url)),
		"..",
		"odoo-session-header-resolver.mjs",
	);
	const resolver = await loadAuthenticatedSessionResolver(modulePath);
	const accepted = await resolveAuthenticatedBrokerSession(resolver, {
		headers: { "x-odoo-v3-broker-session": SESSION_HANDLE },
		method: "POST",
		remoteAddress: "127.0.0.1",
		url: "/chat",
	});
	assert.deepEqual(accepted, { brokerSessionHandle: SESSION_HANDLE });

	for (const request of [
		{
			headers: { "x-odoo-v3-broker-session": SESSION_HANDLE },
			method: "GET",
			remoteAddress: "127.0.0.1",
			url: "/chat",
		},
		{
			headers: { "x-odoo-v3-broker-session": SESSION_HANDLE },
			method: "POST",
			remoteAddress: "10.0.0.8",
			url: "/chat",
		},
		{
			headers: { "x-odoo-v3-broker-session": SESSION_HANDLE },
			method: "POST",
			remoteAddress: "127.0.0.1",
			url: "/session/delete",
		},
		{
			headers: { "x-odoo-v3-broker-session": [SESSION_HANDLE] },
			method: "POST",
			remoteAddress: "127.0.0.1",
			url: "/chat",
		},
		{
			headers: { "x-odoo-v3-broker-session": `${SESSION_HANDLE},${SESSION_HANDLE}` },
			method: "POST",
			remoteAddress: "127.0.0.1",
			url: "/chat",
		},
	]) {
		assert.equal(await resolveAuthenticatedBrokerSession(resolver, request), null);
	}
});

test("the session resolver binds exact bytes and rejects dependency and export expansion", async () => {
	const temp = await mkdtemp(path.join(os.tmpdir(), "pi-v3-pinned-resolver-"));
	try {
		const modulePath = path.join(temp, "resolver.mjs");
		const source = `
export default async function resolver() {
  return { brokerSessionHandle: "${SESSION_HANDLE}" };
}
`;
		await writeFile(modulePath, source, "utf8");
		const resolver = await loadAuthenticatedSessionResolver(modulePath, {
			expectedSha256: sha256(source),
		});
		assert.deepEqual(await resolveAuthenticatedBrokerSession(resolver, {}), {
			brokerSessionHandle: SESSION_HANDLE,
		});

		await writeFile(modulePath, `${source}\n// changed\n`, "utf8");
		await assert.rejects(
			loadAuthenticatedSessionResolver(modulePath, {
				expectedSha256: sha256(source),
			}),
			/SHA-256 does not match/,
		);

		const dependencySource = `
import "./replaceable-identity.mjs";
export default async function resolver() { return null; }
`;
		await writeFile(modulePath, dependencySource, "utf8");
		await assert.rejects(
			loadAuthenticatedSessionResolver(modulePath, {
				expectedSha256: sha256(dependencySource),
			}),
			/dependency-free/,
		);

		const extraExportSource = `
export const extraAuthority = true;
export default async function resolver() { return null; }
`;
		await writeFile(modulePath, extraExportSource, "utf8");
		await assert.rejects(
			loadAuthenticatedSessionResolver(modulePath, {
				expectedSha256: sha256(extraExportSource),
			}),
			/exports are invalid/,
		);
	} finally {
		await rm(temp, { force: true, recursive: true });
	}
});

test("the production resolver loader rejects a missing digest and unsafe ancestor", {
	skip: process.platform !== "linux",
}, async () => {
	const temp = await mkdtemp(path.join(os.tmpdir(), "pi-v3-root-resolver-"));
	try {
		const modulePath = path.join(temp, "resolver.mjs");
		const source = "export default async function resolver() { return null; }\n";
		await writeFile(modulePath, source, { encoding: "utf8", mode: 0o644 });
		await assert.rejects(
			loadAuthenticatedSessionResolver(modulePath, { requireRootOwned: true }),
			/requires a SHA-256 binding/,
		);
		await assert.rejects(
			loadAuthenticatedSessionResolver(modulePath, {
				expectedSha256: sha256(source),
				requireRootOwned: true,
			}),
			/ancestors must be root-owned and non-writable/,
		);
	} finally {
		await rm(temp, { force: true, recursive: true });
	}
});
