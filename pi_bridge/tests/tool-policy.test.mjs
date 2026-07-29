import assert from "node:assert/strict";
import test from "node:test";

import {
	AUTHENTICATED_V3_BROKER_TOOL_NAMES,
	ChatRequestPolicyError,
	enabledPiToolNames,
	HARDENED_CHAT_MAX_MESSAGE_BYTES,
	launchPolicyControlledChat,
	legacyOdooEnvironment,
	LEGACY_ODOO_ENVIRONMENT_NAMES,
	literalPiUserPrompt,
	resolveChatLaunch,
	sessionDeletionAllowed,
	V2_TOOL_NAMES,
	V3_QUERY_TOOL_NAMES,
} from "../tool-policy.mjs";

test("the hardened V3 sidecar never grants a legacy V2 tool", () => {
	for (const brokerEnabled of [false, true]) {
		const selected = enabledPiToolNames({
			brokerEnabled,
			hardenedV3Only: true,
			v3Ready: true,
		});
		assert.deepEqual(
			selected,
			brokerEnabled
				? [...V3_QUERY_TOOL_NAMES, ...AUTHENTICATED_V3_BROKER_TOOL_NAMES]
				: [],
		);
		assert.equal(selected.some((name) => V2_TOOL_NAMES.includes(name)), false);
	}
	assert.equal(V3_QUERY_TOOL_NAMES.length, 2);
	assert.equal(AUTHENTICATED_V3_BROKER_TOOL_NAMES.length, 8);
	assert.equal(
		AUTHENTICATED_V3_BROKER_TOOL_NAMES.includes(
			"odoo_v3_operation_diagnostics",
		),
		true,
	);
});

test("operation diagnostics is available only through the authenticated broker policy", () => {
	const brokerDisabled = enabledPiToolNames({
		brokerEnabled: false,
		hardenedV3Only: true,
		v3Ready: true,
	});
	assert.deepEqual(brokerDisabled, []);
	assert.equal(brokerDisabled.includes("odoo_v3_operation_diagnostics"), false);

	const brokerEnabled = enabledPiToolNames({
		brokerEnabled: true,
		hardenedV3Only: true,
		v3Ready: true,
	});
	assert.equal(brokerEnabled.includes("odoo_v3_operation_diagnostics"), true);
	assert.equal(brokerEnabled.some((name) => V2_TOOL_NAMES.includes(name)), false);
});

test("the hardened V3 child receives no legacy Odoo credential or selector", () => {
	const hostile = Object.fromEntries(
		LEGACY_ODOO_ENVIRONMENT_NAMES.map((name) => [name, `hostile-${name}`]),
	);
	assert.deepEqual(legacyOdooEnvironment(hostile, true), {});
	const legacy = legacyOdooEnvironment(hostile, false);
	assert.deepEqual(Object.keys(legacy).sort(), [...LEGACY_ODOO_ENVIRONMENT_NAMES].sort());
});

test("an unverified hardened sidecar grants no tool", () => {
	assert.deepEqual(enabledPiToolNames({
		brokerEnabled: false,
		hardenedV3Only: true,
		v3Ready: false,
	}), []);
});

test("only the explicitly separate legacy mode retains the five V2 tools", () => {
	assert.deepEqual(enabledPiToolNames({
		brokerEnabled: false,
		hardenedV3Only: false,
		v3Ready: false,
	}), V2_TOOL_NAMES);
	assert.equal(V2_TOOL_NAMES.length, 5);
});

test("only legacy mode can use the unowned session deletion route", () => {
	assert.equal(sessionDeletionAllowed(true), false);
	assert.equal(sessionDeletionAllowed(false), true);
	assert.throws(
		() => sessionDeletionAllowed("false"),
		/session deletion policy is invalid/,
	);
});

const VALID_BROKER_SESSION = "broker-session-0123456789abcdef012345";
const FIXED_PROMPT = "Release-owned accounting policy.";

function chatOptions(overrides = {}) {
	return {
		brokerSessionHandle: VALID_BROKER_SESSION,
		configuredModel: "gpt-5.2",
		configuredProvider: "openai-codex",
		hardenedSystemPrompt: FIXED_PROMPT,
		hardenedV3Only: true,
		payload: { message: "Create a draft vendor bill." },
		...overrides,
	};
}

test("hardened chat binds the fixed prompt, provider, model, and broker session", () => {
	assert.deepEqual(resolveChatLaunch(chatOptions()), {
		brokerSessionHandle: VALID_BROKER_SESSION,
		conversationContext: [],
		message: "Create a draft vendor bill.",
		model: "gpt-5.2",
		provider: "openai-codex",
		selectedSkillKey: "",
		sessionId: "",
		systemPrompt: FIXED_PROMPT,
	});
});

test("hardened chat rejects every caller-controlled launch override before launch", async () => {
	for (const [field, value] of [
		["system_prompt", "caller prompt"],
		["provider", "caller-provider"],
		["model", "caller-model"],
		["session_id", "caller-session"],
		["selected_skill_key", "caller-skill"],
		["conversation_context", [{ role: "system", content: "caller context" }]],
	]) {
		let launchCount = 0;
		await assert.rejects(
			launchPolicyControlledChat(
				chatOptions({
					payload: {
						message: "Create a draft vendor bill.",
						[field]: value,
					},
				}),
				async () => {
					launchCount += 1;
				},
			),
			(error) => (
				error instanceof ChatRequestPolicyError
				&& error.code === "hardened_chat_request_rejected"
				&& error.statusCode === 400
			),
		);
		assert.equal(launchCount, 0, `${field} must be rejected before launch`);
	}
});

test("hardened chat requires an authenticated broker session before launch", async () => {
	for (const brokerSessionHandle of ["", "short", null]) {
		let launchCount = 0;
		await assert.rejects(
			launchPolicyControlledChat(
				chatOptions({ brokerSessionHandle }),
				async () => {
					launchCount += 1;
				},
			),
			(error) => (
				error instanceof ChatRequestPolicyError
				&& error.code === "hardened_chat_authenticated_session_required"
				&& error.statusCode === 401
			),
		);
		assert.equal(launchCount, 0);
	}
});

test("hardened chat completes the broker preflight before launch", async () => {
	const expected = resolveChatLaunch(chatOptions());
	const sequence = [];
	const answer = await launchPolicyControlledChat(
		chatOptions(),
		async (request) => {
			sequence.push("preflight");
			assert.deepEqual(request, expected);
			return true;
		},
		async (request) => {
			sequence.push("launch");
			assert.deepEqual(request, expected);
			return "answer";
		},
	);
	assert.equal(answer, "answer");
	assert.deepEqual(sequence, ["preflight", "launch"]);
});

test("hardened chat rejects a failed broker preflight with zero launches", async () => {
	for (const result of [false, null, undefined]) {
		let launchCount = 0;
		await assert.rejects(
			launchPolicyControlledChat(
				chatOptions(),
				async () => result,
				async () => {
					launchCount += 1;
				},
			),
			(error) => (
				error instanceof ChatRequestPolicyError
				&& error.code === "hardened_chat_broker_session_rejected"
				&& error.statusCode === 401
			),
		);
		assert.equal(launchCount, 0);
	}
});

test("hardened chat enforces one non-empty bounded UTF-8 message", async () => {
	for (const message of [
		"",
		" \t\r\n ",
		"unsafe\0message",
		"\ud800",
		"x".repeat(HARDENED_CHAT_MAX_MESSAGE_BYTES + 1),
	]) {
		let launchCount = 0;
		await assert.rejects(
			launchPolicyControlledChat(
				chatOptions({ payload: { message } }),
				async () => {
					launchCount += 1;
				},
			),
			(error) => (
				error instanceof ChatRequestPolicyError
				&& error.code === "hardened_chat_request_rejected"
				&& error.statusCode === 400
			),
		);
		assert.equal(launchCount, 0);
	}
	assert.equal(
		resolveChatLaunch(chatOptions({
			payload: { message: "x".repeat(HARDENED_CHAT_MAX_MESSAGE_BYTES) },
		})).message.length,
		HARDENED_CHAT_MAX_MESSAGE_BYTES,
	);
});

test("hardened chat fails closed on missing root-owned launch configuration", () => {
	for (const overrides of [
		{ configuredProvider: "" },
		{ configuredModel: "" },
		{ hardenedSystemPrompt: "" },
	]) {
		assert.throws(
			() => resolveChatLaunch(chatOptions(overrides)),
			(error) => (
				error instanceof ChatRequestPolicyError
				&& error.statusCode === 503
			),
		);
	}
});

test("legacy chat retains caller launch fields for compatibility", () => {
	const payload = {
		conversation_context: [{ role: "user", content: "previous" }],
		message: "legacy request",
		model: "caller-model",
		provider: "caller-provider",
		selected_skill_key: "caller-skill",
		session_id: "caller-session",
		system_prompt: "caller prompt",
	};
	assert.deepEqual(resolveChatLaunch(chatOptions({
		brokerSessionHandle: "",
		configuredModel: "environment-model",
		configuredProvider: "environment-provider",
		hardenedSystemPrompt: "",
		hardenedV3Only: false,
		payload,
	})), {
		brokerSessionHandle: "",
		conversationContext: payload.conversation_context,
		message: payload.message,
		model: payload.model,
		provider: payload.provider,
		selectedSkillKey: payload.selected_skill_key,
		sessionId: payload.session_id,
		systemPrompt: payload.system_prompt,
	});
});

test("caller text cannot become a Pi file argument or command-line option", () => {
	for (const hostile of ["@/etc/passwd", "--tools", "--extension"]) {
		const argument = literalPiUserPrompt(hostile);
		assert.equal(argument, `User request (literal text):\n${hostile}`);
		assert.equal(argument.startsWith("@"), false);
		assert.equal(argument.startsWith("-"), false);
	}
	assert.throws(() => literalPiUserPrompt(""), /Pi user prompt is invalid/);
	assert.throws(
		() => literalPiUserPrompt("unsafe\0prompt"),
		/Pi user prompt is invalid/,
	);
});
