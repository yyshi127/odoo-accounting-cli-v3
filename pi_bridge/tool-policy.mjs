import { V3_TOOL_NAMES } from "./extensions/odoo-v3-cli.mjs";

export const V2_TOOL_NAMES = Object.freeze([
	"odoo_get_context",
	"odoo_list_skills",
	"odoo_execute_skill",
	"odoo_list_reports",
	"odoo_export_report",
]);

export const V3_QUERY_TOOL_NAMES = Object.freeze([
	V3_TOOL_NAMES.capabilityList,
	V3_TOOL_NAMES.capabilityGet,
]);

export const AUTHENTICATED_V3_BROKER_TOOL_NAMES = Object.freeze([
	V3_TOOL_NAMES.read,
	V3_TOOL_NAMES.prepare,
	V3_TOOL_NAMES.preview,
	V3_TOOL_NAMES.approveExecute,
	V3_TOOL_NAMES.status,
	V3_TOOL_NAMES.result,
	V3_TOOL_NAMES.diagnostics,
	V3_TOOL_NAMES.recover,
]);

export const LEGACY_ODOO_ENVIRONMENT_NAMES = Object.freeze([
	"ODOO_TOOL_URL",
	"ODOO_TOOL_TOKEN",
	"ODOO_TOOL_DATABASE",
	"ODOO_TOOL_USER_ID",
	"ODOO_TOOL_COMPANY_ID",
]);

export const HARDENED_CHAT_MAX_MESSAGE_BYTES = 8 * 1024;

const BROKER_SESSION_HANDLE = /^[A-Za-z0-9._~-]{32,512}$/;
const PI_SELECTOR = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const MAX_SYSTEM_PROMPT_BYTES = 64 * 1024;

export class ChatRequestPolicyError extends Error {
	constructor(code, statusCode) {
		super(code);
		this.code = code;
		this.statusCode = statusCode;
	}
}

function exactObjectKeys(value, keys) {
	return value !== null
		&& typeof value === "object"
		&& !Array.isArray(value)
		&& JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function validUnicodeString(value) {
	if (typeof value !== "string") return false;
	for (let index = 0; index < value.length; index += 1) {
		const codeUnit = value.charCodeAt(index);
		if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
				return false;
			}
			index += 1;
		} else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
			return false;
		}
	}
	return true;
}

function strictBusinessMessage(value) {
	if (
		!validUnicodeString(value)
		|| value.trim().length === 0
		|| value.includes("\0")
		|| Buffer.byteLength(value, "utf8") > HARDENED_CHAT_MAX_MESSAGE_BYTES
	) {
		throw new ChatRequestPolicyError("hardened_chat_request_rejected", 400);
	}
	return value;
}

function trustedPiSelector(value) {
	if (typeof value !== "string" || PI_SELECTOR.test(value) === false) {
		throw new ChatRequestPolicyError(
			"hardened_chat_runtime_configuration_rejected",
			503,
		);
	}
	return value;
}

function trustedSystemPrompt(value) {
	if (
		!validUnicodeString(value)
		|| value.trim().length === 0
		|| value.includes("\0")
		|| Buffer.byteLength(value, "utf8") > MAX_SYSTEM_PROMPT_BYTES
	) {
		throw new ChatRequestPolicyError(
			"hardened_chat_system_prompt_rejected",
			503,
		);
	}
	return value;
}

export function resolveChatLaunch(options) {
	if (
		!exactObjectKeys(options, [
			"brokerSessionHandle",
			"configuredModel",
			"configuredProvider",
			"hardenedSystemPrompt",
			"hardenedV3Only",
			"payload",
		])
		|| typeof options.hardenedV3Only !== "boolean"
	) {
		throw new ChatRequestPolicyError("chat_launch_policy_rejected", 500);
	}
	const {
		brokerSessionHandle,
		configuredModel,
		configuredProvider,
		hardenedSystemPrompt,
		hardenedV3Only,
		payload,
	} = options;
	if (hardenedV3Only) {
		if (
			typeof brokerSessionHandle !== "string"
			|| BROKER_SESSION_HANDLE.test(brokerSessionHandle) === false
		) {
			throw new ChatRequestPolicyError(
				"hardened_chat_authenticated_session_required",
				401,
			);
		}
		if (!exactObjectKeys(payload, ["message"])) {
			throw new ChatRequestPolicyError("hardened_chat_request_rejected", 400);
		}
		return Object.freeze({
			brokerSessionHandle,
			conversationContext: Object.freeze([]),
			message: strictBusinessMessage(payload.message),
			model: trustedPiSelector(configuredModel),
			provider: trustedPiSelector(configuredProvider),
			selectedSkillKey: "",
			sessionId: "",
			systemPrompt: trustedSystemPrompt(hardenedSystemPrompt),
		});
	}
	const legacyPayload = payload !== null && typeof payload === "object"
		? payload
		: {};
	return Object.freeze({
		brokerSessionHandle:
			typeof brokerSessionHandle === "string" ? brokerSessionHandle : "",
		conversationContext: legacyPayload.conversation_context || [],
		message: legacyPayload.message,
		model: legacyPayload.model || configuredModel || "",
		provider: legacyPayload.provider || configuredProvider || "",
		selectedSkillKey: legacyPayload.selected_skill_key || "",
		sessionId: legacyPayload.session_id || "",
		systemPrompt: legacyPayload.system_prompt,
	});
}

export async function launchPolicyControlledChat(options, preflight, launch) {
	const launchRequest = resolveChatLaunch(options);
	if (options.hardenedV3Only) {
		if (typeof preflight !== "function") {
			throw new ChatRequestPolicyError(
				"hardened_chat_preflight_configuration_rejected",
				500,
			);
		}
		if (await preflight(launchRequest) !== true) {
			throw new ChatRequestPolicyError(
				"hardened_chat_broker_session_rejected",
				401,
			);
		}
	} else if (launch === undefined) {
		launch = preflight;
	}
	if (typeof launch !== "function") {
		throw new ChatRequestPolicyError("chat_launch_function_rejected", 500);
	}
	return await launch(launchRequest);
}

export function legacyOdooEnvironment(source, hardenedV3Only) {
	if (
		source === null
		|| typeof source !== "object"
		|| Array.isArray(source)
		|| typeof hardenedV3Only !== "boolean"
	) {
		throw new Error("legacy Odoo environment policy is invalid");
	}
	if (hardenedV3Only) return Object.freeze({});
	return Object.freeze({
		ODOO_TOOL_COMPANY_ID: source.ODOO_TOOL_COMPANY_ID || "",
		ODOO_TOOL_DATABASE: source.ODOO_TOOL_DATABASE || "",
		ODOO_TOOL_TOKEN: source.ODOO_TOOL_TOKEN || "",
		ODOO_TOOL_URL: source.ODOO_TOOL_URL
			|| "http://127.0.0.1:8069/sudo_ai_bot/pi_tool_call",
		ODOO_TOOL_USER_ID: source.ODOO_TOOL_USER_ID || "",
	});
}

export function sessionDeletionAllowed(hardenedV3Only) {
	if (typeof hardenedV3Only !== "boolean") {
		throw new Error("session deletion policy is invalid");
	}
	return !hardenedV3Only;
}

export function literalPiUserPrompt(prompt) {
	if (typeof prompt !== "string" || prompt.length === 0 || prompt.includes("\0")) {
		throw new Error("Pi user prompt is invalid");
	}
	return `User request (literal text):\n${prompt}`;
}

export function enabledPiToolNames(options) {
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| JSON.stringify(Object.keys(options).sort())
			!== JSON.stringify(["brokerEnabled", "hardenedV3Only", "v3Ready"])
		|| typeof options.brokerEnabled !== "boolean"
		|| typeof options.hardenedV3Only !== "boolean"
		|| typeof options.v3Ready !== "boolean"
	) {
		throw new Error("Pi tool policy options are invalid");
	}
	if (options.hardenedV3Only) {
		if (!options.v3Ready || !options.brokerEnabled) return Object.freeze([]);
		return Object.freeze([
			...V3_QUERY_TOOL_NAMES,
			...AUTHENTICATED_V3_BROKER_TOOL_NAMES,
		]);
	}
	if (!options.v3Ready) return V2_TOOL_NAMES;
	return Object.freeze([
		...V2_TOOL_NAMES,
		...V3_QUERY_TOOL_NAMES,
		...(options.brokerEnabled ? AUTHENTICATED_V3_BROKER_TOOL_NAMES : []),
	]);
}
