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
		if (!options.v3Ready) return Object.freeze([]);
		return Object.freeze([
			...V3_QUERY_TOOL_NAMES,
			...(options.brokerEnabled ? AUTHENTICATED_V3_BROKER_TOOL_NAMES : []),
		]);
	}
	if (!options.v3Ready) return V2_TOOL_NAMES;
	return Object.freeze([
		...V2_TOOL_NAMES,
		...V3_QUERY_TOOL_NAMES,
		...(options.brokerEnabled ? AUTHENTICATED_V3_BROKER_TOOL_NAMES : []),
	]);
}
