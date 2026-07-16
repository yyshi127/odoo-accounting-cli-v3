import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	V3_TOOL_NAMES,
	addUnknownEffectGuidance,
	runV3BrokerOperation,
	runV3Query,
} from "./odoo-v3-cli.mjs";

type JsonValue = unknown;

const endpoint = process.env.ODOO_TOOL_URL || "http://127.0.0.1:8069/sudo_ai_bot/pi_tool_call";
const token = process.env.ODOO_TOOL_TOKEN || "";
const database = process.env.ODOO_TOOL_DATABASE || "";
const userId = process.env.ODOO_TOOL_USER_ID || "";
const companyId = process.env.ODOO_TOOL_COMPANY_ID || "";

async function callOdoo(tool: string, params: Record<string, JsonValue> = {}) {
	const response = await fetch(endpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-Sdoobot-Token": token,
			...(database ? { "X-Odoo-Database": database } : {}),
			...(userId ? { "X-Sdoobot-User-Id": userId } : {}),
			...(companyId ? { "X-Sdoobot-Company-Id": companyId } : {}),
		},
		body: JSON.stringify({ tool, params }),
	});
	const payload = await response.json().catch(() => ({}));
	if (!response.ok || !payload?.ok) {
		throw new Error(payload?.error || `Odoo tool ${tool} failed`);
	}
	return payload.result;
}

function textResult(result: JsonValue) {
	return {
		content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
		details: result,
	};
}

async function callV3Query(action: string, request: Record<string, JsonValue>) {
	return textResult(await runV3Query(action, request));
}

async function callV3Broker(action: string, request: Record<string, JsonValue>) {
	const result = addUnknownEffectGuidance(await runV3BrokerOperation(action, request));
	return textResult(result);
}

const v3OperationReferenceSchema = Type.Object({
	operation_id: Type.String(),
}, { additionalProperties: false });

const v3BusinessParametersSchema = Type.Object({}, {
	additionalProperties: true,
	description:
		"Complete capability business parameters retained verbatim. Identity, authentication, approval, request-signing and signing-key fields are forbidden and broker-owned.",
	propertyNames: {
		not: {
			enum: [
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
			],
		},
	},
});

const getContextTool = defineTool({
	name: "odoo_get_context",
	label: "Odoo Context",
	description:
		"Get the current Odoo database, user, company, currency, allowed companies and today's date. Use this instead of asking the user for company/account set.",
	parameters: Type.Object({}),
	async execute() {
		return textResult(await callOdoo("odoo_get_context"));
	},
});

const listSkillsTool = defineTool({
	name: "odoo_list_skills",
	label: "List Odoo Skills",
	description:
		"List enabled Odoo business skills that Pi can execute, including reports and controlled write flows.",
	parameters: Type.Object({}),
	async execute() {
		return textResult(await callOdoo("odoo_list_skills"));
	},
});

const executeSkillTool = defineTool({
	name: "odoo_execute_skill",
	label: "Execute Odoo Skill",
	description:
		"Execute an enabled Odoo business skill. Use this for custom financial reports and controlled workflows. If dates are required and missing, the tool will return a clarification request.",
	parameters: Type.Object({
		skill_key: Type.String({ description: "Registered Odoo skill key." }),
		date_from: Type.Optional(Type.String({ description: "Start date in YYYY-MM-DD." })),
		date_to: Type.Optional(Type.String({ description: "End date in YYYY-MM-DD." })),
	}),
	async execute(_toolCallId, params) {
		return textResult(await callOdoo("odoo_execute_skill", params));
	},
});

const listReportsTool = defineTool({
	name: "odoo_list_reports",
	label: "List Odoo Reports",
	description: "List Odoo native account.report records available for export.",
	parameters: Type.Object({}),
	async execute() {
		return textResult(await callOdoo("odoo_list_reports"));
	},
});

const exportReportTool = defineTool({
	name: "odoo_export_report",
	label: "Export Odoo Report",
	description:
		"Export an Odoo native financial report to an attachment download URL. Use for native Odoo account.report reports such as cash flow, balance sheet and profit and loss.",
	parameters: Type.Object({
		report_name: Type.String({ description: "Exact or close Odoo report name." }),
		title: Type.Optional(Type.String({ description: "User-facing report title." })),
		date_from: Type.Optional(Type.String({ description: "Start date in YYYY-MM-DD. If omitted, Odoo uses current year-to-date." })),
		date_to: Type.Optional(Type.String({ description: "End date in YYYY-MM-DD. If omitted, Odoo uses current year-to-date." })),
		output_format: Type.Optional(Type.String({ description: "Output format. V1 supports xlsx/excel." })),
	}),
	async execute(_toolCallId, params) {
		return textResult(await callOdoo("odoo_export_report", params));
	},
});

const v3CapabilityListTool = defineTool({
	name: V3_TOOL_NAMES.capabilityList,
	label: "List Odoo V3 Capabilities",
	description:
		"List the complete validated local V3 accounting capability registry. Use this before selecting a read or write capability; this command does not contact Odoo or execute accounting work.",
	parameters: Type.Object({}, { additionalProperties: false }),
	async execute() {
		return await callV3Query("registry.list", {});
	},
});

const v3CapabilityGetTool = defineTool({
	name: V3_TOOL_NAMES.capabilityGet,
	label: "Get Odoo V3 Capability",
	description:
		"Get one exact validated V3 capability definition, including its strict input/output schemas, risk, permissions, approval, idempotency, verification and recovery requirements.",
	parameters: Type.Object({
		capability_id: Type.String({ description: "Exact registered V3 capability ID." }),
	}, { additionalProperties: false }),
	async execute(_toolCallId, params) {
		return await callV3Query("registry.get", params);
	},
});

const v3ReadTool = defineTool({
	name: V3_TOOL_NAMES.read,
	label: "Read Odoo V3 Accounting Data",
	description:
		"Execute one enabled V3 read capability. The local trusted broker derives user, database, and company authority from the independently authenticated chat session; the model cannot supply identity or signatures.",
	parameters: Type.Object({
		capability_id: Type.String({ description: "Exact registered V3 read capability ID." }),
		parameters: v3BusinessParametersSchema,
	}, { additionalProperties: false }),
	async execute(_toolCallId, params) {
		return await callV3Broker("read", params);
	},
});

const v3PrepareTool = defineTool({
	name: V3_TOOL_NAMES.prepare,
	label: "Prepare Odoo V3 Operation",
	description:
		"Prepare one durable V3 accounting write operation from business parameters only. The trusted broker derives request and user/company/database identity. This does not approve or execute it.",
	parameters: Type.Object({
		capability_id: Type.String(),
		parameters: v3BusinessParametersSchema,
	}, { additionalProperties: false }),
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.prepare", params);
	},
});

const v3PreviewTool = defineTool({
	name: V3_TOOL_NAMES.preview,
	label: "Preview Odoo V3 Operation",
	description:
		"Run V3 prechecks and return the immutable business preview before approval. It does not execute the accounting write.",
	parameters: v3OperationReferenceSchema,
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.preview", params);
	},
});

const v3ApproveExecuteTool = defineTool({
	name: V3_TOOL_NAMES.approveExecute,
	label: "Approve and Execute Odoo V3 Operation",
	description:
		"Execute an already-previewed operation only after the independent authenticated approval channel has durably recorded a valid approval. This model tool can provide only operation_id and cannot mint, choose, or sign an approval.",
	parameters: v3OperationReferenceSchema,
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.approve_execute", params);
	},
});

const v3StatusTool = defineTool({
	name: V3_TOOL_NAMES.status,
	label: "Get Odoo V3 Operation Status",
	description:
		"Query the durable V3 operation state. This is the mandatory next call for the same operation_id after any unknown execution effect.",
	parameters: v3OperationReferenceSchema,
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.status", params);
	},
});

const v3ResultTool = defineTool({
	name: V3_TOOL_NAMES.result,
	label: "Get Odoo V3 Verified Result",
	description:
		"Return the terminal V3 result and verification/audit receipt. Do not report accounting success unless the CLI reports a completed or recovered operation with passed verification.",
	parameters: v3OperationReferenceSchema,
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.result", params);
	},
});

const v3RecoverTool = defineTool({
	name: V3_TOOL_NAMES.recover,
	label: "Prepare Odoo V3 Recovery",
	description:
		"Prepare recovery from the verified origin receipt and business recovery inputs. The broker derives the recovery operation/request identity and trusted origin revision; the model cannot supply recovery targets or authority.",
	parameters: Type.Object({
		origin_operation_id: Type.String(),
		recovery_date: Type.String({ description: "Recovery accounting date in YYYY-MM-DD." }),
		reason: Type.String({ minLength: 1, maxLength: 512 }),
		idempotency_key: Type.String(),
	}, { additionalProperties: false }),
	async execute(_toolCallId, params) {
		return await callV3Broker("operation.recover", params);
	},
});

export default function (pi: ExtensionAPI) {
	pi.registerTool(getContextTool);
	pi.registerTool(listSkillsTool);
	pi.registerTool(executeSkillTool);
	pi.registerTool(listReportsTool);
	pi.registerTool(exportReportTool);
	pi.registerTool(v3CapabilityListTool);
	pi.registerTool(v3CapabilityGetTool);
	pi.registerTool(v3ReadTool);
	pi.registerTool(v3PrepareTool);
	pi.registerTool(v3PreviewTool);
	pi.registerTool(v3ApproveExecuteTool);
	pi.registerTool(v3StatusTool);
	pi.registerTool(v3ResultTool);
	pi.registerTool(v3RecoverTool);
}
