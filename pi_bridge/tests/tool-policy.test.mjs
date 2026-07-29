import assert from "node:assert/strict";
import test from "node:test";

import {
	AUTHENTICATED_V3_BROKER_TOOL_NAMES,
	enabledPiToolNames,
	legacyOdooEnvironment,
	LEGACY_ODOO_ENVIRONMENT_NAMES,
	literalPiUserPrompt,
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
		assert.deepEqual(selected, [
			...V3_QUERY_TOOL_NAMES,
			...(brokerEnabled ? AUTHENTICATED_V3_BROKER_TOOL_NAMES : []),
		]);
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
	assert.deepEqual(brokerDisabled, V3_QUERY_TOOL_NAMES);
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
