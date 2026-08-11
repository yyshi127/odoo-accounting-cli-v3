import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
	mkdtemp,
	readFile,
	rm,
} from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
	FINAL_EVIDENCE_COMMIT_TYPE,
	FINAL_EVIDENCE_EVENT_TYPE,
	MAX_FINAL_EVIDENCE_BYTES,
	FinalEvidenceError,
	collectFinalEvidenceStream,
	validateFinalEvidenceChildResult,
} from "../final-evidence.mjs";
import {
	BrokerSessionWriteError,
	writeBrokerSessionHandle,
} from "../trusted-session.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESULT_DIGEST = "b".repeat(64);

function canonicalFrame(value) {
	return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function streamFromEvents(events) {
	const eventFrames = events.map(canonicalFrame);
	return Buffer.concat([
		...eventFrames,
		canonicalFrame({
			event_count: events.length,
			event_type: FINAL_EVIDENCE_COMMIT_TYPE,
			stream_digest: createHash("sha256")
				.update(Buffer.concat(eventFrames))
				.digest("hex"),
		}),
	]);
}

const CLARIFICATION_ANSWER = JSON.stringify({
	action: null,
	business_succeeded: false,
	capability_id: null,
	operation_id: null,
	receipt_id: null,
	result_digest: null,
	status: "clarification_required",
});

const SELF_CLAIMED_SUCCESS = JSON.stringify({
	action: "read",
	business_succeeded: true,
	capability_id: "acct.gl.trial_balance.v1",
	operation_id: null,
	receipt_id: "untrusted-receipt",
	result_digest: RESULT_DIGEST,
	status: "verified_success",
});

function reservePort() {
	return new Promise((resolve, reject) => {
		const probe = net.createServer();
		probe.once("error", reject);
		probe.listen(0, "127.0.0.1", () => {
			const address = probe.address();
			probe.close((error) => {
				if (error) {
					reject(error);
					return;
				}
				resolve(address.port);
			});
		});
	});
}

function spawnFd4Fixture({
	evidence,
	evidenceByteCount = null,
	exitCode = 0,
	stdout = CLARIFICATION_ANSWER,
}) {
	const script = String.raw`
const fs = require("node:fs");
const brokerSessionHandle = fs.readFileSync(3, "utf8");
if (brokerSessionHandle !== "broker-session-handle") {
  throw new Error("unexpected broker session handle");
}
const evidence = process.argv[2] === ""
  ? Buffer.from(process.argv[1], "base64")
  : Buffer.alloc(Number(process.argv[2]), 0x20);
const stdout = Buffer.from(process.argv[3], "base64");
if (evidence.length > 0) fs.writeSync(4, evidence);
fs.closeSync(4);
process.stdout.write(stdout);
process.exitCode = Number(process.argv[4]);
`;
	const child = spawn(process.execPath, [
		"-e",
		script,
		evidence.toString("base64"),
		evidenceByteCount === null ? "" : String(evidenceByteCount),
		Buffer.from(`${stdout}\n`, "utf8").toString("base64"),
		String(exitCode),
	], {
		stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"],
	});
	const brokerWrite = writeBrokerSessionHandle(
		child.stdio[3],
		"broker-session-handle",
	);
	const evidenceResult = collectFinalEvidenceStream(child.stdio[4]);
	const stdoutChunks = [];
	child.stdout.on("data", (chunk) => {
		stdoutChunks.push(Buffer.from(chunk));
	});
	const childExited = new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code) => resolve(code));
	});
	const exited = Promise.all([childExited, brokerWrite]).then(([code]) => code);
	return {
		evidenceResult,
		exited,
		stdout: async () => {
			await exited;
			return Buffer.concat(stdoutChunks);
		},
	};
}

function expectCode(action, code) {
	assert.throws(
		action,
		(error) => error instanceof FinalEvidenceError && error.code === code,
	);
}

test("FD3 remains parent-to-child while FD4 reaches a clean committed EOF", async () => {
	const fixture = spawnFd4Fixture({
		evidence: streamFromEvents([]),
	});
	const [evidenceBuffer, exitCode, stdoutBuffer] = await Promise.all([
		fixture.evidenceResult,
		fixture.exited,
		fixture.stdout(),
	]);
	assert.equal(exitCode, 0);
	assert.deepEqual(
		validateFinalEvidenceChildResult({
			evidenceBuffer,
			exitCode,
			stdoutBuffer,
		}),
		JSON.parse(CLARIFICATION_ANSWER),
	);
});

test("the parent gate rejects missing commit, truncation, and nonzero exit", async () => {
	const missing = spawnFd4Fixture({ evidence: Buffer.alloc(0) });
	const [missingEvidence, missingCode, missingStdout] = await Promise.all([
		missing.evidenceResult,
		missing.exited,
		missing.stdout(),
	]);
	expectCode(
		() => validateFinalEvidenceChildResult({
			evidenceBuffer: missingEvidence,
			exitCode: missingCode,
			stdoutBuffer: missingStdout,
		}),
		"final_evidence_commit_missing",
	);

	const event = {
		action: "read",
		business_succeeded: true,
		capability_id: "acct.gl.trial_balance.v1",
		event_type: FINAL_EVIDENCE_EVENT_TYPE,
		operation_id: null,
		receipt_id: "read-receipt-1",
		result_digest: RESULT_DIGEST,
	};
	const truncated = spawnFd4Fixture({
		evidence: canonicalFrame(event),
	});
	const [truncatedEvidence, truncatedCode, truncatedStdout] = await Promise.all([
		truncated.evidenceResult,
		truncated.exited,
		truncated.stdout(),
	]);
	expectCode(
		() => validateFinalEvidenceChildResult({
			evidenceBuffer: truncatedEvidence,
			exitCode: truncatedCode,
			stdoutBuffer: truncatedStdout,
		}),
		"final_evidence_commit_missing",
	);

	expectCode(
		() => validateFinalEvidenceChildResult({
			evidenceBuffer: streamFromEvents([]),
			exitCode: 1,
			stdoutBuffer: Buffer.from(`${CLARIFICATION_ANSWER}\n`),
		}),
		"final_evidence_child_exit_rejected",
	);
});

test("the FD4 collector rejects oversized child output", async () => {
	const oversized = spawnFd4Fixture({
		evidence: Buffer.alloc(0),
		evidenceByteCount: MAX_FINAL_EVIDENCE_BYTES + 1,
	});
	await assert.rejects(
		oversized.evidenceResult,
		(error) => (
			error instanceof FinalEvidenceError
			&& error.code === "final_evidence_stream_too_large"
		),
	);
	await oversized.exited;
});

test("FD3 write fails closed when the child exits without reading it", {
	skip: process.platform === "linux" ? false : "requires Linux child-process pipe semantics",
}, async () => {
	const child = spawn(process.execPath, [
		"-e",
		"process.exitCode = 0;",
	], {
		stdio: ["ignore", "ignore", "ignore", "pipe"],
	});
	const write = writeBrokerSessionHandle(
		child.stdio[3],
		"broker-session-handle",
	);
	const writeRejected = assert.rejects(
		write,
		(error) => (
			error instanceof BrokerSessionWriteError
			&& error.code === "broker_session_write_failed"
		),
	);
	const exitCode = await new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("close", resolve);
	});
	assert.equal(exitCode, 0);
	await writeRejected;
});

test("FD3 writer preserves an empty legacy value and rejects a late pipe reset", {
	timeout: 1000,
}, async () => {
	class ScriptedStream extends EventEmitter {
		constructor(events) {
			super();
			this.events = events;
			this.observed = null;
		}

		end(value, encoding) {
			this.observed = { encoding, value };
			queueMicrotask(() => {
				for (const [event, argument] of this.events) {
					this.emit(event, argument);
				}
			});
		}
	}

	const clean = new ScriptedStream([
		["finish"],
		["close"],
	]);
	await writeBrokerSessionHandle(clean, "");
	assert.deepEqual(clean.observed, { encoding: "utf8", value: "" });

	const reset = new ScriptedStream([
		["finish"],
		["error", Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" })],
		["close"],
	]);
	await assert.rejects(
		writeBrokerSessionHandle(reset, "broker-session-handle"),
		(error) => (
			error instanceof BrokerSessionWriteError
			&& error.code === "broker_session_write_failed"
		),
	);
});

test("self-claimed success without a matching committed receipt is rejected", () => {
	expectCode(
		() => validateFinalEvidenceChildResult({
			evidenceBuffer: streamFromEvents([]),
			exitCode: 0,
			stdoutBuffer: Buffer.from(`${SELF_CLAIMED_SUCCESS}\n`, "utf8"),
		}),
		"final_answer_evidence_mismatch",
	);
});

test("the hardened server gates FD4 then asks the trusted broker to deliver the result", async () => {
	const source = await readFile(path.join(root, "server.mjs"), "utf8");
	assert.match(
		source,
		/\["ignore", "pipe", "pipe", "pipe", "pipe"\]/,
	);
	assert.match(source, /collectFinalEvidenceStream\(child\.stdio\[4\]\)/);
	assert.match(source, /validateFinalEvidenceChildResult\(\{/);
	assert.match(source, /createFinalResultDeliverer\(\{/);
	assert.match(source, /sessionHandle: resultDeliverySessionHandle/);
	assert.match(source, /await deliverFinalResult\(answer\)/);
	assert.match(source, /serializeFinalDeliveredAnswer\(/);
	assert.match(
		source,
		/const brokerHandleWriteOutcome = writeBrokerSessionHandle\(\s*child\.stdio\[3\],\s*brokerEnabled \? brokerSessionHandle : "",\s*\)\.then\(/,
	);
	assert.match(source, /const brokerWriteOutcome = await brokerHandleWriteOutcome/);
	assert.match(source, /if \(!brokerWriteOutcome\.ok\) throw brokerWriteOutcome\.error/);
	assert.doesNotMatch(
		source,
		/writeBrokerSessionHandle\([^;]*resultDeliverySessionHandle/s,
	);
	assert.match(source, /const PREFLIGHT_TIMEOUT_MS = 5_000/);
	assert.match(source, /const MAX_PI_CHILD_TIMEOUT_MS = 120_000/);
	assert.match(source, /const FINAL_RESULT_DELIVERY_TIMEOUT_MS = 10_000/);
	assert.match(source, /const PI_SERVER_TOTAL_BUDGET_MS = 135_000/);
	assert.match(source, /timeoutMs: PREFLIGHT_TIMEOUT_MS/);
	assert.match(source, /timeoutMs: FINAL_RESULT_DELIVERY_TIMEOUT_MS/);
	assert.match(source, /const MAX_PI_STDERR_BYTES = 64 \* 1024/);
	assert.match(source, /stderrBytes > MAX_PI_STDERR_BYTES/);
	assert.match(source, /new FinalEvidenceError\("pi_stderr_too_large"\)/);
	assert.match(
		source,
		/Number\.isInteger\(error\?\.statusCode\) \? error\.statusCode : 502/,
	);
});

test("the server rejects a child timeout that consumes the reserved boundary margins", async () => {
	const environment = {
		...process.env,
		PI_AGENT_BRIDGE_TIMEOUT_MS: "120001",
	};
	for (const name of [
		"LISTEN_FDNAMES",
		"LISTEN_FDS",
		"LISTEN_PID",
		"ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST",
		"PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE",
		"PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256",
	]) {
		delete environment[name];
	}
	const child = spawn(process.execPath, [path.join(root, "server.mjs")], {
		cwd: root,
		env: environment,
		stdio: ["ignore", "pipe", "pipe"],
	});
	const stderr = [];
	child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
	const exitCode = await new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("exit", resolve);
	});
	assert.notEqual(exitCode, 0);
	assert.match(
		Buffer.concat(stderr).toString("utf8"),
		/PI Agent child timeout configuration is invalid/,
	);
});

test("the real chat launch path computes broker enablement before FD3 write", async () => {
	const sessionDirectory = await mkdtemp(
		path.join(os.tmpdir(), "pi-v3-server-launch-"),
	);
	const port = await reservePort();
	const environment = {
		...process.env,
		PI_AGENT_BRIDGE_HOST: "127.0.0.1",
		PI_AGENT_BRIDGE_PORT: String(port),
		PI_AGENT_BRIDGE_TIMEOUT_MS: "5000",
		PI_AGENT_SESSION_DIR: sessionDirectory,
	};
	for (const name of [
		"LISTEN_FDNAMES",
		"LISTEN_FDS",
		"LISTEN_PID",
		"ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST",
		"PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE",
		"PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256",
		"PI_BRIDGE_HARDENED_V3_ONLY",
		"PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET",
		"PI_BRIDGE_REQUIRE_V3_IDENTITY",
	]) {
		delete environment[name];
	}
	const server = spawn(
		process.execPath,
		[path.join(root, "server.mjs")],
		{
			cwd: root,
			env: environment,
			stdio: ["ignore", "pipe", "pipe"],
		},
	);
	let stderr = "";
	server.stderr.on("data", (chunk) => {
		stderr += chunk.toString("utf8");
	});
	const started = new Promise((resolve, reject) => {
		const deadline = setTimeout(
			() => reject(new Error(`server start timed out: ${stderr}`)),
			5000,
		);
		server.stdout.on("data", (chunk) => {
			if (chunk.toString("utf8").includes("listening on")) {
				clearTimeout(deadline);
				resolve();
			}
		});
		server.once("error", (error) => {
			clearTimeout(deadline);
			reject(error);
		});
		server.once("exit", (code) => {
			clearTimeout(deadline);
			reject(new Error(`server exited ${code}: ${stderr}`));
		});
	});
	try {
		await started;
		const response = await fetch(`http://127.0.0.1:${port}/chat`, {
			body: JSON.stringify({ message: "exercise runPiChat" }),
			headers: { "Content-Type": "application/json" },
			method: "POST",
		});
		const payload = await response.json();
		assert.equal(response.status, 200);
		assert.deepEqual(payload, { answer: "", ok: true });
	} finally {
		server.kill("SIGTERM");
		await new Promise((resolve) => server.once("exit", resolve));
		await rm(sessionDirectory, { force: true, recursive: true });
	}
});

test("the extension has one evidence-wrapped V3 path and an awaited shutdown hook", async () => {
	const source = await readFile(
		path.join(root, "extensions", "odoo-tools.ts"),
		"utf8",
	);
	assert.match(source, /createFinalEvidenceBrokerClient\(\{/);
	assert.match(source, /registerFinalEvidenceSessionShutdown\(pi, \{/);
	assert.match(source, /await runFinalEvidenceBrokerOperation\(action, request\)/);
	assert.match(source, /return await runFinalEvidenceBrokerOperation\("read", \{/);
	assert.doesNotMatch(source, /\brunV3BrokerOperation\b/);
});

test("the hardened prompt permits only the five canonical seven-field forms", async () => {
	const prompt = await readFile(path.join(root, "SYSTEM_PROMPT.md"), "utf8");
	for (const status of [
		"verified_success",
		"verified_diagnostic",
		"awaiting_approval",
		"clarification_required",
		"refused",
	]) {
		assert.match(prompt, new RegExp(`"status":"${status}"`));
	}
	assert.match(prompt, /must be exactly one canonical JSON object/);
	assert.match(prompt, /Do not output Markdown, explanations, questions/);
});
