import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	realpath,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { afterEach } from "node:test";

import {
	PI_BRIDGE_RUNTIME_MEMBERS,
	verifyPiBridgeReleaseBinding,
} from "../release-binding.mjs";

const VERSION = "1.2.3-test";
const COMMIT = "a".repeat(40);
const PYTHON_MANIFEST_DIGEST = "73c5d9c337949bfdd26ef543f9d70ef4e7d2377b9d1a38723b346881ed13d5c9";
const temporaryRoots = [];

function canonicalString(value) {
	return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) => (
		`\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
	));
}

function canonicalJson(value) {
	if (value === null || typeof value === "boolean" || typeof value === "string") {
		return typeof value === "string" ? canonicalString(value) : JSON.stringify(value);
	}
	if (typeof value === "number" && Number.isSafeInteger(value)) {
		return String(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalJson).join(",")}]`;
	}
	return `{${Object.keys(value).sort().map(
		(key) => `${canonicalString(key)}:${canonicalJson(value[key])}`,
	).join(",")}}`;
}

function sha256(content) {
	return createHash("sha256").update(content).digest("hex");
}

async function createFixture({ omittedMember } = {}) {
	const temporary = await mkdtemp(path.join(os.tmpdir(), "pi-v3-release-binding-"));
	temporaryRoots.push(temporary);
	const releaseDirectory = path.join(temporary, "release");
	const bridgeDirectory = path.join(temporary, "runtime", "pi_bridge");
	await mkdir(releaseDirectory, { recursive: true });
	await mkdir(bridgeDirectory, { recursive: true });
	const releaseRoot = await realpath(releaseDirectory);
	const bridgeRoot = await realpath(bridgeDirectory);
	const files = [];
	for (const [index, releasePath] of PI_BRIDGE_RUNTIME_MEMBERS.entries()) {
		const relative = releasePath.slice("pi_bridge/".length);
		const runtimePath = path.join(bridgeRoot, ...relative.split("/"));
		await mkdir(path.dirname(runtimePath), { recursive: true });
		const content = Buffer.from(`runtime-${index}-${releasePath}\n`, "utf8");
		await writeFile(runtimePath, content, { mode: 0o644 });
		if (releasePath !== omittedMember) {
			files.push({ path: releasePath, sha256: sha256(content), size: content.length });
		}
	}
	files.push({
		path: "VERSION",
		sha256: sha256(Buffer.from(`${VERSION}\n`, "utf8")),
		size: Buffer.byteLength(`${VERSION}\n`),
	});
	const unicodeEvidence = Buffer.from("\u8d22\u52a1\u8bc1\u636e\n", "utf8");
	files.push({
		path: "evidence/\u4f1a\u8ba1.json",
		sha256: sha256(unicodeEvidence),
		size: unicodeEvidence.length,
	});
	const unsigned = {
		commit: COMMIT,
		files: files.sort((left, right) => (
			left.path < right.path ? -1 : left.path > right.path ? 1 : 0
		)),
		schema_version: 1,
		version: VERSION,
	};
	const manifest = {
		...unsigned,
		manifest_sha256: sha256(Buffer.from(canonicalJson(unsigned), "utf8")),
	};
	const manifestPath = path.join(releaseRoot, "RELEASE-MANIFEST.json");
	await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
		mode: 0o644,
	});
	return { bridgeRoot, manifest, manifestPath };
}

afterEach(async () => {
	await Promise.all(
		temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
	);
});

test("exact executing Pi Bridge bytes bind to one release manifest identity", async () => {
	const fixture = await createFixture();
	assert.equal(fixture.manifest.manifest_sha256, PYTHON_MANIFEST_DIGEST);

	const binding = verifyPiBridgeReleaseBinding({
		bridgeRoot: fixture.bridgeRoot,
		expectedManifestSha256: fixture.manifest.manifest_sha256,
		manifestPath: fixture.manifestPath,
	});

	assert.deepEqual(binding, {
		commit: COMMIT,
		manifest_sha256: fixture.manifest.manifest_sha256,
		runtime_file_count: PI_BRIDGE_RUNTIME_MEMBERS.length,
		verified: true,
		version: VERSION,
	});
});

test("an older or changed executing Bridge file fails closed", async () => {
	const fixture = await createFixture();
	const serverPath = path.join(fixture.bridgeRoot, "server.mjs");
	await writeFile(serverPath, `${await readFile(serverPath, "utf8")}stale-copy\n`);

	assert.throws(
		() => verifyPiBridgeReleaseBinding({
			bridgeRoot: fixture.bridgeRoot,
			expectedManifestSha256: fixture.manifest.manifest_sha256,
			manifestPath: fixture.manifestPath,
		}),
		/runtime file does not match pi_bridge\/server\.mjs/,
	);
});

test("a manifest cannot be substituted under the configured release digest", async () => {
	const fixture = await createFixture();
	const substituted = { ...fixture.manifest, version: "1.2.3-stale" };
	await writeFile(fixture.manifestPath, JSON.stringify(substituted));

	assert.throws(
		() => verifyPiBridgeReleaseBinding({
			bridgeRoot: fixture.bridgeRoot,
			expectedManifestSha256: fixture.manifest.manifest_sha256,
			manifestPath: fixture.manifestPath,
		}),
		/manifest digest does not match/,
	);
});

test("every executing Bridge member must be declared by the release", async () => {
	const omittedMember = "pi_bridge/extensions/odoo-tools.ts";
	const fixture = await createFixture({ omittedMember });

	assert.throws(
		() => verifyPiBridgeReleaseBinding({
			bridgeRoot: fixture.bridgeRoot,
			expectedManifestSha256: fixture.manifest.manifest_sha256,
			manifestPath: fixture.manifestPath,
		}),
		new RegExp(`omits ${omittedMember.replace(".", "\\.")}`),
	);
});

test("the fixed system prompt is mandatory and immutable", async (t) => {
	await t.test("manifest omission", async () => {
		const omittedMember = "pi_bridge/SYSTEM_PROMPT.md";
		const fixture = await createFixture({ omittedMember });

		assert.throws(
			() => verifyPiBridgeReleaseBinding({
				bridgeRoot: fixture.bridgeRoot,
				expectedManifestSha256: fixture.manifest.manifest_sha256,
				manifestPath: fixture.manifestPath,
			}),
			/omits pi_bridge\/SYSTEM_PROMPT\.md/,
		);
	});

	await t.test("runtime tampering", async () => {
		const fixture = await createFixture();
		const promptPath = path.join(fixture.bridgeRoot, "SYSTEM_PROMPT.md");
		await writeFile(promptPath, `${await readFile(promptPath, "utf8")}tampered\n`);

		assert.throws(
			() => verifyPiBridgeReleaseBinding({
				bridgeRoot: fixture.bridgeRoot,
				expectedManifestSha256: fixture.manifest.manifest_sha256,
				manifestPath: fixture.manifestPath,
			}),
			/runtime file does not match pi_bridge\/SYSTEM_PROMPT\.md/,
		);
	});
});

test("the FD4 final-evidence runtime is mandatory and immutable", async (t) => {
	const releasePath = "pi_bridge/final-evidence.mjs";
	assert.ok(PI_BRIDGE_RUNTIME_MEMBERS.includes(releasePath));

	await t.test("manifest omission", async () => {
		const fixture = await createFixture({ omittedMember: releasePath });

		assert.throws(
			() => verifyPiBridgeReleaseBinding({
				bridgeRoot: fixture.bridgeRoot,
				expectedManifestSha256: fixture.manifest.manifest_sha256,
				manifestPath: fixture.manifestPath,
			}),
			/omits pi_bridge\/final-evidence\.mjs/,
		);
	});

	await t.test("runtime tampering", async () => {
		const fixture = await createFixture();
		const evidencePath = path.join(
			fixture.bridgeRoot,
			"final-evidence.mjs",
		);
		await writeFile(
			evidencePath,
			`${await readFile(evidencePath, "utf8")}tampered\n`,
		);

		assert.throws(
			() => verifyPiBridgeReleaseBinding({
				bridgeRoot: fixture.bridgeRoot,
				expectedManifestSha256: fixture.manifest.manifest_sha256,
				manifestPath: fixture.manifestPath,
			}),
			/runtime file does not match pi_bridge\/final-evidence\.mjs/,
		);
	});
});

test("writable runtime bytes and non-root-managed trees are rejected", async (t) => {
	if (process.platform !== "win32") {
		await t.test("group/world writable file", async () => {
			const fixture = await createFixture();
			const target = path.join(fixture.bridgeRoot, "server.mjs");
			await chmod(target, 0o666);
			assert.equal((await stat(target)).mode & 0o022, 0o022);
			assert.throws(
				() => verifyPiBridgeReleaseBinding({
					bridgeRoot: fixture.bridgeRoot,
					expectedManifestSha256: fixture.manifest.manifest_sha256,
					manifestPath: fixture.manifestPath,
				}),
				/release file is unsafe/,
			);
		});
	}
	if (process.platform === "linux") {
		await t.test("non-root-managed ancestor", async () => {
			const fixture = await createFixture();
			assert.throws(
				() => verifyPiBridgeReleaseBinding({
					bridgeRoot: fixture.bridgeRoot,
					expectedManifestSha256: fixture.manifest.manifest_sha256,
					manifestPath: fixture.manifestPath,
					requireRootOwned: true,
				}),
				/ancestors are not root-managed/,
			);
		});
	}
});
