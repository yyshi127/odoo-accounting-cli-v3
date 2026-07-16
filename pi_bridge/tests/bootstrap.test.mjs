import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
	chmod,
	copyFile,
	cp,
	mkdir,
	mkdtemp,
	readFile,
	readdir,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { afterEach } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
	nodeVersionMeetsEngine,
	verifyCanonicalRelease,
} from "../bootstrap.mjs";
import { PI_BRIDGE_RUNTIME_MEMBERS } from "../release-binding.mjs";

const VERSION = "1.2.3-test";
const COMMIT = "a".repeat(40);
const RELEASE = `${VERSION}-${COMMIT.slice(0, 12)}`;
const temporaryRoots = [];
const rootOwnedTemporaryRoots = [];
const rootIntegrationEnabled = process.platform === "linux"
	&& process.env.PI_BRIDGE_RUN_ROOT_INTEGRATION === "1";

function canonicalString(value) {
	return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) => (
		`\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
	));
}

function canonicalJson(value) {
	if (value === null || typeof value === "boolean" || typeof value === "string") {
		return typeof value === "string" ? canonicalString(value) : JSON.stringify(value);
	}
	if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	return `{${Object.keys(value).sort().map(
		(key) => `${canonicalString(key)}:${canonicalJson(value[key])}`,
	).join(",")}}`;
}

function sha256(content) {
	return createHash("sha256").update(content).digest("hex");
}

async function fixture() {
	const temporary = await mkdtemp(path.join(os.tmpdir(), "pi-v3-bootstrap-"));
	temporaryRoots.push(temporary);
	const installRoot = path.join(temporary, "install");
	const releaseRoot = path.join(installRoot, "releases", RELEASE);
	const anchorDirectory = path.join(installRoot, "trusted-artifacts");
	const packageDirectory = path.join(installRoot, "packages");
	await mkdir(anchorDirectory, { recursive: true });
	await mkdir(packageDirectory, { recursive: true });
	const sources = new Map([
		["bin/odoo-accounting-cli-v3", Buffer.from("verified-cli\n")],
		["pi_bridge/bootstrap.mjs", Buffer.from("verified-bootstrap\n")],
		["pi_bridge/release-binding.mjs", Buffer.from("verified-binding\n")],
		["registry/capabilities.json", Buffer.from("{\"capabilities\":[]}\n")],
		["VERSION", Buffer.from(`${VERSION}\n`)],
	]);
	for (const [relative, content] of sources) {
		const target = path.join(releaseRoot, ...relative.split("/"));
		await mkdir(path.dirname(target), { recursive: true });
		await writeFile(target, content, { mode: 0o644 });
	}
	const unsigned = {
		commit: COMMIT,
		files: [...sources].map(([filePath, content]) => ({
			path: filePath,
			sha256: sha256(content),
			size: content.length,
		})).sort((left, right) => (
			left.path < right.path ? -1 : left.path > right.path ? 1 : 0
		)),
		schema_version: 1,
		version: VERSION,
	};
	const manifest = {
		...unsigned,
		manifest_sha256: sha256(Buffer.from(canonicalJson(unsigned))),
	};
	const manifestPath = path.join(releaseRoot, "RELEASE-MANIFEST.json");
	await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
	const packageContent = Buffer.from("canonical-package-bytes\n");
	const packagePath = path.join(
		packageDirectory,
		`odoo-accounting-cli-v3-${RELEASE}.tar.gz`,
	);
	await writeFile(packagePath, packageContent);
	const anchorPath = path.join(anchorDirectory, `${RELEASE}.json`);
	await writeFile(anchorPath, JSON.stringify({
		commit: COMMIT,
		manifest_sha256: manifest.manifest_sha256,
		package_sha256: sha256(packageContent),
		release: RELEASE,
	}));
	return {
		anchorPath,
		manifest,
		manifestPath,
		packagePath,
		releaseRoot: await realpath(releaseRoot),
	};
}

async function makeDirectoriesTraversable(root) {
	await chmod(root, 0o755);
	for (const entry of await readdir(root, { withFileTypes: true })) {
		if (entry.isDirectory()) {
			await makeDirectoriesTraversable(path.join(root, entry.name));
		}
	}
}

async function writeSources(root, sources) {
	for (const [relative, content] of sources) {
		const target = path.join(root, ...relative.split("/"));
		await mkdir(path.dirname(target), { recursive: true });
		await writeFile(target, content, { mode: 0o644 });
	}
}

async function rootIntegrationFixture() {
	const staging = await mkdtemp(path.join(os.tmpdir(), "pi-v3-bootstrap-stage-"));
	temporaryRoots.push(staging);
	const projectBridge = path.resolve(
		path.dirname(fileURLToPath(import.meta.url)),
		"..",
	);
	const packageJson = await readFile(path.join(projectBridge, "package.json"));
	const packageLock = await readFile(path.join(projectBridge, "package-lock.json"));
	const releaseBinding = await readFile(path.join(projectBridge, "release-binding.mjs"));
	const bootstrap = await readFile(path.join(projectBridge, "bootstrap.mjs"));
	const createRuntimeBinding = await readFile(
		path.join(projectBridge, "create-runtime-binding.mjs"),
	);
	const fakeServer = Buffer.from(`
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
const releaseRoot = path.dirname(
  process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST,
);
const bootstrapModule = await import(pathToFileURL(
  path.join(releaseRoot, "pi_bridge", "bootstrap.mjs"),
).href);
const attestation = bootstrapModule.getPiBridgeBootstrapAttestation();
fs.writeFileSync(process.env.PI_BRIDGE_TEST_ATTESTATION_OUT, JSON.stringify({
  agentDir: process.env.PI_CODING_AGENT_DIR,
  bridgeHost: process.env.PI_AGENT_BRIDGE_HOST,
  bridgePort: process.env.PI_AGENT_BRIDGE_PORT,
  brokerSocket: process.env.ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET,
  cliPath: attestation?.cliPath,
  home: process.env.HOME,
  hardenedV3Only: process.env.PI_BRIDGE_HARDENED_V3_ONLY,
  manifestPath: attestation?.manifestPath,
  nodeSha256: attestation?.runtimeBinding?.node_sha256,
  piEntrypoint: attestation?.piEntrypoint,
  release: attestation?.identity?.release,
  resolverModule: process.env.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE,
  requireSystemdSocket: process.env.PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET,
  runtimeEnvironment: process.env.PI_BRIDGE_RUNTIME_ROOT,
  runtimeManifestSha256: attestation?.runtimeBinding?.runtime_manifest_sha256,
  runtimeRoot: attestation?.runtimeRoot,
  sessionDir: process.env.PI_AGENT_SESSION_DIR,
  verified: attestation?.binding?.verified === true,
}));
`, "utf8");
	const runtimeSources = new Map();
	for (const member of PI_BRIDGE_RUNTIME_MEMBERS) {
		let content = Buffer.from(`placeholder-${member}\n`);
		if (member === "pi_bridge/package.json") content = packageJson;
		if (member === "pi_bridge/package-lock.json") content = packageLock;
		if (member === "pi_bridge/release-binding.mjs") content = releaseBinding;
		if (member === "pi_bridge/server.mjs") content = fakeServer;
		runtimeSources.set(member, content);
	}
	const fakeCli = Buffer.from(`#!/usr/bin/python3 -I
import json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
manifest = json.loads((root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
anchor = json.loads((root.parent.parent / "trusted-artifacts" / (root.name + ".json")).read_text(encoding="utf-8"))
print(json.dumps({
    "command": "release.identity",
    "data": {
        "commit": manifest["commit"],
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": anchor["package_sha256"],
        "registry_digest": "b" * 64,
        "release": anchor["release"],
        "verified": True,
        "version": manifest["version"],
    },
    "ok": True,
}, sort_keys=True))
`, "utf8");
	const releaseSources = new Map(runtimeSources);
	releaseSources.set("bin/odoo-accounting-cli-v3", fakeCli);
	releaseSources.set("pi_bridge/bootstrap.mjs", bootstrap);
	releaseSources.set("pi_bridge/create-runtime-binding.mjs", createRuntimeBinding);
	releaseSources.set("registry/capabilities.json", Buffer.from("{\"capabilities\":[]}\n"));
	releaseSources.set("VERSION", Buffer.from(`${VERSION}\n`));
	const installRoot = path.join(staging, "install");
	const releaseRoot = path.join(installRoot, "releases", RELEASE);
	const runtimeRoot = path.join(staging, "runtime", "pi_bridge");
	await writeSources(releaseRoot, releaseSources);
	await writeSources(
		runtimeRoot,
		new Map([...runtimeSources].map(([name, content]) => (
			[name.slice("pi_bridge/".length), content]
		))),
	);
	const unsigned = {
		commit: COMMIT,
		files: [...releaseSources].map(([filePath, content]) => ({
			path: filePath,
			sha256: sha256(content),
			size: content.length,
		})).sort((left, right) => (
			left.path < right.path ? -1 : left.path > right.path ? 1 : 0
		)),
		schema_version: 1,
		version: VERSION,
	};
	const manifest = {
		...unsigned,
		manifest_sha256: sha256(Buffer.from(canonicalJson(unsigned))),
	};
	await writeFile(
		path.join(releaseRoot, "RELEASE-MANIFEST.json"),
		`${JSON.stringify(manifest, null, 2)}\n`,
	);
	const packageContent = Buffer.from("integration-package\n");
	const packagePath = path.join(
		installRoot,
		"packages",
		`odoo-accounting-cli-v3-${RELEASE}.tar.gz`,
	);
	await mkdir(path.dirname(packagePath), { recursive: true });
	await writeFile(packagePath, packageContent);
	const anchorPath = path.join(installRoot, "trusted-artifacts", `${RELEASE}.json`);
	await mkdir(path.dirname(anchorPath), { recursive: true });
	await writeFile(anchorPath, JSON.stringify({
		commit: COMMIT,
		manifest_sha256: manifest.manifest_sha256,
		package_sha256: sha256(packageContent),
		release: RELEASE,
	}));
	await cp(
		path.join(projectBridge, "node_modules"),
		path.join(runtimeRoot, "node_modules"),
		{ recursive: true, verbatimSymlinks: true },
	);
	const nodePath = path.join(staging, "node");
	await copyFile(process.execPath, nodePath);
	await chmod(nodePath, 0o555);
	await chmod(path.join(releaseRoot, "bin", "odoo-accounting-cli-v3"), 0o555);
	await makeDirectoriesTraversable(staging);

	const productionRoot = path.join(
		"/opt",
		`odoo-v3-pi-bootstrap-test-${process.pid}-${randomBytes(6).toString("hex")}`,
	);
	const moved = spawnSync("sudo", ["mv", "--", staging, productionRoot], {
		encoding: "utf8",
	});
	assert.equal(moved.status, 0, moved.stderr);
	rootOwnedTemporaryRoots.push(productionRoot);
	const owned = spawnSync("sudo", ["chown", "-hR", "0:0", productionRoot], {
		encoding: "utf8",
	});
	assert.equal(owned.status, 0, owned.stderr);
	const canonicalRuntimeRoot = path.join(productionRoot, "runtime", "pi_bridge");
	const bindingCreated = spawnSync("sudo", [
		path.join(productionRoot, "node"),
		path.join(
			productionRoot,
			"install",
			"releases",
			RELEASE,
			"pi_bridge",
			"create-runtime-binding.mjs",
		),
		canonicalRuntimeRoot,
	], { encoding: "utf8" });
	assert.equal(bindingCreated.status, 0, bindingCreated.stderr);
	const evidenceRoot = await mkdtemp(path.join(os.tmpdir(), "pi-v3-bootstrap-result-"));
	temporaryRoots.push(evidenceRoot);
	return {
		bootstrapPath: path.join(
			productionRoot,
			"install",
			"releases",
			RELEASE,
			"pi_bridge",
			"bootstrap.mjs",
		),
		evidencePath: path.join(evidenceRoot, "attestation.json"),
		nodePath: path.join(productionRoot, "node"),
		piEntrypoint: path.join(
			canonicalRuntimeRoot,
			"node_modules",
			"@earendil-works",
			"pi-coding-agent",
			"dist",
			"cli.js",
		),
		productionRoot,
		runtimeRoot: canonicalRuntimeRoot,
	};
}

afterEach(async () => {
	await Promise.all(
		temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
	);
	for (const root of rootOwnedTemporaryRoots.splice(0)) {
		const removed = spawnSync("sudo", ["rm", "-rf", "--", root], {
			encoding: "utf8",
		});
		assert.equal(removed.status, 0, removed.stderr);
	}
});

test("the canonical bootstrap verifies anchor, complete release, and package", async () => {
	const current = await fixture();
	const verified = verifyCanonicalRelease({
		releaseRoot: current.releaseRoot,
		requireRootOwned: false,
	});
	assert.deepEqual(verified, {
		commit: COMMIT,
		manifestPath: current.manifestPath,
		manifest_sha256: current.manifest.manifest_sha256,
		package_sha256: sha256(Buffer.from("canonical-package-bytes\n")),
		release: RELEASE,
		version: VERSION,
	});
});

test("the release Node engine rejects below-boundary runtimes", () => {
	assert.equal(nodeVersionMeetsEngine("22.18.99", ">=22.19.0"), false);
	assert.equal(nodeVersionMeetsEngine("22.19.0", ">=22.19.0"), true);
	assert.equal(nodeVersionMeetsEngine("22.23.1", ">=22.19.0"), true);
	assert.throws(
		() => nodeVersionMeetsEngine("22.19.0", "^22.19.0"),
		/minimum Node version/,
	);
});

test("direct server startup cannot manufacture V3 identity from environment", () => {
	const serverPath = path.resolve(
		path.dirname(fileURLToPath(import.meta.url)),
		"..",
		"server.mjs",
	);
	const environment = {
		...process.env,
		ODOO_ACCOUNTING_CLI_V3_BIN: process.execPath,
		ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST: "f".repeat(64),
		ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST: "e".repeat(64),
		PI_AGENT_BRIDGE_PORT: "0",
		PI_BRIDGE_REQUIRE_V3_IDENTITY: "1",
		ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST: path.resolve(
			path.dirname(serverPath),
			"..",
			"RELEASE-MANIFEST.json",
		),
	};
	delete environment.NODE_OPTIONS;
	delete environment.NODE_PATH;
	const fakeGlobal = `
globalThis[Symbol.for("odoo-accounting-cli-v3.pi-bridge-bootstrap.v1")] =
  Object.freeze({ nonce: "${"f".repeat(64)}" });
await import(${JSON.stringify(pathToFileURL(serverPath).href)});
`;
	const completed = spawnSync(process.execPath, [
		"--input-type=module",
		"--eval",
		fakeGlobal,
	], {
		encoding: "utf8",
		env: environment,
		timeout: 10000,
		windowsHide: true,
	});
	assert.notEqual(completed.status, 0);
	assert.equal(completed.signal, null);
	assert.match(completed.stderr, /V3 bootstrap attestation is unavailable/);
});

test("a systemd-bound sidecar never falls back to a caller-owned port", () => {
	const serverPath = path.resolve(
		path.dirname(fileURLToPath(import.meta.url)),
		"..",
		"server.mjs",
	);
	const environment = {
		...process.env,
		PI_AGENT_BRIDGE_PORT: "0",
		PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET: "1",
	};
	delete environment.LISTEN_FDS;
	delete environment.LISTEN_FDNAMES;
	delete environment.LISTEN_PID;
	delete environment.NODE_OPTIONS;
	delete environment.NODE_PATH;
	const completed = spawnSync(process.execPath, [serverPath], {
		encoding: "utf8",
		env: environment,
		timeout: 10000,
		windowsHide: true,
	});
	assert.notEqual(completed.status, 0);
	assert.equal(completed.signal, null);
	assert.match(completed.stderr, /V3 Pi Bridge systemd socket is unavailable/);
});

test("Linux bootstrap binds Node, every dependency, runtime, and private attestation", {
	skip: rootIntegrationEnabled
		? false
		: "requires Linux, passwordless sudo, and an npm-ci dependency tree",
}, async () => {
	const current = await rootIntegrationFixture();
	let evidenceIndex = 0;
	const launch = (label) => {
		evidenceIndex += 1;
		const evidencePath = path.join(
			path.dirname(current.evidencePath),
			`${evidenceIndex}-${label}.json`,
		);
		const environment = {
			...process.env,
			HOME: "/tmp/hostile-home",
			ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET: "/tmp/hostile.sock",
			PI_AGENT_BRIDGE_HOST: "0.0.0.0",
			PI_AGENT_BRIDGE_PORT: "18787",
			PI_AGENT_SESSION_DIR: "/tmp/hostile-sessions",
			PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE: "/tmp/hostile.mjs",
			PI_BRIDGE_HARDENED_V3_ONLY: "0",
			PI_BRIDGE_REQUIRE_V3_IDENTITY: "0",
			PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET: "0",
			PI_BRIDGE_RUNTIME_ROOT: "/tmp/hostile-runtime",
			PI_BRIDGE_TEST_ATTESTATION_OUT: evidencePath,
			PI_CODING_AGENT_DIR: "/tmp/hostile-agent",
		};
		delete environment.NODE_OPTIONS;
		delete environment.NODE_PATH;
		return {
			completed: spawnSync(current.nodePath, [
				current.bootstrapPath,
				current.runtimeRoot,
			], {
				encoding: "utf8",
				env: environment,
				timeout: 120000,
			}),
			evidencePath,
		};
	};
	const assertRejected = async (observed) => {
		assert.notEqual(observed.completed.status, 0);
		assert.equal(observed.completed.signal, null);
		assert.equal(
			observed.completed.stderr.trim(),
			"V3 Pi Bridge bootstrap verification failed",
		);
		await assert.rejects(readFile(observed.evidencePath), /ENOENT/);
	};

	const accepted = launch("accepted");
	assert.equal(accepted.completed.status, 0, accepted.completed.stderr);
	assert.equal(accepted.completed.signal, null);
	assert.equal(accepted.completed.stderr, "");
	const evidence = JSON.parse(await readFile(accepted.evidencePath, "utf8"));
	assert.equal(
		evidence.agentDir,
		"/var/lib/odoo-accounting-cli-v3-pi-bridge/agent",
	);
	assert.equal(evidence.bridgeHost, "127.0.0.1");
	assert.equal(evidence.bridgePort, "18788");
	assert.equal(
		evidence.brokerSocket,
		"/run/odoo-accounting-cli-v3/pi-broker.sock",
	);
	assert.equal(evidence.cliPath, path.join(
		path.dirname(path.dirname(current.bootstrapPath)),
		"bin",
		"odoo-accounting-cli-v3",
	));
	assert.equal(evidence.manifestPath, path.join(
		path.dirname(path.dirname(current.bootstrapPath)),
		"RELEASE-MANIFEST.json",
	));
	assert.equal(evidence.home, "/var/lib/odoo-accounting-cli-v3-pi-bridge");
	assert.equal(evidence.hardenedV3Only, "1");
	assert.match(evidence.nodeSha256, /^[0-9a-f]{64}$/);
	assert.equal(evidence.piEntrypoint, current.piEntrypoint);
	assert.equal(evidence.release, RELEASE);
	assert.equal(
		evidence.resolverModule,
		path.join(current.runtimeRoot, "odoo-session-header-resolver.mjs"),
	);
	assert.equal(evidence.runtimeEnvironment, current.runtimeRoot);
	assert.equal(evidence.requireSystemdSocket, "1");
	assert.match(evidence.runtimeManifestSha256, /^[0-9a-f]{64}$/);
	assert.equal(evidence.runtimeRoot, current.runtimeRoot);
	assert.equal(
		evidence.sessionDir,
		"/var/lib/odoo-accounting-cli-v3-pi-bridge/sessions",
	);
	assert.equal(evidence.verified, true);

	const originalPi = await readFile(current.piEntrypoint);
	const piBackup = path.join(path.dirname(current.evidencePath), "pi-entrypoint.backup");
	await writeFile(piBackup, originalPi);
	const dependencyChanged = spawnSync("sudo", [
		"python3",
		"-c",
		"import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b'\\n// tampered\\n')",
		current.piEntrypoint,
	], { encoding: "utf8" });
	assert.equal(dependencyChanged.status, 0, dependencyChanged.stderr);
	await assertRejected(launch("dependency-tampered"));
	const dependencyRestored = spawnSync("sudo", [
		"install",
		"-m",
		"0644",
		"-o",
		"root",
		"-g",
		"root",
		piBackup,
		current.piEntrypoint,
	], { encoding: "utf8" });
	assert.equal(dependencyRestored.status, 0, dependencyRestored.stderr);

	const serverPath = path.join(current.runtimeRoot, "server.mjs");
	const runtimeChanged = spawnSync("sudo", ["chmod", "0666", serverPath], {
		encoding: "utf8",
	});
	assert.equal(runtimeChanged.status, 0, runtimeChanged.stderr);
	await assertRejected(launch("runtime-tampered"));
	const runtimeRestored = spawnSync("sudo", ["chmod", "0644", serverPath], {
		encoding: "utf8",
	});
	assert.equal(runtimeRestored.status, 0, runtimeRestored.stderr);

	const nodeChanged = spawnSync("sudo", [
		"python3",
		"-c",
		"import sys; open(sys.argv[1], 'ab').write(b'x')",
		current.nodePath,
	], { encoding: "utf8" });
	assert.equal(nodeChanged.status, 0, nodeChanged.stderr);
	await assertRejected(launch("node-tampered"));
});

test("bootstrap, package, and release file-set changes fail before server import", async (t) => {
	for (const [name, mutate, expected] of [
		["bootstrap bytes", async (current) => {
			await writeFile(
				path.join(current.releaseRoot, "pi_bridge", "bootstrap.mjs"),
				"older-bootstrap\n",
			);
		}, /release file does not match pi_bridge\/bootstrap\.mjs/],
		["canonical package", async (current) => {
			await writeFile(current.packagePath, "different-package\n");
		}, /canonical release package does not match/],
		["extra release file", async (current) => {
			await writeFile(path.join(current.releaseRoot, "untracked.mjs"), "extra\n");
		}, /release file set does not match/],
		["external anchor", async (current) => {
			await writeFile(current.anchorPath, "{}\n");
		}, /external release anchor does not match/],
	]) {
		await t.test(name, async () => {
			const current = await fixture();
			await mutate(current);
			assert.throws(
				() => verifyCanonicalRelease({
					releaseRoot: current.releaseRoot,
					requireRootOwned: false,
				}),
				expected,
			);
		});
	}
});
