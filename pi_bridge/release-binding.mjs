import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SHA256 = /^[0-9a-f]{64}$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const COMMIT = /^[0-9a-f]{40}$/;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_RUNTIME_FILE_BYTES = 4 * 1024 * 1024;

export const PI_BRIDGE_RUNTIME_MEMBERS = Object.freeze([
	"pi_bridge/extensions/odoo-tools.ts",
	"pi_bridge/extensions/odoo-v3-cli.mjs",
	"pi_bridge/odoo-session-header-resolver.mjs",
	"pi_bridge/package-lock.json",
	"pi_bridge/package.json",
	"pi_bridge/release-binding.mjs",
	"pi_bridge/server.mjs",
	"pi_bridge/tool-policy.mjs",
	"pi_bridge/trusted-session.mjs",
]);

function exactKeys(value, keys) {
	return value !== null
		&& typeof value === "object"
		&& !Array.isArray(value)
		&& JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

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
	if (value !== null && typeof value === "object") {
		return `{${Object.keys(value).sort().map(
			(key) => `${canonicalString(key)}:${canonicalJson(value[key])}`,
		).join(",")}}`;
	}
	throw new Error("V3 release manifest contains a non-canonical value");
}

function sameFileIdentity(left, right) {
	return left.dev === right.dev
		&& left.ino === right.ino
		&& left.nlink === right.nlink
		&& left.size === right.size
		&& left.mtimeNs === right.mtimeNs
		&& left.ctimeNs === right.ctimeNs;
}

function requireRootManagedAncestors(filePath) {
	if (process.platform !== "linux" || typeof process.getuid !== "function") {
		throw new Error("Root-managed V3 Pi Bridge binding requires Linux");
	}
	let current = path.dirname(filePath);
	for (;;) {
		const stat = fs.lstatSync(current, { bigint: true });
		if (
			stat.isSymbolicLink()
			|| !stat.isDirectory()
			|| stat.uid !== 0n
			|| (stat.mode & 0o022n) !== 0n
		) {
			throw new Error("V3 Pi Bridge ancestors are not root-managed");
		}
		const parent = path.dirname(current);
		if (parent === current) return;
		current = parent;
	}
}

function readStableFile(filePath, maximumBytes, requireRootOwned) {
	if (typeof filePath !== "string" || !path.isAbsolute(filePath) || filePath.includes("\0")) {
		throw new Error("V3 Pi Bridge release path is invalid");
	}
	if (path.resolve(filePath) !== filePath) {
		throw new Error("V3 Pi Bridge release path is not canonical");
	}
	if (requireRootOwned) requireRootManagedAncestors(filePath);

	const enforceUnixPermissions = process.platform !== "win32";
	const before = fs.lstatSync(filePath, { bigint: true });
	if (
		before.isSymbolicLink()
		|| !before.isFile()
		|| before.nlink !== 1n
		|| before.size < 1n
		|| before.size > BigInt(maximumBytes)
		|| (enforceUnixPermissions && (before.mode & 0o022n) !== 0n)
		|| (requireRootOwned && before.uid !== 0n)
	) {
		throw new Error("V3 Pi Bridge release file is unsafe");
	}
	if (fs.realpathSync.native(filePath) !== filePath) {
		throw new Error("V3 Pi Bridge release file path is not canonical");
	}

	const noFollow = fs.constants.O_NOFOLLOW;
	if (requireRootOwned && typeof noFollow !== "number") {
		throw new Error("V3 Pi Bridge binding requires O_NOFOLLOW support");
	}
	const descriptor = fs.openSync(
		filePath,
		fs.constants.O_RDONLY | (fs.constants.O_CLOEXEC ?? 0) | (noFollow ?? 0),
	);
	let content;
	try {
		const opened = fs.fstatSync(descriptor, { bigint: true });
		if (
			!opened.isFile()
			|| !sameFileIdentity(before, opened)
			|| (enforceUnixPermissions && (opened.mode & 0o022n) !== 0n)
			|| (requireRootOwned && opened.uid !== 0n)
		) {
			throw new Error("V3 Pi Bridge release file changed while opening");
		}
		content = fs.readFileSync(descriptor);
		const afterRead = fs.fstatSync(descriptor, { bigint: true });
		if (!sameFileIdentity(opened, afterRead) || content.length !== Number(opened.size)) {
			throw new Error("V3 Pi Bridge release file changed while reading");
		}
	} finally {
		fs.closeSync(descriptor);
	}
	const after = fs.lstatSync(filePath, { bigint: true });
	if (!sameFileIdentity(before, after) || after.isSymbolicLink()) {
		throw new Error("V3 Pi Bridge release file changed during verification");
	}
	return content;
}

function parseVerifiedManifest(content, expectedManifestSha256) {
	if (typeof expectedManifestSha256 !== "string" || !SHA256.test(expectedManifestSha256)) {
		throw new Error("V3 release manifest SHA-256 is invalid");
	}
	let manifest;
	try {
		manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(content));
	} catch {
		throw new Error("V3 release manifest is not strict UTF-8 JSON");
	}
	if (!exactKeys(manifest, [
		"commit",
		"files",
		"manifest_sha256",
		"schema_version",
		"version",
	])) {
		throw new Error("V3 release manifest fields are invalid");
	}
	if (
		manifest.schema_version !== 1
		|| !VERSION.test(manifest.version)
		|| !COMMIT.test(manifest.commit)
		|| manifest.manifest_sha256 !== expectedManifestSha256
		|| !Array.isArray(manifest.files)
		|| manifest.files.length === 0
	) {
		throw new Error("V3 release manifest identity is invalid");
	}
	const unsigned = { ...manifest };
	delete unsigned.manifest_sha256;
	const actualManifestSha256 = createHash("sha256")
		.update(canonicalJson(unsigned), "utf8")
		.digest("hex");
	if (actualManifestSha256 !== expectedManifestSha256) {
		throw new Error("V3 release manifest digest does not match");
	}

	const files = new Map();
	for (const item of manifest.files) {
		if (
			!exactKeys(item, ["path", "sha256", "size"])
			|| typeof item.path !== "string"
			|| path.posix.isAbsolute(item.path)
			|| path.posix.normalize(item.path) !== item.path
			|| item.path.split("/").some((part) => !part || part === "." || part === "..")
			|| typeof item.sha256 !== "string"
			|| !SHA256.test(item.sha256)
			|| !Number.isSafeInteger(item.size)
			|| item.size < 0
			|| files.has(item.path)
		) {
			throw new Error("V3 release manifest file entry is invalid");
		}
		files.set(item.path, item);
	}
	return { files, manifest };
}

export function verifyPiBridgeReleaseBinding(options = {}) {
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| Object.keys(options).some((key) => ![
			"bridgeRoot",
			"expectedManifestSha256",
			"manifestPath",
			"requireRootOwned",
		].includes(key))
		|| (
			options.requireRootOwned !== undefined
			&& typeof options.requireRootOwned !== "boolean"
		)
	) {
		throw new Error("V3 Pi Bridge release-binding options are invalid");
	}
	const bridgeRoot = options.bridgeRoot;
	if (
		typeof bridgeRoot !== "string"
		|| !path.isAbsolute(bridgeRoot)
		|| bridgeRoot.includes("\0")
		|| path.resolve(bridgeRoot) !== bridgeRoot
		|| fs.realpathSync.native(bridgeRoot) !== bridgeRoot
	) {
		throw new Error("V3 Pi Bridge root is not canonical");
	}
	const requireRootOwned = options.requireRootOwned === true;
	const manifestContent = readStableFile(
		options.manifestPath,
		MAX_MANIFEST_BYTES,
		requireRootOwned,
	);
	const { files, manifest } = parseVerifiedManifest(
		manifestContent,
		options.expectedManifestSha256,
	);

	for (const releasePath of PI_BRIDGE_RUNTIME_MEMBERS) {
		const entry = files.get(releasePath);
		if (!entry) {
			throw new Error(`V3 release manifest omits ${releasePath}`);
		}
		const runtimePath = path.join(
			bridgeRoot,
			...releasePath.slice("pi_bridge/".length).split("/"),
		);
		const content = readStableFile(
			runtimePath,
			MAX_RUNTIME_FILE_BYTES,
			requireRootOwned,
		);
		if (
			content.length !== entry.size
			|| createHash("sha256").update(content).digest("hex") !== entry.sha256
		) {
			throw new Error(`V3 Pi Bridge runtime file does not match ${releasePath}`);
		}
	}

	return Object.freeze({
		commit: manifest.commit,
		manifest_sha256: manifest.manifest_sha256,
		runtime_file_count: PI_BRIDGE_RUNTIME_MEMBERS.length,
		verified: true,
		version: manifest.version,
	});
}
