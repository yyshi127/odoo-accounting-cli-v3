import path from "node:path";
import fs from "node:fs";
import { createHash } from "node:crypto";

const BROKER_SESSION_HANDLE = /^[A-Za-z0-9._~-]{32,512}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_RESOLVER_BYTES = 256 * 1024;

export class BrokerSessionWriteError extends Error {
	constructor() {
		super("Authenticated broker session write failed");
		this.name = "BrokerSessionWriteError";
		this.code = "broker_session_write_failed";
	}
}

export function writeBrokerSessionHandle(stream, sessionHandle) {
	if (
		stream === null
		|| typeof stream !== "object"
		|| typeof stream.once !== "function"
		|| typeof stream.end !== "function"
		|| typeof sessionHandle !== "string"
	) {
		return Promise.reject(new BrokerSessionWriteError());
	}
	return new Promise((resolve, reject) => {
		let finished = false;
		let settled = false;
		const fail = () => {
			if (settled) return;
			settled = true;
			reject(new BrokerSessionWriteError());
		};
		stream.once("finish", () => {
			finished = true;
		});
		stream.once("error", fail);
		stream.once("close", () => {
			if (!finished) {
				fail();
				return;
			}
			if (settled) return;
			settled = true;
			resolve();
		});
		try {
			stream.end(sessionHandle, "utf8");
		} catch {
			fail();
		}
	});
}

export function validBrokerSessionHandle(value) {
	return typeof value === "string" && BROKER_SESSION_HANDLE.test(value);
}

function sameFileIdentity(left, right) {
	return left.dev === right.dev
		&& left.ino === right.ino
		&& left.size === right.size
		&& left.mtimeNs === right.mtimeNs
		&& left.ctimeNs === right.ctimeNs;
}

function requireRootManagedAncestors(modulePath) {
	if (typeof process.getuid !== "function" || process.platform !== "linux") {
		throw new Error("Root-owned authenticated session resolvers require Linux");
	}
	let current = path.dirname(modulePath);
	for (;;) {
		const stat = fs.lstatSync(current, { bigint: true });
		if (
			stat.isSymbolicLink()
			|| !stat.isDirectory()
			|| stat.uid !== 0n
			|| (stat.mode & 0o022n) !== 0n
		) {
			throw new Error(
				"Authenticated session resolver ancestors must be root-owned and non-writable",
			);
		}
		const parent = path.dirname(current);
		if (parent === current) return;
		current = parent;
	}
}

function readVerifiedResolver(modulePath, { expectedSha256, requireRootOwned }) {
	const enforceUnixPermissions = process.platform !== "win32";
	if (expectedSha256 !== undefined && !SHA256.test(expectedSha256)) {
		throw new Error("Authenticated session resolver SHA-256 is invalid");
	}
	if (requireRootOwned && expectedSha256 === undefined) {
		throw new Error("Root-owned authenticated session resolver requires a SHA-256 binding");
	}
	if (path.resolve(modulePath) !== modulePath) {
		throw new Error("Authenticated session resolver module path must be canonical");
	}
	if (requireRootOwned) requireRootManagedAncestors(modulePath);

	const before = fs.lstatSync(modulePath, { bigint: true });
	if (
		before.isSymbolicLink()
		|| !before.isFile()
		|| (enforceUnixPermissions && (before.mode & 0o022n) !== 0n)
		|| (requireRootOwned && before.uid !== 0n)
	) {
		throw new Error(
			"Authenticated session resolver must be a root-owned, non-symlink, non-writable file",
		);
	}
	if (before.size < 1n || before.size > BigInt(MAX_RESOLVER_BYTES)) {
		throw new Error("Authenticated session resolver module size is invalid");
	}
	if (fs.realpathSync.native(modulePath) !== modulePath) {
		throw new Error("Authenticated session resolver module path must be canonical");
	}

	const noFollow = fs.constants.O_NOFOLLOW;
	if (requireRootOwned && typeof noFollow !== "number") {
		throw new Error("Authenticated session resolver requires O_NOFOLLOW support");
	}
	const descriptor = fs.openSync(
		modulePath,
		fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | (noFollow ?? 0),
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
			throw new Error("Authenticated session resolver changed while it was opened");
		}
		content = fs.readFileSync(descriptor);
		const afterRead = fs.fstatSync(descriptor, { bigint: true });
		if (!sameFileIdentity(opened, afterRead) || content.length !== Number(opened.size)) {
			throw new Error("Authenticated session resolver changed while it was read");
		}
	} finally {
		fs.closeSync(descriptor);
	}
	const after = fs.lstatSync(modulePath, { bigint: true });
	if (!sameFileIdentity(before, after) || after.isSymbolicLink()) {
		throw new Error("Authenticated session resolver changed during verification");
	}
	const actualSha256 = createHash("sha256").update(content).digest("hex");
	if (expectedSha256 !== undefined && actualSha256 !== expectedSha256) {
		throw new Error("Authenticated session resolver SHA-256 does not match");
	}
	let source;
	try {
		source = new TextDecoder("utf-8", { fatal: true }).decode(content);
	} catch {
		throw new Error("Authenticated session resolver is not valid UTF-8");
	}
	// The resolver is an immutable, single-file trust adapter. Loading the exact
	// verified bytes from a data URL removes the path race; forbidding module
	// imports prevents an otherwise-unpinned sibling dependency from becoming a
	// second authentication authority.
	if (/\bimport\b/u.test(source) || /\bfrom\s*["']/u.test(source)) {
		throw new Error("Authenticated session resolver must be a dependency-free module");
	}
	return content;
}

export async function loadAuthenticatedSessionResolver(modulePath, options = {}) {
	if (modulePath === undefined || modulePath === null || modulePath === "") {
		return null;
	}
	if (
		typeof modulePath !== "string"
		|| !path.isAbsolute(modulePath)
		|| modulePath.includes("\0")
	) {
		throw new Error("Authenticated session resolver module path must be absolute");
	}
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| Object.keys(options).some(
			(key) => !["expectedSha256", "requireRootOwned"].includes(key),
		)
	) {
		throw new Error("Authenticated session resolver options are invalid");
	}
	const content = readVerifiedResolver(modulePath, {
		expectedSha256: options.expectedSha256,
		requireRootOwned: options.requireRootOwned === true,
	});
	const loaded = await import(`data:text/javascript;base64,${content.toString("base64")}`);
	const exportNames = Object.keys(loaded).sort();
	if (
		JSON.stringify(exportNames) !== JSON.stringify(["default"])
		&& JSON.stringify(exportNames) !== JSON.stringify(["resolveAuthenticatedSession"])
	) {
		throw new Error("Authenticated session resolver module exports are invalid");
	}
	const resolver = loaded.resolveAuthenticatedSession ?? loaded.default;
	if (typeof resolver !== "function") {
		throw new Error("Authenticated session resolver module must export a resolver function");
	}
	return resolver;
}

export async function resolveAuthenticatedBrokerSession(resolver, request) {
	if (resolver === null || resolver === undefined) {
		return null;
	}
	if (typeof resolver !== "function") {
		throw new Error("Authenticated session resolver is invalid");
	}
	const resolved = await resolver(Object.freeze({
		headers: Object.freeze({ ...(request?.headers ?? {}) }),
		method: String(request?.method ?? ""),
		remoteAddress: String(request?.remoteAddress ?? ""),
		url: String(request?.url ?? ""),
	}));
	if (resolved === null || resolved === undefined) {
		return null;
	}
	if (
		typeof resolved !== "object"
		|| Array.isArray(resolved)
		|| JSON.stringify(Object.keys(resolved).sort()) !== JSON.stringify([
			"brokerSessionHandle",
			"resultDeliverySessionHandle",
		])
		|| !validBrokerSessionHandle(resolved.brokerSessionHandle)
		|| !validBrokerSessionHandle(resolved.resultDeliverySessionHandle)
		|| resolved.brokerSessionHandle === resolved.resultDeliverySessionHandle
	) {
		throw new Error("Authenticated session resolver returned an invalid broker session");
	}
	return Object.freeze({
		brokerSessionHandle: resolved.brokerSessionHandle,
		resultDeliverySessionHandle: resolved.resultDeliverySessionHandle,
	});
}
