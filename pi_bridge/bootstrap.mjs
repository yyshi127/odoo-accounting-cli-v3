import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const RELEASE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]{0,255}$/;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 512 * 1024 * 1024;
const MAX_RUNTIME_MEMBERS = 100_000;
const PI_RUNTIME_MANIFEST = "PI-RUNTIME-MANIFEST.json";
let bootstrapAttestation;

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
	throw new Error("release contains a non-canonical manifest value");
}

function sameFileIdentity(left, right) {
	return left.dev === right.dev
		&& left.ino === right.ino
		&& left.nlink === right.nlink
		&& left.size === right.size
		&& left.mtimeNs === right.mtimeNs
		&& left.ctimeNs === right.ctimeNs;
}

function assertRootManagedAncestors(filePath) {
	if (process.platform !== "linux" || typeof process.getuid !== "function") {
		throw new Error("production Pi Bridge bootstrap requires Linux");
	}
	let current = path.dirname(filePath);
	for (;;) {
		const metadata = fs.lstatSync(current, { bigint: true });
		if (
			metadata.isSymbolicLink()
			|| !metadata.isDirectory()
			|| metadata.uid !== 0n
			|| (metadata.mode & 0o022n) !== 0n
		) {
			throw new Error("Pi Bridge bootstrap ancestors are not root-managed");
		}
		const parent = path.dirname(current);
		if (parent === current) return;
		current = parent;
	}
}

function assertCanonicalDirectory(directory, requireRootOwned) {
	if (
		typeof directory !== "string"
		|| !path.isAbsolute(directory)
		|| directory.includes("\0")
		|| path.resolve(directory) !== directory
		|| fs.realpathSync.native(directory) !== directory
	) {
		throw new Error("Pi Bridge bootstrap directory is not canonical");
	}
	if (requireRootOwned) assertRootManagedAncestors(path.join(directory, ".root"));
	const metadata = fs.lstatSync(directory, { bigint: true });
	if (
		metadata.isSymbolicLink()
		|| !metadata.isDirectory()
		|| (requireRootOwned && (
			metadata.uid !== 0n
			|| (metadata.mode & 0o022n) !== 0n
		))
	) {
		throw new Error("Pi Bridge bootstrap directory is unsafe");
	}
}

function withStableFile(
	filePath,
	{ maximumBytes, minimumBytes = 0, requireRootOwned },
	consume,
) {
	if (
		typeof filePath !== "string"
		|| !path.isAbsolute(filePath)
		|| filePath.includes("\0")
		|| path.resolve(filePath) !== filePath
	) {
		throw new Error("Pi Bridge bootstrap file path is invalid");
	}
	if (requireRootOwned) assertRootManagedAncestors(filePath);
	const before = fs.lstatSync(filePath, { bigint: true });
	if (
		before.isSymbolicLink()
		|| !before.isFile()
		|| before.nlink !== 1n
		|| before.size < BigInt(minimumBytes)
		|| before.size > BigInt(maximumBytes)
		|| (requireRootOwned && (
			before.uid !== 0n
			|| (before.mode & 0o022n) !== 0n
		))
		|| fs.realpathSync.native(filePath) !== filePath
	) {
		throw new Error("Pi Bridge bootstrap file is unsafe");
	}
	const noFollow = fs.constants.O_NOFOLLOW;
	if (requireRootOwned && typeof noFollow !== "number") {
		throw new Error("Pi Bridge bootstrap requires O_NOFOLLOW");
	}
	const descriptor = fs.openSync(
		filePath,
		fs.constants.O_RDONLY | (fs.constants.O_CLOEXEC ?? 0) | (noFollow ?? 0),
	);
	let result;
	try {
		const opened = fs.fstatSync(descriptor, { bigint: true });
		if (
			!opened.isFile()
			|| !sameFileIdentity(before, opened)
			|| (requireRootOwned && (
				opened.uid !== 0n
				|| (opened.mode & 0o022n) !== 0n
			))
		) {
			throw new Error("Pi Bridge bootstrap file changed while opening");
		}
		result = consume(descriptor, Number(opened.size));
		const afterRead = fs.fstatSync(descriptor, { bigint: true });
		if (!sameFileIdentity(opened, afterRead)) {
			throw new Error("Pi Bridge bootstrap file changed while reading");
		}
	} finally {
		fs.closeSync(descriptor);
	}
	const after = fs.lstatSync(filePath, { bigint: true });
	if (!sameFileIdentity(before, after) || after.isSymbolicLink()) {
		throw new Error("Pi Bridge bootstrap file changed during verification");
	}
	return result;
}

function readStableFile(filePath, options) {
	return withStableFile(filePath, options, (descriptor, size) => {
		const content = fs.readFileSync(descriptor);
		if (content.length !== size) {
			throw new Error("Pi Bridge bootstrap file read is incomplete");
		}
		return content;
	});
}

function hashStableFile(filePath, options) {
	return withStableFile(filePath, options, (descriptor, size) => {
		const digest = createHash("sha256");
		const buffer = Buffer.allocUnsafe(1024 * 1024);
		let offset = 0;
		while (offset < size) {
			const count = fs.readSync(
				descriptor,
				buffer,
				0,
				Math.min(buffer.length, size - offset),
				offset,
			);
			if (count < 1) {
				throw new Error("Pi Bridge bootstrap file hash is incomplete");
			}
			digest.update(buffer.subarray(0, count));
			offset += count;
		}
		return { sha256: digest.digest("hex"), size };
	});
}

function strictJson(content, label) {
	try {
		return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(content));
	} catch {
		throw new Error(`${label} is not strict UTF-8 JSON`);
	}
}

function manifestEntries(manifest) {
	if (
		!exactKeys(manifest, [
			"commit",
			"files",
			"manifest_sha256",
			"schema_version",
			"version",
		])
		|| manifest.schema_version !== 1
		|| !VERSION.test(manifest.version)
		|| !COMMIT.test(manifest.commit)
		|| !SHA256.test(manifest.manifest_sha256)
		|| !Array.isArray(manifest.files)
		|| manifest.files.length === 0
	) {
		throw new Error("release manifest identity is invalid");
	}
	const entries = new Map();
	for (const item of manifest.files) {
		if (
			!exactKeys(item, ["path", "sha256", "size"])
			|| typeof item.path !== "string"
			|| path.posix.isAbsolute(item.path)
			|| path.posix.normalize(item.path) !== item.path
			|| item.path.split("/").some((part) => !part || part === "." || part === "..")
			|| !SHA256.test(item.sha256)
			|| !Number.isSafeInteger(item.size)
			|| item.size < 0
			|| entries.has(item.path)
		) {
			throw new Error("release manifest file entry is invalid");
		}
		entries.set(item.path, item);
	}
	return entries;
}

function actualReleaseFiles(releaseRoot, requireRootOwned) {
	const files = new Set();
	const pending = [releaseRoot];
	while (pending.length > 0) {
		const current = pending.pop();
		for (const name of fs.readdirSync(current).sort()) {
			const candidate = path.join(current, name);
			const metadata = fs.lstatSync(candidate, { bigint: true });
			if (metadata.isSymbolicLink()) {
				throw new Error("release contains a symlink");
			}
			if (metadata.isDirectory()) {
				if (requireRootOwned && (
					metadata.uid !== 0n
					|| (metadata.mode & 0o022n) !== 0n
				)) {
					throw new Error("release directory is not root-managed");
				}
				pending.push(candidate);
				continue;
			}
			if (!metadata.isFile()) {
				throw new Error("release contains a non-regular member");
			}
			const relative = path.relative(releaseRoot, candidate).split(path.sep).join("/");
			if (relative !== "RELEASE-MANIFEST.json") files.add(relative);
		}
	}
	return files;
}

function assertSeparateRuntime(releaseRoot, runtimeRoot) {
	if (
		runtimeRoot === releaseRoot
		|| runtimeRoot.startsWith(`${releaseRoot}${path.sep}`)
		|| releaseRoot.startsWith(`${runtimeRoot}${path.sep}`)
	) {
		throw new Error("Pi Bridge runtime must be separate from the immutable release");
	}
}

function parseNumericVersion(value, label) {
	const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value ?? "");
	if (!match) throw new Error(`${label} is not a stable numeric version`);
	return match.slice(1).map((part) => Number(part));
}

export function nodeVersionMeetsEngine(version, engine) {
	const match = /^>=(\d+)\.(\d+)\.(\d+)$/.exec(engine ?? "");
	if (!match) {
		throw new Error("release does not declare one minimum Node version");
	}
	const minimum = match.slice(1).map((part) => Number(part));
	const current = parseNumericVersion(version, "running Node");
	for (let index = 0; index < minimum.length; index += 1) {
		if (current[index] > minimum[index]) return true;
		if (current[index] < minimum[index]) return false;
	}
	return true;
}

function assertSupportedNode(engine) {
	if (!nodeVersionMeetsEngine(process.versions.node, engine)) {
		throw new Error("running Node does not satisfy the release engine");
	}
}

function readPiDependencySpec(releaseRoot) {
	const packageDocument = strictJson(readStableFile(
		path.join(releaseRoot, "pi_bridge", "package.json"),
		{
			maximumBytes: MAX_JSON_BYTES,
			minimumBytes: 1,
			requireRootOwned: true,
		},
	), "Pi Bridge package");
	const lockContent = readStableFile(
		path.join(releaseRoot, "pi_bridge", "package-lock.json"),
		{
			maximumBytes: MAX_JSON_BYTES,
			minimumBytes: 1,
			requireRootOwned: true,
		},
	);
	const lock = strictJson(lockContent, "Pi dependency lock");
	const packageName = "@earendil-works/pi-coding-agent";
	const expectedVersion = packageDocument?.dependencies?.[packageName];
	const nodeEngine = packageDocument?.engines?.node;
	const rootPackage = lock?.packages?.[""];
	const lockedPackage = lock?.packages?.[`node_modules/${packageName}`];
	if (
		lock?.lockfileVersion !== 3
		|| typeof expectedVersion !== "string"
		|| expectedVersion !== rootPackage?.dependencies?.[packageName]
		|| expectedVersion !== lockedPackage?.version
		|| typeof lockedPackage?.integrity !== "string"
		|| !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(lockedPackage.integrity)
		|| JSON.stringify(lockedPackage.bin) !== JSON.stringify({ pi: "dist/cli.js" })
		|| typeof nodeEngine !== "string"
	) {
		throw new Error("Pi dependency lock does not pin the runtime entrypoint");
	}
	assertSupportedNode(nodeEngine);
	return Object.freeze({
		expectedVersion,
		lockSha256: createHash("sha256").update(lockContent).digest("hex"),
		nodeEngine,
		packageName,
	});
}

function dependencyMembers(nodeModulesRoot) {
	assertCanonicalDirectory(nodeModulesRoot, true);
	const members = [];
	const pending = [nodeModulesRoot];
	while (pending.length > 0) {
		const current = pending.pop();
		for (const name of fs.readdirSync(current).sort()) {
			const candidate = path.join(current, name);
			const relative = path.relative(nodeModulesRoot, candidate)
				.split(path.sep).join("/");
			const before = fs.lstatSync(candidate, { bigint: true });
			if (before.isSymbolicLink()) {
				if (before.uid !== 0n || before.nlink !== 1n) {
					throw new Error("Pi dependency symlink is unsafe");
				}
				const target = fs.readlinkSync(candidate);
				const after = fs.lstatSync(candidate, { bigint: true });
				if (
					!target
					|| target.includes("\0")
					|| !sameFileIdentity(before, after)
				) {
					throw new Error("Pi dependency symlink changed during verification");
				}
				const resolved = fs.realpathSync.native(candidate);
				if (!resolved.startsWith(`${nodeModulesRoot}${path.sep}`)) {
					throw new Error("Pi dependency symlink escapes node_modules");
				}
				const resolvedMetadata = fs.lstatSync(resolved, { bigint: true });
				if (
					!resolvedMetadata.isFile()
					|| resolvedMetadata.nlink !== 1n
					|| resolvedMetadata.uid !== 0n
					|| (resolvedMetadata.mode & 0o022n) !== 0n
				) {
					throw new Error("Pi dependency symlink target is unsafe");
				}
				members.push({ path: relative, target, type: "symlink" });
			} else if (before.isDirectory()) {
				if (before.uid !== 0n || (before.mode & 0o022n) !== 0n) {
					throw new Error("Pi dependency directory is not root-managed");
				}
				pending.push(candidate);
			} else if (before.isFile()) {
				const observed = hashStableFile(candidate, {
					maximumBytes: MAX_PACKAGE_BYTES,
					requireRootOwned: true,
				});
				members.push({
					path: relative,
					sha256: observed.sha256,
					size: observed.size,
					type: "file",
				});
			} else {
				throw new Error("Pi dependency tree contains a non-file member");
			}
			if (members.length > MAX_RUNTIME_MEMBERS) {
				throw new Error("Pi dependency tree is too large");
			}
		}
	}
	members.sort((left, right) => (
		left.path < right.path ? -1 : left.path > right.path ? 1 : 0
	));
	if (members.length === 0) throw new Error("Pi dependency tree is empty");
	return members;
}

function validateRuntimeManifest(document) {
	if (
		!exactKeys(document, [
			"files",
			"manifest_sha256",
			"node",
			"package_lock_sha256",
			"release",
			"release_manifest_sha256",
			"schema_version",
		])
		|| document.schema_version !== 1
		|| !RELEASE_NAME.test(document.release)
		|| !SHA256.test(document.release_manifest_sha256)
		|| !SHA256.test(document.package_lock_sha256)
		|| !SHA256.test(document.manifest_sha256)
		|| !Array.isArray(document.files)
		|| document.files.length === 0
		|| document.files.length > MAX_RUNTIME_MEMBERS
		|| !exactKeys(document.node, [
			"arch",
			"path",
			"platform",
			"sha256",
			"size",
			"version",
		])
		|| typeof document.node.arch !== "string"
		|| typeof document.node.platform !== "string"
		|| typeof document.node.path !== "string"
		|| !path.isAbsolute(document.node.path)
		|| path.resolve(document.node.path) !== document.node.path
		|| !SHA256.test(document.node.sha256)
		|| !Number.isSafeInteger(document.node.size)
		|| document.node.size < 1
	) {
		throw new Error("Pi runtime manifest is invalid");
	}
	parseNumericVersion(document.node.version, "anchored Node");
	let previous = "";
	for (const item of document.files) {
		if (
			item === null
			|| typeof item !== "object"
			|| Array.isArray(item)
			|| typeof item.path !== "string"
			|| path.posix.isAbsolute(item.path)
			|| path.posix.normalize(item.path) !== item.path
			|| item.path.split("/").some((part) => !part || part === "." || part === "..")
			|| item.path <= previous
		) {
			throw new Error("Pi runtime manifest member is invalid");
		}
		previous = item.path;
		if (item.type === "file") {
			if (
				!exactKeys(item, ["path", "sha256", "size", "type"])
				|| !SHA256.test(item.sha256)
				|| !Number.isSafeInteger(item.size)
				|| item.size < 0
			) {
				throw new Error("Pi runtime file member is invalid");
			}
		} else if (
			item.type !== "symlink"
			|| !exactKeys(item, ["path", "target", "type"])
			|| typeof item.target !== "string"
			|| !item.target
			|| item.target.includes("\0")
		) {
			throw new Error("Pi runtime symlink member is invalid");
		}
	}
	const unsigned = { ...document };
	delete unsigned.manifest_sha256;
	if (
		createHash("sha256").update(canonicalJson(unsigned), "utf8").digest("hex")
		!== document.manifest_sha256
	) {
		throw new Error("Pi runtime manifest digest does not match");
	}
	return document;
}

function validateInstalledPiPackage(nodeModulesRoot, dependencySpec) {
	const installedPackagePath = path.join(
		nodeModulesRoot,
		"@earendil-works",
		"pi-coding-agent",
		"package.json",
	);
	const installedPackage = strictJson(readStableFile(installedPackagePath, {
		maximumBytes: MAX_JSON_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	}), "installed Pi package");
	if (
		installedPackage?.name !== dependencySpec.packageName
		|| installedPackage?.version !== dependencySpec.expectedVersion
		|| JSON.stringify(installedPackage?.bin) !== JSON.stringify({ pi: "dist/cli.js" })
	) {
		throw new Error("installed Pi package does not match the release lock");
	}
	const piEntrypoint = path.join(
		path.dirname(installedPackagePath),
		"dist",
		"cli.js",
	);
	withStableFile(piEntrypoint, {
		maximumBytes: MAX_RELEASE_FILE_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	}, () => true);
	return piEntrypoint;
}

function fsyncDirectory(directory) {
	const descriptor = fs.openSync(
		directory,
		fs.constants.O_RDONLY
			| (fs.constants.O_DIRECTORY ?? 0)
			| (fs.constants.O_CLOEXEC ?? 0),
	);
	try {
		fs.fsyncSync(descriptor);
	} finally {
		fs.closeSync(descriptor);
	}
}

function writeExclusiveRootJson(filePath, document) {
	assertRootManagedAncestors(filePath);
	const directory = path.dirname(filePath);
	assertCanonicalDirectory(directory, true);
	const content = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, "utf8");
	let descriptor;
	let created = false;
	try {
		descriptor = fs.openSync(
			filePath,
			fs.constants.O_WRONLY
				| fs.constants.O_CREAT
				| fs.constants.O_EXCL
				| (fs.constants.O_CLOEXEC ?? 0)
				| (fs.constants.O_NOFOLLOW ?? 0),
			0o444,
		);
		created = true;
		fs.fchownSync(descriptor, 0, 0);
		fs.fchmodSync(descriptor, 0o444);
		fs.writeFileSync(descriptor, content);
		fs.fsyncSync(descriptor);
		const completedDescriptor = descriptor;
		descriptor = undefined;
		fs.closeSync(completedDescriptor);
		fsyncDirectory(directory);
		withStableFile(filePath, {
			maximumBytes: MAX_JSON_BYTES,
			minimumBytes: 1,
			requireRootOwned: true,
		}, () => true);
	} catch (error) {
		if (descriptor !== undefined) {
			try { fs.closeSync(descriptor); } catch { /* retain the original error */ }
		}
		if (created) {
			try {
				fs.unlinkSync(filePath);
				fsyncDirectory(directory);
			} catch { /* retain the original error */ }
		}
		throw error;
	}
}

export function verifyCanonicalRelease(options = {}) {
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| !exactKeys(options, ["releaseRoot", "requireRootOwned"])
		|| typeof options.requireRootOwned !== "boolean"
	) {
		throw new Error("Pi Bridge bootstrap release options are invalid");
	}
	const releaseRoot = options.releaseRoot;
	const requireRootOwned = options.requireRootOwned;
	assertCanonicalDirectory(releaseRoot, requireRootOwned);
	if (path.basename(path.dirname(releaseRoot)) !== "releases") {
		throw new Error("Pi Bridge release is outside the releases root");
	}
	const releaseName = path.basename(releaseRoot);
	if (!RELEASE_NAME.test(releaseName)) {
		throw new Error("Pi Bridge release name is invalid");
	}
	const installRoot = path.dirname(path.dirname(releaseRoot));
	const manifestPath = path.join(releaseRoot, "RELEASE-MANIFEST.json");
	const anchorPath = path.join(
		installRoot,
		"trusted-artifacts",
		`${releaseName}.json`,
	);
	const manifest = strictJson(readStableFile(manifestPath, {
		maximumBytes: MAX_JSON_BYTES,
		minimumBytes: 1,
		requireRootOwned,
	}), "release manifest");
	const anchor = strictJson(readStableFile(anchorPath, {
		maximumBytes: MAX_JSON_BYTES,
		minimumBytes: 1,
		requireRootOwned,
	}), "release anchor");
	const entries = manifestEntries(manifest);
	const expectedReleaseName = `${manifest.version}-${manifest.commit.slice(0, 12)}`;
	if (
		!exactKeys(anchor, ["commit", "manifest_sha256", "package_sha256", "release"])
		|| anchor.release !== releaseName
		|| releaseName !== expectedReleaseName
		|| anchor.commit !== manifest.commit
		|| anchor.manifest_sha256 !== manifest.manifest_sha256
		|| !SHA256.test(anchor.package_sha256)
	) {
		throw new Error("external release anchor does not match the release");
	}
	const unsigned = { ...manifest };
	delete unsigned.manifest_sha256;
	if (
		createHash("sha256").update(canonicalJson(unsigned), "utf8").digest("hex")
		!== manifest.manifest_sha256
	) {
		throw new Error("release manifest digest does not match");
	}
	for (const required of [
		"bin/odoo-accounting-cli-v3",
		"pi_bridge/bootstrap.mjs",
		"pi_bridge/release-binding.mjs",
		"registry/capabilities.json",
	]) {
		if (!entries.has(required)) {
			throw new Error(`release manifest omits ${required}`);
		}
	}
	const actualFiles = actualReleaseFiles(releaseRoot, requireRootOwned);
	if (
		actualFiles.size !== entries.size
		|| [...actualFiles].some((name) => !entries.has(name))
	) {
		throw new Error("release file set does not match the manifest");
	}
	for (const [name, entry] of entries) {
		const candidate = path.join(releaseRoot, ...name.split("/"));
		const observed = hashStableFile(candidate, {
			maximumBytes: MAX_RELEASE_FILE_BYTES,
			requireRootOwned,
		});
		if (observed.size !== entry.size || observed.sha256 !== entry.sha256) {
			throw new Error(`release file does not match ${name}`);
		}
	}
	const packagePath = path.join(
		installRoot,
		"packages",
		`odoo-accounting-cli-v3-${releaseName}.tar.gz`,
	);
	const observedPackage = hashStableFile(packagePath, {
		maximumBytes: MAX_PACKAGE_BYTES,
		minimumBytes: 1,
		requireRootOwned,
	});
	if (observedPackage.sha256 !== anchor.package_sha256) {
		throw new Error("canonical release package does not match the external anchor");
	}
	return Object.freeze({
		commit: manifest.commit,
		manifestPath,
		manifest_sha256: manifest.manifest_sha256,
		package_sha256: anchor.package_sha256,
		release: releaseName,
		version: manifest.version,
	});
}

export function createPiRuntimeBinding(options = {}) {
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| !exactKeys(options, ["releaseRoot", "runtimeRoot"])
		|| typeof process.getuid !== "function"
		|| process.getuid() !== 0
	) {
		throw new Error("Pi runtime binding creation requires a root installer");
	}
	const release = verifyCanonicalRelease({
		releaseRoot: options.releaseRoot,
		requireRootOwned: true,
	});
	const runtimeRoot = options.runtimeRoot;
	assertCanonicalDirectory(runtimeRoot, true);
	assertSeparateRuntime(options.releaseRoot, runtimeRoot);
	const dependencySpec = readPiDependencySpec(options.releaseRoot);
	const nodeIdentity = hashStableFile(process.execPath, {
		maximumBytes: MAX_PACKAGE_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	});
	const nodeModulesRoot = path.join(runtimeRoot, "node_modules");
	const files = dependencyMembers(nodeModulesRoot);
	validateInstalledPiPackage(nodeModulesRoot, dependencySpec);
	const unsigned = {
		files,
		node: {
			arch: process.arch,
			path: process.execPath,
			platform: process.platform,
			sha256: nodeIdentity.sha256,
			size: nodeIdentity.size,
			version: process.versions.node,
		},
		package_lock_sha256: dependencySpec.lockSha256,
		release: release.release,
		release_manifest_sha256: release.manifest_sha256,
		schema_version: 1,
	};
	const manifest = {
		...unsigned,
		manifest_sha256: createHash("sha256")
			.update(canonicalJson(unsigned), "utf8").digest("hex"),
	};
	const manifestPath = path.join(runtimeRoot, PI_RUNTIME_MANIFEST);
	const installRoot = path.dirname(path.dirname(options.releaseRoot));
	const anchorPath = path.join(
		installRoot,
		"trusted-artifacts",
		`${release.release}.pi-runtime.json`,
	);
	writeExclusiveRootJson(manifestPath, manifest);
	try {
		writeExclusiveRootJson(anchorPath, {
			release: release.release,
			release_manifest_sha256: release.manifest_sha256,
			runtime_manifest_sha256: manifest.manifest_sha256,
			schema_version: 1,
		});
	} catch (error) {
		fs.unlinkSync(manifestPath);
		fsyncDirectory(path.dirname(manifestPath));
		throw error;
	}
	return Object.freeze({
		anchorPath,
		manifestPath,
		node_sha256: nodeIdentity.sha256,
		release: release.release,
		runtime_manifest_sha256: manifest.manifest_sha256,
	});
}

export function verifyPiRuntimeBinding(options = {}) {
	if (
		options === null
		|| typeof options !== "object"
		|| Array.isArray(options)
		|| !exactKeys(options, ["releaseRoot", "runtimeRoot"])
	) {
		throw new Error("Pi runtime binding options are invalid");
	}
	const release = verifyCanonicalRelease({
		releaseRoot: options.releaseRoot,
		requireRootOwned: true,
	});
	const runtimeRoot = options.runtimeRoot;
	assertCanonicalDirectory(runtimeRoot, true);
	assertSeparateRuntime(options.releaseRoot, runtimeRoot);
	const dependencySpec = readPiDependencySpec(options.releaseRoot);
	const manifestPath = path.join(runtimeRoot, PI_RUNTIME_MANIFEST);
	const installRoot = path.dirname(path.dirname(options.releaseRoot));
	const anchorPath = path.join(
		installRoot,
		"trusted-artifacts",
		`${release.release}.pi-runtime.json`,
	);
	const manifest = validateRuntimeManifest(strictJson(readStableFile(
		manifestPath,
		{
			maximumBytes: MAX_JSON_BYTES,
			minimumBytes: 1,
			requireRootOwned: true,
		},
	), "Pi runtime manifest"));
	const anchor = strictJson(readStableFile(anchorPath, {
		maximumBytes: MAX_JSON_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	}), "Pi runtime anchor");
	if (
		!exactKeys(anchor, [
			"release",
			"release_manifest_sha256",
			"runtime_manifest_sha256",
			"schema_version",
		])
		|| anchor.schema_version !== 1
		|| anchor.release !== release.release
		|| anchor.release_manifest_sha256 !== release.manifest_sha256
		|| anchor.runtime_manifest_sha256 !== manifest.manifest_sha256
		|| manifest.release !== release.release
		|| manifest.release_manifest_sha256 !== release.manifest_sha256
		|| manifest.package_lock_sha256 !== dependencySpec.lockSha256
		|| manifest.node.path !== process.execPath
		|| manifest.node.version !== process.versions.node
		|| manifest.node.platform !== process.platform
		|| manifest.node.arch !== process.arch
	) {
		throw new Error("Pi runtime anchor does not match this release and process");
	}
	const nodeIdentity = hashStableFile(process.execPath, {
		maximumBytes: MAX_PACKAGE_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	});
	if (
		nodeIdentity.sha256 !== manifest.node.sha256
		|| nodeIdentity.size !== manifest.node.size
	) {
		throw new Error("running Node does not match the Pi runtime anchor");
	}
	const nodeModulesRoot = path.join(runtimeRoot, "node_modules");
	const observedFiles = dependencyMembers(nodeModulesRoot);
	if (JSON.stringify(observedFiles) !== JSON.stringify(manifest.files)) {
		throw new Error("installed Pi dependency bytes do not match the runtime anchor");
	}
	const piEntrypoint = validateInstalledPiPackage(
		nodeModulesRoot,
		dependencySpec,
	);
	return Object.freeze({
		anchorPath,
		manifestPath,
		node_sha256: nodeIdentity.sha256,
		node_version: process.versions.node,
		piEntrypoint,
		pi_version: dependencySpec.expectedVersion,
		release: release.release,
		release_manifest_sha256: release.manifest_sha256,
		runtime_manifest_sha256: manifest.manifest_sha256,
		verified: true,
	});
}

function verifiedCliIdentity(release) {
	const cliPath = path.join(
		path.dirname(release.manifestPath),
		"bin",
		"odoo-accounting-cli-v3",
	);
	const environment = { ...process.env };
	for (const name of [
		"LD_AUDIT",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
		"NODE_OPTIONS",
		"NODE_PATH",
		"PYTHONHOME",
		"PYTHONPATH",
	]) {
		delete environment[name];
	}
	const completed = spawnSync(cliPath, ["release", "identity"], {
		cwd: path.dirname(cliPath),
		encoding: "utf8",
		env: environment,
		maxBuffer: 1024 * 1024,
		timeout: 30000,
		windowsHide: true,
	});
	if (
		completed.status !== 0
		|| completed.signal !== null
		|| completed.error
		|| completed.stderr.trim() !== ""
	) {
		throw new Error("verified V3 CLI identity is unavailable");
	}
	let envelope;
	try {
		envelope = JSON.parse(completed.stdout.trim());
	} catch {
		throw new Error("verified V3 CLI identity is invalid");
	}
	const identity = envelope?.data;
	if (
		envelope?.ok !== true
		|| envelope?.command !== "release.identity"
		|| !exactKeys(identity, [
			"commit",
			"manifest_sha256",
			"package_sha256",
			"registry_digest",
			"release",
			"verified",
			"version",
		])
		|| identity.verified !== true
		|| identity.commit !== release.commit
		|| identity.version !== release.version
		|| identity.release !== release.release
		|| identity.manifest_sha256 !== release.manifest_sha256
		|| identity.package_sha256 !== release.package_sha256
		|| !SHA256.test(identity.registry_digest)
	) {
		throw new Error("verified V3 CLI identity does not match the bootstrap anchor");
	}
	return { cliPath, identity: Object.freeze({ ...identity }) };
}

export function getPiBridgeBootstrapAttestation() {
	return bootstrapAttestation;
}

async function main() {
	if (
		process.platform !== "linux"
		|| process.execArgv.length !== 0
		|| process.argv.length !== 3
	) {
		throw new Error("Pi Bridge bootstrap requires fixed Linux Node invocation");
	}
	for (const name of [
		"LD_AUDIT",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
		"NODE_OPTIONS",
		"NODE_PATH",
	]) {
		if (process.env[name]) {
			throw new Error("Pi Bridge bootstrap rejects Node loader environment");
		}
	}
	const runtimeRoot = path.resolve(process.argv[2]);
	process.env.HOME = "/var/lib/odoo-accounting-cli-v3-pi-bridge";
	process.env.PI_AGENT_BRIDGE_HOST = "127.0.0.1";
	process.env.PI_AGENT_BRIDGE_PORT = "18788";
	process.env.PI_AGENT_SESSION_DIR =
		"/var/lib/odoo-accounting-cli-v3-pi-bridge/sessions";
	process.env.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE = path.join(
		runtimeRoot,
		"odoo-session-header-resolver.mjs",
	);
	process.env.PI_BRIDGE_HARDENED_V3_ONLY = "1";
	process.env.PI_BRIDGE_REQUIRE_V3_IDENTITY = "1";
	process.env.PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET = "1";
	process.env.PI_BRIDGE_RUNTIME_ROOT = runtimeRoot;
	process.env.PI_CODING_AGENT_DIR =
		"/var/lib/odoo-accounting-cli-v3-pi-bridge/agent";
	process.env.ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET =
		"/run/odoo-accounting-cli-v3/pi-broker.sock";
	const bootstrapPath = fileURLToPath(import.meta.url);
	const releaseRoot = path.dirname(path.dirname(bootstrapPath));
	if (bootstrapPath !== path.join(releaseRoot, "pi_bridge", "bootstrap.mjs")) {
		throw new Error("Pi Bridge bootstrap path is invalid");
	}
	withStableFile(process.execPath, {
		maximumBytes: MAX_PACKAGE_BYTES,
		minimumBytes: 1,
		requireRootOwned: true,
	}, () => true);
	const release = verifyCanonicalRelease({
		releaseRoot,
		requireRootOwned: true,
	});
	assertCanonicalDirectory(runtimeRoot, true);
	assertSeparateRuntime(releaseRoot, runtimeRoot);
	const { cliPath, identity } = verifiedCliIdentity(release);
	const verifierPath = path.join(releaseRoot, "pi_bridge", "release-binding.mjs");
	const { verifyPiBridgeReleaseBinding } = await import(pathToFileURL(verifierPath).href);
	const binding = verifyPiBridgeReleaseBinding({
		bridgeRoot: runtimeRoot,
		expectedManifestSha256: release.manifest_sha256,
		manifestPath: release.manifestPath,
		requireRootOwned: true,
	});
	if (
		binding.version !== release.version
		|| binding.commit !== release.commit
	) {
		throw new Error("Pi Bridge runtime does not match the canonical release");
	}
	const runtimeBinding = verifyPiRuntimeBinding({ releaseRoot, runtimeRoot });
	if (
		runtimeBinding.release_manifest_sha256 !== release.manifest_sha256
		|| runtimeBinding.release !== release.release
	) {
		throw new Error("Pi dependency runtime does not match the canonical release");
	}
	const attestation = Object.freeze({
		binding: Object.freeze({ ...binding }),
		cliPath,
		identity,
		manifestPath: release.manifestPath,
		nonce: randomBytes(32).toString("hex"),
		piEntrypoint: runtimeBinding.piEntrypoint,
		runtimeBinding,
		runtimeRoot,
	});
	if (bootstrapAttestation !== undefined) {
		throw new Error("Pi Bridge bootstrap attestation is already set");
	}
	bootstrapAttestation = attestation;
	process.env.ODOO_ACCOUNTING_CLI_V3_BIN = cliPath;
	process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST = identity.manifest_sha256;
	process.env.ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST = identity.registry_digest;
	process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST = release.manifestPath;
	delete process.env.NODE_OPTIONS;
	delete process.env.NODE_PATH;
	delete process.env.LD_AUDIT;
	delete process.env.LD_LIBRARY_PATH;
	delete process.env.LD_PRELOAD;
	const serverPath = path.join(runtimeRoot, "server.mjs");
	await import(pathToFileURL(serverPath).href);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
	main().catch(() => {
		process.stderr.write("V3 Pi Bridge bootstrap verification failed\n");
		process.exitCode = 1;
	});
}
