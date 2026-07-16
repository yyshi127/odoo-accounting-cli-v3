import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyPiBridgeReleaseBinding } from "./release-binding.mjs";
import {
  enabledPiToolNames,
  legacyOdooEnvironment,
  LEGACY_ODOO_ENVIRONMENT_NAMES,
  literalPiUserPrompt,
  sessionDeletionAllowed,
} from "./tool-policy.mjs";
import {
  loadAuthenticatedSessionResolver,
  resolveAuthenticatedBrokerSession,
  validBrokerSessionHandle,
} from "./trusted-session.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function rootOwnedCanonicalFile(filePath) {
  if (
    process.platform !== "linux"
    || typeof filePath !== "string"
    || !path.isAbsolute(filePath)
    || filePath.includes("\0")
    || path.resolve(filePath) !== filePath
    || fs.realpathSync.native(filePath) !== filePath
  ) {
    return false;
  }
  const file = fs.lstatSync(filePath, { bigint: true });
  if (
    file.isSymbolicLink()
    || !file.isFile()
    || file.nlink !== 1n
    || file.uid !== 0n
    || (file.mode & 0o022n) !== 0n
  ) {
    return false;
  }
  let current = path.dirname(filePath);
  for (;;) {
    const directory = fs.lstatSync(current, { bigint: true });
    if (
      directory.isSymbolicLink()
      || !directory.isDirectory()
      || directory.uid !== 0n
      || (directory.mode & 0o022n) !== 0n
    ) {
      return false;
    }
    const parent = path.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

async function loadBootstrapContext() {
  try {
    const manifestPath = process.env.ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST || "";
    if (
      !path.isAbsolute(manifestPath)
      || manifestPath.includes("\0")
      || path.basename(manifestPath) !== "RELEASE-MANIFEST.json"
    ) {
      return null;
    }
    const releaseRoot = path.dirname(manifestPath);
    const bootstrapPath = path.join(releaseRoot, "pi_bridge", "bootstrap.mjs");
    if (!rootOwnedCanonicalFile(bootstrapPath)) return null;
    const bootstrapModule = await import(pathToFileURL(bootstrapPath).href);
    const attestation = bootstrapModule.getPiBridgeBootstrapAttestation?.();
    return attestation === undefined
      ? null
      : { attestation, bootstrapModule, releaseRoot };
  } catch {
    return null;
  }
}

const bootstrapContext = await loadBootstrapContext();
const bootstrapAttestation = bootstrapContext?.attestation;
const host = process.env.PI_AGENT_BRIDGE_HOST || "127.0.0.1";
const port = Number(process.env.PI_AGENT_BRIDGE_PORT || 18787);
const packageJsonPath = path.join(__dirname, "package.json");
const packageJson = fs.existsSync(packageJsonPath)
  ? JSON.parse(fs.readFileSync(packageJsonPath, "utf8"))
  : {};
const piVersion = packageJson.dependencies?.["@earendil-works/pi-coding-agent"] || "unknown";
const piBin = typeof bootstrapAttestation?.piEntrypoint === "string"
  ? bootstrapAttestation.piEntrypoint
  : "";
const chatTimeoutMs = Number(process.env.PI_AGENT_BRIDGE_TIMEOUT_MS || 120000);
const sessionDir = process.env.PI_AGENT_SESSION_DIR || "/home/odoo/.pi/sdoobot-sessions";
const contextDir = path.join(sessionDir, "contexts");
const sha256 = /^[0-9a-f]{64}$/;
const v3CliBin = typeof bootstrapAttestation?.cliPath === "string"
  ? bootstrapAttestation.cliPath
  : "";
const v3BrokerSocketPath = process.env.ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET || "";
const authenticatedSessionResolverModule =
  process.env.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE || "";
const authenticatedSessionResolverSha256 =
  process.env.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256 || "";
const v3BrokerSocketConfigured =
  path.isAbsolute(v3BrokerSocketPath) && !v3BrokerSocketPath.includes("\0");
const authenticatedSessionResolver = await loadAuthenticatedSessionResolver(
  authenticatedSessionResolverModule,
  {
    expectedSha256: authenticatedSessionResolverModule
      ? authenticatedSessionResolverSha256
      : undefined,
    requireRootOwned: true,
  },
);

function loadV3Identity() {
  try {
    const identity = bootstrapAttestation?.identity;
    const binding = bootstrapAttestation?.binding;
    const runtimeBinding = bootstrapAttestation?.runtimeBinding;
    if (
      bootstrapAttestation === null
      || typeof bootstrapAttestation !== "object"
      || Array.isArray(bootstrapAttestation)
      || JSON.stringify(Object.keys(bootstrapAttestation).sort()) !== JSON.stringify([
        "binding",
        "cliPath",
        "identity",
        "manifestPath",
        "nonce",
        "piEntrypoint",
        "runtimeBinding",
        "runtimeRoot",
      ])
      || bootstrapAttestation.runtimeRoot !== __dirname
      || !sha256.test(bootstrapAttestation.nonce)
      || !path.isAbsolute(bootstrapAttestation.manifestPath)
      || bootstrapAttestation.manifestPath.includes("\0")
      || !path.isAbsolute(v3CliBin)
      || v3CliBin.includes("\0")
      || !path.isAbsolute(piBin)
      || piBin.includes("\0")
      || piBin !== path.join(
        __dirname,
        "node_modules",
        "@earendil-works",
        "pi-coding-agent",
        "dist",
        "cli.js",
      )
      || JSON.stringify(Object.keys(identity ?? {}).sort()) !== JSON.stringify([
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
        "verified",
        "version",
      ])
      || JSON.stringify(Object.keys(binding ?? {}).sort()) !== JSON.stringify([
        "commit",
        "manifest_sha256",
        "runtime_file_count",
        "verified",
        "version",
      ])
      || JSON.stringify(Object.keys(runtimeBinding ?? {}).sort()) !== JSON.stringify([
        "anchorPath",
        "manifestPath",
        "node_sha256",
        "node_version",
        "piEntrypoint",
        "pi_version",
        "release",
        "release_manifest_sha256",
        "runtime_manifest_sha256",
        "verified",
      ])
      || identity.verified !== true
      || binding.verified !== true
      || runtimeBinding.verified !== true
      || !sha256.test(identity.manifest_sha256)
      || !sha256.test(identity.registry_digest)
      || !sha256.test(identity.package_sha256)
      || binding.manifest_sha256 !== identity.manifest_sha256
      || binding.commit !== identity.commit
      || binding.version !== identity.version
      || runtimeBinding.release !== identity.release
      || runtimeBinding.release_manifest_sha256 !== identity.manifest_sha256
      || runtimeBinding.piEntrypoint !== piBin
      || runtimeBinding.manifestPath !== path.join(
        __dirname,
        "PI-RUNTIME-MANIFEST.json",
      )
      || !sha256.test(runtimeBinding.node_sha256)
      || !sha256.test(runtimeBinding.runtime_manifest_sha256)
      || typeof identity.version !== "string"
      || !identity.version
      || typeof identity.commit !== "string"
      || !identity.commit
      || bootstrapAttestation.manifestPath !== path.join(
        path.dirname(path.dirname(v3CliBin)),
        "RELEASE-MANIFEST.json",
      )
      || bootstrapContext?.releaseRoot !== path.dirname(
        bootstrapAttestation.manifestPath,
      )
    ) {
      throw new Error("invalid identity");
    }
    return Object.freeze({ ...identity });
  } catch {
    return { verified: false, error: "V3 bootstrap attestation is unavailable" };
  }
}

const v3Identity = loadV3Identity();
function loadV3ReleaseBinding() {
  if (v3Identity.verified !== true) {
    return { verified: false, error: "V3 release identity is unavailable" };
  }
  try {
    if (
      path.basename(v3CliBin) !== "odoo-accounting-cli-v3"
      || path.resolve(v3CliBin) !== v3CliBin
      || fs.realpathSync.native(v3CliBin) !== v3CliBin
    ) {
      throw new Error("invalid V3 launcher path");
    }
    const manifestPath = bootstrapAttestation.manifestPath;
    const binding = verifyPiBridgeReleaseBinding({
      bridgeRoot: __dirname,
      expectedManifestSha256: v3Identity.manifest_sha256,
      manifestPath,
      requireRootOwned: process.platform === "linux",
    });
    if (
      binding.version !== v3Identity.version
      || binding.commit !== v3Identity.commit
    ) {
      throw new Error("V3 identity and Pi Bridge binding differ");
    }
    const runtimeBinding = bootstrapContext.bootstrapModule.verifyPiRuntimeBinding({
      releaseRoot: bootstrapContext.releaseRoot,
      runtimeRoot: __dirname,
    });
    if (
      runtimeBinding.release !== v3Identity.release
      || runtimeBinding.release_manifest_sha256 !== v3Identity.manifest_sha256
      || runtimeBinding.node_sha256
        !== bootstrapAttestation.runtimeBinding.node_sha256
      || runtimeBinding.runtime_manifest_sha256
        !== bootstrapAttestation.runtimeBinding.runtime_manifest_sha256
      || runtimeBinding.piEntrypoint !== piBin
    ) {
      throw new Error("V3 runtime binding and bootstrap attestation differ");
    }
    return Object.freeze({ ...binding, manifestPath, runtimeBinding });
  } catch {
    return { verified: false, error: "V3 Pi Bridge release binding is invalid" };
  }
}

const v3ReleaseBinding = loadV3ReleaseBinding();
const v3Ready = v3Identity.verified === true && v3ReleaseBinding.verified === true;
if (process.env.PI_BRIDGE_REQUIRE_V3_IDENTITY === "1" && !v3Ready) {
  throw new Error(
    v3Identity.verified === true
      ? v3ReleaseBinding.error
      : (v3Identity.error || "V3 release identity verification failed"),
  );
}

function inheritedSystemdSocket() {
  const listenPid = process.env.LISTEN_PID || "";
  const listenFds = process.env.LISTEN_FDS || "";
  const listenFdNames = process.env.LISTEN_FDNAMES || "";
  const configured = Boolean(listenPid || listenFds || listenFdNames);
  if (!configured) {
    if (process.env.PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET === "1") {
      throw new Error("V3 Pi Bridge systemd socket is unavailable");
    }
    return null;
  }
  if (
    process.platform !== "linux"
    || listenPid !== String(process.pid)
    || listenFds !== "1"
    || listenFdNames !== "odoo-v3-pi-http"
    || !fs.fstatSync(3).isSocket()
  ) {
    throw new Error("V3 Pi Bridge systemd socket activation is invalid");
  }
  delete process.env.LISTEN_PID;
  delete process.env.LISTEN_FDS;
  delete process.env.LISTEN_FDNAMES;
  return 3;
}

const systemdListenFd = inheritedSystemdSocket();
let socketBoundaryReady = systemdListenFd === null;
const hardenedV3Only = process.env.PI_BRIDGE_HARDENED_V3_ONLY === "1";
if (hardenedV3Only && !v3Ready) {
  throw new Error("Hardened Pi Bridge requires a verified V3 release");
}

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readRequestJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 100000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function safeSessionId(value) {
  const sessionId = String(value || "").trim();
  if (!sessionId) {
    return "";
  }
  if (!/^[A-Za-z0-9_.:-]{1,120}$/.test(sessionId)) {
    throw new Error("Invalid session_id");
  }
  return sessionId;
}

function listSessionFiles(dir, sessionId) {
  const matches = [];
  if (!fs.existsSync(dir)) {
    return matches;
  }
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name.includes(sessionId)) {
        matches.push(fullPath);
      }
    }
  }
  return matches;
}

function deletePiSessions(sessionIds) {
  fs.mkdirSync(sessionDir, { recursive: true });
  const deleted = [];
  for (const rawId of sessionIds || []) {
    const sessionId = safeSessionId(rawId);
    if (!sessionId) {
      continue;
    }
    for (const filePath of listSessionFiles(sessionDir, sessionId)) {
      fs.rmSync(filePath, { force: true });
      deleted.push(filePath);
    }
  }
  return deleted;
}

function renderContextMarkdown({ sessionId, selectedSkillKey, conversationContext }) {
  const lines = [
    "# Sdoobot Odoo Session Context",
    "",
    "This file belongs to one Odoo chat conversation. Use it as conversation memory.",
    "The Odoo backend still owns database, user, company and permission scope.",
    "",
  ];
  if (selectedSkillKey) {
    lines.push(`selected_skill_key: ${selectedSkillKey}`, "");
    lines.push("When selected_skill_key is present, prefer calling odoo_execute_skill with that key.", "");
  }
  const items = Array.isArray(conversationContext) ? conversationContext : [];
  if (items.length) {
    lines.push("## Recent Messages", "");
    for (const item of items.slice(-12)) {
      const role = String(item?.role || "message").replace(/[^a-zA-Z0-9_-]/g, "");
      const body = String(item?.body || "").trim();
      if (body) {
        lines.push(`### ${role}`, body, "");
      }
    }
  }
  if (sessionId) {
    lines.push("## Session", "", `session_id: ${sessionId}`, "");
  }
  return lines.join("\n");
}

function writeContextFile({ sessionId, selectedSkillKey, conversationContext }) {
  const cleanSessionId = safeSessionId(sessionId);
  if (!cleanSessionId) {
    return "";
  }
  fs.mkdirSync(contextDir, { recursive: true });
  const filePath = path.join(contextDir, `${cleanSessionId}.md`);
  fs.writeFileSync(filePath, renderContextMarkdown({
    sessionId: cleanSessionId,
    selectedSkillKey,
    conversationContext,
  }), "utf8");
  return filePath;
}

function piChildEnvironment() {
  const environment = {
    ...process.env,
    PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR || "/home/odoo/.pi/agent",
    PI_CODING_AGENT_SESSION_DIR: sessionDir,
    ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET: v3BrokerSocketPath,
    ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST:
      v3Ready ? v3Identity.manifest_sha256 : "",
    ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST:
      v3Ready ? v3Identity.registry_digest : "",
    ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST:
      v3Ready ? v3ReleaseBinding.manifestPath : "",
  };
  for (const name of LEGACY_ODOO_ENVIRONMENT_NAMES) delete environment[name];
  Object.assign(
    environment,
    legacyOdooEnvironment(process.env, hardenedV3Only),
  );
  delete environment.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE;
  delete environment.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256;
  delete environment.NODE_OPTIONS;
  delete environment.NODE_PATH;
  delete environment.LD_AUDIT;
  delete environment.LD_LIBRARY_PATH;
  delete environment.LD_PRELOAD;
  const allowedV3Environment = new Set([
    "ODOO_ACCOUNTING_CLI_V3_BIN",
    "ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET",
    "ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST",
    "ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST",
    "ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST",
  ]);
  for (const name of Object.keys(environment)) {
    if (
      name.startsWith("ODOO_ACCOUNTING_CLI_V3_")
      && !allowedV3Environment.has(name)
    ) {
      delete environment[name];
    }
    if (name.startsWith("JITI_") || name.startsWith("TS_NODE_")) {
      delete environment[name];
    }
  }
  return environment;
}

function runPiChat({
  message,
  systemPrompt,
  provider,
  model,
  sessionId,
  selectedSkillKey,
  conversationContext,
  brokerSessionHandle,
}) {
  return new Promise((resolve, reject) => {
    const prompt = String(message || "").trim();
    if (!prompt) {
      reject(new Error("Empty message"));
      return;
    }
    let cleanSessionId = "";
    try {
      cleanSessionId = safeSessionId(sessionId);
    } catch (error) {
      reject(error);
      return;
    }
    fs.mkdirSync(sessionDir, { recursive: true });
    const contextFile = cleanSessionId ? writeContextFile({
      sessionId: cleanSessionId,
      selectedSkillKey,
      conversationContext,
    }) : "";
    const brokerEnabled =
      v3Ready
      && v3BrokerSocketConfigured
      && validBrokerSessionHandle(brokerSessionHandle);
    const enabledToolNames = enabledPiToolNames({
      brokerEnabled,
      hardenedV3Only,
      v3Ready,
    });
    const args = [
      "--print",
      "--no-builtin-tools",
      "--no-context-files",
      "--no-extensions",
      "--extension",
      path.join(__dirname, "extensions", "odoo-tools.ts"),
      "--tools",
      enabledToolNames.join(","),
    ];
    if (cleanSessionId) {
      args.push("--session-dir", sessionDir, "--session-id", cleanSessionId);
    } else {
      args.push("--no-session");
    }
    if (provider) {
      args.push("--provider", String(provider));
    }
    if (model) {
      args.push("--model", String(model));
    }
    if (systemPrompt) {
      args.push("--system-prompt", String(systemPrompt));
    }
    if (contextFile) {
      args.push(`@${contextFile}`);
    }
    args.push(literalPiUserPrompt(prompt));

    const child = spawn(process.execPath, [piBin, ...args], {
      cwd: __dirname,
      env: piChildEnvironment(),
      stdio: ["ignore", "pipe", "pipe", "pipe"],
    });
    child.stdio[3].end(brokerEnabled ? brokerSessionHandle : "", "utf8");
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("Pi Agent timed out"));
    }, chatTimeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(stderr || `Pi exited with code ${code}`));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

async function authenticatedBrokerSession(req) {
  try {
    return await resolveAuthenticatedBrokerSession(
      authenticatedSessionResolver,
      {
        headers: req.headers,
        method: req.method,
        remoteAddress: req.socket.remoteAddress,
        url: req.url,
      },
    );
  } catch {
    throw new Error("Authenticated V3 broker session resolution failed");
  }
}

const server = http.createServer((req, res) => {
  if (!socketBoundaryReady) {
    req.socket.destroy();
    return;
  }
  if (req.method === "GET" && req.url === "/health") {
    json(res, 200, {
      ok: true,
      mode: hardenedV3Only ? "v3-hardened" : "legacy",
      service: hardenedV3Only
        ? "odoo-accounting-cli-v3-pi-bridge"
        : "sudo-pi-agent-bridge",
      piAgent: piVersion,
      v3Identity,
      v3ReleaseBinding: v3ReleaseBinding.verified === true
        ? {
            commit: v3ReleaseBinding.commit,
            manifest_sha256: v3ReleaseBinding.manifest_sha256,
            runtime_file_count: v3ReleaseBinding.runtime_file_count,
            runtime: {
              node_sha256: v3ReleaseBinding.runtimeBinding.node_sha256,
              node_version: v3ReleaseBinding.runtimeBinding.node_version,
              pi_version: v3ReleaseBinding.runtimeBinding.pi_version,
              runtime_manifest_sha256:
                v3ReleaseBinding.runtimeBinding.runtime_manifest_sha256,
            },
            verified: true,
            version: v3ReleaseBinding.version,
          }
        : v3ReleaseBinding,
      v3Broker: {
        authenticatedSessionResolverConfigured:
          authenticatedSessionResolver !== null,
        socketConfigured: v3BrokerSocketConfigured,
        writesRequireAuthenticatedSession: true,
      },
    });
    return;
  }
  if (req.method === "POST" && req.url === "/chat") {
    readRequestJson(req)
      .then(async (payload) => ({
        brokerSession: await authenticatedBrokerSession(req),
        payload,
      }))
      .then(({ brokerSession, payload }) => runPiChat({
          message: payload.message,
          systemPrompt: payload.system_prompt,
          provider: payload.provider || process.env.PI_AGENT_PROVIDER || "",
          model: payload.model || process.env.PI_AGENT_MODEL || "",
          sessionId: payload.session_id || "",
          selectedSkillKey: payload.selected_skill_key || "",
          conversationContext: payload.conversation_context || [],
          brokerSessionHandle: brokerSession?.brokerSessionHandle || "",
        }))
      .then((answer) => json(res, 200, { ok: true, answer }))
      .catch((error) => json(res, 502, { ok: false, error: error.message || String(error) }));
    return;
  }
  if (req.method === "POST" && req.url === "/session/delete") {
    if (!sessionDeletionAllowed(hardenedV3Only)) {
      json(res, 404, { ok: false, error: "Not found" });
      return;
    }
    readRequestJson(req)
      .then((payload) => deletePiSessions(payload.session_ids || []))
      .then((deleted) => json(res, 200, { ok: true, deleted }))
      .catch((error) => json(res, 400, { ok: false, error: error.message || String(error) }));
    return;
  }
  if (req.method === "POST" && req.url === "/rpc") {
    json(res, 501, {
      ok: false,
      error: "Pi RPC bridge is not enabled yet. Use /chat for plain text calls.",
    });
    return;
  }
  json(res, 404, { ok: false, error: "Not found" });
});

const listenOptions = systemdListenFd === null
  ? { host, port }
  : { exclusive: true, fd: systemdListenFd };
server.listen(listenOptions, () => {
  if (systemdListenFd !== null) {
    const address = server.address();
    if (
      address === null
      || typeof address === "string"
      || address.address !== "127.0.0.1"
      || address.family !== "IPv4"
      || address.port !== 18788
    ) {
      server.close(() => process.exit(1));
      return;
    }
    socketBoundaryReady = true;
  }
  const serviceName = hardenedV3Only
    ? "odoo-accounting-cli-v3-pi-bridge"
    : "sudo-pi-agent-bridge";
  console.log(`${serviceName} listening on http://${host}:${port}`);
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});
