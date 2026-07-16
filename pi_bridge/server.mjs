import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { V3_TOOL_NAMES } from "./extensions/odoo-v3-cli.mjs";
import {
  loadAuthenticatedSessionResolver,
  resolveAuthenticatedBrokerSession,
  validBrokerSessionHandle,
} from "./trusted-session.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const host = process.env.PI_AGENT_BRIDGE_HOST || "127.0.0.1";
const port = Number(process.env.PI_AGENT_BRIDGE_PORT || 18787);
const packageJsonPath = path.join(__dirname, "package.json");
const packageJson = fs.existsSync(packageJsonPath)
  ? JSON.parse(fs.readFileSync(packageJsonPath, "utf8"))
  : {};
const piVersion = packageJson.dependencies?.["@earendil-works/pi-coding-agent"] || "unknown";
const piBin = path.join(__dirname, "node_modules", ".bin", "pi");
const chatTimeoutMs = Number(process.env.PI_AGENT_BRIDGE_TIMEOUT_MS || 120000);
const sessionDir = process.env.PI_AGENT_SESSION_DIR || "/home/odoo/.pi/sdoobot-sessions";
const contextDir = path.join(sessionDir, "contexts");
const sha256 = /^[0-9a-f]{64}$/;
const v3CliBin = process.env.ODOO_ACCOUNTING_CLI_V3_BIN || "";
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
  if (!path.isAbsolute(v3CliBin) || v3CliBin.includes("\0")) {
    return { verified: false, error: "V3 CLI launcher is not configured" };
  }
  const completed = spawnSync(v3CliBin, ["release", "identity"], {
    cwd: path.dirname(v3CliBin),
    encoding: "utf8",
    env: process.env,
    timeout: 30000,
    windowsHide: true,
  });
  if (completed.status !== 0 || completed.signal !== null || completed.stderr.trim()) {
    return { verified: false, error: "V3 release identity is unavailable" };
  }
  try {
    const envelope = JSON.parse(completed.stdout.trim());
    const identity = envelope?.data;
    if (
      envelope?.ok !== true
      || envelope?.command !== "release.identity"
      || identity?.verified !== true
      || !sha256.test(identity.manifest_sha256)
      || !sha256.test(identity.registry_digest)
      || !sha256.test(identity.package_sha256)
      || typeof identity.version !== "string"
      || !identity.version
      || typeof identity.commit !== "string"
      || !identity.commit
    ) {
      throw new Error("invalid identity");
    }
    return Object.freeze({ ...identity });
  } catch {
    return { verified: false, error: "V3 release identity response is invalid" };
  }
}

const v3Identity = loadV3Identity();
if (process.env.PI_BRIDGE_REQUIRE_V3_IDENTITY === "1" && v3Identity.verified !== true) {
  throw new Error(v3Identity.error || "V3 release identity verification failed");
}
const alwaysAvailableToolNames = [
  "odoo_get_context",
  "odoo_list_skills",
  "odoo_execute_skill",
  "odoo_list_reports",
  "odoo_export_report",
  V3_TOOL_NAMES.capabilityList,
  V3_TOOL_NAMES.capabilityGet,
];
const authenticatedV3BrokerToolNames = [
  V3_TOOL_NAMES.read,
  V3_TOOL_NAMES.prepare,
  V3_TOOL_NAMES.preview,
  V3_TOOL_NAMES.approveExecute,
  V3_TOOL_NAMES.status,
  V3_TOOL_NAMES.result,
  V3_TOOL_NAMES.recover,
];

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
    ODOO_TOOL_URL: process.env.ODOO_TOOL_URL || "http://127.0.0.1:8069/sudo_ai_bot/pi_tool_call",
    ODOO_TOOL_TOKEN: process.env.ODOO_TOOL_TOKEN || "",
    ODOO_TOOL_DATABASE: process.env.ODOO_TOOL_DATABASE || "",
    ODOO_TOOL_USER_ID: process.env.ODOO_TOOL_USER_ID || "",
    ODOO_TOOL_COMPANY_ID: process.env.ODOO_TOOL_COMPANY_ID || "",
    ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET: v3BrokerSocketPath,
    ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST:
      v3Identity.verified === true ? v3Identity.manifest_sha256 : "",
    ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST:
      v3Identity.verified === true ? v3Identity.registry_digest : "",
  };
  delete environment.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE;
  delete environment.PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256;
  const allowedV3Environment = new Set([
    "ODOO_ACCOUNTING_CLI_V3_BIN",
    "ODOO_ACCOUNTING_CLI_V3_BROKER_SOCKET",
    "ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST",
    "ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST",
  ]);
  for (const name of Object.keys(environment)) {
    if (
      name.startsWith("ODOO_ACCOUNTING_CLI_V3_")
      && !allowedV3Environment.has(name)
    ) {
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
      v3Identity.verified === true
      && v3BrokerSocketConfigured
      && validBrokerSessionHandle(brokerSessionHandle);
    const enabledToolNames = brokerEnabled
      ? [...alwaysAvailableToolNames, ...authenticatedV3BrokerToolNames]
      : alwaysAvailableToolNames;
    const args = [
      "--print",
      "--no-builtin-tools",
      "--no-context-files",
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
    args.push(prompt);

    const child = spawn(piBin, args, {
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
  if (req.method === "GET" && req.url === "/health") {
    json(res, 200, {
      ok: true,
      service: "sudo-pi-agent-bridge",
      piAgent: piVersion,
      v3Identity,
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

server.listen(port, host, () => {
  console.log(`sudo-pi-agent-bridge listening on http://${host}:${port}`);
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});
