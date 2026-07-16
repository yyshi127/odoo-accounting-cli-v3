import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "pi_bridge"


def test_canonical_pi_bridge_is_release_owned_and_has_no_caller_identity_override():
    server = (BRIDGE / "server.mjs").read_text(encoding="utf-8")
    runner = (BRIDGE / "extensions" / "odoo-v3-cli.mjs").read_text(
        encoding="utf-8"
    )
    extension = (BRIDGE / "extensions" / "odoo-tools.ts").read_text(
        encoding="utf-8"
    )
    readme = (BRIDGE / "README.md").read_text(encoding="utf-8")
    bootstrap = (BRIDGE / "bootstrap.mjs").read_text(encoding="utf-8")
    trusted_session = (BRIDGE / "trusted-session.mjs").read_text(encoding="utf-8")
    release_binding = (BRIDGE / "release-binding.mjs").read_text(
        encoding="utf-8"
    )
    package = json.loads((BRIDGE / "package.json").read_text(encoding="utf-8"))

    for path in (
        BRIDGE / "server.mjs",
        BRIDGE / "bootstrap.mjs",
        BRIDGE / "create-runtime-binding.mjs",
        BRIDGE / "extensions" / "odoo-v3-cli.mjs",
        BRIDGE / "extensions" / "odoo-tools.ts",
        BRIDGE / "package-lock.json",
        BRIDGE / "package.json",
        BRIDGE / "README.md",
        BRIDGE / "release-binding.mjs",
        BRIDGE / "tool-policy.mjs",
        BRIDGE / "tests" / "odoo-v3-cli.test.mjs",
        BRIDGE / "tests" / "bootstrap.test.mjs",
        BRIDGE / "tests" / "release-binding.test.mjs",
        BRIDGE / "tests" / "tool-policy.test.mjs",
        BRIDGE / "tests" / "trusted-broker.test.mjs",
        BRIDGE / "trusted-session.mjs",
    ):
        assert path.is_file()

    for forbidden in (
        "payload.odoo_tool_url",
        "payload.odoo_tool_token",
        "payload.odoo_database",
        "payload.odoo_user_id",
        "payload.odoo_company_id",
    ):
        assert forbidden not in server
    assert "v3Identity" in server
    assert "bootstrapAttestation" in server
    assert "Symbol.for(" not in server
    assert "getPiBridgeBootstrapAttestation" in server
    assert "spawnSync" not in server
    assert "release.identity" not in server
    assert "PI_BRIDGE_REQUIRE_V3_IDENTITY" in server
    assert "verifyPiBridgeReleaseBinding" in server
    assert "v3ReleaseBinding" in server
    assert "enabledPiToolNames" in server
    assert "PI_BRIDGE_HARDENED_V3_ONLY" in server
    assert "LEGACY_ODOO_ENVIRONMENT_NAMES" in server
    assert "legacyOdooEnvironment(process.env, hardenedV3Only)" in server
    assert "args.push(literalPiUserPrompt(prompt))" in server
    assert "args.push(prompt)" not in server
    assert "sessionDeletionAllowed(hardenedV3Only)" in server
    assert server.index("sessionDeletionAllowed(hardenedV3Only)") < server.index(
        "deletePiSessions(payload.session_ids || [])"
    )
    assert "ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST" in server
    assert '"--no-extensions"' in server
    assert "delete environment.NODE_OPTIONS" in server
    assert "delete environment.NODE_PATH" in server
    assert "delete environment.LD_PRELOAD" in server
    assert "PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET" in server
    assert 'listenFdNames !== "odoo-v3-pi-http"' in server
    assert "fs.fstatSync(3).isSocket()" in server
    assert 'address.address !== "127.0.0.1"' in server
    assert "address.port !== 18788" in server
    assert "if (!socketBoundaryReady)" in server
    assert "spawn(process.execPath, [piBin, ...args]" in server
    assert "release.identity" in bootstrap
    for boundary in (
        "verifyCanonicalRelease",
        "trusted-artifacts",
        "package_sha256",
        "actualReleaseFiles",
        "createPiRuntimeBinding",
        "verifyPiRuntimeBinding",
        "dependencyMembers",
        "runtime_manifest_sha256",
        "node_sha256",
        "fsyncDirectory",
        "O_NOFOLLOW",
        "process.execArgv.length !== 0",
        "Pi Bridge bootstrap rejects Node loader environment",
        "await import(pathToFileURL(serverPath).href)",
    ):
        assert boundary in bootstrap
    assert "Symbol.for(" not in bootstrap
    assert "ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST" in runner
    assert "ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST" in runner
    assert "receipt.release_digest === expectedReleaseDigest" in runner
    assert "receipt.registry_digest === expectedRegistryDigest" in runner
    assert "bridge_v3_broker_required" in runner
    for broker_owned_field in (
        '"broker_socket"',
        '"cli_path"',
        '"config_path"',
        '"registry_digest"',
        '"release_digest"',
        '"runtime_config_path"',
    ):
        assert broker_owned_field in runner
    assert "runV3BrokerOperation" in extension
    assert "verifyPiBridgeReleaseBinding" in extension
    assert "if (exposeV3Tools)" in extension
    assert 'callV3Broker("operation.approve_execute", params)' in extension
    assert 'callV3Query("registry.list", {})' in extension
    for forbidden_schema in (
        "v3ContextSchema",
        "v3ApprovalSchema",
        "context: v3ContextSchema",
        "approval: v3ApprovalSchema",
        "approver_user_id: Type",
        "auth_signature: Type",
        "request_id: Type",
    ):
        assert forbidden_schema not in extension

    assert "PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_MODULE" in server
    assert "PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256" in server
    assert "PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256" in readme
    for boundary in (
        "O_NOFOLLOW",
        "fs.fstatSync",
        'createHash("sha256")',
        "data:text/javascript;base64",
        "dependency-free module",
        "requireRootManagedAncestors",
    ):
        assert boundary in trusted_session
    for boundary in (
        "PI_BRIDGE_RUNTIME_MEMBERS",
        "manifest_sha256",
        "O_NOFOLLOW",
        "fs.fstatSync",
        'createHash("sha256")',
        "requireRootManagedAncestors",
        "before.nlink !== 1n",
    ):
        assert boundary in release_binding
    assert "resolveAuthenticatedBrokerSession" in server
    assert 'stdio: ["ignore", "pipe", "pipe", "pipe"]' in server
    assert "child.stdio[3].end" in server
    assert "ODOO_ACCOUNTING_CLI_V3_BROKER_SESSION" not in server
    assert "brokerSessionHandle: payload.session_id" not in server
    tool_policy = (BRIDGE / "tool-policy.mjs").read_text(encoding="utf-8")
    assert "AUTHENTICATED_V3_BROKER_TOOL_NAMES" in tool_policy
    assert "literalPiUserPrompt" in tool_policy
    assert "sessionDeletionAllowed" in tool_policy
    assert "enabledPiToolNames" in server
    assert "if (!hardenedV3Only)" in extension
    assert "writesRequireAuthenticatedSession: true" in server
    assert "separate authenticated product channel" in readme
    assert "must never mint an approval" in readme
    assert package["private"] is True
    assert package["dependencies"] == {
        "@earendil-works/pi-coding-agent": "0.80.6"
    }
    assert "trusted-broker.test.mjs" in package["scripts"]["test"]
    assert "bootstrap.test.mjs" in package["scripts"]["test"]
    assert "release-binding.test.mjs" in package["scripts"]["test"]
    assert "tool-policy.test.mjs" in package["scripts"]["test"]
    package_lock = json.loads(
        (BRIDGE / "package-lock.json").read_text(encoding="utf-8")
    )
    assert package_lock["lockfileVersion"] == 3
    assert package_lock["packages"][
        "node_modules/@earendil-works/pi-coding-agent"
    ]["version"] == "0.80.6"
