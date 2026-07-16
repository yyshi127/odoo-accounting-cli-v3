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
    trusted_session = (BRIDGE / "trusted-session.mjs").read_text(encoding="utf-8")
    package = json.loads((BRIDGE / "package.json").read_text(encoding="utf-8"))

    for path in (
        BRIDGE / "server.mjs",
        BRIDGE / "extensions" / "odoo-v3-cli.mjs",
        BRIDGE / "extensions" / "odoo-tools.ts",
        BRIDGE / "package-lock.json",
        BRIDGE / "package.json",
        BRIDGE / "README.md",
        BRIDGE / "tests" / "odoo-v3-cli.test.mjs",
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
    assert "release.identity" in server
    assert 'spawnSync(v3CliBin, ["release", "identity"]' in server
    assert "PI_BRIDGE_REQUIRE_V3_IDENTITY" in server
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
    assert "resolveAuthenticatedBrokerSession" in server
    assert 'stdio: ["ignore", "pipe", "pipe", "pipe"]' in server
    assert "child.stdio[3].end" in server
    assert "ODOO_ACCOUNTING_CLI_V3_BROKER_SESSION" not in server
    assert "brokerSessionHandle: payload.session_id" not in server
    assert "authenticatedV3BrokerToolNames" in server
    assert "writesRequireAuthenticatedSession: true" in server
    assert "separate authenticated product channel" in readme
    assert "must never mint an approval" in readme
    assert package["private"] is True
    assert package["dependencies"] == {
        "@earendil-works/pi-coding-agent": "0.80.6"
    }
    assert "trusted-broker.test.mjs" in package["scripts"]["test"]
    package_lock = json.loads(
        (BRIDGE / "package-lock.json").read_text(encoding="utf-8")
    )
    assert package_lock["lockfileVersion"] == 3
    assert package_lock["packages"][
        "node_modules/@earendil-works/pi-coding-agent"
    ]["version"] == "0.80.6"
