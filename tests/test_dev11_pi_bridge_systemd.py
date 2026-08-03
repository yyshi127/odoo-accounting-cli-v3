from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
from collections import defaultdict
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEV11_ROOT = PROJECT_ROOT / "deployment" / "dev11"
SERVICE = DEV11_ROOT / "systemd" / "odoo-accounting-cli-v3-pi-bridge.service"
SOCKET = DEV11_ROOT / "systemd" / "odoo-accounting-cli-v3-pi-bridge.socket"
RENDERER = DEV11_ROOT / "render-pi-bridge-service.py"


def _load_renderer():
    specification = importlib.util.spec_from_file_location(
        "dev11_pi_renderer", RENDERER
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _unit(text: str) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = defaultdict(list)
            sections[line[1:-1]] = current
            continue
        assert current is not None and "=" in line
        key, value = line.split("=", 1)
        current[key].append(value)
    return sections


def _one(section: dict[str, list[str]], key: str) -> str:
    assert len(section[key]) == 1
    return section[key][0]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _anchored_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    renderer = _load_renderer()
    install_root = tmp_path / "install"
    releases_root = install_root / "releases"
    runtimes_root = install_root / "pi-runtime"
    version = "0.1.0.dev11"
    commit = "a" * 40
    release_name = f"{version}-{commit[:12]}"
    release_root = releases_root / release_name
    runtime_root = runtimes_root / release_name / "pi_bridge"
    node_path = tmp_path / "node"
    node_content = b"anchored-node\n"
    node_path.write_bytes(node_content)
    template_path = release_root / renderer._SERVICE
    template_path.parent.mkdir(parents=True)
    template_path.write_text(
        SERVICE.read_text("utf-8").replace(
            "/opt/odoo-accounting-cli-v3", install_root.as_posix()
        ),
        encoding="utf-8",
    )
    package_lock = b'{"lockfileVersion":3}\n'
    lock_path = release_root / "pi_bridge" / "package-lock.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_bytes(package_lock)
    (release_root / "pi_bridge" / "bootstrap.mjs").write_text(
        "// canonical bootstrap\n", encoding="utf-8"
    )
    release_files = []
    for candidate in sorted(release_root.rglob("*")):
        if candidate.is_file():
            content = candidate.read_bytes()
            release_files.append(
                {
                    "path": candidate.relative_to(release_root).as_posix(),
                    "sha256": _sha(content),
                    "size": len(content),
                }
            )
    unsigned_release = {
        "commit": commit,
        "files": release_files,
        "schema_version": 1,
        "version": version,
    }
    release_manifest = {
        **unsigned_release,
        "manifest_sha256": _sha(_canonical(unsigned_release)),
    }
    (release_root / "RELEASE-MANIFEST.json").write_text(
        json.dumps(release_manifest), encoding="utf-8"
    )
    package_content = b"canonical release package\n"
    packages = install_root / "packages"
    packages.mkdir(parents=True)
    (packages / f"odoo-accounting-cli-v3-{release_name}.tar.gz").write_bytes(
        package_content
    )
    trusted = install_root / "trusted-artifacts"
    trusted.mkdir()
    (trusted / f"{release_name}.json").write_text(
        json.dumps(
            {
                "commit": commit,
                "manifest_sha256": release_manifest["manifest_sha256"],
                "package_sha256": _sha(package_content),
                "release": release_name,
            }
        ),
        encoding="utf-8",
    )
    runtime_root.mkdir(parents=True)
    unsigned_runtime = {
        "files": [
            {
                "path": "@earendil-works/pi-coding-agent/dist/cli.js",
                "sha256": "b" * 64,
                "size": 1,
                "type": "file",
            }
        ],
        "node": {
            "arch": "x64",
            "path": node_path.as_posix(),
            "platform": "linux",
            "sha256": _sha(node_content),
            "size": len(node_content),
            "version": "22.22.1",
        },
        "package_lock_sha256": _sha(package_lock),
        "release": release_name,
        "release_manifest_sha256": release_manifest["manifest_sha256"],
        "schema_version": 1,
    }
    runtime_manifest = {
        **unsigned_runtime,
        "manifest_sha256": _sha(_canonical(unsigned_runtime)),
    }
    (runtime_root / "PI-RUNTIME-MANIFEST.json").write_text(
        json.dumps(runtime_manifest), encoding="utf-8"
    )
    (trusted / f"{release_name}.pi-runtime.json").write_text(
        json.dumps(
            {
                "release": release_name,
                "release_manifest_sha256": release_manifest["manifest_sha256"],
                "runtime_manifest_sha256": runtime_manifest["manifest_sha256"],
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(renderer, "_INSTALL_ROOT", install_root)
    monkeypatch.setattr(renderer, "_RELEASES_ROOT", releases_root)
    monkeypatch.setattr(renderer, "_RUNTIMES_ROOT", runtimes_root)
    monkeypatch.setattr(renderer, "_NODE_PATH", node_path)
    return renderer, release_root, runtime_root, node_path


def test_template_is_a_non_conflicting_fail_closed_sidecar() -> None:
    sections = _unit(SERVICE.read_text("utf-8"))
    assert set(sections) == {"Unit", "Service"}
    unit = sections["Unit"]
    service = sections["Service"]
    assert set(unit["Requires"]) == {
        "odoo-accounting-cli-v3-pi-bridge.socket",
        "odoo-accounting-cli-v3-pi-broker.socket",
    }
    assert _one(service, "User") == "odoo-v3-pi-broker"
    assert _one(service, "Group") == "odoo-v3-pi-broker"
    assert _one(service, "SupplementaryGroups") == "odoo-v3-runtime"
    environments = set(service["Environment"])
    assert (
        "PI_CODING_AGENT_DIR=/var/lib/odoo-accounting-cli-v3-pi-bridge/agent"
        in environments
    )
    assert "PI_AGENT_BRIDGE_HOST=127.0.0.1" in environments
    assert "PI_AGENT_BRIDGE_PORT=18788" in environments
    assert "PI_BRIDGE_REQUIRE_V3_IDENTITY=1" in environments
    assert "PI_BRIDGE_REQUIRE_SYSTEMD_SOCKET=1" in environments
    assert "PI_BRIDGE_HARDENED_V3_ONLY=1" in environments
    assert all("18787" not in item for item in environments)
    assert _one(service, "EnvironmentFile") == (
        "/etc/odoo-accounting-cli-v3/pi-bridge-v3.env"
    )
    assert set(_one(service, "UnsetEnvironment").split()) >= {
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
    }
    assert shlex.split(_one(service, "ExecStart")) == [
        "@V3_NODE@",
        "/opt/odoo-accounting-cli-v3/releases/@V3_RELEASE@/pi_bridge/bootstrap.mjs",
        "/opt/odoo-accounting-cli-v3/pi-runtime/@V3_RELEASE@/pi_bridge",
    ]
    assert _one(service, "Sockets") == (
        "odoo-accounting-cli-v3-pi-bridge.socket"
    )
    lines = SERVICE.read_text("utf-8").splitlines()
    environment_file_index = lines.index(
        "EnvironmentFile=/etc/odoo-accounting-cli-v3/pi-bridge-v3.env"
    )
    fixed_environment_indexes = [
        index
        for index, line in enumerate(lines)
        if line.startswith("Environment=")
    ]
    assert environment_file_index < min(fixed_environment_indexes)
    for key, expected in {
        "AmbientCapabilities": "",
        "CapabilityBoundingSet": "",
        "NoNewPrivileges": "yes",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
        "ProtectSystem": "strict",
        "RestrictNamespaces": "yes",
        "RestrictSUIDSGID": "yes",
        "TimeoutStopSec": "150s",
        "UMask": "0077",
    }.items():
        assert _one(service, key) == expected


def test_socket_unit_reserves_the_independent_loopback_port_for_the_sidecar() -> None:
    sections = _unit(SOCKET.read_text("utf-8"))
    assert set(sections) == {"Unit", "Socket", "Install"}
    socket = sections["Socket"]
    assert _one(socket, "ListenStream") == "127.0.0.1:18788"
    assert _one(socket, "Accept") == "no"
    assert _one(socket, "Service") == (
        "odoo-accounting-cli-v3-pi-bridge.service"
    )
    assert _one(socket, "FileDescriptorName") == "odoo-v3-pi-http"
    assert _one(socket, "ReusePort") == "no"
    assert _one(sections["Install"], "WantedBy") == "sockets.target"


def test_renderer_binds_release_runtime_and_exact_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer, release_root, runtime_root, node_path = _anchored_fixture(
        tmp_path, monkeypatch
    )
    rendered = renderer.render_pi_bridge_service(
        release_root,
        runtime_root,
        script_root=release_root,
        require_root_owner=False,
    )
    assert "@V3_RELEASE@" not in rendered
    assert "@V3_NODE@" not in rendered
    assert f"ExecStart={node_path.as_posix()} " in rendered
    assert release_root.name in rendered
    assert runtime_root.as_posix() in rendered

    node_path.write_bytes(b"different node bytes\n")
    with pytest.raises(renderer.RenderError, match="Node or package lock"):
        renderer.render_pi_bridge_service(
            release_root,
            runtime_root,
            script_root=release_root,
            require_root_owner=False,
        )


def test_renderer_rejects_runtime_anchor_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer, release_root, runtime_root, _node_path = _anchored_fixture(
        tmp_path, monkeypatch
    )
    anchor_path = renderer._INSTALL_ROOT / "trusted-artifacts" / (
        f"{release_root.name}.pi-runtime.json"
    )
    anchor = json.loads(anchor_path.read_text("utf-8"))
    anchor["runtime_manifest_sha256"] = "f" * 64
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")
    with pytest.raises(renderer.RenderError, match="runtime identity"):
        renderer.render_pi_bridge_service(
            release_root,
            runtime_root,
            script_root=release_root,
            require_root_owner=False,
        )
