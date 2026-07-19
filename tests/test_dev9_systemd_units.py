from __future__ import annotations

import shlex
import hashlib
import importlib.util
import json
import os
from collections import defaultdict
from pathlib import Path, PurePosixPath

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_ROOT = PROJECT_ROOT / "deployment" / "dev9" / "systemd"
FINALIZER_SYSTEMD_ROOT = PROJECT_ROOT / "deployment" / "dev23" / "systemd"
SERVICE_NAME = "odoo-accounting-cli-v3-broker.service"
FINALIZER_SERVICE_NAME = "odoo-accounting-cli-v3-effect-finalizer.service"
SOCKETS = {
    "odoo-accounting-cli-v3-pi-broker.socket": {
        "path": "/run/odoo-accounting-cli-v3/pi-broker.sock",
        "group": "odoo-v3-pi-broker",
        "descriptor": "odoo-v3-pi-broker",
    },
    "odoo-accounting-cli-v3-session-mint.socket": {
        "path": "/run/odoo-accounting-cli-v3/session-mint.sock",
        "group": "odoo-v3-odoo-control",
        "descriptor": "odoo-v3-session-mint",
    },
    "odoo-accounting-cli-v3-trusted-approval.socket": {
        "path": "/run/odoo-accounting-cli-v3/trusted-approval.sock",
        "group": "odoo-v3-odoo-control",
        "descriptor": "odoo-v3-trusted-approval",
    },
}
TMPFILES_NAME = "odoo-accounting-cli-v3-tmpfiles.conf"
RENDERER = PROJECT_ROOT / "deployment" / "dev9" / "render-systemd-service.py"
BROKER_RUNTIME_EXAMPLE = PROJECT_ROOT / "deployment" / "dev9" / (
    "broker-runtime.example.json"
)
PRODUCTION_RELEASES_ROOT = Path("/opt/odoo-accounting-cli-v3/releases")
HISTORICAL_STATE_ROOT = PurePosixPath("/var/lib/odoo-accounting-cli-v3")
BROKER_HOME = PurePosixPath("/var/lib/odoo-accounting-cli-v3-broker")


def _unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for number, raw_line in enumerate(path.read_text("utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            assert name and name not in sections, (path, number, line)
            current = defaultdict(list)
            sections[name] = current
            continue
        assert current is not None and "=" in line, (path, number, line)
        key, value = line.split("=", 1)
        assert key and key.strip() == key, (path, number, line)
        current[key].append(value)
    return sections


def _one(section: dict[str, list[str]], key: str) -> str:
    values = section[key]
    assert len(values) == 1, (key, values)
    return values[0]


def _load_renderer():
    specification = importlib.util.spec_from_file_location("dev9_renderer", RENDERER)
    assert specification is not None and specification.loader is not None
    renderer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(renderer)
    return renderer


def _write_anchored_release(
    install_root: Path,
    release_name: str,
    *,
    exec_releases_root: Path = PRODUCTION_RELEASES_ROOT,
) -> tuple[Path, Path, tuple[Path, ...]]:
    release_root = install_root / "releases" / release_name
    service_path = release_root / "deployment" / "dev9" / "systemd" / SERVICE_NAME
    finalizer_service_path = (
        release_root
        / "deployment"
        / "dev23"
        / "systemd"
        / FINALIZER_SERVICE_NAME
    )
    package = release_root / "src" / "odoo_accounting_cli_v3"
    package.mkdir(parents=True)
    service_path.parent.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "release.py").write_text(
        (PROJECT_ROOT / "src" / "odoo_accounting_cli_v3" / "release.py").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    launchers = tuple(
        release_root / "bin" / name
        for name in (
            "odoo-accounting-cli-v3",
            "odoo-accounting-cli-v3-broker",
            "odoo-accounting-cli-v3-effect-finalizer",
        )
    )
    for launcher in launchers:
        launcher.parent.mkdir(parents=True, exist_ok=True)
        launcher.write_text("#!/usr/bin/python3 -I\n", encoding="utf-8")
        if os.name == "posix":
            launcher.chmod(0o555)
    service = (SYSTEMD_ROOT / SERVICE_NAME).read_text(encoding="utf-8")
    service = service.replace(
        PRODUCTION_RELEASES_ROOT.as_posix(), exec_releases_root.as_posix()
    )
    service_path.write_text(service, encoding="utf-8")
    finalizer_service_path.parent.mkdir(parents=True)
    finalizer_service = (
        FINALIZER_SYSTEMD_ROOT / FINALIZER_SERVICE_NAME
    ).read_text(encoding="utf-8")
    finalizer_service = finalizer_service.replace(
        PRODUCTION_RELEASES_ROOT.as_posix(), exec_releases_root.as_posix()
    )
    finalizer_service_path.write_text(finalizer_service, encoding="utf-8")
    files = []
    for path in sorted(release_root.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(release_root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            )
    unsigned = {
        "schema_version": 1,
        "version": "0.1.0.dev9",
        "commit": "a" * 40,
        "files": files,
    }
    manifest_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest = {**unsigned, "manifest_sha256": manifest_digest}
    (release_root / "RELEASE-MANIFEST.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    anchors = install_root / "trusted-artifacts"
    anchors.mkdir()
    (anchors / f"{release_name}.json").write_text(
        json.dumps(
            {
                "commit": "a" * 40,
                "manifest_sha256": manifest_digest,
                "package_sha256": "b" * 64,
                "release": release_name,
            }
        ),
        encoding="utf-8",
    )
    return release_root, service_path, launchers


def test_dev9_systemd_asset_inventory_is_exact() -> None:
    assert {path.name for path in SYSTEMD_ROOT.iterdir() if path.is_file()} == {
        SERVICE_NAME,
        *SOCKETS,
        TMPFILES_NAME,
    }


def test_socket_units_have_exact_identity_and_access_boundaries() -> None:
    for name, expected in SOCKETS.items():
        sections = _unit(SYSTEMD_ROOT / name)
        assert set(sections) == {"Unit", "Socket", "Install"}
        unit = sections["Unit"]
        socket = sections["Socket"]
        install = sections["Install"]

        assert _one(unit, "Before") == SERVICE_NAME
        assert _one(socket, "ListenStream") == expected["path"]
        assert _one(socket, "Accept") == "no"
        assert _one(socket, "Service") == SERVICE_NAME
        assert _one(socket, "FileDescriptorName") == expected["descriptor"]
        assert _one(socket, "SocketUser") == "root"
        assert _one(socket, "SocketGroup") == expected["group"]
        assert _one(socket, "SocketMode") == "0660"
        assert _one(socket, "DirectoryMode") == "0750"
        assert _one(socket, "RemoveOnStop") == "yes"
        assert _one(install, "WantedBy") == "sockets.target"
        assert set(socket) == {
            "ListenStream",
            "Accept",
            "Service",
            "FileDescriptorName",
            "SocketUser",
            "SocketGroup",
            "SocketMode",
            "DirectoryMode",
            "RemoveOnStop",
        }


def test_service_consumes_only_the_three_named_sockets_as_dedicated_user() -> None:
    sections = _unit(SYSTEMD_ROOT / SERVICE_NAME)
    assert set(sections) == {"Unit", "Service"}
    unit = sections["Unit"]
    service = sections["Service"]
    socket_names = set(SOCKETS)

    assert set(unit["Requires"]) == socket_names
    assert len(unit["Requires"]) == len(socket_names)
    assert set(unit["After"]) == socket_names
    assert len(unit["After"]) == len(socket_names)
    assert set(service["Sockets"]) == socket_names
    assert len(service["Sockets"]) == len(socket_names)
    assert _one(service, "Type") == "simple"
    assert _one(service, "User") == "odoo-v3-broker"
    assert _one(service, "Group") == "odoo-v3-broker"
    assert _one(service, "SupplementaryGroups") == "odoo-v3-runtime"

    command = shlex.split(_one(service, "ExecStart"))
    assert command == [
        "/opt/odoo-accounting-cli-v3/releases/@V3_RELEASE@/bin/odoo-accounting-cli-v3-broker",
        "--config",
        "/etc/odoo-accounting-cli-v3/broker-runtime.json",
    ]
    assert _one(service, "NoNewPrivileges") == "yes"
    assert _one(service, "CapabilityBoundingSet") == ""
    assert _one(service, "AmbientCapabilities") == ""
    assert _one(service, "RestrictSUIDSGID") == "yes"
    assert _one(service, "RestrictAddressFamilies") == "AF_UNIX AF_INET AF_INET6"
    assert _one(service, "ProtectSystem") == "strict"
    assert _one(service, "ProtectHome") == "yes"
    assert _one(service, "StateDirectory") == BROKER_HOME.name
    assert _one(service, "StateDirectoryMode") == "0700"
    assert _one(service, "Environment") == f"HOME={BROKER_HOME}"
    assert _one(service, "ReadWritePaths") == str(HISTORICAL_STATE_ROOT)
    assert BROKER_HOME != HISTORICAL_STATE_ROOT
    assert HISTORICAL_STATE_ROOT not in BROKER_HOME.parents
    assert BROKER_HOME not in HISTORICAL_STATE_ROOT.parents
    assert _one(service, "UMask") == "0077"
    assert _one(service, "TimeoutStopSec") == "135s"
    assert all("%" not in item for values in service.values() for item in values)


def test_configured_store_paths_are_explicit_and_outside_managed_broker_home() -> None:
    config = json.loads(BROKER_RUNTIME_EXAMPLE.read_text("utf-8"))
    paths = {
        PurePosixPath(config[field])
        for field in (
            "shared_write_state_path",
            "trusted_session_state_path",
            "broker_audit_state_path",
        )
    }

    assert len(paths) == 3
    assert {path.parent for path in paths} == {
        HISTORICAL_STATE_ROOT / "broker-state"
    }
    assert all(path.is_absolute() for path in paths)
    assert all(HISTORICAL_STATE_ROOT in path.parents for path in paths)
    assert all(BROKER_HOME not in path.parents for path in paths)


def test_service_renderer_requires_an_anchored_release_and_removes_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_renderer()
    release_name = "0.1.0.dev9-aaaaaaaaaaaa"
    install_root = tmp_path / "install"
    release_root, service_path, launchers = _write_anchored_release(
        install_root,
        release_name,
        exec_releases_root=install_root / "releases",
    )
    monkeypatch.setattr(renderer, "_PRODUCTION_RELEASES_ROOT", release_root.parent)

    rendered = renderer.render_service(
        release_root,
        script_root=release_root,
        require_root_owner=False,
    )
    assert "@V3_RELEASE@" not in rendered
    assert f"/releases/{release_name}/bin/odoo-accounting-cli-v3-broker" in rendered

    if os.name == "posix":
        launchers[-1].chmod(0o444)
        with pytest.raises(renderer.RenderError, match="launcher mode"):
            renderer.render_service(
                release_root,
                script_root=release_root,
                require_root_owner=False,
            )
        launchers[-1].chmod(0o555)

    changed = service_path.read_text(encoding="utf-8").replace(
        "@V3_RELEASE@", "tampered"
    )
    service_path.write_text(changed, encoding="utf-8")
    with pytest.raises(renderer.RenderError):
        renderer.render_service(
            release_root,
            script_root=release_root,
            require_root_owner=False,
        )


def test_service_renderer_binds_production_execstart_to_the_verified_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_renderer()
    assert renderer._PRODUCTION_RELEASES_ROOT == PRODUCTION_RELEASES_ROOT
    release_name = "0.1.0.dev9-same-release"
    trusted_install = tmp_path / "trusted-install"
    trusted_root, _, _ = _write_anchored_release(
        trusted_install,
        release_name,
        exec_releases_root=trusted_install / "releases",
    )
    monkeypatch.setattr(
        renderer, "_PRODUCTION_RELEASES_ROOT", trusted_root.parent
    )
    monkeypatch.setattr(renderer, "_secure_root_path", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        renderer,
        "_verify_canonical_launchers",
        lambda *_args, **_kwargs: None,
    )

    rendered = renderer.render_service(
        trusted_root,
        script_root=trusted_root,
        require_root_owner=True,
    )
    assert [line for line in rendered.splitlines() if line.startswith("ExecStart=")] == [
        "ExecStart="
        f"{(trusted_root / 'bin' / 'odoo-accounting-cli-v3-broker').as_posix()} "
        "--config /etc/odoo-accounting-cli-v3/broker-runtime.json"
    ]

    alternate_install = tmp_path / "alternate-install"
    alternate_root, _, _ = _write_anchored_release(
        alternate_install,
        release_name,
        exec_releases_root=trusted_root.parent,
    )
    with pytest.raises(renderer.RenderError, match="production releases root"):
        renderer.render_service(
            alternate_root,
            script_root=alternate_root,
            require_root_owner=True,
        )

    mismatched_install = tmp_path / "mismatched-install"
    mismatched_root, _, _ = _write_anchored_release(
        mismatched_install,
        release_name,
        exec_releases_root=alternate_root.parent,
    )
    monkeypatch.setattr(renderer, "_PRODUCTION_RELEASES_ROOT", mismatched_root.parent)
    with pytest.raises(renderer.RenderError, match="ExecStart"):
        renderer.render_service(
            mismatched_root,
            script_root=mismatched_root,
            require_root_owner=True,
        )


def test_service_renderer_binds_effect_finalizer_to_same_verified_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_renderer()
    release_name = "0.1.0.dev23-effect-finalizer"
    install_root = tmp_path / "install"
    release_root, _, _ = _write_anchored_release(
        install_root,
        release_name,
        exec_releases_root=install_root / "releases",
    )
    monkeypatch.setattr(renderer, "_PRODUCTION_RELEASES_ROOT", release_root.parent)

    rendered = renderer.render_service(
        release_root,
        script_root=release_root,
        require_root_owner=False,
        component="effect-finalizer",
    )

    assert "@V3_RELEASE@" not in rendered
    assert (
        "ExecStart="
        f"{release_root.as_posix()}/bin/odoo-accounting-cli-v3-effect-finalizer "
        "--config /etc/odoo-accounting-cli-v3/effect-finalizer-runtime.json"
    ) in rendered

    with pytest.raises(renderer.RenderError, match="component"):
        renderer.render_service(
            release_root,
            script_root=release_root,
            require_root_owner=False,
            component="unknown",
        )


def test_tmpfiles_boundary_owns_the_shared_runtime_parent() -> None:
    text = (SYSTEMD_ROOT / TMPFILES_NAME).read_text("utf-8")
    assert text == "d /run/odoo-accounting-cli-v3 0750 root odoo-v3-runtime -\n"
    parent = text.split()[1]
    assert {
        str(PurePosixPath(value["path"]).parent) for value in SOCKETS.values()
    } == {parent}
