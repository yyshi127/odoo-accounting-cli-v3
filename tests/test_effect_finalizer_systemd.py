from __future__ import annotations

import shlex
import tomllib
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_ROOT = PROJECT_ROOT / "deployment" / "dev23"
SYSTEMD_ROOT = DEPLOYMENT_ROOT / "systemd"
SERVICE_NAME = "odoo-accounting-cli-v3-effect-finalizer.service"
SOCKET_NAME = "odoo-accounting-cli-v3-effect-finalizer.socket"
SOCKET_PATH = "/run/odoo-accounting-cli-v3/effect-finalizer.sock"


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


def test_finalizer_deployment_asset_inventory_is_exact() -> None:
    assert {
        path.relative_to(DEPLOYMENT_ROOT).as_posix()
        for path in DEPLOYMENT_ROOT.rglob("*")
        if path.is_file()
    } == {
        "README.md",
        f"systemd/{SERVICE_NAME}",
        f"systemd/{SOCKET_NAME}",
    }


def test_finalizer_socket_is_root_broker_group_mode_0660() -> None:
    sections = _unit(SYSTEMD_ROOT / SOCKET_NAME)
    assert set(sections) == {"Unit", "Socket", "Install"}
    unit = sections["Unit"]
    socket = sections["Socket"]

    assert _one(unit, "Before") == SERVICE_NAME
    assert _one(socket, "ListenStream") == SOCKET_PATH
    assert _one(socket, "Accept") == "no"
    assert _one(socket, "Service") == SERVICE_NAME
    assert _one(socket, "FileDescriptorName") == "odoo-v3-effect-finalizer"
    assert _one(socket, "SocketUser") == "root"
    assert _one(socket, "SocketGroup") == "odoo-v3-broker"
    assert _one(socket, "SocketMode") == "0660"
    assert _one(socket, "DirectoryMode") == "0750"
    assert _one(socket, "RemoveOnStop") == "yes"
    assert _one(sections["Install"], "WantedBy") == "sockets.target"


def test_finalizer_service_is_dedicated_secret_free_and_hardened() -> None:
    sections = _unit(SYSTEMD_ROOT / SERVICE_NAME)
    assert set(sections) == {"Unit", "Service"}
    unit = sections["Unit"]
    service = sections["Service"]

    assert unit["Requires"] == [SOCKET_NAME]
    assert unit["After"] == [SOCKET_NAME]
    assert _one(service, "Type") == "simple"
    assert _one(service, "User") == "odoo-v3-effect-finalizer"
    assert _one(service, "Group") == "odoo-v3-effect-finalizer"
    assert _one(service, "SupplementaryGroups") == "odoo-v3-runtime"
    assert _one(service, "Sockets") == SOCKET_NAME
    assert _one(service, "StateDirectory") == (
        "odoo-accounting-cli-v3-effect-finalizer"
    )
    assert _one(service, "StateDirectoryMode") == "0700"
    assert service["Environment"] == [
        "HOME=/var/lib/odoo-accounting-cli-v3-effect-finalizer"
    ]
    assert "EnvironmentFile" not in service

    assert shlex.split(_one(service, "ExecStart")) == [
        "/opt/odoo-accounting-cli-v3/releases/@V3_RELEASE@/bin/odoo-accounting-cli-v3-effect-finalizer",
        "--config",
        "/etc/odoo-accounting-cli-v3/effect-finalizer-runtime.json",
    ]
    unset = set(shlex.split(_one(service, "UnsetEnvironment")))
    assert {
        "PYTHONPATH",
        "LD_PRELOAD",
        "PGHOST",
        "PGPASSFILE",
        "PGPASSWORD",
        "PGOPTIONS",
    }.issubset(unset)
    assert _one(service, "UMask") == "0077"
    assert _one(service, "NoNewPrivileges") == "yes"
    assert _one(service, "CapabilityBoundingSet") == ""
    assert _one(service, "AmbientCapabilities") == ""
    assert _one(service, "PrivateNetwork") == "yes"
    assert _one(service, "PrivateTmp") == "yes"
    assert _one(service, "ProtectHome") == "yes"
    assert _one(service, "ProtectProc") == "invisible"
    assert _one(service, "ProtectSystem") == "strict"
    assert _one(service, "RestrictAddressFamilies") == "AF_UNIX"
    assert _one(service, "RestrictNamespaces") == "yes"
    assert "odoo-v3-broker" not in service["SupplementaryGroups"]
    assert "write-runtime" not in _one(service, "ExecStart")
    assert "hmac" not in _one(service, "ExecStart")
    assert "pgpass" not in _one(service, "ExecStart")


def test_console_entry_and_runbook_keep_dependency_and_production_gates() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text("utf-8"))
    assert project["project"]["scripts"][
        "odoo-accounting-cli-v3-effect-finalizer"
    ] == "odoo_accounting_cli_v3.effect_finalizer_main:main"

    runbook = (DEPLOYMENT_ROOT / "README.md").read_text("utf-8")
    normalized = " ".join(runbook.split())
    assert "socket_group_gid" in normalized
    assert "actual numeric GID of `odoo-v3-broker`" in normalized
    assert "/usr/bin/python3" in normalized
    assert "import the required Odoo and" in normalized
    assert "leave the finalizer and all production writes" in normalized
    assert "V2 remains running and unchanged" in normalized
    assert "Do not add an `EnvironmentFile`" in normalized
