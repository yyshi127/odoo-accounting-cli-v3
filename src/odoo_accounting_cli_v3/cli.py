"""Installable, JSON-oriented command line boundary for the V3 gateway."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, NoReturn

import click

from . import __version__
from .contracts import ContractError, validate_value
from .odoo.runner import (
    OdooRunnerError,
    RuntimeConfig,
    load_runtime_config,
    load_runtime_secrets,
    run_odoo_shell,
)
from .receipts import ReceiptError, verify_read_receipt
from .registry import Capability, load_registry, registry_digest, validate_registry
from .release import ReleaseError, verify_manifest


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _success(command: str, data: dict[str, Any]) -> None:
    click.echo(_json({"command": command, "data": data, "ok": True}))


class CliFailure(click.ClickException):
    """A stable machine-readable CLI failure."""

    def __init__(self, *, command: str, code: str, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.command = command
        self.code = code
        self.exit_code = exit_code

    def show(self, file: Any | None = None) -> None:
        stream = file if file is not None else click.get_text_stream("stderr")
        click.echo(
            _json(
                {
                    "command": self.command,
                    "error": {
                        "code": self.code,
                        "message": self.message,
                        "odoo_action_performed": False,
                        "retryable": False,
                    },
                    "ok": False,
                }
            ),
            file=stream,
        )


def _load_capabilities() -> tuple[Capability, ...]:
    packaged = resources.files("odoo_accounting_cli_v3").joinpath("data", "capabilities.json")
    if packaged.is_file():
        with packaged.open(encoding="utf-8") as stream:
            return validate_registry(json.load(stream))

    # Source-tree fallback for an editable checkout. Built wheels always use the
    # packaged copy above, so an installed CLI does not depend on its cwd.
    source_registry = Path(__file__).resolve().parents[2] / "registry" / "capabilities.json"
    if source_registry.is_file():
        return load_registry(source_registry)
    raise CliFailure(
        command="registry.load",
        code="registry_unavailable",
        message="The validated capability registry is not present in this installation.",
        exit_code=4,
    )


def _load_release_identity(
    root: Path | None = None, *, command: str = "release.identity"
) -> dict[str, Any]:
    release_root = root or Path(__file__).resolve().parents[2]
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_path = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="release_identity_unavailable",
            message="The release manifest or external deployment anchor is unavailable.",
            exit_code=5,
        ) from exc
    expected_anchor_fields = {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "release",
    }
    if (
        not isinstance(anchor, dict)
        or set(anchor) != expected_anchor_fields
        or anchor["release"] != release_root.name
        or anchor["commit"] != manifest.get("commit")
        or not isinstance(anchor.get("package_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", anchor["package_sha256"]) is None
    ):
        raise CliFailure(
            command=command,
            code="release_identity_mismatch",
            message="The deployment anchor does not match this release.",
            exit_code=5,
        )
    try:
        verify_manifest(
            release_root,
            manifest,
            expected_manifest_sha256=anchor["manifest_sha256"],
        )
        capabilities = load_registry(release_root / "registry" / "capabilities.json")
    except (OSError, ValueError, ReleaseError) as exc:
        raise CliFailure(
            command=command,
            code="release_verification_failed",
            message="The installed release failed integrity verification.",
            exit_code=5,
        ) from exc
    return {
        "commit": manifest["commit"],
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": anchor["package_sha256"],
        "registry_digest": registry_digest(capabilities),
        "release": anchor["release"],
        "verified": True,
        "version": manifest["version"],
    }


def _assert_runtime_release(config: RuntimeConfig, identity: dict[str, Any]) -> None:
    source_release = Path(__file__).resolve().parents[2]
    if source_release != config.release_root.resolve():
        raise CliFailure(
            command="read",
            code="runtime_release_mismatch",
            message="The CLI process and configured Odoo runner are not from the same release.",
            exit_code=5,
        )
    if identity.get("version") != __version__:
        raise CliFailure(
            command="read",
            code="runtime_release_mismatch",
            message="The CLI version does not match the configured verified release.",
            exit_code=5,
        )


def _assert_verified_read_result(
    request: dict[str, Any],
    result: dict[str, Any],
    config: RuntimeConfig,
    identity: dict[str, Any],
) -> None:
    context = request.get("context")
    receipt = result.get("receipt") if isinstance(result, dict) else None
    if not isinstance(context, dict) or not isinstance(receipt, dict):
        raise CliFailure(
            command="read",
            code="verified_receipt_missing",
            message="Odoo did not return a verified read receipt.",
            exit_code=6,
        )
    try:
        capability_id = request["capability_id"]
        capabilities = load_registry(config.release_root / "registry" / "capabilities.json")
        capability = next(item for item in capabilities if item.id == capability_id)
        validate_value(result, capability.data["output_schema"])
        body = {key: value for key, value in result.items() if key != "receipt"}
        _auth_secret, receipt_secret = load_runtime_secrets(config)
        verify_read_receipt(
            receipt,
            capability_id=capability_id,
            parameters=request["parameters"],
            result_body=body,
            auth_token_id=context["auth_token_id"],
            principal=context["principal"],
            odoo_instance_id=config.instance_id,
            database_name=config.database_name,
            database_uuid=config.database_uuid,
            company_id=context["company_id"],
            user_id=context["user_id"],
            registry_digest=identity["registry_digest"],
            release_digest=identity["manifest_sha256"],
            expected_record_count=body["page"]["total_count"],
            now=datetime.now(timezone.utc),
            consume_receipt=lambda *_args: True,
            expected_key_id=config.receipt_key_id,
            secret=receipt_secret,
        )
    except (
        ContractError,
        KeyError,
        OdooRunnerError,
        ReceiptError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise CliFailure(
            command="read",
            code="verified_receipt_mismatch",
            message=(
                "The Odoo read result or receipt does not match the request, "
                "strict capability contract, signature, and verified runtime."
            ),
            exit_code=6,
        ) from exc


def _read_request(command: str, request_json: str | None) -> dict[str, Any]:
    raw = request_json
    if raw is None:
        if sys.stdin.isatty():
            raise CliFailure(
                command=command,
                code="request_required",
                message="Provide a JSON object with --request-json or on standard input.",
            )
        raw = sys.stdin.read()
    if not raw.strip():
        raise CliFailure(
            command=command,
            code="request_required",
            message="A non-empty JSON request object is required.",
        )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="invalid_json",
            message="The request is not valid JSON.",
        ) from exc
    if not isinstance(value, dict):
        raise CliFailure(
            command=command,
            code="invalid_request",
            message="The request must be a JSON object.",
        )
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _gateway_unavailable(command: str, request_json: str | None) -> NoReturn:
    _read_request(command, request_json)
    raise CliFailure(
        command=command,
        code="gateway_not_configured",
        message=(
            "The durable authenticated operation gateway is not configured; "
            "no Odoo action was performed."
        ),
        exit_code=3,
    )


@click.group()
@click.version_option(version=__version__, prog_name="odoo-accounting-cli-v3")
def main() -> None:
    """Controlled Odoo 19 accounting capability gateway."""


@main.group("registry")
def registry_group() -> None:
    """Inspect the validated local capability registry."""


@main.group("release")
def release_group() -> None:
    """Inspect the externally anchored release identity."""


@release_group.command("identity")
def release_identity() -> None:
    _success("release.identity", _load_release_identity())


@registry_group.command("list")
def registry_list() -> None:
    """Return every registered capability without executing Odoo."""

    capabilities = _load_capabilities()
    items = sorted((capability.data for capability in capabilities), key=lambda item: item["id"])
    _success(
        "registry.list",
        {
            "capabilities": items,
            "count": len(items),
            "registry_digest": registry_digest(capabilities),
        },
    )


@registry_group.command("get")
@click.option("--capability-id", required=True, help="Exact registered capability ID.")
def registry_get(capability_id: str) -> None:
    """Return one registered capability without executing Odoo."""

    capabilities = _load_capabilities()
    capability = next((item for item in capabilities if item.id == capability_id), None)
    if capability is None:
        raise CliFailure(
            command="registry.get",
            code="capability_not_found",
            message="The requested capability is not registered.",
            exit_code=4,
        )
    _success(
        "registry.get",
        {
            "capability": capability.data,
            "registry_digest": registry_digest(capabilities),
        },
    )


@main.command("read")
@click.option(
    "--runtime-config",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Absolute path to the root-managed Odoo runtime configuration.",
)
@click.option(
    "--timeout-seconds",
    type=click.FloatRange(min=0, min_open=True),
    default=30.0,
    show_default=True,
)
@click.option(
    "--request-json",
    help="Complete request as a JSON object; if omitted, read it from standard input.",
)
def read_capability(
    runtime_config: Path,
    timeout_seconds: float,
    request_json: str | None,
) -> None:
    """Execute one enabled, authenticated read capability in Odoo."""

    request = _read_request("read", request_json)
    try:
        config = load_runtime_config(runtime_config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command="read",
            code="runtime_configuration_rejected",
            message="The root-managed Odoo runtime configuration was rejected.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.release_root, command="read")
    _assert_runtime_release(config, identity)
    try:
        result = run_odoo_shell(
            config,
            request,
            release_digest=identity["manifest_sha256"],
            timeout_seconds=timeout_seconds,
        )
    except OdooRunnerError as exc:
        raise CliFailure(
            command="read",
            code="odoo_read_failed",
            message="The authenticated Odoo read did not produce a verified result.",
            exit_code=6,
        ) from exc
    _assert_verified_read_result(request, result, config, identity)
    _success(
        "read",
        {
            "capability_id": request.get("capability_id"),
            "release_identity": identity,
            "result": result,
            "runtime": config.runtime_identity,
        },
    )


@main.group("operation")
def operation_group() -> None:
    """Durable write lifecycle commands (currently disabled)."""


def _request_option(function: Any) -> Any:
    return click.option(
        "--request-json",
        help="Complete request as a JSON object; if omitted, read it from standard input.",
    )(function)


@operation_group.command("prepare")
@_request_option
def operation_prepare(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.prepare", request_json)


@operation_group.command("preview")
@_request_option
def operation_preview(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.preview", request_json)


@operation_group.command("approve-execute")
@_request_option
def operation_approve_execute(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.approve_execute", request_json)


@operation_group.command("status")
@_request_option
def operation_status(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.status", request_json)


@operation_group.command("verify")
@_request_option
def operation_verify(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.verify", request_json)


@operation_group.command("recover")
@_request_option
def operation_recover(request_json: str | None) -> NoReturn:
    _gateway_unavailable("operation.recover", request_json)


if __name__ == "__main__":
    main()
