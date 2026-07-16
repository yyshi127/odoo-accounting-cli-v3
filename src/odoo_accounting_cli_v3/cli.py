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
from .auth import authentication_request_digest
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
from .write_api import WriteApiError, parse_write_api_request


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _success(
    command: str,
    data: dict[str, Any],
    *,
    business_succeeded: bool | None = None,
) -> None:
    response: dict[str, Any] = {"command": command, "data": data, "ok": True}
    if business_succeeded is not None:
        response["business_succeeded"] = business_succeeded
    click.echo(_json(response))


class CliFailure(click.ClickException):
    """A stable machine-readable CLI failure."""

    def __init__(
        self,
        *,
        command: str,
        code: str,
        message: str,
        exit_code: int = 2,
        retryable: bool = False,
        odoo_effect: str | None = None,
        operation_id: str | None = None,
        state: str | None = None,
    ) -> None:
        super().__init__(message)
        if odoo_effect not in {None, "none", "unknown"}:
            raise ValueError("odoo_effect must be none or unknown")
        self.command = command
        self.code = code
        self.exit_code = exit_code
        self.retryable = retryable
        self.odoo_effect = odoo_effect
        self.operation_id = operation_id
        self.state = state

    def show(self, file: Any | None = None) -> None:
        stream = file if file is not None else click.get_text_stream("stderr")
        if self.odoo_effect is None:
            error: dict[str, Any] = {
                "code": self.code,
                "message": self.message,
                "odoo_action_performed": False,
                "retryable": self.retryable,
            }
        else:
            error = {
                "code": self.code,
                "message": self.message,
                "odoo_effect": self.odoo_effect,
                "retryable": self.retryable,
            }
            if self.operation_id is not None:
                error["operation_id"] = self.operation_id
            if self.state is not None:
                error["state"] = self.state
        click.echo(
            _json({"command": self.command, "error": error, "ok": False}),
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
    expected_package_path = (
        config.release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{config.release_root.name}.tar.gz"
    )
    if source_release != config.release_root.resolve():
        raise CliFailure(
            command="read",
            code="runtime_release_mismatch",
            message="The CLI process and configured Odoo runner are not from the same release.",
            exit_code=5,
        )
    if (
        identity.get("version") != __version__
        or identity.get("package_sha256") != config.canonical_package_sha256
        or config.canonical_package_path != expected_package_path
    ):
        raise CliFailure(
            command="read",
            code="runtime_release_mismatch",
            message="The CLI or canonical package does not match the configured verified release.",
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
        if context["auth_request_digest"] != authentication_request_digest(
            capability_id, request["parameters"]
        ):
            raise ValueError("authenticated request content digest mismatch")
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
            environment=config.environment,
            capability_channel=config.capability_channel,
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
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json,
        )
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


def _reject_non_finite_json(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def _write_cli_failure(
    *,
    command: str,
    code: str,
    message: str,
    odoo_effect: str,
    operation_id: str | None = None,
    state: str | None = None,
    retryable: bool = False,
    exit_code: int = 2,
) -> CliFailure:
    return CliFailure(
        command=command,
        code=code,
        message=message,
        retryable=retryable,
        odoo_effect=odoo_effect,
        operation_id=operation_id,
        state=state,
        exit_code=exit_code,
    )


def _operation_id_from_request(action: str, payload: dict[str, Any]) -> str | None:
    field = "recovery_operation_id" if action == "operation.recover" else "operation_id"
    value = payload.get(field)
    return value if isinstance(value, str) else None


def _business_succeeded(data: dict[str, Any]) -> bool:
    verification = data.get("verification")
    return (
        data.get("operation_state") in {"completed", "recovered"}
        and isinstance(verification, dict)
        and verification.get("passed") is True
    )


def _execute_write_command(
    *,
    command: str,
    action: str,
    request_json: str | None,
    report_business_result: bool = False,
) -> None:
    try:
        request = _read_request(command, request_json)
    except CliFailure as exc:
        raise _write_cli_failure(
            command=command,
            code=exc.code,
            message=exc.message,
            odoo_effect="none",
            exit_code=exc.exit_code,
        ) from exc

    try:
        parsed = parse_write_api_request(action, request)
    except WriteApiError as exc:
        raise _write_cli_failure(
            command=command,
            code="invalid_request",
            message="The write request does not match the exact action contract.",
            odoo_effect="none",
        ) from exc

    operation_id = _operation_id_from_request(action, parsed.payload)
    uncertain_effect = "unknown" if action == "operation.approve_execute" else "none"
    try:
        # The dispatcher owns root-managed runtime paths and secrets. They are
        # deliberately absent from the Pi-facing command surface.
        from .write_app import execute_write_action

        raw_data = execute_write_action(action, parsed)
        if not isinstance(raw_data, dict):
            raise TypeError("write dispatcher returned a non-object")
        data = json.loads(
            json.dumps(
                raw_data,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except CliFailure as exc:
        raise _write_cli_failure(
            command=command,
            code=exc.code,
            message=exc.message,
            odoo_effect=exc.odoo_effect or uncertain_effect,
            operation_id=exc.operation_id or operation_id,
            state=exc.state,
            retryable=exc.retryable,
            exit_code=exc.exit_code,
        ) from exc
    except Exception as exc:
        code = getattr(exc, "code", None)
        structured = isinstance(code, str) and bool(code.strip())
        effect = getattr(exc, "odoo_effect", uncertain_effect)
        if effect not in {"none", "unknown"}:
            effect = uncertain_effect
        retryable = getattr(exc, "retryable", False)
        if type(retryable) is not bool:
            retryable = False
        exception_operation_id = getattr(exc, "operation_id", operation_id)
        if not isinstance(exception_operation_id, str):
            exception_operation_id = operation_id
        state = getattr(exc, "state", None)
        if not isinstance(state, str):
            state = None
        raise _write_cli_failure(
            command=command,
            code=code if structured else "write_action_failed",
            message=(
                str(getattr(exc, "message", exc))
                if structured
                else "The durable write action did not return a trusted result."
            ),
            odoo_effect=effect,
            operation_id=exception_operation_id,
            state=state,
            retryable=retryable,
            exit_code=int(getattr(exc, "exit_code", 3))
            if type(getattr(exc, "exit_code", 3)) is int
            else 3,
        ) from exc

    _success(
        command,
        data,
        business_succeeded=_business_succeeded(data)
        if report_business_result
        else None,
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
    """Durable, authenticated write lifecycle commands."""


def _request_option(function: Any) -> Any:
    return click.option(
        "--request-json",
        help="Complete request as a JSON object; if omitted, read it from standard input.",
    )(function)


@operation_group.command("prepare")
@_request_option
def operation_prepare(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.prepare",
        action="operation.prepare",
        request_json=request_json,
    )


@operation_group.command("preview")
@_request_option
def operation_preview(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.preview",
        action="operation.preview",
        request_json=request_json,
    )


@operation_group.command("approve-execute")
@_request_option
def operation_approve_execute(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.approve_execute",
        action="operation.approve_execute",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("status")
@_request_option
def operation_status(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.status",
        action="operation.status",
        request_json=request_json,
    )


@operation_group.command("result")
@_request_option
def operation_result(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.result",
        action="operation.result",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("verify")
@_request_option
def operation_verify(request_json: str | None) -> None:
    """Compatibility alias for the read-only operation result action."""

    _execute_write_command(
        command="operation.verify",
        action="operation.result",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("recover")
@_request_option
def operation_recover(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.recover",
        action="operation.recover",
        request_json=request_json,
    )


if __name__ == "__main__":
    main()
