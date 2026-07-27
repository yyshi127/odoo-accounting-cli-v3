"""Installable, JSON-oriented command line boundary for the V3 gateway."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from importlib import resources, util
from pathlib import Path
from typing import Any, NoReturn

import click

from . import __version__
from .auth import authentication_request_digest
from .contracts import ContractError, validate_value
from .effect_finalizer import (
    EffectFinalizationError,
    validate_effect_finalization_evidence_shape,
)
from .odoo.runner import (
    READ_REJECTION_CODES,
    OdooRunnerError,
    RuntimeConfig,
    load_runtime_config,
    load_runtime_secrets,
    require_staged_test_evidence_runtime,
    run_read_boundary_evidence,
    run_odoo_shell,
)
from .receipts import ReceiptError, verify_read_receipt
from .registry import Capability, load_registry, registry_digest, validate_registry
from .release import ReleaseError, verify_manifest
from .write_api import WriteApiError, parse_write_api_request
from .write_runtime import WriteRuntimeError, load_write_runtime_config


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


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
        rejection_code: str | None = None,
    ) -> None:
        super().__init__(message)
        if odoo_effect not in {None, "none", "unknown"}:
            raise ValueError("odoo_effect must be none or unknown")
        if rejection_code is not None and rejection_code not in READ_REJECTION_CODES:
            raise ValueError("read rejection code is not allowlisted")
        self.command = command
        self.code = code
        self.exit_code = exit_code
        self.retryable = retryable
        self.odoo_effect = odoo_effect
        self.operation_id = operation_id
        self.state = state
        self.rejection_code = rejection_code

    def show(self, file: Any | None = None) -> None:
        stream = file if file is not None else click.get_text_stream("stderr")
        if self.odoo_effect is None:
            error: dict[str, Any] = {
                "code": self.code,
                "message": self.message,
                "odoo_action_performed": False,
                "retryable": self.retryable,
            }
            if self.rejection_code is not None:
                error["rejection_code"] = self.rejection_code
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


def _assert_runtime_release(
    config: RuntimeConfig,
    identity: dict[str, Any],
    *,
    command: str = "read",
) -> None:
    source_release = Path(__file__).resolve().parents[2]
    expected_package_path = (
        config.release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{config.release_root.name}.tar.gz"
    )
    if source_release != config.release_root.resolve():
        raise CliFailure(
            command=command,
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
            command=command,
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


def _load_sandbox_write_evidence_verifier() -> Any:
    path = Path(__file__).resolve().parents[2] / "tools" / "verify_sandbox_write_evidence.py"
    spec = util.spec_from_file_location(
        "odoo_accounting_cli_v3_release_sandbox_write_evidence_verifier",
        path,
    )
    if spec is None or spec.loader is None:
        raise CliFailure(
            command="evidence.verify-sandbox-write",
            code="sandbox_write_evidence_verifier_unavailable",
            message="The exact-release sandbox write evidence verifier is unavailable.",
            exit_code=5,
        )
    module = util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except OSError as exc:
        raise CliFailure(
            command="evidence.verify-sandbox-write",
            code="sandbox_write_evidence_verifier_unavailable",
            message="The exact-release sandbox write evidence verifier is unavailable.",
            exit_code=5,
        ) from exc
    return module


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _validate_sandbox_write_evidence_root(
    path: Path,
    *,
    release_root: Path,
    minimum_free_bytes: int,
) -> dict[str, Any]:
    if not path.is_absolute():
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must be absolute.",
            exit_code=5,
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root is unavailable.",
            exit_code=5,
        ) from exc
    if not resolved.is_dir() or path.is_symlink():
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must be a real directory.",
            exit_code=5,
        )
    if _is_within(resolved, release_root):
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must not be inside the immutable release.",
            exit_code=5,
        )
    if os.name == "posix":
        import stat

        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise CliFailure(
                command="evidence.sandbox-write-preflight",
                code="sandbox_write_evidence_root_rejected",
                message="The sandbox write evidence root must be root-owned and not group/world writable.",
                exit_code=5,
            )
    usage = shutil.disk_usage(resolved)
    free_bytes = usage.free
    if free_bytes < minimum_free_bytes:
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_capacity_rejected",
            message="The sandbox write evidence filesystem does not have enough free bytes.",
            exit_code=5,
        )
    return {
        "path": str(resolved),
        "available_bytes": free_bytes,
        "minimum_free_bytes": minimum_free_bytes,
    }


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
    operation_id = data.get("operation_id")
    if (
        data.get("operation_state") not in {"completed", "recovered"}
        or not isinstance(operation_id, str)
        or not operation_id
        or not isinstance(verification, dict)
        or verification.get("passed") is not True
    ):
        return False
    try:
        finalization = validate_effect_finalization_evidence_shape(
            data.get("database_finalization")
        )
    except EffectFinalizationError:
        return False
    audit_receipt = data.get("audit_receipt")
    if (
        not isinstance(audit_receipt, dict)
        or finalization["database_uuid"] != audit_receipt.get("database_uuid")
    ):
        return False
    if finalization["resolution_kind"] == "verified":
        return (
            finalization["operation_id"] == operation_id
            and finalization["resolution_operation_id"] == operation_id
        )
    return (
        finalization["operation_id"] != operation_id
        and finalization["resolution_operation_id"] == operation_id
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


@main.group("evidence")
def evidence_group() -> None:
    """Run exact-release internal safety evidence probes."""


@evidence_group.command("read-boundary")
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
    "--launcher-diagnostics",
    is_flag=True,
    hidden=True,
    help="Emit Odoo launcher checkpoints and Odoo startup logs to stderr for failed evidence triage.",
)
def evidence_read_boundary(
    runtime_config: Path,
    timeout_seconds: float,
    launcher_diagnostics: bool,
) -> None:
    """Prove the Odoo shell PostgreSQL rollback-only boundary."""

    command = "evidence.read-boundary"
    try:
        config = load_runtime_config(runtime_config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command=command,
            code="runtime_configuration_rejected",
            message="The root-managed Odoo runtime configuration was rejected.",
            exit_code=5,
        ) from exc
    try:
        require_staged_test_evidence_runtime(config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command=command,
            code="evidence_scope_rejected",
            message="DML read-boundary evidence requires a staged test runtime.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.release_root, command=command)
    _assert_runtime_release(config, identity, command=command)
    try:
        evidence = run_read_boundary_evidence(
            config,
            release_digest=identity["manifest_sha256"],
            timeout_seconds=timeout_seconds,
            launcher_diagnostics=launcher_diagnostics,
        )
    except OdooRunnerError as exc:
        if launcher_diagnostics:
            click.echo(str(exc), err=True)
        raise CliFailure(
            command=command,
            code="odoo_read_boundary_evidence_failed",
            message="Odoo did not return verified read-boundary evidence.",
            exit_code=6,
        ) from exc
    _success(
        command,
        {
            "evidence": evidence,
            "release_identity": identity,
            "runtime": config.runtime_identity,
        },
    )


@evidence_group.command("verify-sandbox-write")
@click.option(
    "--evidence-json",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox write evidence JSON bundle to verify.",
)
@click.option(
    "--assemble-from",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Input manifest whose retained artifacts will be assembled and verified.",
)
def evidence_verify_sandbox_write(
    evidence_json: Path | None,
    assemble_from: Path | None,
) -> None:
    """Verify a retained sandbox write evidence bundle without authorizing production."""

    command = "evidence.verify-sandbox-write"
    if (evidence_json is None) == (assemble_from is None):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_input_required",
            message="Provide exactly one of --evidence-json or --assemble-from.",
            exit_code=2,
        )
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        if assemble_from is not None:
            document = verifier.assemble_path(assemble_from)
            evidence = verifier.verify_document(document)
        else:
            evidence = verifier.verify_path(evidence_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_rejected",
                message="The sandbox write evidence bundle failed promotion-admission checks.",
                exit_code=6,
            ) from exc
        raise
    if (
        evidence.get("release_sha256") != identity["manifest_sha256"]
        or evidence.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The sandbox write evidence bundle is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "evidence": evidence,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("review-write-promotion")
@click.option(
    "--evidence-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox write evidence JSON bundle to bind to the promotion review.",
)
@click.option(
    "--candidate-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Non-authorizing write promotion candidate JSON.",
)
def evidence_review_write_promotion(
    evidence_json: Path,
    candidate_json: Path,
) -> None:
    """Review whether sandbox evidence may support staged sandbox promotion."""

    command = "evidence.review-write-promotion"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        review = verifier.review_promotion_candidate_paths(evidence_json, candidate_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="write_promotion_candidate_rejected",
                message="The write promotion candidate is not supported by exact-release sandbox evidence.",
                exit_code=6,
            ) from exc
        raise
    if (
        review.get("release_sha256") != identity["manifest_sha256"]
        or review.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="write_promotion_release_mismatch",
            message="The write promotion review is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "release_identity": identity,
            "promotion_review": review,
        },
        business_succeeded=False,
    )


@evidence_group.command("build-sandbox-write-input")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Metadata JSON beside standard retained sandbox-write artifacts.",
)
def evidence_build_sandbox_write_input(metadata_json: Path) -> None:
    """Build a verified sandbox-write evidence input manifest from retained files."""

    command = "evidence.build-sandbox-write-input"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        manifest = verifier.build_input_manifest_path(metadata_json)
        evidence = verifier.verify_document(
            verifier.assemble_document(manifest, base_dir=metadata_json.parent)
        )
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_input_rejected",
                message="The sandbox write evidence input manifest could not be built from retained files.",
                exit_code=6,
            ) from exc
        raise
    if (
        evidence.get("release_sha256") != identity["manifest_sha256"]
        or evidence.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The sandbox write evidence input is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "input_manifest": manifest,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("inspect-sandbox-write-root")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Metadata JSON beside standard retained sandbox-write artifacts.",
)
def evidence_inspect_sandbox_write_root(metadata_json: Path) -> None:
    """Inspect a retained sandbox-write evidence root without authorizing production."""

    command = "evidence.inspect-sandbox-write-root"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        report = verifier.inspect_retained_root_path(metadata_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_root_rejected",
                message="The retained sandbox write evidence root is incomplete or unsafe.",
                exit_code=6,
            ) from exc
        raise
    if (
        report.get("release_sha256") != identity["manifest_sha256"]
        or report.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The retained sandbox write evidence root is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "release_identity": identity,
            "root_report": report,
        },
        business_succeeded=False,
    )


def _load_write_capability_implementation(command: str) -> tuple[Any, Any]:
    try:
        from .odoo.write_handlers import _CAPABILITIES as odoo_write_capabilities
        from .write_service import _ALLOWED_MODELS as allowed_models_by_capability
    except Exception as exc:
        raise CliFailure(
            command=command,
            code="write_capability_runtime_unavailable",
            message="The write capability implementation allowlists are unavailable.",
            exit_code=5,
        ) from exc
    return odoo_write_capabilities, allowed_models_by_capability


def _write_capability_readiness_report(
    capability: Capability,
    *,
    allowed_models_by_capability: Any,
    odoo_write_capabilities: Any,
) -> dict[str, Any]:
    capability_id = capability.id

    data = capability.data
    allowed_models = sorted(allowed_models_by_capability.get(capability_id, ()))
    checks = {
        "approval_policy_present": (
            data["approval"].get("required") is True
            and isinstance(data["approval"].get("policy"), str)
            and bool(data["approval"]["policy"].strip())
            and isinstance(data["approval"].get("ttl_seconds"), int)
            and 1 <= data["approval"]["ttl_seconds"] <= 900
        ),
        "idempotency_policy_present": (
            data["idempotency"].get("required") is True
            and isinstance(data["idempotency"].get("scope"), str)
            and bool(data["idempotency"]["scope"].strip())
        ),
        "odoo_handler_supported": capability_id in odoo_write_capabilities,
        "production_not_enabled": "production" not in data["enabled_environments"],
        "write_not_enabled": data["enabled_environments"] == [],
        "write_not_staged": data.get("staged_environments", []) == [],
        "recovery_method_present": (
            isinstance(data["recovery"].get("method"), str)
            and bool(data["recovery"]["method"].strip())
        ),
        "service_allowed_models_present": bool(allowed_models),
        "strict_input_schema": (
            data["input_schema"].get("type") == "object"
            and data["input_schema"].get("additionalProperties") is False
        ),
        "strict_output_schema": (
            data["output_schema"].get("type") == "object"
            and data["output_schema"].get("additionalProperties") is False
        ),
    }
    sandbox_drill_admissible = all(checks.values())
    return {
        "allowed_models": allowed_models,
        "capability": {
            "access": data["access"],
            "approval": data["approval"],
            "company_scope": data["company_scope"],
            "enabled_environments": data["enabled_environments"],
            "evidence_level": data["evidence"]["level"],
            "id": capability_id,
            "idempotency": data["idempotency"],
            "recovery": data["recovery"],
            "risk_level": data["risk_level"],
            "staged_environments": data.get("staged_environments", []),
        },
        "checks": checks,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "sandbox_drill_admissible": sandbox_drill_admissible,
    }


@evidence_group.command("write-capability-readiness")
@click.option(
    "--capability-id",
    required=True,
    help="Exact registered write capability to check before sandbox drill collection.",
)
def evidence_write_capability_readiness(capability_id: str) -> None:
    """Check static readiness before a real sandbox write evidence drill."""

    command = "evidence.write-capability-readiness"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    capability = next((item for item in capabilities if item.id == capability_id), None)
    if capability is None or capability.data["access"] != "write":
        raise CliFailure(
            command=command,
            code="write_capability_rejected",
            message="The readiness gate must target one registered write capability.",
            exit_code=5,
        )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    report = _write_capability_readiness_report(
        capability,
        allowed_models_by_capability=allowed_models_by_capability,
        odoo_write_capabilities=odoo_write_capabilities,
    )
    _success(
        command,
        {
            **report,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("write-capabilities-readiness")
def evidence_write_capabilities_readiness() -> None:
    """Check static readiness for every registered write capability."""

    command = "evidence.write-capabilities-readiness"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    write_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "write"),
        key=lambda item: item.id,
    )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    reports = [
        _write_capability_readiness_report(
            capability,
            allowed_models_by_capability=allowed_models_by_capability,
            odoo_write_capabilities=odoo_write_capabilities,
        )
        for capability in write_capabilities
    ]
    admissible_count = sum(
        1 for report in reports if report["sandbox_drill_admissible"] is True
    )
    _success(
        command,
        {
            "admissible_count": admissible_count,
            "capabilities": reports,
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": identity,
            "sandbox_drill_admissible": admissible_count == len(reports),
            "total_write_capabilities": len(reports),
        },
        business_succeeded=False,
    )


@evidence_group.command("sandbox-write-preflight")
@click.option(
    "--capability-id",
    required=True,
    help="Exact registered write capability that this sandbox evidence drill will collect.",
)
@click.option(
    "--company-id",
    required=True,
    type=click.IntRange(min=1),
    help="Exact Odoo company ID that this sandbox evidence drill is bound to.",
)
@click.option(
    "--write-runtime-config",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Root-managed write runtime configuration for a staged sandbox.",
)
@click.option(
    "--evidence-root",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Existing root-owned directory for retained sandbox write evidence.",
)
@click.option(
    "--min-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
    help="Minimum free bytes required before starting sandbox write evidence collection.",
)
def evidence_sandbox_write_preflight(
    capability_id: str,
    company_id: int,
    write_runtime_config: Path,
    evidence_root: Path,
    min_free_bytes: int,
) -> None:
    """Read-only gate before any real sandbox accounting write drill."""

    command = "evidence.sandbox-write-preflight"
    capability = next(
        (item for item in _load_capabilities() if item.id == capability_id),
        None,
    )
    if capability is None or capability.data["access"] != "write":
        raise CliFailure(
            command=command,
            code="sandbox_write_capability_rejected",
            message="The sandbox write preflight must target one registered write capability.",
            exit_code=5,
        )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    readiness_report = _write_capability_readiness_report(
        capability,
        allowed_models_by_capability=allowed_models_by_capability,
        odoo_write_capabilities=odoo_write_capabilities,
    )
    if readiness_report["sandbox_drill_admissible"] is not True:
        raise CliFailure(
            command=command,
            code="sandbox_write_readiness_rejected",
            message="The write capability is not statically admissible for sandbox drill collection.",
            exit_code=5,
        )
    try:
        config = load_write_runtime_config(write_runtime_config)
    except WriteRuntimeError as exc:
        raise CliFailure(
            command=command,
            code="write_runtime_rejected",
            message="The write runtime is not a valid staged sandbox configuration.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.base_runtime.release_root, command=command)
    _assert_runtime_release(config.base_runtime, identity, command=command)
    database_name = config.base_runtime.database_name
    if (
        config.write_execution_mode != "sandbox_staged"
        or config.base_runtime.environment != "sandbox"
        or config.base_runtime.capability_channel != "staged"
        or re.search(r"(^|[_-])sandbox([_-]|$)", database_name) is None
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_scope_rejected",
            message="The write runtime is not bound to a clearly named staged sandbox database.",
            exit_code=5,
        )
    evidence_root_status = _validate_sandbox_write_evidence_root(
        evidence_root,
        release_root=config.base_runtime.release_root,
        minimum_free_bytes=min_free_bytes,
    )
    preflight_manifest = {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-preflight.v1",
        "capability_id": capability_id,
        "company_id": company_id,
        "database_name": database_name,
        "database_uuid": config.base_runtime.database_uuid,
        "environment": config.base_runtime.environment,
        "evidence_root": evidence_root_status,
        "production_promotion_allowed": False,
        "readiness_report": readiness_report,
        "readiness_report_sha256": _sha256_json(readiness_report),
        "real_odoo_write_performed": False,
        "registry_digest": identity["registry_digest"],
        "release_identity": {
            "commit": identity["commit"],
            "manifest_sha256": identity["manifest_sha256"],
            "package_sha256": identity["package_sha256"],
            "release": identity["release"],
        },
        "runtime": config.runtime_identity,
        "write_execution_mode": config.write_execution_mode,
    }
    _success(
        command,
        {
            "capability_id": capability_id,
            "company_id": company_id,
            "database_name": database_name,
            "evidence_root": evidence_root_status,
            "preflight_manifest": preflight_manifest,
            "preflight_manifest_sha256": _sha256_json(preflight_manifest),
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": identity,
            "runtime": config.runtime_identity,
            "sandbox_write_evidence_collection_admissible": True,
        },
        business_succeeded=False,
    )


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
        rejection_code = (
            exc.rejection_code
            if config.environment == "test"
            and config.capability_channel == "staged"
            else None
        )
        raise CliFailure(
            command="read",
            code="odoo_read_failed",
            message="The authenticated Odoo read did not produce a verified result.",
            exit_code=6,
            rejection_code=rejection_code,
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
