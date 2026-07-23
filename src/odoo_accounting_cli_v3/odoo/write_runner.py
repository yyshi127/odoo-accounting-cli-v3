"""Sealed Odoo-shell transport for prechecked and approved accounting writes.

Only fixed, parent-selected actions cross this boundary.  Requests and the
minimum action-specific key material are carried in a sealed private file
descriptor; neither is placed in argv or the child environment.
"""

from __future__ import annotations

import base64
import hmac
import json
import math
import os
import secrets as secret_tokens
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..auth import authentication_request_digest, verify_request_context
from ..effect_finalizer_runtime import EffectFinalizerClientRuntime
from ..operations import canonical_json
from ..registry import Capability, registry_digest
from ..write_runtime import (
    WRITE_EXECUTION_MODES,
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRoleConfig,
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
)
from .bootstrap import (
    bind_non_superuser_environment,
    database_uuid,
    request_context_from_mapping,
)
from .runner import (
    MARKER,
    MAX_PRIVATE_PAYLOAD_BYTES,
    MAX_TIMEOUT_SECONDS,
    SHA256,
    OdooRunnerError,
    RuntimeConfig,
    _absolute_path,
    _load_json_object,
    _normalize_request_json,
    _private_payload_fd,
    _run_child_process,
    _safe_environment,
    _strict_text,
    _validate_canonical_package_binding,
    _validate_runtime_paths,
    _verify_child_release,
)
from .write_bootstrap import APPROVER_GROUP, execute_write_from_odoo_shell
from .write_precheck import execute_write_precheck_from_odoo_shell


WRITE_CHILD_PROTOCOL_VERSION = 1
ACTION_PRECHECK = "write_precheck"
ACTION_EXECUTOR = "authorize_executor"
ACTION_APPROVER = "authorize_approver"
ACTION_APPROVED_WRITE = "approved_write"
WRITE_ACTIONS = frozenset(
    {ACTION_PRECHECK, ACTION_EXECUTOR, ACTION_APPROVER, ACTION_APPROVED_WRITE}
)

WRITE_RUNTIME_IDENTITY_FIELDS = frozenset(
    {
        "instance_id",
        "environment",
        "capability_channel",
        "database_name",
        "database_uuid",
        "write_execution_mode",
        "write_runtime_schema_version",
        "write_runtime_config_sha256",
    }
)
PAYLOAD_FIELDS = frozenset(
    {
        "protocol",
        "action",
        "runtime",
        "request_json",
        "credentials",
        "release_digest",
        "canonical_package_path",
        "canonical_package_sha256",
        "release_root",
        "module_guard",
    }
)
RESPONSE_FIELDS = frozenset({"ok", "action", "runtime", "result"})
CREDENTIAL_FIELDS = frozenset({"key_id", "secret"})
ISSUER_CREDENTIAL_FIELDS = frozenset({"issuer", "key_id", "secret"})
ACTION_CREDENTIAL_ROLES = {
    ACTION_PRECHECK: ("write_auth",),
    ACTION_EXECUTOR: ("write_auth",),
    ACTION_APPROVER: ("write_auth",),
    ACTION_APPROVED_WRITE: (
        "write_auth",
        "approval",
        "execution",
        "verification",
    ),
}

MODULE_GUARDED_ACTIONS = frozenset({ACTION_PRECHECK, ACTION_APPROVED_WRITE})
MODULE_GUARD_LOCK_TIMEOUT_MS = 3_000


def acquire_module_guard(
    base_runtime: RuntimeConfig,
    *,
    timeout_seconds: float,
    lock_timeout_ms: int,
) -> Any:
    """Late-bind the Linux-only guard so local imports remain side-effect free."""

    from .module_guard import acquire_module_guard as acquire

    return acquire(
        base_runtime,
        timeout_seconds=timeout_seconds,
        lock_timeout_ms=lock_timeout_ms,
    )
ISSUER_ROLES = frozenset({"execution", "verification"})
RUNTIME_ROLE_NAMES = (
    "write_auth",
    "approval",
    "execution",
    "verification",
    "recovery",
    "write_receipt",
)
RUNTIME_ISSUER_ROLES = frozenset({"execution", "verification", "recovery"})
PRECHECK_RESULT_FIELDS = frozenset(
    {
        "capability_id",
        "company_id",
        "parameters_digest",
        "passed",
        "checks",
        "handler_details",
        "runtime_binding",
        "registry_digest",
        "release_digest",
    }
)
APPROVER_REQUEST_FIELDS = frozenset({"context", "capability_id", "parameters"})
APPROVER_PARAMETERS_FIELDS = frozenset({"approver_user_id", "company_id"})
APPROVER_RESULT_FIELDS = frozenset(
    {
        "authorized",
        "approver_user_id",
        "company_id",
        "capability_id",
        "runtime_binding",
        "registry_digest",
        "release_digest",
    }
)
EXECUTOR_RESULT_FIELDS = frozenset(
    {
        "authorized",
        "user_id",
        "company_id",
        "capability_id",
        "missing_groups",
        "runtime_binding",
        "registry_digest",
        "release_digest",
    }
)
APPROVED_RESULT_FIELDS = frozenset(
    {"execution", "verification", "reconciliation_only"}
)
RESULT_PART_FIELDS = frozenset({"result", "evidence"})
MIN_SECRET_BYTES = 32
MAX_SECRET_BYTES = 4096


def _mode_binding(
    mode: Any, environment: Any, capability_channel: Any, action: str
) -> None:
    if action not in WRITE_ACTIONS:
        raise OdooRunnerError("write action is invalid")
    if mode not in WRITE_EXECUTION_MODES:
        raise OdooRunnerError("write execution mode is invalid")
    if mode == "disabled":
        if action in {ACTION_EXECUTOR, ACTION_APPROVER}:
            return
        raise OdooRunnerError("Odoo accounting writes are disabled")
    if mode == "sandbox_staged" and (
        environment != "sandbox" or capability_channel != "staged"
    ):
        raise OdooRunnerError("sandbox-staged write runtime binding is invalid")
    if mode == "enabled" and capability_channel != "enabled":
        raise OdooRunnerError("enabled write runtime binding is invalid")


def _validate_parent_inputs(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    release_digest: str,
    timeout_seconds: float,
    action: str,
) -> None:
    if not isinstance(config, WriteRuntimeConfig):
        raise OdooRunnerError("a validated write runtime configuration is required")
    if not isinstance(secrets, WriteRuntimeSecrets):
        raise OdooRunnerError("validated write runtime secrets are required")
    if config.schema_version != WRITE_RUNTIME_SCHEMA_VERSION:
        raise OdooRunnerError("write runtime schema version is invalid")
    if not isinstance(config.effect_finalizer, EffectFinalizerClientRuntime):
        raise OdooRunnerError("effect finalizer runtime is invalid")
    if not isinstance(config.base_runtime, RuntimeConfig):
        raise OdooRunnerError("validated base runtime configuration is required")
    if (
        not isinstance(config.config_fingerprint, str)
        or SHA256.fullmatch(config.config_fingerprint) is None
    ):
        raise OdooRunnerError("write runtime configuration fingerprint is invalid")
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("release_digest must be a lowercase SHA-256 digest")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise OdooRunnerError(
            f"timeout_seconds must be positive and no greater than {MAX_TIMEOUT_SECONDS:g}"
        )
    _mode_binding(
        config.write_execution_mode,
        config.base_runtime.environment,
        config.base_runtime.capability_channel,
        action,
    )
    key_ids: list[str] = []
    issuers: list[str] = []
    materials: list[bytes] = []
    for role_name in RUNTIME_ROLE_NAMES:
        role = getattr(config, role_name, None)
        material = getattr(secrets, role_name, None)
        if not isinstance(role, WriteRoleConfig):
            raise OdooRunnerError(f"{role_name} write role is invalid")
        key_ids.append(_strict_text(role.key_id, f"{role_name}.key_id"))
        if role_name in RUNTIME_ISSUER_ROLES:
            issuers.append(_strict_text(role.issuer, f"{role_name}.issuer"))
        elif role.issuer is not None:
            raise OdooRunnerError(f"{role_name}.issuer is forbidden")
        if (
            not isinstance(material, bytes)
            or not MIN_SECRET_BYTES <= len(material) <= MAX_SECRET_BYTES
        ):
            raise OdooRunnerError(f"{role_name} secret is invalid")
        materials.append(material)
    if len(set(key_ids)) != len(key_ids) or len(set(issuers)) != len(issuers):
        raise OdooRunnerError("write runtime role identities are not distinct")
    for index, left in enumerate(materials):
        if any(hmac.compare_digest(left, right) for right in materials[index + 1 :]):
            raise OdooRunnerError("write runtime secrets are not distinct")


def _credential(role: WriteRoleConfig, material: bytes) -> dict[str, str]:
    value = {
        "key_id": role.key_id,
        "secret": base64.b64encode(material).decode("ascii"),
    }
    if role.issuer is not None:
        value["issuer"] = role.issuer
    return value


def _credentials(
    config: WriteRuntimeConfig, secrets: WriteRuntimeSecrets, action: str
) -> dict[str, dict[str, str]]:
    return {
        role_name: _credential(
            getattr(config, role_name), getattr(secrets, role_name)
        )
        for role_name in ACTION_CREDENTIAL_ROLES[action]
    }


def _write_child_source(
    config: RuntimeConfig, payload_fd: int, marker: str, action: str
) -> str:
    source_root = str(config.release_root / "src")
    return (
        "import sys\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "from odoo_accounting_cli_v3.odoo.write_runner import _write_child_main\n"
        f"_write_child_main(env, {payload_fd!r}, {marker!r}, {action!r})\n"
    )


def _validate_result_part(value: Any, label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != RESULT_PART_FIELDS:
        raise OdooRunnerError(f"{label} response fields are invalid")
    if not isinstance(value["result"], Mapping) or not isinstance(
        value["evidence"], Mapping
    ):
        raise OdooRunnerError(f"{label} response content is invalid")


def _validate_action_result(action: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OdooRunnerError("Odoo shell write result must be an object")
    if action == ACTION_PRECHECK:
        if set(value) != PRECHECK_RESULT_FIELDS or value.get("passed") is not True:
            raise OdooRunnerError("Odoo shell precheck result fields are invalid")
    elif action == ACTION_APPROVER:
        if (
            set(value) != APPROVER_RESULT_FIELDS
            or type(value.get("authorized")) is not bool
        ):
            raise OdooRunnerError("Odoo shell approver result fields are invalid")
    elif action == ACTION_EXECUTOR:
        if (
            set(value) != EXECUTOR_RESULT_FIELDS
            or type(value.get("authorized")) is not bool
            or not isinstance(value.get("missing_groups"), list)
        ):
            raise OdooRunnerError("Odoo shell executor result fields are invalid")
    elif action == ACTION_APPROVED_WRITE:
        if (
            set(value) != APPROVED_RESULT_FIELDS
            or type(value.get("reconciliation_only")) is not bool
        ):
            raise OdooRunnerError("Odoo shell approved-write result fields are invalid")
        _validate_result_part(value["execution"], "execution")
        verification = value["verification"]
        if verification is not None:
            _validate_result_part(verification, "verification")
    else:  # Defensive: public callers never accept an action argument.
        raise OdooRunnerError("write action is invalid")
    return value


def _parse_write_response(
    stdout: Any, marker: str, config: WriteRuntimeConfig, action: str
) -> dict[str, Any]:
    if not isinstance(stdout, str) or stdout.count(marker) != 1:
        raise OdooRunnerError("Odoo shell did not emit exactly one write result marker")
    marked_lines = [line for line in stdout.splitlines() if line.startswith(marker)]
    if len(marked_lines) != 1:
        raise OdooRunnerError("Odoo shell write result marker is not on a dedicated line")
    response = _load_json_object(
        marked_lines[0][len(marker) :], "Odoo shell write response"
    )
    if (
        set(response) != RESPONSE_FIELDS
        or response.get("ok") is not True
        or response.get("action") != action
    ):
        raise OdooRunnerError("Odoo shell write response fields are invalid")
    runtime = response.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != WRITE_RUNTIME_IDENTITY_FIELDS:
        raise OdooRunnerError("Odoo shell write runtime identity is invalid")
    if runtime != config.runtime_identity:
        raise OdooRunnerError(
            "Odoo shell write runtime identity does not match configuration"
        )
    return _validate_action_result(action, response.get("result"))


def _run_odoo_write_action(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    request: dict[str, Any] | str,
    *,
    action: str,
    release_digest: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    _validate_parent_inputs(
        config, secrets, release_digest, timeout_seconds, action
    )
    request_json = _normalize_request_json(request)
    base = config.base_runtime
    _validate_canonical_package_binding(base)
    _verify_child_release(
        base.release_root,
        release_digest,
        base.canonical_package_path,
        base.canonical_package_sha256,
    )
    _validate_runtime_paths(base)
    marker = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{secret_tokens.token_hex(24)}__:"
    if MARKER.fullmatch(marker) is None:
        raise OdooRunnerError("write result marker generation failed")
    argv = [
        str(base.odoo_python),
        str(base.odoo_bin),
        "shell",
        "-c",
        str(base.odoo_config),
        "-d",
        base.database_name,
        "--no-http",
    ]
    deadline = time.monotonic() + float(timeout_seconds)

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise OdooRunnerError("Odoo shell write action timed out")
        return value

    guard = None
    try:
        if action in MODULE_GUARDED_ACTIONS:
            acquisition_timeout = remaining()
            guard = acquire_module_guard(
                base,
                timeout_seconds=acquisition_timeout,
                lock_timeout_ms=min(
                    MODULE_GUARD_LOCK_TIMEOUT_MS,
                    max(1, math.floor(acquisition_timeout * 1_000)),
                ),
            )
        if guard is None:
            guard_evidence = None
        else:
            raw_guard_evidence = guard.evidence
            if not isinstance(raw_guard_evidence, Mapping):
                raise OdooRunnerError("module guard evidence is invalid")
            guard_evidence = json.loads(canonical_json(raw_guard_evidence))
        payload = canonical_json(
            {
                "protocol": WRITE_CHILD_PROTOCOL_VERSION,
                "action": action,
                "runtime": config.runtime_identity,
                "request_json": request_json,
                "credentials": _credentials(config, secrets, action),
                "release_digest": release_digest,
                "canonical_package_path": str(base.canonical_package_path),
                "canonical_package_sha256": base.canonical_package_sha256,
                "release_root": str(base.release_root),
                "module_guard": guard_evidence,
            }
        )
        with _private_payload_fd(payload) as payload_fd:
            completed = _run_child_process(
                argv,
                source=_write_child_source(base, payload_fd, marker, action),
                payload_fd=payload_fd,
                timeout_seconds=remaining(),
                cwd=str(base.release_root),
                env=_safe_environment(base),
            )
        if completed.returncode != 0:
            raise OdooRunnerError(
                f"Odoo shell write action exited with status {completed.returncode}"
            )
        result = _parse_write_response(completed.stdout, marker, config, action)
        if guard is not None:
            final_evidence = guard.final_probe(timeout_seconds=remaining())
            if canonical_json(final_evidence) != canonical_json(guard_evidence):
                raise OdooRunnerError("module guard final evidence changed")
            guard.release(timeout_seconds=remaining())
            guard = None
        return result
    finally:
        if guard is not None:
            try:
                guard.abort()
            except BaseException:
                pass


def run_odoo_write_precheck(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    request: dict[str, Any] | str,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Execute one fixed read-only Odoo write precheck."""

    return _run_odoo_write_action(
        config,
        secrets,
        request,
        action=ACTION_PRECHECK,
        release_digest=release_digest,
        timeout_seconds=timeout_seconds,
    )


def run_odoo_authorize_approver(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    request: dict[str, Any] | str,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Read an approver's current company and group authorization from Odoo."""

    return _run_odoo_write_action(
        config,
        secrets,
        request,
        action=ACTION_APPROVER,
        release_digest=release_digest,
        timeout_seconds=timeout_seconds,
    )


def run_odoo_authorize_executor(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    request: dict[str, Any] | str,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Read the requester's current company and capability ACL from Odoo."""

    return _run_odoo_write_action(
        config,
        secrets,
        request,
        action=ACTION_EXECUTOR,
        release_digest=release_digest,
        timeout_seconds=timeout_seconds,
    )


def run_odoo_approved_write(
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
    request: dict[str, Any] | str,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Execute one fixed approved write and return its anchored phase evidence."""

    return _run_odoo_write_action(
        config,
        secrets,
        request,
        action=ACTION_APPROVED_WRITE,
        release_digest=release_digest,
        timeout_seconds=timeout_seconds,
    )


def _read_child_payload(payload_fd: int) -> dict[str, Any]:
    if isinstance(payload_fd, bool) or not isinstance(payload_fd, int) or payload_fd <= 2:
        raise OdooRunnerError("write child payload is invalid")
    try:
        with os.fdopen(payload_fd, "rb", closefd=True) as stream:
            payload_bytes = stream.read(MAX_PRIVATE_PAYLOAD_BYTES + 1)
        if not payload_bytes or len(payload_bytes) > MAX_PRIVATE_PAYLOAD_BYTES:
            raise OdooRunnerError("write child payload is invalid")
        payload = _load_json_object(
            payload_bytes.decode("utf-8"), "write child payload"
        )
    except OdooRunnerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OdooRunnerError("write child payload is invalid") from exc
    if (
        set(payload) != PAYLOAD_FIELDS
        or payload.get("protocol") != WRITE_CHILD_PROTOCOL_VERSION
    ):
        raise OdooRunnerError("write child payload fields are invalid")
    action = payload.get("action")
    module_guard = payload.get("module_guard")
    if (
        action in MODULE_GUARDED_ACTIONS
        and not isinstance(module_guard, dict)
    ) or (
        action not in MODULE_GUARDED_ACTIONS
        and module_guard is not None
    ):
        raise OdooRunnerError("write child module guard binding is invalid")
    if action in MODULE_GUARDED_ACTIONS:
        from .module_guard import ModuleGuardError, ModuleGuardEvidence

        try:
            payload["module_guard"] = ModuleGuardEvidence.from_mapping(
                module_guard
            ).as_dict()
        except ModuleGuardError as exc:
            raise OdooRunnerError(
                "write child module guard evidence is invalid"
            ) from exc
    return payload


def _child_runtime(
    payload: Mapping[str, Any], expected_action: str
) -> tuple[dict[str, Any], RuntimeConfig]:
    action = payload.get("action")
    if action != expected_action or action not in WRITE_ACTIONS:
        raise OdooRunnerError("write child action binding mismatch")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != WRITE_RUNTIME_IDENTITY_FIELDS:
        raise OdooRunnerError("write child runtime identity is invalid")
    if (
        runtime.get("write_runtime_schema_version")
        != WRITE_RUNTIME_SCHEMA_VERSION
        or not isinstance(runtime.get("write_runtime_config_sha256"), str)
        or SHA256.fullmatch(runtime["write_runtime_config_sha256"]) is None
    ):
        raise OdooRunnerError("write child runtime identity is invalid")
    _mode_binding(
        runtime.get("write_execution_mode"),
        runtime.get("environment"),
        runtime.get("capability_channel"),
        action,
    )
    release_root = _absolute_path(payload.get("release_root"), "release_root")
    base = RuntimeConfig(
        instance_id=runtime["instance_id"],
        environment=runtime["environment"],
        capability_channel=runtime["capability_channel"],
        database_name=runtime["database_name"],
        database_uuid=runtime["database_uuid"],
        odoo_python=release_root / ".unused-odoo-python",
        odoo_python_sha256="0" * 64,
        odoo_bin=release_root / ".unused-odoo-bin",
        odoo_bin_sha256="0" * 64,
        odoo_config=release_root / ".unused-odoo.conf",
        odoo_config_sha256="0" * 64,
        release_root=release_root,
        canonical_package_path=_absolute_path(
            payload.get("canonical_package_path"), "canonical_package_path"
        ),
        canonical_package_sha256=payload.get("canonical_package_sha256"),
        auth_state_path=release_root / ".unused-read-auth-state",
        receipt_state_path=release_root / ".unused-read-receipt-state",
        auth_key_id="unused-read-auth",
        receipt_key_id="unused-read-receipt",
        auth_secret_path=release_root / ".unused-read-auth-secret",
        receipt_secret_path=release_root / ".unused-read-receipt-secret",
    )
    if base.runtime_identity != {
        key: runtime[key]
        for key in base.runtime_identity
    }:
        raise OdooRunnerError("write child base runtime identity is invalid")
    return runtime, base


def _decode_credential(
    credentials: Mapping[str, Any], role_name: str
) -> tuple[bytes, str, str | None]:
    value = credentials.get(role_name)
    fields = ISSUER_CREDENTIAL_FIELDS if role_name in ISSUER_ROLES else CREDENTIAL_FIELDS
    if not isinstance(value, Mapping) or set(value) != fields:
        raise OdooRunnerError(f"write child {role_name} credential is invalid")
    key_id = _strict_text(value.get("key_id"), f"{role_name}.key_id")
    issuer = (
        _strict_text(value.get("issuer"), f"{role_name}.issuer")
        if role_name in ISSUER_ROLES
        else None
    )
    encoded = value.get("secret")
    if not isinstance(encoded, str) or not encoded:
        raise OdooRunnerError(f"write child {role_name} credential is invalid")
    try:
        material = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as exc:
        raise OdooRunnerError(
            f"write child {role_name} credential is invalid"
        ) from exc
    if not MIN_SECRET_BYTES <= len(material) <= MAX_SECRET_BYTES:
        raise OdooRunnerError(f"write child {role_name} credential is invalid")
    return material, key_id, issuer


def _decode_credentials(
    payload: Mapping[str, Any], action: str
) -> dict[str, tuple[bytes, str, str | None]]:
    credentials = payload.get("credentials")
    roles = ACTION_CREDENTIAL_ROLES[action]
    if not isinstance(credentials, Mapping) or set(credentials) != set(roles):
        raise OdooRunnerError("write child credential roles are invalid")
    return {
        role_name: _decode_credential(credentials, role_name)
        for role_name in roles
    }


def _child_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    request_json = payload.get("request_json")
    if not isinstance(request_json, str):
        raise OdooRunnerError("write child request is invalid")
    normalized = _normalize_request_json(request_json)
    if normalized != request_json:
        raise OdooRunnerError("write child request is not canonical JSON")
    return _load_json_object(request_json, "write child request")


def _assert_actual_database(root_env: Any, runtime: Mapping[str, Any]) -> None:
    actual_name = getattr(getattr(root_env, "cr", None), "dbname", None)
    actual_uuid = database_uuid(root_env)
    if (
        actual_name != runtime["database_name"]
        or actual_uuid != runtime["database_uuid"]
    ):
        raise OdooRunnerError("write child Odoo database identity mismatch")


def _execute_authorize_approver(
    root_env: Any,
    request: Any,
    *,
    capabilities: tuple[Capability, ...],
    auth_secret: bytes,
    auth_key_id: str,
    release_digest: str,
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(request, Mapping) or set(request) != APPROVER_REQUEST_FIELDS:
        raise OdooRunnerError("approver authorization request fields are invalid")
    capability_id = request.get("capability_id")
    parameters = request.get("parameters")
    if (
        not isinstance(capability_id, str)
        or not capability_id.strip()
        or not isinstance(parameters, Mapping)
        or set(parameters) != APPROVER_PARAMETERS_FIELDS
    ):
        raise OdooRunnerError("approver authorization request is invalid")
    approver_user_id = parameters.get("approver_user_id")
    company_id = parameters.get("company_id")
    if (
        isinstance(approver_user_id, bool)
        or not isinstance(approver_user_id, int)
        or approver_user_id <= 0
        or isinstance(company_id, bool)
        or not isinstance(company_id, int)
        or company_id <= 0
    ):
        raise OdooRunnerError("approver authorization identifiers are invalid")
    context = request_context_from_mapping(request.get("context"))
    if (
        context.company_id != company_id
        or company_id not in context.allowed_company_ids
        or context.odoo_instance_id != runtime["instance_id"]
        or context.database_name != runtime["database_name"]
        or context.database_uuid != runtime["database_uuid"]
        or context.environment != runtime["environment"]
    ):
        raise OdooRunnerError("approver authorization runtime binding mismatch")
    verify_request_context(
        context,
        now=datetime.now(timezone.utc),
        secret=auth_secret,
        expected_key_id=auth_key_id,
    )
    expected_request_digest = authentication_request_digest(
        capability_id, dict(parameters)
    )
    if not hmac.compare_digest(
        context.auth_request_digest, expected_request_digest
    ):
        raise OdooRunnerError("signed approver authorization digest mismatch")
    matches = [item for item in capabilities if item.id == capability_id]
    if len(matches) != 1 or matches[0].data.get("access") != "write":
        raise OdooRunnerError("approver authorization capability is invalid")
    bound_env = bind_non_superuser_environment(root_env, context)
    approver = bound_env["res.users"].browse(approver_user_id).exists()
    authorized = bool(
        approver
        and len(approver) == 1
        and approver.active
        and company_id in approver.company_ids.ids
        and approver.has_group(APPROVER_GROUP)
    )
    return {
        "authorized": authorized,
        "approver_user_id": approver_user_id,
        "company_id": company_id,
        "capability_id": capability_id,
        "runtime_binding": {
            "odoo_instance_id": runtime["instance_id"],
            "database_name": runtime["database_name"],
            "database_uuid": runtime["database_uuid"],
            "environment": runtime["environment"],
            "capability_channel": runtime["capability_channel"],
        },
        "registry_digest": registry_digest(capabilities),
        "release_digest": release_digest,
    }


def _execute_authorize_executor(
    root_env: Any,
    request: Any,
    *,
    capabilities: tuple[Capability, ...],
    auth_secret: bytes,
    auth_key_id: str,
    release_digest: str,
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(request, Mapping) or set(request) != APPROVER_REQUEST_FIELDS:
        raise OdooRunnerError("executor authorization request fields are invalid")
    capability_id = request.get("capability_id")
    parameters = request.get("parameters")
    if (
        not isinstance(capability_id, str)
        or not capability_id.strip()
        or not isinstance(parameters, Mapping)
    ):
        raise OdooRunnerError("executor authorization request is invalid")
    context = request_context_from_mapping(request.get("context"))
    if (
        context.company_id not in context.allowed_company_ids
        or parameters.get("company_id") != context.company_id
        or context.odoo_instance_id != runtime["instance_id"]
        or context.database_name != runtime["database_name"]
        or context.database_uuid != runtime["database_uuid"]
        or context.environment != runtime["environment"]
    ):
        raise OdooRunnerError("executor authorization runtime binding mismatch")
    verify_request_context(
        context,
        now=datetime.now(timezone.utc),
        secret=auth_secret,
        expected_key_id=auth_key_id,
    )
    expected_request_digest = authentication_request_digest(
        capability_id, dict(parameters)
    )
    if not hmac.compare_digest(
        context.auth_request_digest, expected_request_digest
    ):
        raise OdooRunnerError("signed executor authorization digest mismatch")
    matches = [item for item in capabilities if item.id == capability_id]
    if len(matches) != 1 or matches[0].data.get("access") != "write":
        raise OdooRunnerError("executor authorization capability is invalid")
    capability = matches[0]
    bound_env = bind_non_superuser_environment(root_env, context)
    user = bound_env.user
    required_groups = sorted(
        {"odoo_accounting_cli_v3_control.group_executor", *capability.data["odoo_permissions"]}
    )
    missing_groups = [group for group in required_groups if not user.has_group(group)]
    authorized = bool(
        getattr(user, "id", None) == getattr(bound_env, "uid", None) == context.user_id
        and user.active
        and context.company_id in user.company_ids.ids
        and not missing_groups
    )
    return {
        "authorized": authorized,
        "user_id": context.user_id,
        "company_id": context.company_id,
        "capability_id": capability_id,
        "missing_groups": missing_groups,
        "runtime_binding": {
            "odoo_instance_id": runtime["instance_id"],
            "database_name": runtime["database_name"],
            "database_uuid": runtime["database_uuid"],
            "environment": runtime["environment"],
            "capability_channel": runtime["capability_channel"],
        },
        "registry_digest": registry_digest(capabilities),
        "release_digest": release_digest,
    }


def _write_child_main(
    root_env: Any, payload_fd: int, marker: str, expected_action: str
) -> None:
    """Odoo-shell entrypoint for one parent-selected write action."""

    if not isinstance(marker, str) or MARKER.fullmatch(marker) is None:
        raise OdooRunnerError("write child result marker is invalid")
    if expected_action not in WRITE_ACTIONS:
        raise OdooRunnerError("write child expected action is invalid")
    payload = _read_child_payload(payload_fd)
    runtime, base = _child_runtime(payload, expected_action)
    release_root = base.release_root.resolve()
    if Path(__file__).resolve().parents[3] != release_root:
        raise OdooRunnerError("write child code is not loaded from the configured release")
    release_digest = payload.get("release_digest")
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("write child release digest is invalid")
    _validate_canonical_package_binding(base)
    capabilities = tuple(
        _verify_child_release(
            release_root,
            release_digest,
            base.canonical_package_path,
            base.canonical_package_sha256,
        )
    )
    if not capabilities or any(not isinstance(item, Capability) for item in capabilities):
        raise OdooRunnerError("write child registry is invalid")
    _assert_actual_database(root_env, runtime)
    request = _child_request(payload)
    credentials = _decode_credentials(payload, expected_action)
    write_auth_secret, write_auth_key_id, _ = credentials["write_auth"]

    if expected_action == ACTION_PRECHECK:
        result = execute_write_precheck_from_odoo_shell(
            root_env,
            request,
            capabilities=capabilities,
            auth_secret=write_auth_secret,
            auth_key_id=write_auth_key_id,
            expected_registry_digest=registry_digest(capabilities),
            release_digest=release_digest,
            odoo_instance_id=base.instance_id,
            environment=base.environment,
            capability_channel=base.capability_channel,
        )
    elif expected_action == ACTION_EXECUTOR:
        result = _execute_authorize_executor(
            root_env,
            request,
            capabilities=capabilities,
            auth_secret=write_auth_secret,
            auth_key_id=write_auth_key_id,
            release_digest=release_digest,
            runtime=runtime,
        )
    elif expected_action == ACTION_APPROVER:
        result = _execute_authorize_approver(
            root_env,
            request,
            capabilities=capabilities,
            auth_secret=write_auth_secret,
            auth_key_id=write_auth_key_id,
            release_digest=release_digest,
            runtime=runtime,
        )
    else:
        approval_secret, approval_key_id, _ = credentials["approval"]
        execution_secret, execution_key_id, execution_issuer = credentials[
            "execution"
        ]
        verification_secret, verification_key_id, verification_issuer = credentials[
            "verification"
        ]
        result = execute_write_from_odoo_shell(
            root_env,
            request,
            capabilities=capabilities,
            auth_secret=write_auth_secret,
            auth_key_id=write_auth_key_id,
            approval_secret=approval_secret,
            approval_key_id=approval_key_id,
            execution_secret=execution_secret,
            execution_key_id=execution_key_id,
            execution_issuer=execution_issuer,
            verification_secret=verification_secret,
            verification_key_id=verification_key_id,
            verification_issuer=verification_issuer,
            release_digest=release_digest,
            odoo_instance_id=base.instance_id,
            environment=base.environment,
            capability_channel=base.capability_channel,
        )
    detached = json.loads(canonical_json(_validate_action_result(expected_action, result)))
    response = {
        "ok": True,
        "action": expected_action,
        "runtime": runtime,
        "result": detached,
    }
    print(marker + canonical_json(response).decode("utf-8"), flush=True)


__all__ = [
    "run_odoo_approved_write",
    "run_odoo_authorize_approver",
    "run_odoo_authorize_executor",
    "run_odoo_write_precheck",
]
