"""Production composition root for the six Pi-facing write actions."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .auth import (
    context_payload,
    sign_request_context,
    verify_write_action_context,
)
from .contracts import ContractError, validate_value
from .effect_finalizer import EffectFinalizationError
from .effect_finalizer_runtime import EffectFinalizerClientRuntime
from .effect_finalizer_uds import (
    EffectFinalizerConnectedClient,
    EffectFinalizerUdsError,
    SystemdMainProcessPeerPolicy,
)
from .gateway import RequestContext
from .operations import Operation, State, canonical_json
from .persistence import SQLitePersistence
from .receipts import create_read_receipt
from .registry import Capability, load_registry, registry_digest
from .write_api import WriteApiRequest
from .write_protocol import (
    approved_write_authentication_parameters,
    approval_to_mapping,
    operation_to_mapping,
    trusted_result_from_mapping,
)
from .write_runtime import (
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
    load_write_runtime_config,
    load_write_runtime_secrets,
)
from .write_service import (
    BackendEvidence,
    BackendWriteOutcome,
    DurableWriteService,
    WriteServiceSecurity,
)
from .odoo.write_runner import (
    run_odoo_approved_write,
    run_odoo_authorize_approver,
    run_odoo_authorize_executor,
    run_odoo_write_precheck,
)
from .odoo.runner import load_runtime_secrets


WRITE_RUNTIME_CONFIG_PATH = Path(
    "/etc/odoo-accounting-cli-v3/write-runtime.json"
)
_TRUSTED_RUNTIME_CONFIG_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG"
)
_TRUSTED_RUNTIME_CONFIG_SHA256_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_SHA256"
)
_TRUSTED_RUNTIME_CONFIG_FD_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_FD"
)
_EXPECTED_RELEASE_DIGEST_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST"
)
_EXPECTED_REGISTRY_DIGEST_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST"
)
_EFFECT_FINALIZER_FD_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_EFFECT_FINALIZER_FD"
)
_TRUSTED_DEADLINE_MONOTONIC_ENV = (
    "ODOO_ACCOUNTING_CLI_V3_TRUSTED_DEADLINE_MONOTONIC"
)
_TRUSTED_RUNTIME_ENVIRONMENT = (
    _TRUSTED_RUNTIME_CONFIG_ENV,
    _TRUSTED_RUNTIME_CONFIG_SHA256_ENV,
    _TRUSTED_RUNTIME_CONFIG_FD_ENV,
    _EXPECTED_RELEASE_DIGEST_ENV,
    _EXPECTED_REGISTRY_DIGEST_ENV,
    _TRUSTED_DEADLINE_MONOTONIC_ENV,
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_TRUSTED_RUNTIME_CONFIG_BYTES = 65_536
# The Pi broker client has a fixed 120-second outer deadline.  Retain explicit
# margin for historical-child teardown, response verification, audit, and UDS
# serialization so an ordinary write cannot systematically finish after its
# caller has already reported an unknown outcome.
ODOO_WRITE_TIMEOUT_SECONDS = 90.0
# A successful approved write still has to cross the independent PostgreSQL
# finalizer, commit the local terminal receipt, and return through the
# historical router.  Never lend this tail budget to an Odoo subprocess.
POST_ODOO_LOCAL_MARGIN_SECONDS = 5.0
MIN_ODOO_CALL_TIMEOUT_SECONDS = 0.05
_MUTATING_ACTIONS = frozenset(
    {
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
        "operation.recover",
    }
)
_DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1"


class WriteApplicationError(ValueError):
    """Stable safe error consumed by the JSON CLI boundary."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        odoo_effect: str,
        operation_id: str | None = None,
        state: str | None = None,
        retryable: bool = False,
        exit_code: int = 3,
    ) -> None:
        super().__init__(message)
        if odoo_effect not in {"none", "unknown"}:
            raise ValueError("write application Odoo effect is invalid")
        self.code = code
        self.message = message
        self.odoo_effect = odoo_effect
        self.operation_id = operation_id
        self.state = state
        self.retryable = retryable
        self.exit_code = exit_code


def _trusted_runtime_error() -> WriteApplicationError:
    return WriteApplicationError(
        code="trusted_runtime_handoff_rejected",
        message="The historical write runtime handoff is invalid.",
        odoo_effect="none",
        exit_code=5,
    )


def _trusted_deadline_error() -> WriteApplicationError:
    return WriteApplicationError(
        code="trusted_deadline_exhausted",
        message="The trusted write request has no safe Odoo execution budget remaining.",
        odoo_effect="none",
        retryable=True,
    )


def _effect_finalizer_handoff_error() -> WriteApplicationError:
    return WriteApplicationError(
        code="effect_finalizer_handoff_rejected",
        message="The independent database finalizer handoff is invalid.",
        odoo_effect="none",
        exit_code=5,
    )


def _unavailable_effect_finalizer(_intent: Any) -> Any:
    raise EffectFinalizationError(
        "this write action has no independent finalizer channel"
    )


def _load_effect_finalizer_handoff(
    action: str,
    config: WriteRuntimeConfig,
    *,
    trusted_runtime_handoff: bool,
) -> tuple[Any, Any, EffectFinalizerConnectedClient | None]:
    runtime = getattr(config, "effect_finalizer", None)
    descriptor_value = os.environ.get(_EFFECT_FINALIZER_FD_ENV)
    if not isinstance(runtime, EffectFinalizerClientRuntime):
        raise _effect_finalizer_handoff_error()
    if action != "operation.approve_execute":
        if descriptor_value is not None:
            raise _effect_finalizer_handoff_error()
        return (
            _unavailable_effect_finalizer,
            runtime.finalization_identity,
            None,
        )
    if (
        not trusted_runtime_handoff
        or not isinstance(descriptor_value, str)
        or not descriptor_value.isascii()
        or not descriptor_value.isdecimal()
        or descriptor_value.startswith("0")
    ):
        raise _effect_finalizer_handoff_error()
    descriptor = int(descriptor_value)
    if descriptor < 3 or descriptor > 1_048_576:
        raise _effect_finalizer_handoff_error()
    try:
        client = EffectFinalizerConnectedClient.from_inherited_fd(
            descriptor,
            expected_identity=runtime.finalization_identity,
            response_sender_policy=SystemdMainProcessPeerPolicy(
                expected_uid=runtime.finalizer_service_uid,
                expected_gid=runtime.finalizer_service_gid,
                systemd_unit=runtime.finalizer_systemd_unit,
            ),
            request_io_timeout_seconds=runtime.request_io_timeout_seconds,
            max_request_bytes=runtime.max_request_bytes,
            max_response_bytes=runtime.max_response_bytes,
        )
    except (EffectFinalizerUdsError, OSError, ValueError) as exc:
        raise _effect_finalizer_handoff_error() from exc
    return client.finalize, runtime.finalization_identity, client


def _same_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(
        os.path.abspath(second)
    )


def _read_inherited_runtime_config(
    path: Path,
    descriptor: int,
    expected_digest: str,
) -> bytes:
    """Verify the router-opened config descriptor against its exact path.

    Environment values alone are intentionally insufficient: a historical
    child must inherit a read-only descriptor for the exact root-managed file
    selected and hash-checked by the router.
    """

    try:
        before = path.lstat()
        if (
            not path.is_absolute()
            or not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or not _same_path(path.resolve(strict=True), path)
        ):
            raise _trusted_runtime_error()
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise _trusted_runtime_error()
        if os.name == "posix":
            import fcntl

            access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            if access_mode != os.O_RDONLY:
                raise _trusted_runtime_error()
        offset = 0
        chunks: list[bytes] = []
        total = 0
        while True:
            if hasattr(os, "pread"):
                chunk = os.pread(descriptor, 4096, offset)
            else:  # pragma: no cover - production child runtime is POSIX.
                os.lseek(descriptor, offset, os.SEEK_SET)
                chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            offset += len(chunk)
            total += len(chunk)
            if total > _MAX_TRUSTED_RUNTIME_CONFIG_BYTES:
                raise _trusted_runtime_error()
            chunks.append(chunk)
        after = path.lstat()
        opened_after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        opened_identity = (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_size,
            opened_after.st_mtime_ns,
            opened_after.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or before_identity != opened_identity
            or not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
        ):
            raise _trusted_runtime_error()
        raw = b"".join(chunks)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_digest):
            raise _trusted_runtime_error()
        return raw
    except WriteApplicationError:
        raise
    except (OSError, ValueError) as exc:
        raise _trusted_runtime_error() from exc


def _select_write_runtime_config(
) -> tuple[
    Path,
    str | None,
    str | None,
    int | None,
    str | None,
    float | None,
]:
    values = {name: os.environ.get(name) for name in _TRUSTED_RUNTIME_ENVIRONMENT}
    present = {name for name, value in values.items() if value is not None}
    if not present:
        return WRITE_RUNTIME_CONFIG_PATH, None, None, None, None, None
    if present != set(_TRUSTED_RUNTIME_ENVIRONMENT):
        raise _trusted_runtime_error()

    path_value = values[_TRUSTED_RUNTIME_CONFIG_ENV]
    config_digest = values[_TRUSTED_RUNTIME_CONFIG_SHA256_ENV]
    descriptor_value = values[_TRUSTED_RUNTIME_CONFIG_FD_ENV]
    release_digest = values[_EXPECTED_RELEASE_DIGEST_ENV]
    registry_digest_value = values[_EXPECTED_REGISTRY_DIGEST_ENV]
    deadline_value = values[_TRUSTED_DEADLINE_MONOTONIC_ENV]
    if (
        not isinstance(path_value, str)
        or not path_value
        or "\x00" in path_value
        or len(path_value) > 4096
        or not isinstance(config_digest, str)
        or _SHA256.fullmatch(config_digest) is None
        or not isinstance(release_digest, str)
        or _SHA256.fullmatch(release_digest) is None
        or not isinstance(registry_digest_value, str)
        or _SHA256.fullmatch(registry_digest_value) is None
        or not isinstance(descriptor_value, str)
        or not descriptor_value.isascii()
        or not descriptor_value.isdecimal()
        or descriptor_value.startswith("0")
        or not isinstance(deadline_value, str)
        or not deadline_value
        or not deadline_value.isascii()
        or deadline_value != deadline_value.strip()
        or len(deadline_value) > 64
    ):
        raise _trusted_runtime_error()
    try:
        deadline_monotonic = float(deadline_value)
    except ValueError as exc:
        raise _trusted_runtime_error() from exc
    if (
        not math.isfinite(deadline_monotonic)
        or deadline_monotonic <= time.monotonic()
    ):
        raise _trusted_runtime_error()
    path = Path(path_value)
    if not path.is_absolute():
        raise _trusted_runtime_error()
    descriptor = int(descriptor_value)
    if descriptor < 3 or descriptor > 1_048_576:
        raise _trusted_runtime_error()
    _read_inherited_runtime_config(path, descriptor, config_digest)
    return (
        path,
        release_digest,
        registry_digest_value,
        descriptor,
        config_digest,
        deadline_monotonic,
    )


def _odoo_call_timeout(
    config: WriteRuntimeConfig,
    trusted_deadline_monotonic: float | None,
) -> float:
    if trusted_deadline_monotonic is None:
        return ODOO_WRITE_TIMEOUT_SECONDS
    runtime = getattr(config, "effect_finalizer", None)
    if not isinstance(runtime, EffectFinalizerClientRuntime):
        raise _effect_finalizer_handoff_error()
    remaining = (
        trusted_deadline_monotonic
        - time.monotonic()
        - runtime.request_io_timeout_seconds
        - POST_ODOO_LOCAL_MARGIN_SECONDS
    )
    if remaining <= MIN_ODOO_CALL_TIMEOUT_SECONDS:
        raise _trusted_deadline_error()
    return min(ODOO_WRITE_TIMEOUT_SECONDS, remaining)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WriteApplicationError(
            code="invalid_backend_evidence",
            message=f"The trusted Odoo {label} is not an object.",
            odoo_effect="unknown",
        )
    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WriteApplicationError(
            code="invalid_backend_evidence",
            message=f"The trusted Odoo {label} is not canonical JSON.",
            odoo_effect="unknown",
        ) from exc
    if not isinstance(detached, dict):  # pragma: no cover - canonical invariant
        raise WriteApplicationError(
            code="invalid_backend_evidence",
            message=f"The trusted Odoo {label} is invalid.",
            odoo_effect="unknown",
        )
    return detached


def _context_mapping(context: RequestContext) -> dict[str, Any]:
    return {**context_payload(context), "auth_signature": context.auth_signature}


def _internal_context(
    external: RequestContext,
    *,
    capability_id: str,
    parameters: dict[str, Any],
    purpose: str,
    config: WriteRuntimeConfig,
    secrets: WriteRuntimeSecrets,
) -> RequestContext:
    issued_at = _utcnow()
    expires_at = min(
        external.auth_expires_at,
        issued_at + timedelta(minutes=5),
    )
    if expires_at <= issued_at:
        raise WriteApplicationError(
            code="authentication_expired",
            message="The authenticated write action expired before Odoo validation.",
            odoo_effect="none",
        )
    token_digest = hashlib.sha256(
        canonical_json(
            {
                "external_auth_token_id": external.auth_token_id,
                "capability_id": capability_id,
                "parameters": parameters,
                "purpose": purpose,
            }
        )
    ).hexdigest()
    return sign_request_context(
        auth_token_id=f"internal-{token_digest}",
        principal=external.principal,
        odoo_instance_id=external.odoo_instance_id,
        database_name=external.database_name,
        database_uuid=external.database_uuid,
        user_id=external.user_id,
        company_id=external.company_id,
        allowed_company_ids=external.allowed_company_ids,
        environment=external.environment,
        capability_id=capability_id,
        parameters=parameters,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=config.write_auth.key_id,
        secret=secrets.write_auth,
    )


def _load_verified_release_identity(config: WriteRuntimeConfig) -> dict[str, Any]:
    # Reuse the same externally anchored verifier as the read path so CLI,
    # runner and Odoo cannot silently select different same-version trees.
    try:
        from .cli import _assert_runtime_release, _load_release_identity
        from .odoo.runner import _validate_canonical_package_binding

        _validate_canonical_package_binding(config.base_runtime)
        identity = _load_release_identity(
            config.base_runtime.release_root,
            command="operation.runtime",
        )
        _assert_runtime_release(config.base_runtime, identity)
        return identity
    except Exception as exc:
        raise WriteApplicationError(
            code="write_release_rejected",
            message="The write runtime does not match one verified V3 release package.",
            odoo_effect="none",
            exit_code=5,
        ) from exc


def _assert_external_runtime(
    context: RequestContext, config: WriteRuntimeConfig
) -> None:
    base = config.base_runtime
    if (
        context.odoo_instance_id != base.instance_id
        or context.database_name != base.database_name
        or context.database_uuid != base.database_uuid
        or context.environment != base.environment
        or context.company_id not in context.allowed_company_ids
    ):
        raise WriteApplicationError(
            code="write_runtime_binding_mismatch",
            message="The signed write action does not match the configured Odoo runtime.",
            odoo_effect="none",
        )


def _operation_response(
    operation: Operation, *, next_action: str | None = None
) -> dict[str, Any]:
    result = {
        "operation_id": operation.operation_id,
        "operation_state": operation.state.value,
        "capability_id": operation.capability_id,
        "operation_revision": operation.revision,
        "operation_digest": operation.digest,
        "operation": operation_to_mapping(operation),
        "result_available": operation.state in {State.COMPLETED, State.FAILED},
    }
    if next_action is not None:
        result["next_action"] = next_action
    return result


def _next_action(operation: Operation) -> str:
    if operation.state in {State.PREPARED, State.PRECHECKED}:
        return "operation.preview"
    if operation.state in {
        State.AWAITING_APPROVAL,
        State.APPROVED,
        State.EXECUTING,
        State.VERIFYING,
    }:
        return "operation.approve_execute"
    if operation.state == State.RECOVERED:
        return "operation.diagnostics"
    return "operation.result"


def _expected_runtime_binding(config: WriteRuntimeConfig) -> dict[str, Any]:
    base = config.base_runtime
    return {
        "odoo_instance_id": base.instance_id,
        "database_name": base.database_name,
        "database_uuid": base.database_uuid,
        "environment": base.environment,
        "capability_channel": base.capability_channel,
    }


def _backend_evidence(value: Any, label: str) -> BackendEvidence:
    if not isinstance(value, dict) or set(value) != {"result", "evidence"}:
        raise WriteApplicationError(
            code="invalid_backend_evidence",
            message=f"The trusted Odoo {label} envelope is invalid.",
            odoo_effect="unknown",
        )
    try:
        result = trusted_result_from_mapping(value["result"])
    except Exception as exc:
        raise WriteApplicationError(
            code="invalid_backend_evidence",
            message=f"The trusted Odoo {label} signature envelope is invalid.",
            odoo_effect="unknown",
        ) from exc
    return BackendEvidence(
        result=result,
        evidence=_canonical_object(value["evidence"], f"{label} evidence"),
    )


def _operation_id(parsed: WriteApiRequest) -> str | None:
    field = (
        "recovery_operation_id"
        if parsed.action == "operation.recover"
        else "operation_id"
    )
    value = parsed.payload.get(field)
    return value if isinstance(value, str) else None


def _safe_state(store: SQLitePersistence | None, operation_id: str | None) -> str | None:
    if store is None or operation_id is None:
        return None
    try:
        return store.get_operation(operation_id).state.value
    except Exception:
        return None


def execute_write_action(
    action: str,
    parsed: WriteApiRequest,
) -> dict[str, Any]:
    """Execute one exact Pi action through the durable production composition."""

    if not isinstance(parsed, WriteApiRequest) or action != parsed.action:
        raise WriteApplicationError(
            code="invalid_write_action",
            message="The parsed write action binding is invalid.",
            odoo_effect="none",
        )
    operation_id = _operation_id(parsed)
    store: SQLitePersistence | None = None
    odoo_write_attempted = False
    finalizer_client: EffectFinalizerConnectedClient | None = None

    try:
        (
            runtime_config_path,
            expected_release_digest,
            expected_registry_digest,
            trusted_runtime_descriptor,
            trusted_runtime_digest,
            trusted_deadline_monotonic,
        ) = _select_write_runtime_config()
        config = load_write_runtime_config(runtime_config_path)
        if (
            trusted_runtime_descriptor is not None
            and trusted_runtime_digest is not None
        ):
            # Pin the path to the same open file again after the loader's own
            # validation, closing the only remaining replacement window.
            _read_inherited_runtime_config(
                runtime_config_path,
                trusted_runtime_descriptor,
                trusted_runtime_digest,
            )
        secrets = load_write_runtime_secrets(config)
        identity = _load_verified_release_identity(config)
        if (
            expected_release_digest is not None
            and (
                identity.get("manifest_sha256") != expected_release_digest
                or identity.get("registry_digest") != expected_registry_digest
            )
        ):
            raise _trusted_runtime_error()
        capabilities = load_registry(
            config.base_runtime.release_root / "registry" / "capabilities.json"
        )
        observed_registry_digest = registry_digest(capabilities)
        if (
            identity.get("registry_digest") != observed_registry_digest
            or (
                expected_registry_digest is not None
                and observed_registry_digest != expected_registry_digest
            )
        ):
            raise WriteApplicationError(
                code="write_registry_rejected",
                message="The write registry does not match the verified V3 release.",
                odoo_effect="none",
                exit_code=5,
            )
        _assert_external_runtime(parsed.context, config)
        (
            effect_finalizer,
            effect_finalizer_identity,
            finalizer_client,
        ) = _load_effect_finalizer_handoff(
            action,
            config,
            trusted_runtime_handoff=trusted_runtime_descriptor is not None,
        )

        def authenticate(context: RequestContext) -> bool:
            try:
                return verify_write_action_context(
                    context,
                    action=parsed.action,
                    request=parsed.signed_request,
                    now=_utcnow(),
                    secret=secrets.write_auth,
                    expected_key_id=config.write_auth.key_id,
                )
            except Exception as exc:
                raise WriteApplicationError(
                    code="write_action_authentication_failed",
                    message="The write action signature, lifetime, or content binding is invalid.",
                    odoo_effect="none",
                ) from exc

        authenticate(parsed.context)
        if config.write_execution_mode == "disabled" and action in _MUTATING_ACTIONS:
            raise WriteApplicationError(
                code="accounting_writes_disabled",
                message="Accounting write lifecycle mutations are disabled by runtime policy.",
                odoo_effect="none",
            )
        # The persistence receipt verifier is exclusively for read receipts.
        # Write receipts are release-pinned and verified by the write service
        # and Broker response verifier, so the shared write-state database must
        # not be bound to one release's write-receipt key.
        store = SQLitePersistence(config.write_state_path)
        availability_channel = (
            "staged"
            if config.write_execution_mode == "sandbox_staged"
            else config.base_runtime.capability_channel
        )
        release_digest = identity["manifest_sha256"]
        executor_acl_cache: dict[tuple[Any, ...], bool] = {}
        approver_acl_cache: dict[tuple[Any, ...], bool] = {}
        service_holder: list[DurableWriteService] = []

        def acl_check(
            context: RequestContext,
            capability: Capability,
            parameters: dict[str, Any] | None,
        ) -> bool:
            if parameters is None:
                return False
            parameter_digest = hashlib.sha256(canonical_json(parameters)).hexdigest()
            key = (
                context.user_id,
                context.company_id,
                capability.id,
                parameter_digest,
            )
            if key not in executor_acl_cache:
                internal = _internal_context(
                    context,
                    capability_id=capability.id,
                    parameters=parameters,
                    purpose="authorize_executor",
                    config=config,
                    secrets=secrets,
                )
                try:
                    result = run_odoo_authorize_executor(
                        config,
                        secrets,
                        {
                            "context": _context_mapping(internal),
                            "capability_id": capability.id,
                            "parameters": parameters,
                        },
                        release_digest=release_digest,
                        timeout_seconds=_odoo_call_timeout(
                            config, trusted_deadline_monotonic
                        ),
                    )
                except Exception as exc:
                    raise WriteApplicationError(
                        code="odoo_executor_acl_unavailable",
                        message="Odoo could not verify the executor ACL without writing.",
                        odoo_effect="none",
                        retryable=True,
                    ) from exc
                executor_acl_cache[key] = bool(
                    result.get("authorized") is True
                    and result.get("user_id") == context.user_id
                    and result.get("company_id") == context.company_id
                    and result.get("capability_id") == capability.id
                    and result.get("missing_groups") == []
                    and result.get("runtime_binding")
                    == _expected_runtime_binding(config)
                    and result.get("registry_digest") == registry_digest(capabilities)
                    and result.get("release_digest") == release_digest
                )
            return executor_acl_cache[key]

        def approver_authorized(
            approver_user_id: int,
            company_id: int,
            capability_id: str,
        ) -> bool:
            key = (approver_user_id, company_id, capability_id)
            if key not in approver_acl_cache:
                parameters = {
                    "approver_user_id": approver_user_id,
                    "company_id": company_id,
                }
                internal = _internal_context(
                    parsed.context,
                    capability_id=capability_id,
                    parameters=parameters,
                    purpose="authorize_approver",
                    config=config,
                    secrets=secrets,
                )
                try:
                    result = run_odoo_authorize_approver(
                        config,
                        secrets,
                        {
                            "context": _context_mapping(internal),
                            "capability_id": capability_id,
                            "parameters": parameters,
                        },
                        release_digest=release_digest,
                        timeout_seconds=_odoo_call_timeout(
                            config, trusted_deadline_monotonic
                        ),
                    )
                except Exception as exc:
                    raise WriteApplicationError(
                        code="odoo_approver_acl_unavailable",
                        message="Odoo could not verify the approver ACL without writing.",
                        odoo_effect="none",
                        retryable=True,
                    ) from exc
                approver_acl_cache[key] = bool(
                    result.get("authorized") is True
                    and result.get("approver_user_id") == approver_user_id
                    and result.get("company_id") == company_id
                    and result.get("capability_id") == capability_id
                    and result.get("runtime_binding")
                    == _expected_runtime_binding(config)
                    and result.get("registry_digest") == registry_digest(capabilities)
                    and result.get("release_digest") == release_digest
                )
            return approver_acl_cache[key]

        def precheck(
            context: RequestContext,
            capability: Capability,
            operation: Operation,
            expected_registry_digest: str,
            expected_release_digest: str,
        ) -> dict[str, Any]:
            trusted_plan = service_holder[0].trusted_recovery_plan(
                context, operation
            )
            internal = _internal_context(
                context,
                capability_id=capability.id,
                parameters=operation.parameters,
                purpose="write_precheck",
                config=config,
                secrets=secrets,
            )
            try:
                result = run_odoo_write_precheck(
                    config,
                    secrets,
                    {
                        "context": _context_mapping(internal),
                        "capability_id": capability.id,
                        "parameters": operation.parameters,
                        "trusted_recovery_plan": trusted_plan,
                    },
                    release_digest=expected_release_digest,
                    timeout_seconds=_odoo_call_timeout(
                        config, trusted_deadline_monotonic
                    ),
                )
            except Exception as exc:
                raise WriteApplicationError(
                    code="odoo_write_precheck_failed",
                    message="Odoo did not return a passing immutable write preview.",
                    odoo_effect="none",
                    retryable=True,
                ) from exc
            if result.get("registry_digest") != expected_registry_digest:
                raise WriteApplicationError(
                    code="odoo_write_precheck_mismatch",
                    message="The Odoo write preview registry binding is invalid.",
                    odoo_effect="none",
                )
            if (
                result.get("release_digest") != expected_release_digest
                or result.get("runtime_binding")
                != {
                    "user_id": context.user_id,
                    "odoo_instance_id": config.base_runtime.instance_id,
                    "database_name": config.base_runtime.database_name,
                    "database_uuid": config.base_runtime.database_uuid,
                    "environment": config.base_runtime.environment,
                    "capability_channel": config.base_runtime.capability_channel,
                }
            ):
                raise WriteApplicationError(
                    code="odoo_write_precheck_mismatch",
                    message="The Odoo write preview runtime or release binding is invalid.",
                    odoo_effect="none",
                )
            return _canonical_object(result, "write precheck")

        def combined_write(
            context: RequestContext,
            capability: Capability,
            operation: Operation,
            approval: Any,
            expected_registry_digest: str,
            expected_release_digest: str,
        ) -> BackendWriteOutcome:
            nonlocal odoo_write_attempted
            reconciliation_only = parsed.payload["reconciliation_only"]
            trusted_plan = service_holder[0].trusted_recovery_plan(
                context, operation
            )
            internal = _internal_context(
                context,
                capability_id=capability.id,
                parameters=approved_write_authentication_parameters(
                    operation.parameters, reconciliation_only
                ),
                purpose="approved_write",
                config=config,
                secrets=secrets,
            )
            timeout_seconds = _odoo_call_timeout(
                config, trusted_deadline_monotonic
            )
            odoo_write_attempted = True
            try:
                response = run_odoo_approved_write(
                    config,
                    secrets,
                    {
                        "context": _context_mapping(internal),
                        "operation": operation_to_mapping(operation),
                        "approval": approval_to_mapping(approval),
                        "trusted_recovery_plan": trusted_plan,
                        "reconciliation_only": reconciliation_only,
                    },
                    release_digest=expected_release_digest,
                    timeout_seconds=timeout_seconds,
                )
            except Exception as exc:
                raise WriteApplicationError(
                    code="odoo_write_outcome_unknown",
                    message="The approved Odoo write did not return a trusted anchored outcome.",
                    odoo_effect="unknown",
                    operation_id=operation.operation_id,
                    state=operation.state.value,
                    retryable=True,
                ) from exc
            if expected_registry_digest != registry_digest(capabilities):
                raise WriteApplicationError(
                    code="odoo_write_registry_mismatch",
                    message="The approved Odoo write registry binding changed.",
                    odoo_effect="unknown",
                    operation_id=operation.operation_id,
                )
            if response.get("reconciliation_only") is not reconciliation_only:
                raise WriteApplicationError(
                    code="odoo_write_reconciliation_mode_mismatch",
                    message="The Odoo reconciliation permission binding changed.",
                    odoo_effect="unknown",
                    operation_id=operation.operation_id,
                )
            execution = _backend_evidence(response.get("execution"), "execution")
            verification_value = response.get("verification")
            verification = (
                None
                if verification_value is None
                else _backend_evidence(verification_value, "verification")
            )
            return BackendWriteOutcome(
                execution=execution,
                verification=verification,
            )

        def unavailable_backend(*_args: Any, **_kwargs: Any) -> Any:
            raise WriteApplicationError(
                code="combined_odoo_backend_required",
                message="The atomic Odoo write and verification backend is required.",
                odoo_effect="unknown",
                operation_id=operation_id,
            )

        security = WriteServiceSecurity(
            approval_key_id=config.approval.key_id,
            approval_secret=secrets.approval,
            approval_ttl_seconds=900,
            execution_key_id=config.execution.key_id,
            execution_secret=secrets.execution,
            execution_issuers=frozenset({config.execution.issuer}),
            verification_key_id=config.verification.key_id,
            verification_secret=secrets.verification,
            verification_issuers=frozenset({config.verification.issuer}),
            receipt_key_id=config.write_receipt.key_id,
            receipt_secret=secrets.write_receipt,
        )
        service = DurableWriteService(
            capabilities,
            release_digest=release_digest,
            store=store,
            security=security,
            authenticate_context=authenticate,
            acl_check=acl_check,
            approver_authorized=approver_authorized,
            precheck_executor=precheck,
            write_executor=unavailable_backend,
            verification_executor=unavailable_backend,
            availability_channel=availability_channel,
            now=_utcnow,
            effect_finalizer=effect_finalizer,
            effect_finalizer_identity=effect_finalizer_identity,
            execute_and_verify=combined_write,
        )
        service_holder.append(service)
        payload = parsed.payload

        if action == "operation.prepare":
            operation = service.prepare(
                parsed.context,
                operation_id=payload["operation_id"],
                request_id=payload["request_id"],
                capability_id=payload["capability_id"],
                parameters=payload["parameters"],
            )
            return _operation_response(
                operation, next_action="operation.preview"
            )
        if action == "operation.preview":
            return service.preview(parsed.context, payload["operation_id"])
        if action == "operation.approve_execute":
            if parsed.approval is None:  # pragma: no cover - parser invariant
                raise WriteApplicationError(
                    code="approval_required",
                    message="A valid approval is required.",
                    odoo_effect="none",
                )
            return service.approve_execute(
                parsed.context,
                parsed.approval,
                reconciliation_only=payload["reconciliation_only"],
            )
        if action == "operation.status":
            operation = service.status(parsed.context, payload["operation_id"])
            return _operation_response(
                operation, next_action=_next_action(operation)
            )
        if action == "operation.result":
            return service.result(parsed.context, payload["operation_id"])
        if action == "operation.diagnostics":
            capability = next(
                (
                    item
                    for item in capabilities
                    if item.id == _DIAGNOSTICS_CAPABILITY_ID
                ),
                None,
            )
            if capability is None or capability.data.get("access") != "read":
                raise WriteApplicationError(
                    code="operation_diagnostics_registry_rejected",
                    message="The diagnostics capability is not registered as a read.",
                    odoo_effect="none",
                    operation_id=payload["operation_id"],
                    exit_code=5,
                )
            result_body = {
                **service.operation_diagnostics(
                    parsed.context,
                    company_id=payload["company_id"],
                    operation_id=payload["operation_id"],
                ),
                "page": {"count": 1, "total_count": 1},
            }
            observed_at = _utcnow()
            _unused_auth_secret, read_receipt_secret = load_runtime_secrets(
                config.base_runtime
            )
            parameters = {
                "company_id": payload["company_id"],
                "operation_id": payload["operation_id"],
            }
            receipt = create_read_receipt(
                receipt_id=str(uuid.uuid4()),
                capability_id=_DIAGNOSTICS_CAPABILITY_ID,
                parameters=parameters,
                result_body=result_body,
                auth_token_id=parsed.context.auth_token_id,
                principal=parsed.context.principal,
                odoo_instance_id=parsed.context.odoo_instance_id,
                database_name=parsed.context.database_name,
                database_uuid=parsed.context.database_uuid,
                company_id=parsed.context.company_id,
                user_id=parsed.context.user_id,
                registry_digest=observed_registry_digest,
                release_digest=release_digest,
                environment=parsed.context.environment,
                capability_channel=availability_channel,
                record_count=1,
                observed_at=observed_at,
                key_id=config.base_runtime.receipt_key_id,
                secret=read_receipt_secret,
            )
            result = {**result_body, "receipt": receipt}
            try:
                validate_value(result, capability.data["output_schema"])
            except ContractError as exc:
                raise WriteApplicationError(
                    code="operation_diagnostics_output_rejected",
                    message="The trusted diagnostics result violates its registered schema.",
                    odoo_effect="none",
                    operation_id=payload["operation_id"],
                    exit_code=5,
                ) from exc
            receipt_store = SQLitePersistence(
                config.base_runtime.receipt_state_path,
                receipt_key_id=config.base_runtime.receipt_key_id,
                receipt_secret=read_receipt_secret,
            )
            receipt_store.record_verified_read(
                receipt=receipt,
                capability_id=_DIAGNOSTICS_CAPABILITY_ID,
                parameters=parameters,
                result_body=result_body,
                auth_token_id=parsed.context.auth_token_id,
                principal=parsed.context.principal,
                odoo_instance_id=parsed.context.odoo_instance_id,
                database_name=parsed.context.database_name,
                database_uuid=parsed.context.database_uuid,
                company_id=parsed.context.company_id,
                user_id=parsed.context.user_id,
                registry_digest=observed_registry_digest,
                release_digest=release_digest,
                environment=parsed.context.environment,
                capability_channel=availability_channel,
                expected_record_count=1,
                now=observed_at,
            )
            return result
        if action == "operation.recover":
            prepared_recovery = service.prepare_recovery(
                parsed.context,
                **payload,
            )
            return {
                **_operation_response(
                    prepared_recovery["operation"],
                    next_action=prepared_recovery["next_action"],
                ),
                "origin_operation_id": prepared_recovery[
                    "origin_operation_id"
                ],
                "origin_operation_revision": prepared_recovery[
                    "origin_operation_revision"
                ],
                "recovery_plan_digest": prepared_recovery[
                    "recovery_plan_digest"
                ],
            }
        raise WriteApplicationError(
            code="invalid_write_action",
            message="The write action is not supported.",
            odoo_effect="none",
        )
    except WriteApplicationError as exc:
        if not odoo_write_attempted:
            raise
        raise WriteApplicationError(
            code=exc.code,
            message=exc.message,
            odoo_effect="unknown",
            operation_id=exc.operation_id or operation_id,
            state=_safe_state(store, exc.operation_id or operation_id) or exc.state,
            retryable=True,
            exit_code=exc.exit_code,
        ) from exc
    except Exception as exc:
        effect = "unknown" if odoo_write_attempted else "none"
        raise WriteApplicationError(
            code=(
                "odoo_write_outcome_unverified"
                if odoo_write_attempted
                else "write_lifecycle_rejected"
            ),
            message=(
                "The Odoo write may have been attempted but no verified result was accepted."
                if odoo_write_attempted
                else "The authenticated write lifecycle request was rejected before Odoo execution."
            ),
            odoo_effect=effect,
            operation_id=operation_id,
            state=_safe_state(store, operation_id),
            retryable=odoo_write_attempted,
        ) from exc
    finally:
        if finalizer_client is not None:
            try:
                finalizer_client.close()
            except Exception:
                pass


__all__ = [
    "WRITE_RUNTIME_CONFIG_PATH",
    "WriteApplicationError",
    "execute_write_action",
]
