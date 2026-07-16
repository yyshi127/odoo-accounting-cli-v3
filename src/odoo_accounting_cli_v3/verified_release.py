"""Public retained-release verification seam for the trusted broker runtime."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .odoo.runner import (
    RuntimeConfig,
    _validate_canonical_package_binding,
    load_runtime_secrets,
)
from .operations import Operation, canonical_json
from .registry import Capability, load_registry, registry_digest
from .trusted_authority_bootstrap import TrustedAuthorityRuntimeConfig
from .write_runtime import (
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
    load_write_runtime_secrets,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_FIELDS = frozenset(
    {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
        "verified",
        "version",
    }
)


class VerifiedReleaseError(ValueError):
    """One retained release could not be proven safe for broker use."""


@dataclass(frozen=True, slots=True)
class VerifiedReleaseRoute:
    """One immutable route with validated registry and purpose-specific keys."""

    release_digest: str
    registry_digest: str
    authority_config: TrustedAuthorityRuntimeConfig
    release_identity_json: str
    capabilities: tuple[Capability, ...]
    read_auth_secret: bytes = field(repr=False, compare=False)
    read_receipt_secret: bytes = field(repr=False, compare=False)
    write_secrets: WriteRuntimeSecrets = field(repr=False, compare=False)

    @property
    def release_identity(self) -> dict[str, Any]:
        return json.loads(self.release_identity_json)

    @property
    def write_runtime(self) -> WriteRuntimeConfig:
        return self.authority_config.write_runtime

    @property
    def base_runtime(self) -> RuntimeConfig:
        return self.write_runtime.base_runtime

    def approval_ttl_seconds(self, operation: Operation) -> int:
        """Resolve TTL only from this release's verified capability registry."""

        if (
            not isinstance(operation, Operation)
            or operation.release_digest != self.release_digest
            or operation.registry_digest != self.registry_digest
        ):
            raise VerifiedReleaseError("operation release route is invalid")
        capability = next(
            (item for item in self.capabilities if item.id == operation.capability_id),
            None,
        )
        approval = None if capability is None else capability.data.get("approval")
        ttl = None if not isinstance(approval, Mapping) else approval.get("ttl_seconds")
        if (
            capability is None
            or capability.data.get("access") != "write"
            or not isinstance(approval, Mapping)
            or approval.get("required") is not True
            or type(ttl) is not int
            or ttl <= 0
        ):
            raise VerifiedReleaseError("capability approval policy is invalid")
        return ttl

    def assert_executing_broker_source(
        self,
        module_file: str | Path,
        *,
        package_version: str,
    ) -> None:
        """Bind the running broker module to this manifest-verified release."""

        if (
            not isinstance(module_file, (str, Path))
            or not isinstance(package_version, str)
            or not package_version
        ):
            raise VerifiedReleaseError("executing broker identity is invalid")
        supplied = Path(module_file)
        expected = (
            self.base_runtime.release_root
            / "src"
            / "odoo_accounting_cli_v3"
            / "trusted_broker_app.py"
        )
        try:
            supplied_resolved = supplied.resolve(strict=True)
            expected_resolved = expected.resolve(strict=True)
        except OSError as exc:
            raise VerifiedReleaseError(
                "executing broker source is unavailable"
            ) from exc
        identity = self.release_identity
        if (
            supplied.is_symlink()
            or supplied_resolved != expected_resolved
            or identity.get("version") != package_version
            or identity.get("manifest_sha256") != self.release_digest
            or identity.get("registry_digest") != self.registry_digest
        ):
            raise VerifiedReleaseError(
                "executing broker source differs from the current release"
            )


def _identity(value: object) -> tuple[dict[str, Any], str]:
    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise VerifiedReleaseError("release identity is invalid") from exc
    if not isinstance(detached, dict) or set(detached) != _IDENTITY_FIELDS:
        raise VerifiedReleaseError("release identity fields are invalid")
    for field_name in ("manifest_sha256", "package_sha256", "registry_digest"):
        if (
            type(detached[field_name]) is not str
            or _SHA256.fullmatch(detached[field_name]) is None
        ):
            raise VerifiedReleaseError("release identity digest is invalid")
    for field_name in ("commit", "release", "version"):
        value = detached[field_name]
        if (
            type(value) is not str
            or not value.strip()
            or value != value.strip()
            or len(value) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise VerifiedReleaseError("release identity text is invalid")
    if detached["verified"] is not True:
        raise VerifiedReleaseError("release identity is not verified")
    return detached, canonical_json(detached).decode("utf-8")


def load_verified_release_route(
    authority_config: TrustedAuthorityRuntimeConfig,
    *,
    expected_release_digest: str,
    expected_registry_digest: str,
) -> VerifiedReleaseRoute:
    """Verify current or retained release without imposing current-source equality."""

    if (
        type(authority_config) is not TrustedAuthorityRuntimeConfig
        or type(expected_release_digest) is not str
        or _SHA256.fullmatch(expected_release_digest) is None
        or type(expected_registry_digest) is not str
        or _SHA256.fullmatch(expected_registry_digest) is None
    ):
        raise VerifiedReleaseError("verified release route arguments are invalid")
    write_runtime = authority_config.write_runtime
    if type(write_runtime) is not WriteRuntimeConfig or type(
        write_runtime.base_runtime
    ) is not RuntimeConfig:
        raise VerifiedReleaseError("verified release runtime is invalid")
    base = write_runtime.base_runtime
    try:
        _validate_canonical_package_binding(base)
        from .cli import _load_release_identity

        raw_identity = _load_release_identity(base.release_root, command="broker.start")
        identity, identity_json = _identity(raw_identity)
        capabilities = tuple(
            load_registry(base.release_root / "registry" / "capabilities.json")
        )
        read_secrets = load_runtime_secrets(base)
        write_secrets = load_write_runtime_secrets(write_runtime)
    except VerifiedReleaseError:
        raise
    except Exception as exc:
        raise VerifiedReleaseError("retained release verification failed") from exc
    if (
        identity["manifest_sha256"] != expected_release_digest
        or identity["registry_digest"] != expected_registry_digest
        or identity["package_sha256"] != base.canonical_package_sha256
        or identity["release"] != base.release_root.name
        or not capabilities
        or any(type(item) is not Capability for item in capabilities)
        or len({item.id for item in capabilities}) != len(capabilities)
        or registry_digest(capabilities) != expected_registry_digest
        or not isinstance(read_secrets, tuple)
        or len(read_secrets) != 2
        or any(type(secret) is not bytes or len(secret) < 32 for secret in read_secrets)
        or type(write_secrets) is not WriteRuntimeSecrets
    ):
        raise VerifiedReleaseError("retained release binding is invalid")
    return VerifiedReleaseRoute(
        release_digest=expected_release_digest,
        registry_digest=expected_registry_digest,
        authority_config=authority_config,
        release_identity_json=identity_json,
        capabilities=capabilities,
        read_auth_secret=read_secrets[0],
        read_receipt_secret=read_secrets[1],
        write_secrets=write_secrets,
    )


__all__ = [
    "VerifiedReleaseError",
    "VerifiedReleaseRoute",
    "load_verified_release_route",
]
